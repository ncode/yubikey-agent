package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-piv/piv-go/piv"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

var enabledSlots = []piv.Slot{
	piv.SlotAuthentication,
	piv.SlotSignature,
	piv.SlotKeyManagement,
	piv.SlotCardAuthentication,
}

// Yubi contains information about a YubiKey
type Yubi struct {
	Name   string
	Device *piv.YubiKey
	Serial uint32
}

// LoadYubiKeys loads all connected YubiKeys.
func LoadYubiKeys() (yubikeys []*Yubi, err error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		return nil, errors.New("no smart card detected")
	}

	// Track opened devices for cleanup on error
	var openedDevices []*piv.YubiKey
	defer func() {
		if err != nil {
			// Close all opened devices if we're returning an error
			for _, d := range openedDevices {
				if closeErr := d.Close(); closeErr != nil {
					log.Printf("Warning: failed to close device during cleanup: %v", closeErr)
				}
			}
		}
	}()

	for _, card := range cards {
		if strings.HasPrefix(strings.ToLower(card), "yubico") {
			device, err := piv.Open(card)
			if err != nil {
				return nil, fmt.Errorf("failed to open device %s: %w", card, err)
			}
			openedDevices = append(openedDevices, device)

			serial, err := device.Serial()
			if err != nil {
				// Log the error but continue with serial 0
				log.Printf("Warning: failed to get serial for %s: %v", card, err)
			}
			yubi := &Yubi{
				Name:   card,
				Serial: serial,
				Device: device,
			}
			yubikeys = append(yubikeys, yubi)
		}
	}

	return yubikeys, nil
}

// Agent manages YubiKey-based SSH keys.
type Agent struct {
	mu sync.Mutex
	yk *Yubi

	touchNotification *time.Timer
	touchMu           sync.Mutex // Separate mutex for touch notification
}

// Ensure Agent implements agent.Agent
var _ agent.Agent = &Agent{}

func NewAgent() *Agent {
	return &Agent{}
}

// Run starts the agent listening on a Unix socket specified by `listen`.
func Run() {
	socket := viper.GetString("listen")

	log.Printf("Starting agent on socket %s...", socket)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		log.Println("Warning: yubikey-agent is meant to run as a background daemon.")
		log.Println("Running multiple instances is likely to lead to conflicts.")
		log.Println("Consider using launchd or systemd services.")
	}

	a := NewAgent()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			a.Close()
		}
	}()

	// Remove any stale socket, then create its directory
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: failed to remove stale socket: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		log.Fatalln("Failed to create UNIX socket folder:", err)
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		log.Fatalln("Failed to listen on UNIX socket:", err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			type temporary interface {
				Temporary() bool
			}
			if te, ok := err.(temporary); ok && te.Temporary() {
				log.Println("Temporary Accept error, sleeping 1s:", err)
				time.Sleep(time.Second)
				continue
			}
			log.Fatalln("Failed to accept connections:", err)
		}
		go a.serveConn(conn)
	}
}

func (a *Agent) serveConn(c net.Conn) {
	if err := agent.ServeAgent(a, c); err != nil && err != io.EOF {
		log.Println("Agent client connection ended with error:", err)
	}
}

// Close disconnects from YubiKey device
func (a *Agent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Also clean up touch notification
	a.touchMu.Lock()
	if a.touchNotification != nil {
		a.touchNotification.Stop()
		a.touchNotification = nil
	}
	a.touchMu.Unlock()

	if a.yk != nil {
		log.Println("Received SIGHUP, dropping YubiKey transaction...")
		err := a.yk.Device.Close()
		a.yk = nil
		return err
	}
	return nil
}

// ==================================
// YubiKey logic
// ==================================

func healthy(yk *piv.YubiKey) bool {
	_, err := yk.AttestationCertificate()
	return err == nil
}

func (a *Agent) ensureYK() error {
	if a.yk == nil || !healthy(a.yk.Device) {
		if a.yk != nil {
			log.Println("Reconnecting to the YubiKey...")
			if err := a.yk.Device.Close(); err != nil {
				log.Printf("Warning: failed to close previous YubiKey connection: %v", err)
			}
		} else {
			log.Println("Connecting to the YubiKey...")
		}
		yk, err := a.connectToYK()
		if err != nil {
			return err
		}
		a.yk = yk
	}
	return nil
}

func (a *Agent) connectToYK() (*Yubi, error) {
	yubikeys, err := LoadYubiKeys()
	if err != nil {
		return nil, err
	}
	serial := viper.GetUint32("serial")
	if serial != 0 {
		for _, yk := range yubikeys {
			if serial == yk.Serial {
				return yk, nil
			}
		}
		return nil, fmt.Errorf("unable to find YubiKey with serial #%d", serial)
	} else if len(yubikeys) == 1 {
		return yubikeys[0], nil
	}
	return nil, fmt.Errorf("unable to connect to any YubiKey device")
}

func getPublicKey(yk *piv.YubiKey, slot piv.Slot) (ssh.PublicKey, error) {
	cert, err := yk.Certificate(slot)
	if err != nil {
		return nil, fmt.Errorf("could not get public key from slot %x: %w", slot.Key, err)
	}
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
	case *rsa.PublicKey:
	default:
		return nil, fmt.Errorf("unexpected public key type: %T", cert.PublicKey)
	}
	pk, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to process public key: %w", err)
	}
	return pk, nil
}

func (a *Agent) getPIN() (string, error) {
	// Use separate mutex for touch notification
	a.touchMu.Lock()
	if a.touchNotification != nil && a.touchNotification.Stop() {
		defer func() {
			a.touchNotification.Reset(5 * time.Second)
			a.touchMu.Unlock()
		}()
	} else {
		a.touchMu.Unlock()
	}

	r, _ := a.yk.Device.Retries()
	// NOTE: getPIN is implemented in prompt_darwin.go or prompt_pinentry.go
	return getPIN(a.yk.Serial, r)
}

func (a *Agent) signersYubi() ([]ssh.Signer, error) {
	var signers []ssh.Signer
	for _, slot := range enabledSlots {
		pk, err := getPublicKey(a.yk.Device, slot)
		if err != nil {
			continue
		}
		priv, err := a.yk.Device.PrivateKey(
			slot,
			pk.(ssh.CryptoPublicKey).CryptoPublicKey(),
			piv.KeyAuth{PINPrompt: a.getPIN},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare private key from slot %x: %w", slot, err)
		}
		s, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare signer from slot %x: %w", slot, err)
		}
		signers = append(signers, s)
	}
	return signers, nil
}

// ==================================
// Agent Methods
// ==================================

// List returns all public keys from the YubiKey.
func (a *Agent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var out []*agent.Key

	if err := a.ensureYK(); err != nil {
		return nil, err
	}

	for _, slot := range enabledSlots {
		pk, err := getPublicKey(a.yk.Device, slot)
		if err != nil {
			continue
		}
		comment := fmt.Sprintf("%s #%d PIV Slot %x", a.yk.Name, a.yk.Serial, slot.Key)
		out = append(out, &agent.Key{
			Format:  pk.Type(),
			Blob:    pk.Marshal(),
			Comment: comment,
		})
	}

	return out, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	pubKeyBlob := key.Marshal()

	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	// Start a timer for "touch needed" notifications
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a.touchMu.Lock()
	a.touchNotification = time.NewTimer(5 * time.Second)
	a.touchMu.Unlock()

	defer func() {
		a.touchMu.Lock()
		if a.touchNotification != nil {
			a.touchNotification.Stop()
			a.touchNotification = nil
		}
		a.touchMu.Unlock()
	}()

	go func() {
		a.touchMu.Lock()
		timer := a.touchNotification
		a.touchMu.Unlock()

		if timer != nil {
			select {
			case <-timer.C:
				showNotification("Waiting for YubiKey touch...")
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		signers, err := a.signersYubi()
		if err != nil {
			return nil, err
		}
		foundMatch := false
		for _, s := range signers {
			if bytes.Equal(s.PublicKey().Marshal(), pubKeyBlob) {
				foundMatch = true
				alg := key.Type()
				if alg == ssh.KeyAlgoRSA && (flags&agent.SignatureFlagRsaSha256 != 0) {
					alg = ssh.SigAlgoRSASHA2256
				} else if alg == ssh.KeyAlgoRSA && (flags&agent.SignatureFlagRsaSha512 != 0) {
					alg = ssh.SigAlgoRSASHA2512
				}
				if algorithmSigner, ok := s.(ssh.AlgorithmSigner); ok {
					sig, sErr := algorithmSigner.SignWithAlgorithm(rand.Reader, data, alg)
					if sErr != nil {
						// e.g. "remaining tries"
						if strings.Contains(sErr.Error(), "remaining") {
							continue
						}
						return nil, sErr
					}
					return sig, nil
				}
				// fallback
				sig, sErr := s.Sign(rand.Reader, data)
				return sig, sErr
			}
		}
		if !foundMatch {
			return nil, fmt.Errorf("no private keys match the requested public key")
		}
	}
}

// Signers returns a slice of signers from the YubiKey
func (a *Agent) Signers() ([]ssh.Signer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := a.ensureYK(); err != nil {
		return nil, err
	}

	return a.signersYubi()
}

// showNotification is used to show a desktop notification after waiting 5s for YubiKey touch.
func showNotification(message string) {
	switch runtime.GOOS {
	case "darwin":
		message = strings.ReplaceAll(message, `\`, `\\`)
		message = strings.ReplaceAll(message, `"`, `\"`)
		appleScript := `display notification "%s" with title "yubikey-agent"`
		_ = exec.Command("osascript", "-e", fmt.Sprintf(appleScript, message)).Run()
	case "linux":
		_ = exec.Command("notify-send", "-i", "dialog-password", "yubikey-agent", message).Run()
	}
}

// Add returns an error as we only support YubiKey keys.
func (a *Agent) Add(key agent.AddedKey) error {
	return fmt.Errorf("yubikey-agent: adding keys is not supported, only YubiKey keys are available")
}

// Remove returns an error as we only support YubiKey keys.
func (a *Agent) Remove(key ssh.PublicKey) error {
	return fmt.Errorf("yubikey-agent: removing keys is not supported, only YubiKey keys are available")
}

// RemoveAll returns success as there are no keys to remove (YubiKey keys cannot be removed).
func (a *Agent) RemoveAll() error {
	return nil
}

// Lock returns an error as locking is not supported for YubiKey-only agent.
func (a *Agent) Lock(passphrase []byte) error {
	return fmt.Errorf("yubikey-agent: locking is not supported")
}

// Unlock returns an error as locking is not supported for YubiKey-only agent.
func (a *Agent) Unlock(passphrase []byte) error {
	return fmt.Errorf("yubikey-agent: locking is not supported")
}
