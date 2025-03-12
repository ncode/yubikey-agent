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

	for _, card := range cards {
		if strings.HasPrefix(strings.ToLower(card), "yubico") {
			device, err := piv.Open(card)
			if err != nil {
				return nil, err
			}
			serial, _ := device.Serial()
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

// storedKey holds a local (non-YubiKey) key in memory.
type storedKey struct {
	privateKey       interface{}      // The actual private key
	certificate      *ssh.Certificate // optional
	comment          string
	lifetimeSecs     uint32
	confirmBeforeUse bool
}

// Agent combines YubiKey-based keys with local ephemeral keys.
type Agent struct {
	mu sync.Mutex
	yk *Yubi

	touchNotification *time.Timer

	// Local key support:
	localKeys      map[string]*storedKey
	locked         bool
	lockPassphrase []byte
}

// Ensure Agent implements agent.ExtendedAgent
var _ agent.ExtendedAgent = &Agent{}

func NewAgent() *Agent {
	return &Agent{
		localKeys: make(map[string]*storedKey),
	}
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

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			a.Close()
		}
	}()

	// Remove any stale socket, then create its directory
	_ = os.Remove(socket)
	if err := os.MkdirAll(filepath.Dir(socket), 0777); err != nil {
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
			_ = a.yk.Device.Close()
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
	if a.touchNotification != nil && a.touchNotification.Stop() {
		defer a.touchNotification.Reset(5 * time.Second)
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
// The Combined Agent Methods
// ==================================

// List returns all public keys from both local ephemeral keys and the YubiKey.
func (a *Agent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked {
		return nil, errors.New("agent is locked")
	}

	var out []*agent.Key

	// 1) local ephemeral
	for _, sk := range a.localKeys {
		signer, err := ssh.NewSignerFromKey(sk.privateKey)
		if err != nil {
			continue
		}
		pub := signer.PublicKey()
		if sk.certificate != nil {
			pub = sk.certificate
		}
		out = append(out, &agent.Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: sk.comment,
		})
	}

	// 2) YubiKey-based
	if err := a.ensureYK(); err == nil {
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
	}

	return out, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked {
		return nil, errors.New("agent is locked")
	}

	pubKeyBlob := key.Marshal()

	// 1) Try local ephemeral keys
	if sk, found := a.localKeys[string(pubKeyBlob)]; found {
		signer, err := ssh.NewSignerFromKey(sk.privateKey)
		if err != nil {
			return nil, err
		}
		if sk.certificate != nil {
			signer, err = ssh.NewCertSigner(sk.certificate, signer)
			if err != nil {
				return nil, err
			}
		}
		alg := signer.PublicKey().Type()
		if alg == ssh.KeyAlgoRSA && (flags&agent.SignatureFlagRsaSha256 != 0) {
			alg = ssh.SigAlgoRSASHA2256
		} else if alg == ssh.KeyAlgoRSA && (flags&agent.SignatureFlagRsaSha512 != 0) {
			alg = ssh.SigAlgoRSASHA2512
		}
		if algorithmSigner, ok := signer.(ssh.AlgorithmSigner); ok {
			sig, err := algorithmSigner.SignWithAlgorithm(rand.Reader, data, alg)
			return sig, err
		}
		// fallback
		sig, err := signer.Sign(rand.Reader, data)
		return sig, err
	}

	// 2) Fallback to YubiKey-based
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	// Start a timer for "touch needed" notifications
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.touchNotification = time.NewTimer(5 * time.Second)
	go func() {
		select {
		case <-a.touchNotification.C:
			showNotification("Waiting for YubiKey touch...")
		case <-ctx.Done():
			a.touchNotification.Stop()
			return
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

// Signers returns a slice of signers (local ephemeral + YubiKey)
func (a *Agent) Signers() ([]ssh.Signer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked {
		return nil, errors.New("agent is locked")
	}

	var out []ssh.Signer

	// local ephemeral
	for _, sk := range a.localKeys {
		s, err := ssh.NewSignerFromKey(sk.privateKey)
		if err == nil {
			if sk.certificate != nil {
				s, _ = ssh.NewCertSigner(sk.certificate, s)
			}
			out = append(out, s)
		}
	}

	// YubiKey
	if err := a.ensureYK(); err == nil {
		ykSigners, err := a.signersYubi()
		if err == nil {
			out = append(out, ykSigners...)
		}
	}
	return out, nil
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

// Extension is unimplemented; you can implement or leave as-is.
func (a *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

// ======================
// Local Key Mgmt Methods
// ======================

// Add adds a new local ephemeral key to memory (e.g. from `ssh-add`).
func (a *Agent) Add(k agent.AddedKey) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked {
		return errors.New("agent is locked")
	}

	signer, err := ssh.NewSignerFromKey(k.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create signer: %v", err)
	}
	pubBlob := signer.PublicKey().Marshal()

	var cert *ssh.Certificate
	if k.Certificate != nil {
		cert = k.Certificate
	}

	a.localKeys[string(pubBlob)] = &storedKey{
		privateKey:       k.PrivateKey,
		certificate:      cert,
		comment:          k.Comment,
		lifetimeSecs:     k.LifetimeSecs,
		confirmBeforeUse: k.ConfirmBeforeUse,
	}
	return nil
}

// Remove removes a local ephemeral key from memory by its public key blob.
func (a *Agent) Remove(key ssh.PublicKey) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked {
		return errors.New("agent is locked")
	}
	pubBlob := key.Marshal()
	delete(a.localKeys, string(pubBlob))
	return nil
}

// RemoveAll removes all local ephemeral keys (but not hardware keys).
func (a *Agent) RemoveAll() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked {
		return errors.New("agent is locked")
	}
	a.localKeys = make(map[string]*storedKey)
	return nil
}

// Lock locks the agent so no operations can be done until unlocked.
func (a *Agent) Lock(passphrase []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.locked {
		return errors.New("agent is already locked")
	}
	a.locked = true
	a.lockPassphrase = append([]byte(nil), passphrase...) // store copy
	return nil
}

// Unlock unlocks the agent, allowing operations again.
func (a *Agent) Unlock(passphrase []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.locked {
		return errors.New("agent is not locked")
	}
	if !bytes.Equal(passphrase, a.lockPassphrase) {
		return errors.New("incorrect passphrase")
	}
	a.locked = false
	a.lockPassphrase = nil
	return nil
}
