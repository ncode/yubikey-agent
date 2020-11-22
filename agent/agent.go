// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

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
	"github.com/gopasspw/gopass/pkg/pinentry"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

var enabledSlots = []piv.Slot{
	piv.SlotAuthentication,
	piv.SlotSignature,
	piv.SlotKeyManagement,
	piv.SlotCardAuthentication,
}

// Yubi contains all the information about a YubiKey
type Yubi struct {
	Name   string
	Device *piv.YubiKey
	Serial uint32
}

// LoadYubiKeys load all connected YubiKeys, it's possible to filter and load only one passing the serial
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
			yk, err := piv.Open(card)
			if err != nil {
				return nil, err
			}
			serial, _ := yk.Serial()
			yubi := &Yubi{
				Name:   card,
				Serial: serial,
				Device: yk,
			}
			yubikeys = append(yubikeys, yubi)
		}
	}

	return yubikeys, err
}

// Run executes the agent using the specified socket path
func Run() {
	if _, err := exec.LookPath(pinentry.GetBinary()); err != nil {
		log.Fatalf("PIN entry program %q not found!", pinentry.GetBinary())
	}

	socket := viper.GetString("listen")

	log.Printf("Starting agent on socket %s...", socket)
	if terminal.IsTerminal(int(os.Stdin.Fd())) {
		log.Println("Warning: yubikey-agent is meant to run as a background daemon.")
		log.Println("Running multiple instances is likely to lead to conflicts.")
		log.Println("Consider using the launchd or systemd services.")
	}

	a := &Agent{}

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			a.Close()
		}
	}()

	os.Remove(socket)
	if err := os.MkdirAll(filepath.Dir(socket), 0777); err != nil {
		log.Fatalln("Failed to create UNIX socket folder:", err)
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		log.Fatalln("Failed to listen on UNIX socket:", err)
	}

	for {
		c, err := l.Accept()
		if err != nil {
			type temporary interface {
				Temporary() bool
			}
			if err, ok := err.(temporary); ok && err.Temporary() {
				log.Println("Temporary Accept error, sleeping 1s:", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Fatalln("Failed to accept connections:", err)
		}
		go a.serveConn(c)
	}
}

// Agent holds status of the current agent in use and
// all yubikeys associated with it
type Agent struct {
	mu     sync.Mutex
	yk     *piv.YubiKey
	serial uint32

	// touchNotification is armed by Sign to show a notification if waiting for
	// more than a few seconds for the touch operation. It is paused and reset
	// by getPIN so it won't fire while waiting for the PIN.
	touchNotification *time.Timer
}

var _ agent.ExtendedAgent = &Agent{}

func (a *Agent) serveConn(c net.Conn) {
	if err := agent.ServeAgent(a, c); err != io.EOF {
		log.Println("Agent client connection ended with error:", err)
	}
}

func healthy(yk *piv.YubiKey) bool {
	// We can't use Serial because it locks the session on older firmwares, and
	// can't use Retries because it fails when the session is unlocked.
	_, err := yk.AttestationCertificate()
	return err == nil
}

func (a *Agent) ensureYK() error {
	if a.yk == nil || !healthy(a.yk) {
		if a.yk != nil {
			log.Println("Reconnecting to the YubiKey...")
			a.yk.Close()
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

func (a *Agent) connectToYK() (*piv.YubiKey, error) {
	yubikeys, err := LoadYubiKeys()
	if err != nil {
		return nil, err
	}

	serial := viper.GetUint32("serial")
	if serial != 0 {
		for _, key := range yubikeys {
			if serial == key.Serial {
				a.serial = key.Serial
				return key.Device, nil
			}
		}
		return nil, fmt.Errorf("unable to find YubiKey with serial #%d", serial)
	} else if len(yubikeys) == 1 {
		return yubikeys[0].Device, nil
	}

	return nil, fmt.Errorf("unable to connect to any YubiKey device")
}

// Close finish the connection to the YubiKey device and unlock it
func (a *Agent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.yk != nil {
		log.Println("Received SIGHUP, dropping YubiKey transaction...")
		err := a.yk.Close()
		a.yk = nil
		return err
	}
	return nil
}

func (a *Agent) getPIN() (string, error) {
	if a.touchNotification != nil && a.touchNotification.Stop() {
		defer a.touchNotification.Reset(5 * time.Second)
	}
	p, err := pinentry.New()
	if err != nil {
		return "", fmt.Errorf("failed to start %q: %w", pinentry.GetBinary(), err)
	}
	defer p.Close()
	p.Set("title", "yubikey-agent PIN Prompt")
	var retries string
	if r, err := a.yk.Retries(); err == nil {
		retries = fmt.Sprintf(" (%d tries remaining)", r)
	}
	p.Set("desc", fmt.Sprintf("YubiKey serial number: %d"+retries, a.serial))
	p.Set("prompt", "Please enter your PIN:")

	// Enable opt-in external PIN caching (in the OS keychain).
	// https://gist.github.com/mdeguzis/05d1f284f931223624834788da045c65#file-info-pinentry-L324
	// p.Option("allow-external-password-cache")
	// p.Set("KEYINFO", fmt.Sprintf("--yubikey-id-%d", a.serial))

	pin, err := p.GetPin()
	return string(pin), err
}

func (a *Agent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	var keys []*agent.Key
	for _, slot := range enabledSlots {
		var pk ssh.PublicKey
		var err error
		pk, err = getPublicKey(a.yk, slot)
		if err != nil {
			continue
		}
		k := &agent.Key{
			Format:  pk.Type(),
			Blob:    pk.Marshal(),
			Comment: fmt.Sprintf("YubiKey #%d PIV Slot %x", a.serial, slot.Key),
		}
		keys = append(keys, k)
	}
	return keys, nil
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

func (a *Agent) Signers() ([]ssh.Signer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	return a.signers()
}

func (a *Agent) signers() ([]ssh.Signer, error) {
	var signers []ssh.Signer
	for _, slot := range enabledSlots {
		pk, err := getPublicKey(a.yk, slot)
		if err != nil {
			continue
		}
		priv, err := a.yk.PrivateKey(
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

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.touchNotification = time.NewTimer(5 * time.Second)
	go func() {
		select {
		case <-a.touchNotification.C:
		case <-ctx.Done():
			a.touchNotification.Stop()
			return
		}
		showNotification("Waiting for YubiKey touch...")
	}()

	for {
		signers, err := a.signers()
		if err != nil {
			return nil, err
		}
		for _, s := range signers {
			if !bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
				continue
			}

			alg := key.Type()
			switch {
			case alg == ssh.KeyAlgoRSA && flags&agent.SignatureFlagRsaSha256 != 0:
				alg = ssh.SigAlgoRSASHA2256
			case alg == ssh.KeyAlgoRSA && flags&agent.SignatureFlagRsaSha512 != 0:
				alg = ssh.SigAlgoRSASHA2512
			}

			var sg *ssh.Signature
			sg, err = s.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, data, alg)
			if err != nil {
				break
			}

			return sg, err
		}
		if err == nil {
			return nil, fmt.Errorf("no private keys match the requested public key")
		} else if strings.Contains(err.Error(), "remaining") {
			continue
		}
		return nil, err
	}
}

func showNotification(message string) {
	switch runtime.GOOS {
	case "darwin":
		message = strings.ReplaceAll(message, `\`, `\\`)
		message = strings.ReplaceAll(message, `"`, `\"`)
		appleScript := `display notification "%s" with title "yubikey-agent"`
		exec.Command("osascript", "-e", fmt.Sprintf(appleScript, message)).Run()
	case "linux":
		exec.Command("notify-send", "-i", "dialog-password", "yubikey-agent", message).Run()
	}
}

func (a *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

var ErrOperationUnsupported = errors.New("operation unsupported")

func (a *Agent) Add(key agent.AddedKey) error {
	return ErrOperationUnsupported
}
func (a *Agent) Remove(key ssh.PublicKey) error {
	return ErrOperationUnsupported
}
func (a *Agent) RemoveAll() error {
	return ErrOperationUnsupported
}
func (a *Agent) Lock(passphrase []byte) error {
	return ErrOperationUnsupported
}
func (a *Agent) Unlock(passphrase []byte) error {
	return ErrOperationUnsupported
}
