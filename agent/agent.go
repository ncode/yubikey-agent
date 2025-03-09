// Copyright 2020 Google LLC
// Copyright 2025 Juliano Martinez <juliano@martinez.io>
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

	"github.com/go-piv/piv-go/v2/piv"
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

// Yubi contains all the information about a YubiKey
type Yubi struct {
	Name   string
	Device *piv.YubiKey
	Serial uint32
}

// LoadYubiKeys loads all connected YubiKeys, but if a `--serial` is provided,
// only the matching YubiKey will be returned. This ensures we never "touch"
// any other YubiKeys if `serial` is set.
func LoadYubiKeys() ([]*Yubi, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		return nil, errors.New("no smart card detected")
	}

	serial := viper.GetUint32("serial")
	var yubikeys []*Yubi

	for _, card := range cards {
		// Only consider Yubico cards
		if !strings.HasPrefix(strings.ToLower(card), "yubico") {
			continue
		}
		device, err := piv.Open(card)
		if err != nil {
			// Could not open this card; skip
			continue
		}
		sn, _ := device.Serial()

		// If a serial is provided and this doesn't match, skip this device entirely.
		if serial != 0 && sn != serial {
			device.Close()
			continue
		}

		yubikeys = append(yubikeys, &Yubi{
			Name:   card,
			Serial: sn,
			Device: device,
		})

		// If we were looking for a specific serial, we can stop early after finding it.
		if serial != 0 {
			break
		}
	}

	// If we have none, return an appropriate error message.
	if len(yubikeys) == 0 {
		if serial != 0 {
			return nil, fmt.Errorf("unable to find YubiKey with serial #%d", serial)
		}
		return nil, errors.New("unable to connect to any YubiKey device")
	}
	return yubikeys, nil
}

// Run executes the agent using the specified socket path
func Run() {
	socket := viper.GetString("listen")

	log.Printf("Starting agent on socket %s...", socket)
	if term.IsTerminal(int(os.Stdin.Fd())) {
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
		conn, err := l.Accept()
		if err != nil {
			type temporary interface {
				Temporary() bool
			}
			if terr, ok := err.(temporary); ok && terr.Temporary() {
				log.Println("Temporary Accept error, sleeping 1s:", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Fatalln("Failed to accept connections:", err)
		}
		go a.serveConn(conn)
	}
}

// Agent holds status of the current agent in use and
// all yubikeys associated with it
type Agent struct {
	mu sync.Mutex

	// Instead of a single YubiKey, store all discovered YubiKeys:
	yks []*Yubi

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

// ensureYK checks if we still have healthy connections to our YubiKeys,
// and reconnects if necessary.
func (a *Agent) ensureYK() error {
	// If we have at least one YubiKey, check if they're all healthy:
	if len(a.yks) > 0 {
		allHealthy := true
		for _, yk := range a.yks {
			if !healthy(yk.Device) {
				allHealthy = false
				break
			}
		}
		if allHealthy {
			return nil
		}
		// If any device isn't healthy, close and reload them all
		for _, yk := range a.yks {
			_ = yk.Device.Close()
		}
		a.yks = nil
		log.Println("Reconnecting to the YubiKeys...")
	}

	// (Re)load
	yks, err := a.connectToAllYubi()
	if err != nil {
		return err
	}
	a.yks = yks
	return nil
}

// connectToAllYubi simply calls LoadYubiKeys() to retrieve
// either the one matching serial or all if no serial is set.
func (a *Agent) connectToAllYubi() ([]*Yubi, error) {
	return LoadYubiKeys()
}

// Close finishes the connection to the YubiKey devices.
func (a *Agent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.yks) > 0 {
		log.Println("Received SIGHUP, dropping YubiKey transaction(s)...")
		for _, yk := range a.yks {
			_ = yk.Device.Close()
		}
		a.yks = nil
	}
	return nil
}

// List returns a list of all available keys from all YubiKeys.
func (a *Agent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKeys: %w", err)
	}

	var keys []*agent.Key
	for _, yk := range a.yks {
		for _, slot := range enabledSlots {
			pk, err := getPublicKey(yk.Device, slot)
			if err != nil {
				continue
			}
			k := &agent.Key{
				Format:  pk.Type(),
				Blob:    pk.Marshal(),
				Comment: fmt.Sprintf("%s #%d PIV Slot %x", yk.Name, yk.Serial, slot.Key),
			}
			keys = append(keys, k)
		}
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

// Signers returns signers for all available keys on all YubiKeys.
func (a *Agent) Signers() ([]ssh.Signer, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKeys: %w", err)
	}

	return a.signers()
}

// getPINFor returns a function that prompts for the PIN for a specific YubiKey.
func (a *Agent) getPINFor(yk *Yubi) func() (string, error) {
	return func() (string, error) {
		if a.touchNotification != nil && a.touchNotification.Stop() {
			defer a.touchNotification.Reset(5 * time.Second)
		}
		r, _ := yk.Device.Retries()
		return getPIN(yk.Serial, r)
	}
}

// signers gathers signers from all loaded YubiKeys.
func (a *Agent) signers() ([]ssh.Signer, error) {
	var signers []ssh.Signer
	for _, yk := range a.yks {
		for _, slot := range enabledSlots {
			pk, err := getPublicKey(yk.Device, slot)
			if err != nil {
				continue
			}
			priv, err := yk.Device.PrivateKey(
				slot,
				pk.(ssh.CryptoPublicKey).CryptoPublicKey(),
				piv.KeyAuth{PINPrompt: a.getPINFor(yk)},
			)
			if err != nil {
				continue
			}
			s, err := ssh.NewSignerFromKey(priv)
			if err != nil {
				return nil, fmt.Errorf("failed to prepare signer from slot %x: %w", slot, err)
			}
			signers = append(signers, s)
		}
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
		return nil, fmt.Errorf("could not reach YubiKeys: %w", err)
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
			case alg == ssh.KeyAlgoRSA && (flags&agent.SignatureFlagRsaSha256 != 0):
				alg = ssh.SigAlgoRSASHA2256
			case alg == ssh.KeyAlgoRSA && (flags&agent.SignatureFlagRsaSha512 != 0):
				alg = ssh.SigAlgoRSASHA2512
			}

			sg, err := s.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, data, alg)
			if err != nil {
				// If the PIN prompt indicated we still have retries left, try again
				if strings.Contains(err.Error(), "remaining") {
					continue
				}
				return nil, err
			}
			return sg, nil
		}
		// If we found no matching private key, return an error.
		return nil, fmt.Errorf("no private keys match the requested public key")
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
