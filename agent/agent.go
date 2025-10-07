// Copyright 2020 Google LLC
// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

// Package agent implements an SSH agent that uses YubiKey PIV tokens for key operations.
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

const (
	// TouchNotificationTimeout is how long to wait before showing a touch notification
	TouchNotificationTimeout = 5 * time.Second

	// TemporaryErrorRetryDelay is how long to wait before retrying after a temporary error
	TemporaryErrorRetryDelay = time.Second

	// SocketDirPermissions is the permission mode for the socket directory
	SocketDirPermissions = 0700

	// SignOperationTimeout is the maximum time allowed for a sign operation
	// This prevents indefinite blocking waiting for YubiKey touch
	SignOperationTimeout = 2 * time.Minute
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
	return LoadYubiKeysContext(context.Background())
}

// LoadYubiKeysContext loads all connected YubiKeys with context support.
// If ctx is cancelled during loading, it returns ctx.Err().
func LoadYubiKeysContext(ctx context.Context) ([]*Yubi, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return nil, err
	}

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
		// Check context before each card
		if err := ctx.Err(); err != nil {
			// Clean up any already-opened devices
			for _, yk := range yubikeys {
				yk.Device.Close()
			}
			return nil, err
		}

		yk, err := tryOpenYubiKey(card, serial)
		if err != nil {
			// Log and skip this card
			log.Printf("Skipping card %s: %v", card, err)
			continue
		}
		if yk == nil {
			// This card was filtered out (wrong serial), already closed
			continue
		}

		yubikeys = append(yubikeys, yk)

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

// tryOpenYubiKey attempts to open and validate a single YubiKey card.
// Returns nil, nil if the card should be skipped (e.g., wrong serial).
// Returns nil, error if there was an error opening the card.
// Returns *Yubi, nil if the card was successfully opened and validated.
func tryOpenYubiKey(card string, filterSerial uint32) (*Yubi, error) {
	// Only consider Yubico cards
	if !strings.HasPrefix(strings.ToLower(card), "yubico") {
		return nil, nil
	}

	device, err := piv.Open(card)
	if err != nil {
		return nil, fmt.Errorf("failed to open: %w", err)
	}

	// Ensure device is closed if we don't return it successfully
	var yk *Yubi
	defer func() {
		if yk == nil {
			device.Close()
		}
	}()

	sn, err := device.Serial()
	if err != nil {
		// Log warning but continue with serial 0
		log.Printf("Warning: failed to get serial for %s: %v", card, err)
		sn = 0
	}

	// If a serial is provided and this doesn't match, filter it out
	if filterSerial != 0 && sn != filterSerial {
		return nil, nil
	}

	yk = &Yubi{
		Name:   card,
		Serial: sn,
		Device: device,
	}
	return yk, nil
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

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			a.Close()
		}
	}()

	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: failed to remove stale socket: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(socket), SocketDirPermissions); err != nil {
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
				time.Sleep(TemporaryErrorRetryDelay)
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
	mu sync.RWMutex

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

// healthy checks if the YubiKey connection is still functional.
// We can't use Serial because it locks the session on older firmwares, and
// can't use Retries because it fails when the session is unlocked.
func (y *Yubi) healthy() bool {
	_, err := y.Device.AttestationCertificate()
	return err == nil
}

// ensureYK checks if we still have healthy connections to our YubiKeys,
// and reconnects if necessary.
func (a *Agent) ensureYK() error {
	// If we have at least one YubiKey, check if they're all healthy:
	if len(a.yks) > 0 {
		allHealthy := true
		for _, yk := range a.yks {
			if !yk.healthy() {
				allHealthy = false
				break
			}
		}
		if allHealthy {
			return nil
		}
		// If any device isn't healthy, close and reload them all
		for _, yk := range a.yks {
			if err := yk.Device.Close(); err != nil {
				log.Printf("Warning: failed to close unhealthy YubiKey %s: %v", yk.Name, err)
			}
		}
		a.yks = nil
		log.Println("Reconnecting to the YubiKeys...")
	}

	// (Re)load
	yks, err := LoadYubiKeys()
	if err != nil {
		return err
	}
	a.yks = yks
	return nil
}

// Close finishes the connection to the YubiKey devices.
func (a *Agent) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Stop any pending touch notification
	if a.touchNotification != nil {
		a.touchNotification.Stop()
	}

	if len(a.yks) > 0 {
		log.Println("Received SIGHUP, dropping YubiKey transaction(s)...")
		for _, yk := range a.yks {
			if err := yk.Device.Close(); err != nil {
				log.Printf("Warning: failed to close YubiKey %s: %v", yk.Name, err)
			}
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
			defer a.touchNotification.Reset(TouchNotificationTimeout)
		}
		r, err := yk.Device.Retries()
		if err != nil {
			log.Printf("Warning: failed to get retries: %v", err)
			r = 0
		}
		return getPIN(yk.Serial, r)
	}
}

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

// setupTouchNotification sets up a timer to show a notification if YubiKey touch is needed
func (a *Agent) setupTouchNotification() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	a.touchNotification = time.NewTimer(TouchNotificationTimeout)
	go func() {
		select {
		case <-a.touchNotification.C:
		case <-ctx.Done():
			a.touchNotification.Stop()
			return
		}
		showNotification("Waiting for YubiKey touch...")
	}()
	return ctx, cancel
}

// signatureAlgorithm determines the signature algorithm based on key type and flags
func signatureAlgorithm(key ssh.PublicKey, flags agent.SignatureFlags) string {
	alg := key.Type()
	switch {
	case alg == ssh.KeyAlgoRSA && (flags&agent.SignatureFlagRsaSha256 != 0):
		return ssh.SigAlgoRSASHA2256
	case alg == ssh.KeyAlgoRSA && (flags&agent.SignatureFlagRsaSha512 != 0):
		return ssh.SigAlgoRSASHA2512
	default:
		return alg
	}
}

// performSignature attempts to sign data with the matching signer
func (a *Agent) performSignature(signers []ssh.Signer, key ssh.PublicKey, data []byte, alg string) (*ssh.Signature, error) {
	keyBlob := key.Marshal()
	for _, s := range signers {
		if !bytes.Equal(s.PublicKey().Marshal(), keyBlob) {
			continue
		}

		sg, err := s.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, data, alg)
		if err != nil {
			// If the PIN prompt indicated we still have retries left, try again
			if strings.Contains(err.Error(), "remaining") {
				return nil, err // Let caller retry
			}
			return nil, err
		}
		return sg, nil
	}
	return nil, fmt.Errorf("no private keys match the requested public key")
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKeys: %w", err)
	}

	// Create context with timeout for the entire sign operation
	ctx, cancel := context.WithTimeout(context.Background(), SignOperationTimeout)
	defer cancel()

	// Set up touch notification
	_, cancelTouch := a.setupTouchNotification()
	defer cancelTouch()

	alg := signatureAlgorithm(key, flags)

	// Channel to receive signature result
	type result struct {
		sig *ssh.Signature
		err error
	}
	resultCh := make(chan result, 1)

	go func() {
		for {
			signers, err := a.signers()
			if err != nil {
				resultCh <- result{nil, err}
				return
			}

			sig, err := a.performSignature(signers, key, data, alg)
			if err != nil && strings.Contains(err.Error(), "remaining") {
				// Retry if PIN failed but we have retries left
				continue
			}
			resultCh <- result{sig, err}
			return
		}
	}()

	// Wait for either result or timeout
	select {
	case res := <-resultCh:
		return res.sig, res.err
	case <-ctx.Done():
		return nil, fmt.Errorf("sign operation timed out after %v (touch required?): %w", SignOperationTimeout, ctx.Err())
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
