// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/spf13/viper"
)

type setupTestDevice struct {
	*piv.YubiKey
	certs     map[piv.Slot]bool
	keys      map[piv.Slot]bool
	probeErr  error
	version   piv.Version
	mutations int
}

type incrementalTestDevice struct {
	setupTestDevice
	metadata          *piv.Metadata
	metadataErr       error
	metadataPIN       string
	public            crypto.PublicKey
	generatedKey      []byte
	storedCertificate bool
}

func (d *incrementalTestDevice) Metadata(pin string) (*piv.Metadata, error) {
	d.metadataPIN = pin
	return d.metadata, d.metadataErr
}
func (d *incrementalTestDevice) GenerateKey(key []byte, _ piv.Slot, _ piv.Key) (crypto.PublicKey, error) {
	d.generatedKey = key
	return d.public, nil
}
func (d *incrementalTestDevice) SetCertificate(_ []byte, _ piv.Slot, _ *x509.Certificate) error {
	d.storedCertificate = true
	return nil
}

func TestSetupSlotUsesCurrentPINForMetadata(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 24)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := &incrementalTestDevice{metadata: &piv.Metadata{ManagementKey: &key}, public: &priv.PublicKey}
	prompted := false
	err = setupSlot(d, piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyAlways,
		func() (string, error) { prompted = true; return "87654321", nil },
		func() ([]byte, error) {
			t.Error("prompted to reset a configured device")
			return nil, errors.New("unexpected new PIN")
		})
	if err != nil {
		t.Fatal(err)
	}
	if !prompted || d.metadataPIN != "87654321" {
		t.Errorf("prompted = %v, metadata PIN = %q", prompted, d.metadataPIN)
	}
	if !bytes.Equal(d.generatedKey, key) || !d.storedCertificate || d.mutations != 0 {
		t.Error("did not reuse the stored management key without changing credentials")
	}
}

func TestSetupSlotDoesNotReinitializeOnMetadataError(t *testing.T) {
	sentinel := errors.New("incorrect PIN")
	d := &incrementalTestDevice{metadataErr: sentinel}
	prompted := false
	err := setupSlot(d, piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyAlways,
		func() (string, error) { return "87654321", nil },
		func() ([]byte, error) { prompted = true; return nil, errors.New("unexpected new PIN") })
	if !errors.Is(err, sentinel) || prompted || d.mutations != 0 {
		t.Errorf("error = %v, new PIN prompted = %v, mutations = %d", err, prompted, d.mutations)
	}
}

func (d *setupTestDevice) Certificate(s piv.Slot) (*x509.Certificate, error) {
	if d.certs[s] {
		return &x509.Certificate{}, nil
	}
	return nil, piv.ErrNotFound
}
func (d *setupTestDevice) KeyInfo(s piv.Slot) (piv.KeyInfo, error) {
	if d.probeErr != nil {
		return piv.KeyInfo{}, d.probeErr
	}
	if d.keys[s] {
		return piv.KeyInfo{Algorithm: piv.AlgorithmEC256}, nil
	}
	return piv.KeyInfo{}, piv.ErrNotFound
}
func (d *setupTestDevice) Version() piv.Version { return d.version }
func (d *setupTestDevice) SetManagementKey(_, _ []byte) error {
	d.mutations++
	return errors.New("stop before mutation")
}

func TestSetupPreservesExistingSlots(t *testing.T) {
	for _, slot := range enabledSlots {
		for _, certificate := range []bool{true, false} {
			t.Run(fmt.Sprintf("slot_%x/certificate_%v", slot.Key, certificate), func(t *testing.T) {
				d := &setupTestDevice{certs: map[piv.Slot]bool{slot: certificate}, keys: map[piv.Slot]bool{slot: true}, version: piv.Version{Major: 5, Minor: 3}}
				prompted := false
				err := runSetup(d, func() ([]byte, error) { prompted = true; return nil, errors.New("unexpected PIN prompt") }, false)
				if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%x", slot.Key)) {
					t.Errorf("error = %v, want occupied slot %x", err, slot.Key)
				}
				if prompted || d.mutations != 0 {
					t.Errorf("prompted = %v, mutations = %d before detecting existing key", prompted, d.mutations)
				}
			})
		}
	}
}

func TestSetupFailsClosedWhenSlotInspectionFails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version piv.Version
		err     error
	}{
		{"reader error", piv.Version{Major: 5, Minor: 3}, errors.New("reader disconnected")},
		{"older firmware", piv.Version{Major: 4, Minor: 3}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &setupTestDevice{version: tc.version, probeErr: tc.err}
			prompted := false
			err := runSetup(d, func() ([]byte, error) { prompted = true; return nil, errors.New("unexpected PIN prompt") }, false)
			if err == nil || prompted || d.mutations != 0 {
				t.Errorf("error = %v, prompted = %v, mutations = %d", err, prompted, d.mutations)
			}
		})
	}
}

func TestGetSingleYubiKeyClosesRejectedDevices(t *testing.T) {
	viper.Set("serial", uint32(0))
	defer viper.Set("serial", nil)
	source := &testYubiSource{cards: []string{"A", "B"}, devices: map[string]*Yubi{"A": {Name: "A"}, "B": {Name: "B"}}}
	if _, err := getSingleYubiKeyContext(context.Background(), source); err == nil {
		t.Fatal("accepted multiple devices")
	}
	if len(source.closed) != 2 {
		t.Fatalf("closed %v, want both devices", source.closed)
	}
}

func TestSetupSlotMissingMetadataDoesNotChangeCustomCredentials(t *testing.T) {
	d := &incrementalTestDevice{metadata: &piv.Metadata{}}
	prompted := false
	err := setupSlot(d, piv.SlotAuthentication, piv.PINPolicyOnce, piv.TouchPolicyAlways,
		func() (string, error) { return "87654321", nil },
		func() ([]byte, error) { prompted = true; return []byte("12345678"), nil })
	if err == nil || prompted || d.mutations != 0 {
		t.Fatalf("error = %v, prompted = %v, mutations = %d", err, prompted, d.mutations)
	}
}

func TestSetupEmptyDeviceReachesPINPrompt(t *testing.T) {
	for _, reset := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicitly_reset_%v", reset), func(t *testing.T) {
			version := piv.Version{Major: 5, Minor: 3}
			if reset {
				version = piv.Version{Major: 4, Minor: 3}
			}
			d := &setupTestDevice{version: version}
			stopped := errors.New("stop before provisioning")
			err := runSetup(d, func() ([]byte, error) { return nil, stopped }, reset)
			if !errors.Is(err, stopped) || d.mutations != 0 {
				t.Fatalf("error = %v, mutations = %d", err, d.mutations)
			}
		})
	}
}

// TestRandomSerialNumber tests that randomSerialNumber generates valid serial numbers
func TestRandomSerialNumber(t *testing.T) {
	serial, err := randomSerialNumber()
	if err != nil {
		t.Fatalf("randomSerialNumber() returned error: %v", err)
	}
	if serial == nil {
		t.Error("randomSerialNumber() returned nil serial number")
	}
	if serial.BitLen() == 0 {
		t.Error("randomSerialNumber() returned zero serial number")
	}
	// Serial number should be within reasonable bounds (128 bits)
	if serial.BitLen() > 128 {
		t.Errorf("randomSerialNumber() returned serial with too many bits: %d", serial.BitLen())
	}
}

// TestRandomSerialNumberUniqueness tests that multiple calls produce different numbers
func TestRandomSerialNumberUniqueness(t *testing.T) {
	serial1, err1 := randomSerialNumber()
	serial2, err2 := randomSerialNumber()

	if err1 != nil {
		t.Fatalf("First randomSerialNumber() returned error: %v", err1)
	}
	if err2 != nil {
		t.Fatalf("Second randomSerialNumber() returned error: %v", err2)
	}

	// While technically possible to get the same number twice,
	// with 128-bit random numbers this is astronomically unlikely
	if serial1.Cmp(serial2) == 0 {
		t.Error("randomSerialNumber() produced identical serial numbers in successive calls")
	}
}

// TestSlotConfigs verifies that the default slot configurations are valid
func TestSlotConfigs(t *testing.T) {
	if len(defaultSlotConfigs) == 0 {
		t.Fatal("defaultSlotConfigs should not be empty")
	}

	// Verify we have the expected 4 slots
	if len(defaultSlotConfigs) != 4 {
		t.Errorf("Expected 4 slot configs, got %d", len(defaultSlotConfigs))
	}

	// Check that all slots are unique
	seen := make(map[uint32]bool)
	for _, cfg := range defaultSlotConfigs {
		if seen[uint32(cfg.slot.Key)] {
			t.Errorf("Duplicate slot found: %x", cfg.slot.Key)
		}
		seen[uint32(cfg.slot.Key)] = true
	}
}

func TestSlotConfigPolicies(t *testing.T) {
	expected := map[uint32]piv.PINPolicy{
		uint32(piv.SlotAuthentication.Key):     piv.PINPolicyOnce,
		uint32(piv.SlotSignature.Key):          piv.PINPolicyAlways,
		uint32(piv.SlotKeyManagement.Key):      piv.PINPolicyOnce,
		uint32(piv.SlotCardAuthentication.Key): piv.PINPolicyNever,
	}

	for _, cfg := range defaultSlotConfigs {
		want, ok := expected[uint32(cfg.slot.Key)]
		if !ok {
			continue
		}
		if cfg.pinPolicy != want {
			t.Errorf("slot %x pinPolicy = %v, want %v", cfg.slot.Key, cfg.pinPolicy, want)
		}
	}
}

// TestConstants verifies that constants are set to expected values
func TestConstants(t *testing.T) {
	if RequiredPINLength != 8 {
		t.Errorf("RequiredPINLength = %d, want 8", RequiredPINLength)
	}
	if CertificateValidityYears != 42 {
		t.Errorf("CertificateValidityYears = %d, want 42", CertificateValidityYears)
	}
}

// TestErrInvalidPINLength tests the ErrInvalidPINLength error type
func TestErrInvalidPINLength(t *testing.T) {
	tests := []struct {
		name     string
		required int
		got      int
		expected string
	}{
		{
			name:     "too short",
			required: 8,
			got:      4,
			expected: "PIN needs to be 8 characters, got 4",
		},
		{
			name:     "too long",
			required: 8,
			got:      12,
			expected: "PIN needs to be 8 characters, got 12",
		},
		{
			name:     "empty",
			required: 8,
			got:      0,
			expected: "PIN needs to be 8 characters, got 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrInvalidPINLength{Required: tt.required, Got: tt.got}
			if err.Error() != tt.expected {
				t.Errorf("ErrInvalidPINLength.Error() = %q, want %q", err.Error(), tt.expected)
			}
		})
	}
}

// TestErrPINMismatch tests the ErrPINMismatch sentinel error
func TestErrPINMismatch(t *testing.T) {
	if ErrPINMismatch == nil {
		t.Error("ErrPINMismatch should not be nil")
	}
	if ErrPINMismatch.Error() != "PINs don't match" {
		t.Errorf("ErrPINMismatch.Error() = %q, want %q", ErrPINMismatch.Error(), "PINs don't match")
	}
}
