// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package agent

import (
	"testing"
)

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
