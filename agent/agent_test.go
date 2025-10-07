// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package agent

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TestSignatureAlgorithm tests the signature algorithm selection logic
func TestSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		keyType  string
		flags    agent.SignatureFlags
		expected string
	}{
		{
			name:     "RSA with SHA256 flag",
			keyType:  ssh.KeyAlgoRSA,
			flags:    agent.SignatureFlagRsaSha256,
			expected: ssh.SigAlgoRSASHA2256,
		},
		{
			name:     "RSA with SHA512 flag",
			keyType:  ssh.KeyAlgoRSA,
			flags:    agent.SignatureFlagRsaSha512,
			expected: ssh.SigAlgoRSASHA2512,
		},
		{
			name:     "RSA with no flags",
			keyType:  ssh.KeyAlgoRSA,
			flags:    0,
			expected: ssh.KeyAlgoRSA,
		},
		{
			name:     "ECDSA defaults to key type",
			keyType:  ssh.KeyAlgoECDSA256,
			flags:    0,
			expected: ssh.KeyAlgoECDSA256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock public key with the specified type
			mockKey := &mockPublicKey{keyType: tt.keyType}
			result := signatureAlgorithm(mockKey, tt.flags)
			if result != tt.expected {
				t.Errorf("signatureAlgorithm() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestLoadYubiKeysContextCancellation tests that LoadYubiKeysContext respects cancellation
func TestLoadYubiKeysContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := LoadYubiKeysContext(ctx)
	if err == nil {
		t.Error("LoadYubiKeysContext should return error when context is cancelled")
	}
	if err != context.Canceled {
		t.Errorf("LoadYubiKeysContext error = %v, want %v", err, context.Canceled)
	}
}

// TestLoadYubiKeysContextTimeout tests that LoadYubiKeysContext respects timeout
func TestLoadYubiKeysContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for timeout
	time.Sleep(10 * time.Millisecond)

	_, err := LoadYubiKeysContext(ctx)
	if err == nil {
		t.Error("LoadYubiKeysContext should return error when context times out")
	}
}

// TestGetSingleYubiKeyContext tests context support in GetSingleYubiKeyContext
func TestGetSingleYubiKeyContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := GetSingleYubiKeyContext(ctx)
	if err == nil {
		t.Error("GetSingleYubiKeyContext should return error when context is cancelled")
	}
}

// TestAgentInterfaceCompliance verifies that Agent implements the required interfaces
func TestAgentInterfaceCompliance(t *testing.T) {
	var _ agent.ExtendedAgent = &Agent{}
}

// mockPublicKey is a simple mock for testing
type mockPublicKey struct {
	keyType string
}

func (m *mockPublicKey) Type() string {
	return m.keyType
}

func (m *mockPublicKey) Marshal() []byte {
	return []byte("mock-key")
}

func (m *mockPublicKey) Verify(data []byte, sig *ssh.Signature) error {
	return nil
}
