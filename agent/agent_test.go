// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
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
			expected: ssh.KeyAlgoRSASHA256,
		},
		{
			name:     "RSA with SHA512 flag",
			keyType:  ssh.KeyAlgoRSA,
			flags:    agent.SignatureFlagRsaSha512,
			expected: ssh.KeyAlgoRSASHA512,
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

// TestIsRetriableAuthError tests the isRetriableAuthError function
func TestIsRetriableAuthError(t *testing.T) {
	tests := []struct {
		name            string
		err             error
		expectedRetries int
	}{
		{
			name:            "nil error",
			err:             nil,
			expectedRetries: 0,
		},
		{
			name:            "generic error",
			err:             errors.New("some error"),
			expectedRetries: 0,
		},
		{
			name:            "AuthErr with retries",
			err:             &piv.AuthErr{Retries: 2},
			expectedRetries: 2,
		},
		{
			name:            "AuthErr with zero retries",
			err:             &piv.AuthErr{Retries: 0},
			expectedRetries: 0,
		},
		{
			name:            "AuthErr with one retry",
			err:             &piv.AuthErr{Retries: 1},
			expectedRetries: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRetriableAuthError(tt.err)
			if result != tt.expectedRetries {
				t.Errorf("isRetriableAuthError() = %d, want %d", result, tt.expectedRetries)
			}
		})
	}
}

// TestIsRetriableAuthErrorWrapped tests that isRetriableAuthError works with wrapped errors
func TestIsRetriableAuthErrorWrapped(t *testing.T) {
	authErr := &piv.AuthErr{Retries: 3}
	wrappedErr := errors.Join(errors.New("operation failed"), authErr)

	result := isRetriableAuthError(wrappedErr)
	if result != 3 {
		t.Errorf("isRetriableAuthError() with wrapped error = %d, want 3", result)
	}
}

// TestErrOperationUnsupported tests the ErrOperationUnsupported sentinel error
func TestErrOperationUnsupported(t *testing.T) {
	if ErrOperationUnsupported == nil {
		t.Error("ErrOperationUnsupported should not be nil")
	}
	if ErrOperationUnsupported.Error() != "operation unsupported" {
		t.Errorf("ErrOperationUnsupported.Error() = %q, want %q",
			ErrOperationUnsupported.Error(), "operation unsupported")
	}
}

// TestAgentUnsupportedOperations tests that unsupported operations return correct error
func TestAgentUnsupportedOperations(t *testing.T) {
	a := &Agent{}

	if err := a.Add(agent.AddedKey{}); err != ErrOperationUnsupported {
		t.Errorf("Add() = %v, want ErrOperationUnsupported", err)
	}
	if err := a.Remove(nil); err != ErrOperationUnsupported {
		t.Errorf("Remove() = %v, want ErrOperationUnsupported", err)
	}
	if err := a.RemoveAll(); err != ErrOperationUnsupported {
		t.Errorf("RemoveAll() = %v, want ErrOperationUnsupported", err)
	}
	if err := a.Lock(nil); err != ErrOperationUnsupported {
		t.Errorf("Lock() = %v, want ErrOperationUnsupported", err)
	}
	if err := a.Unlock(nil); err != ErrOperationUnsupported {
		t.Errorf("Unlock() = %v, want ErrOperationUnsupported", err)
	}
}

// TestAgentExtension tests that Extension returns ErrExtensionUnsupported
func TestAgentExtension(t *testing.T) {
	a := &Agent{}
	_, err := a.Extension("test", nil)
	if err != agent.ErrExtensionUnsupported {
		t.Errorf("Extension() = %v, want ErrExtensionUnsupported", err)
	}
}
