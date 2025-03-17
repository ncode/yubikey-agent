// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package agent

import (
	"fmt"
	"os"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/term"
)

// UnblockPIN uses the PUK to unblock a locked PIN
func UnblockPIN(yk *piv.YubiKey) error {
	// First, check if the PIN is actually blocked
	count, err := yk.Retries()
	if err != nil {
		return fmt.Errorf("failed to get PIN retries: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("PIN is not blocked, no need to unblock")
	}

	// Get the current PUK from the user
	fmt.Print("Enter the current PUK: ")
	puk, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to read PUK: %w", err)
	}
	fmt.Println()

	// Get the new PIN
	fmt.Print("Enter new PIN: ")
	newPIN, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to read new PIN: %w", err)
	}
	fmt.Println()

	// Confirm the new PIN
	fmt.Print("Confirm new PIN: ")
	confirmPIN, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to read confirmation PIN: %w", err)
	}
	fmt.Println()

	// Check if PINs match
	if string(newPIN) != string(confirmPIN) {
		return fmt.Errorf("new PIN and confirmation do not match")
	}

	// Unblock the PIN by setting again the pin using the PUK
	if err = yk.Unblock(string(puk), string(newPIN)); err != nil {
		return fmt.Errorf("failed to unblock PIN: %w", err)
	}

	fmt.Println("✅ PIN successfully unblocked and reset")
	return nil
}
