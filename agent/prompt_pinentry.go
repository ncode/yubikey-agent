// Copyright 2020 Google LLC
// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

//go:build !darwin

package agent

import (
	"context"
	"fmt"

	"github.com/twpayne/go-pinentry-minimal/pinentry"
)

func getPIN(ctx context.Context, serial uint32, retries int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	client, err := pinentry.NewClient(
		pinentry.WithProcess(&pinentryProcess{ctx: ctx}),
		pinentry.WithBinaryNameFromGnuPGAgentConf(),
		pinentry.WithGPGTTY(),
		pinentry.WithTitle("yubikey-agent PIN Prompt"),
		pinentry.WithDesc(fmt.Sprintf("YubiKey serial number: %d (%d tries remaining)", serial, retries)),
		pinentry.WithPrompt("Please enter your PIN:"),
		// Do not enable an external password cache: a stale cached PIN would
		// otherwise consume hardware retries without fresh user input. PIN-once
		// caching remains the responsibility of the YubiKey's PIV session.
	)
	if err != nil {
		return "", err
	}
	defer client.Close()

	pin, _, err := client.GetPIN()
	return pin, err
}
