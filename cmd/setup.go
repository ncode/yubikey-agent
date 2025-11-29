// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package cmd

import (
	"fmt"

	"github.com/ncode/yubikey-agent/agent"

	"github.com/spf13/cobra"
)

var reallyDeleteAllPivKeys bool

// setupCmd represents the setup command
var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "setup the specified YubiKey",
	RunE: func(cmd *cobra.Command, args []string) error {
		yk, err := agent.GetSingleYubiKey()
		if err != nil {
			return err
		}
		if reallyDeleteAllPivKeys {
			fmt.Println("Resetting YubiKey PIV applet...")
			if err := yk.Device.Reset(); err != nil {
				return fmt.Errorf("failed to reset YubiKey: %w", err)
			}
		}
		return agent.RunSetup(yk.Device)
	},
}

func init() {
	rootCmd.AddCommand(setupCmd)
	setupCmd.PersistentFlags().BoolVar(&reallyDeleteAllPivKeys, "really-delete-all-piv-keys", false, "wipe all current keys on your device")
}
