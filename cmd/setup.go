// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package cmd

import (
	"fmt"
	"os"

	"github.com/ncode/yubikey-agent/agent"

	"github.com/spf13/cobra"
)

var reallyDeleteAllPivKeys bool
var serial int

// setupCmd represents the setup command
var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "setup the specified YubiKey",
	Run: func(cmd *cobra.Command, args []string) {
		yk, err := agent.GetSingleYubiKey()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if reallyDeleteAllPivKeys {
			fmt.Println("Resetting YubiKey PIV applet...")
			if err := yk.Device.Reset(); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		agent.RunSetup(yk.Device)
	},
}

func init() {
	rootCmd.AddCommand(setupCmd)
	setupCmd.PersistentFlags().BoolVar(&reallyDeleteAllPivKeys, "really-delete-all-piv-keys", false, "wipe all current keys on your device")
	setupCmd.PersistentFlags().IntVar(&serial, "serial", 0, "define the yubikey to be used")
}
