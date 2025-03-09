// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package cmd

import (
	"log"

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
		yubikeys, err := agent.LoadYubiKeys()
		if err != nil {
			log.Fatalln(err)
		}
		if len(yubikeys) == 1 {
			if reallyDeleteAllPivKeys {
				agent.RunReset(yubikeys[0].Device)
			}
			agent.RunSetup(yubikeys[0].Device)
		} else {
			if serial == 0 {
				log.Fatalln("you must specify --serial when having more than one yubikey connected")
			}

			for _, key := range yubikeys {
				if uint32(serial) == key.Serial {
					if reallyDeleteAllPivKeys {
						agent.RunReset(key.Device)
					}
					agent.RunSetup(key.Device)
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(setupCmd)
	setupCmd.PersistentFlags().BoolVar(&reallyDeleteAllPivKeys, "really-delete-all-piv-keys", false, "wipe all current keys on your device")
	setupCmd.PersistentFlags().IntVar(&serial, "serial", 0, "define the yubikey to be used")
}
