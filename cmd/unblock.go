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

// unblockCmd represents the unblock command
var unblockCmd = &cobra.Command{
	Use:   "unblock",
	Short: "unblocks the specified YubiKey",
	Run: func(cmd *cobra.Command, args []string) {
		yubikeys, err := agent.LoadYubiKeys()
		if err != nil {
			log.Fatalln(err)
		}

		if len(yubikeys) == 1 {
			err = agent.UnblockPIN(yubikeys[0].Device)
			if err != nil {
				log.Fatalln(err)
			}
		} else {
			if serial == 0 {
				log.Fatalln("you must specify --serial when having more than one yubikey connected")
			}

			for _, key := range yubikeys {
				if uint32(serial) == key.Serial {
					err = agent.UnblockPIN(key.Device)
					if err != nil {
						log.Fatalln(err)
					}
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(unblockCmd)
}
