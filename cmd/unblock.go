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
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// unblockCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// unblockCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
