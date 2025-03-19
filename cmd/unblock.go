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

// unblockCmd represents the unblock command
var unblockCmd = &cobra.Command{
	Use:   "unblock",
	Short: "unblocks the specified YubiKey",
	Run: func(cmd *cobra.Command, args []string) {
		yk, err := agent.GetSingleYubiKey()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		err = agent.UnblockPIN(yk.Device)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(unblockCmd)
}
