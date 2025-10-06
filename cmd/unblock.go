// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package cmd

import (
	"github.com/ncode/yubikey-agent/agent"
	"github.com/spf13/cobra"
)

// unblockCmd represents the unblock command
var unblockCmd = &cobra.Command{
	Use:   "unblock",
	Short: "unblocks the specified YubiKey",
	RunE: func(cmd *cobra.Command, args []string) error {
		yk, err := agent.GetSingleYubiKey()
		if err != nil {
			return err
		}

		err = agent.UnblockPIN(yk.Device)
		if err != nil {
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(unblockCmd)
}
