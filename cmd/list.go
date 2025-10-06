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

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "list available YubiKey devices connected",
	RunE: func(cmd *cobra.Command, args []string) error {
		yubikeys, err := agent.LoadYubiKeys()
		if err != nil {
			return err
		}
		for _, yubi := range yubikeys {
			fmt.Printf("🔐 %s #%d\n", yubi.Name, yubi.Serial)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
