// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package cmd

import (
	"fmt"
	"log"

	"github.com/ncode/yubikey-agent/agent"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "list available YubiKey devices connected",
	Run: func(cmd *cobra.Command, args []string) {
		yubikeys, err := agent.LoadYubiKeys()
		if err != nil {
			log.Fatalln(err)
		}
		for _, yubi := range yubikeys {
			fmt.Printf("🔐 %s #%d\n", yubi.Name, yubi.Serial)
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
