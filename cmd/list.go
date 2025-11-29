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
	"github.com/spf13/viper"
)

var plainOutput bool

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
			if viper.GetBool("plain") {
				fmt.Printf("%s #%d\n", yubi.Name, yubi.Serial)
			} else {
				fmt.Printf("🔐 %s #%d\n", yubi.Name, yubi.Serial)
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.Flags().BoolVar(&plainOutput, "plain", false, "use plain text output without emojis")
	_ = viper.BindPFlag("plain", listCmd.Flags().Lookup("plain"))
}
