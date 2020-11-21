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
		yubikeys, err := agent.ListYubiKeys()
		if err != nil {
			log.Fatalln(err)
		}
		for _, key := range yubikeys {
			fmt.Printf("🔐 %s\n", key)
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
