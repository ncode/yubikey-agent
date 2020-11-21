package cmd

import (
	"github.com/ncode/yubikey-agent/agent"

	"github.com/spf13/cobra"
)

var reallyDeleteAllPivKeys bool

// setupCmd represents the setup command
var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "setup the specified YubiKey",
	Run: func(cmd *cobra.Command, args []string) {
		yk := agent.ConnectForSetup()
		if reallyDeleteAllPivKeys {
			agent.RunReset(yk)
		}
		agent.RunSetup(yk)
	},
}

func init() {
	rootCmd.AddCommand(setupCmd)
	setupCmd.PersistentFlags().BoolVar(&reallyDeleteAllPivKeys, "really-delete-all-piv-keys", false, "wipe all current keys on your device")
}
