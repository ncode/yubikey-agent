// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package cmd

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strconv"

	"github.com/ncode/yubikey-agent/agent"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Version is the version of the agent. It is set at build time using the following command:
// go build -ldflags "-X github.com/ncode/yubikey-agent/cmd.Version="
var Version string
var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "yubikey-agent",
	Short: "yubikey-agent is a seamless ssh-agent for YubiKeys.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initConfig()
	},
	Run: func(cmd *cobra.Command, args []string) {
		agent.Run()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var homeDir string

func init() {
	var err error
	homeDir, err = os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to determine home directory: %v", err)
	}
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.yubikey-agent.yaml)")
	rootCmd.PersistentFlags().Uint32P("serial", "s", 0, "serial of the device you would like to use")
	_ = viper.BindPFlag("serial", rootCmd.PersistentFlags().Lookup("serial"))
	rootCmd.PersistentFlags().StringP("listen", "l", fmt.Sprintf("%s/.ssh/yubikey-agent.sock", homeDir), "Run the agent, listening on the UNIX socket at PATH (default is $HOME/.ssh/yubikey-agent.sock)")
	_ = viper.BindPFlag("listen", rootCmd.PersistentFlags().Lookup("listen"))

	if Version != "" {
		rootCmd.Version = Version
	} else if buildInfo, ok := debug.ReadBuildInfo(); ok {
		rootCmd.Version = buildInfo.Main.Version
	} else {
		rootCmd.Version = "(unknown version)"
	}
	agent.Version = rootCmd.Version
}

// initConfig reads in config file and ENV variables if set.
func initConfig() error {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Search config in home directory with name ".yubikey-agent" (without extension).
		viper.AddConfigPath(homeDir)
		viper.SetConfigName(".yubikey-agent")
	}

	viper.AutomaticEnv() // read in environment variables that match

	if err := viper.ReadInConfig(); err != nil {
		var missing viper.ConfigFileNotFoundError
		if cfgFile != "" || !errors.As(err, &missing) {
			return fmt.Errorf("read configuration: %w", err)
		}
		// The default file is optional; flags and environment still need validation.
	}
	if viper.IsSet("serial") {
		if _, err := strconv.ParseUint(viper.GetString("serial"), 0, 32); err != nil {
			return fmt.Errorf("invalid serial: expected an unsigned 32-bit integer: %w", err)
		}
	}
	return nil
}
