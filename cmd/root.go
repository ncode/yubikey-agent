// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package cmd

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/ncode/yubikey-agent/agent"
	"github.com/spf13/cobra"

	homedir "github.com/mitchellh/go-homedir"
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

func init() {
	cobra.OnInitialize(initConfig)
	home, err := homedir.Dir()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.yubikey-agent.yaml)")
	rootCmd.PersistentFlags().Uint32P("serial", "s", 0, "serial of the device you would like to use")
	viper.BindPFlag("serial", rootCmd.PersistentFlags().Lookup("serial"))
	rootCmd.PersistentFlags().StringP("listen", "l", fmt.Sprintf("%s/.ssh/yubikey-agent.sock", home), "Run the agent, listening on the UNIX socket at PATH (default is $HOME/.ssh.yubikey-agent.sock)")
	viper.BindPFlag("listen", rootCmd.PersistentFlags().Lookup("listen"))

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
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".yubikey-agent" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".yubikey-agent")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}

	if viper.GetUint32("serial") != 0 {
		fmt.Println("Using serial:", viper.GetUint32("serial"))
	}
}
