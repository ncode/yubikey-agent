// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// TestRootCommand tests the root command structure
func TestRootCommand(t *testing.T) {
	if rootCmd == nil {
		t.Fatal("rootCmd should not be nil")
	}

	if rootCmd.Use != "yubikey-agent" {
		t.Errorf("rootCmd.Use = %q, want %q", rootCmd.Use, "yubikey-agent")
	}

	if rootCmd.Short == "" {
		t.Error("rootCmd.Short should not be empty")
	}
}

// TestSubcommands tests that all expected subcommands are registered
func TestSubcommands(t *testing.T) {
	expectedCommands := []string{"setup", "list", "unblock"}

	for _, name := range expectedCommands {
		found := false
		for _, cmd := range rootCmd.Commands() {
			if cmd.Name() == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected subcommand %q not found", name)
		}
	}
}

// TestSetupCommandFlags tests setup command flags
func TestSetupCommandFlags(t *testing.T) {
	flag := setupCmd.PersistentFlags().Lookup("really-delete-all-piv-keys")
	if flag == nil {
		t.Fatal("setup command should have --really-delete-all-piv-keys flag")
	}
	if flag.DefValue != "false" {
		t.Errorf("--really-delete-all-piv-keys default = %q, want %q", flag.DefValue, "false")
	}
}

// TestListCommandFlags tests list command flags
func TestListCommandFlags(t *testing.T) {
	flag := listCmd.Flags().Lookup("plain")
	if flag == nil {
		t.Fatal("list command should have --plain flag")
	}
	if flag.DefValue != "false" {
		t.Errorf("--plain default = %q, want %q", flag.DefValue, "false")
	}
}

// TestRootCommandFlags tests root command persistent flags
func TestRootCommandFlags(t *testing.T) {
	tests := []struct {
		name         string
		flag         string
		shorthand    string
		defaultValue string
	}{
		{
			name:         "config flag",
			flag:         "config",
			shorthand:    "",
			defaultValue: "",
		},
		{
			name:      "serial flag",
			flag:      "serial",
			shorthand: "s",
		},
		{
			name:      "listen flag",
			flag:      "listen",
			shorthand: "l",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := rootCmd.PersistentFlags().Lookup(tt.flag)
			if flag == nil {
				t.Errorf("root command should have --%s flag", tt.flag)
				return
			}
			if tt.shorthand != "" && flag.Shorthand != tt.shorthand {
				t.Errorf("--%s shorthand = %q, want %q", tt.flag, flag.Shorthand, tt.shorthand)
			}
		})
	}
}

// TestHelpOutput tests that help output contains expected information
func TestHelpOutput(t *testing.T) {
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetArgs(nil)
		_ = rootCmd.Flags().Set("help", "false")
	})
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"--help"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("Execute() with --help returned error: %v", err)
	}

	output := buf.String()
	expectedStrings := []string{
		"yubikey-agent",
		"setup",
		"list",
		"unblock",
	}

	for _, s := range expectedStrings {
		if !strings.Contains(output, s) {
			t.Errorf("Help output should contain %q", s)
		}
	}
}

func TestConfigValidationBeforeHandler(t *testing.T) {
	originalRun := rootCmd.Run
	originalHome := homeDir
	serialFlag := rootCmd.PersistentFlags().Lookup("serial")
	originalSerial, originalSerialChanged := serialFlag.Value.String(), serialFlag.Changed
	t.Cleanup(func() {
		rootCmd.Run = originalRun
		homeDir = originalHome
		cfgFile = ""
		_ = serialFlag.Value.Set(originalSerial)
		serialFlag.Changed = originalSerialChanged
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		viper.Reset()
		_ = viper.BindPFlag("serial", rootCmd.PersistentFlags().Lookup("serial"))
		_ = viper.BindPFlag("listen", rootCmd.PersistentFlags().Lookup("listen"))
		_ = viper.BindPFlag("plain", listCmd.Flags().Lookup("plain"))
	})
	for _, tc := range []struct {
		name, contents              string
		explicit, exists, wantError bool
		serialEnv, serialArg        string
		wantSerial                  uint32
	}{
		{name: "explicit missing", explicit: true, wantError: true},
		{name: "explicit malformed", explicit: true, exists: true, contents: "serial: [", wantError: true},
		{name: "discovered malformed", exists: true, contents: "serial: [", wantError: true},
		{name: "invalid serial", explicit: true, exists: true, contents: "serial: not-a-number\n", wantError: true},
		{name: "negative serial", explicit: true, exists: true, contents: "serial: -1\n", wantError: true},
		{name: "serial overflow", explicit: true, exists: true, contents: "serial: 4294967296\n", wantError: true},
		{name: "optional missing"},
		{name: "valid", explicit: true, exists: true, contents: "serial: 123456\n", wantSerial: 123456},
		{name: "maximum serial", explicit: true, exists: true, contents: "serial: 4294967295\n", wantSerial: 4294967295},
		{name: "invalid serial environment", serialEnv: "not-a-number", wantError: true},
		{name: "valid serial environment", serialEnv: "42", wantSerial: 42},
		{name: "serial flag overrides invalid config", explicit: true, exists: true, contents: "serial: not-a-number\n", serialArg: "42", wantSerial: 42},
	} {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			_ = serialFlag.Value.Set("0")
			serialFlag.Changed = false
			if err := viper.BindPFlag("serial", serialFlag); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SERIAL", tc.serialEnv)
			homeDir = t.TempDir()
			path := filepath.Join(homeDir, ".yubikey-agent.yaml")
			if tc.exists {
				if err := os.WriteFile(path, []byte(tc.contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cfgFile = ""
			args := []string{}
			if tc.explicit {
				args = []string{"--config", path}
			}
			if tc.serialArg != "" {
				args = append(args, "--serial", tc.serialArg)
			}
			called := false
			rootCmd.Run = func(_ *cobra.Command, _ []string) { called = true }
			rootCmd.SetArgs(args)
			rootCmd.SetOut(new(bytes.Buffer))
			rootCmd.SetErr(new(bytes.Buffer))
			err := rootCmd.Execute()
			if (err != nil) != tc.wantError {
				t.Errorf("error = %v, wantError %v", err, tc.wantError)
			}
			if called == tc.wantError {
				t.Errorf("handler called = %v, want %v", called, !tc.wantError)
			}
			if !tc.wantError && viper.GetUint32("serial") != tc.wantSerial {
				t.Fatalf("effective serial = %d, want %d", viper.GetUint32("serial"), tc.wantSerial)
			}
		})
	}
}

// TestVersionSet tests that version is properly set
func TestVersionSet(t *testing.T) {
	if rootCmd.Version == "" {
		t.Error("rootCmd.Version should not be empty after init")
	}
}
