// Copyright 2025 Juliano Martinez <juliano@martinez.io>
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package cmd

import (
	"bytes"
	"strings"
	"testing"
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

// TestVersionSet tests that version is properly set
func TestVersionSet(t *testing.T) {
	if rootCmd.Version == "" {
		t.Error("rootCmd.Version should not be empty after init")
	}
}
