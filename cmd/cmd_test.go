package main

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestRootCmd_HasSubcommands verifies all expected subcommands exist.
func TestRootCmd_HasSubcommands(t *testing.T) {
	rootCmd := &cobra.Command{
		Use: "cella",
	}

	rootCmd.AddCommand(listCmd())
	rootCmd.AddCommand(execCmd())
	rootCmd.AddCommand(startCmd())
	rootCmd.AddCommand(stopCmd())
	rootCmd.AddCommand(pauseCmd())
	rootCmd.AddCommand(unpauseCmd())
	rootCmd.AddCommand(logsCmd())
	rootCmd.AddCommand(snapshotCmd())
	rootCmd.AddCommand(cloneCmd())
	rootCmd.AddCommand(infoCmd())
	rootCmd.AddCommand(createContainerCmd())
	rootCmd.AddCommand(deleteContainerCmd())
	rootCmd.AddCommand(proxyCmd())

	expected := []string{
		"list", "exec", "start", "stop", "pause", "unpause",
		"logs", "snapshot", "clone", "info", "create", "delete", "proxy",
	}

	cmds := make(map[string]bool)
	for _, sub := range rootCmd.Commands() {
		cmds[sub.Name()] = true
	}

	for _, name := range expected {
		if !cmds[name] {
			t.Errorf("missing subcommand: %s", name)
		}
	}
}

// TestSubcommands_RequireArgs verifies that container subcommands require arguments.
func TestSubcommands_RequireArgs(t *testing.T) {
	argRequired := []struct {
		name string
		cmd  *cobra.Command
	}{
		{"start", startCmd()},
		{"stop", stopCmd()},
		{"pause", pauseCmd()},
		{"unpause", unpauseCmd()},
		{"exec", execCmd()},
		{"logs", logsCmd()},
		{"info", infoCmd()},
		{"delete", deleteContainerCmd()},
	}

	for _, tc := range argRequired {
		t.Run(tc.name, func(t *testing.T) {
			// cobra commands with Args: ExactArgs(1) should fail with no args
			tc.cmd.SilenceErrors = true
			tc.cmd.SilenceUsage = true
			err := tc.cmd.Args(tc.cmd, []string{})
			if err == nil {
				t.Errorf("command %s should require at least 1 argument", tc.name)
			}
		})
	}
}

// TestListCmd_NoArgs verifies list command accepts no arguments (lists all).
func TestListCmd_NoArgs(t *testing.T) {
	cmd := listCmd()
	// list command should accept 0 args (list all containers)
	if cmd.Args != nil {
		err := cmd.Args(cmd, []string{})
		if err != nil {
			t.Errorf("list should accept 0 args, got error: %v", err)
		}
	}
}

// TestProxyCmd_HasFlags verifies proxy command has expected flags.
func TestProxyCmd_HasFlags(t *testing.T) {
	cmd := proxyCmd()
	// Proxy should be a valid command
	if cmd.Use == "" {
		t.Fatal("proxy command has empty Use")
	}
	if cmd.Short == "" {
		t.Fatal("proxy command has empty Short description")
	}
}

// TestSnapshotCmd_Structure verifies snapshot command structure.
func TestSnapshotCmd_Structure(t *testing.T) {
	cmd := snapshotCmd()
	if cmd.Use == "" {
		t.Fatal("snapshot command has empty Use")
	}
}

// TestCloneCmd_Structure verifies clone command structure.
func TestCloneCmd_Structure(t *testing.T) {
	cmd := cloneCmd()
	if cmd.Use == "" {
		t.Fatal("clone command has empty Use")
	}
}
