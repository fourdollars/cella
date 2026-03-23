package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/fourdoors/cella/internal/lxd"
	"github.com/fourdoors/cella/internal/tui"
	"github.com/spf13/cobra"
)

var version = "0.1.0-dev"

func main() {
	rootCmd := &cobra.Command{
		Use:   "cella",
		Short: "cella — LXC/LXD container management TUI",
		Long: `cella (Latin: "small room") is a terminal UI for managing and
monitoring LXC/LXD containers with real-time metrics, syscall tracing,
and security policy management.`,
		Version: version,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTUI()
		},
	}

	rootCmd.AddCommand(listCmd())
	rootCmd.AddCommand(topCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runTUI() error {
	p := tea.NewProgram(
		tui.NewApp(),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)
	_, err := p.Run()
	return err
}

func listCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List all LXC containers",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := lxd.NewClient("")
			if err != nil {
				return err
			}
			containers, err := client.ListContainers(context.Background())
			if err != nil {
				return err
			}

			fmt.Printf("%-20s %-10s %-8s %-18s %-10s %-6s\n",
				"NAME", "STATUS", "TYPE", "IP", "MEMORY", "PIDs")
			fmt.Println(strings.Repeat("─", 80))

			for _, c := range containers {
				ip := c.IP
				if ip == "" {
					ip = "-"
				}
				mem := "-"
				if c.MemoryCur > 0 {
					mem = formatBytes(c.MemoryCur)
				}
				fmt.Printf("%-20s %-10s %-8s %-18s %-10s %-6d\n",
					c.Name, c.Status, c.Type, ip, mem, c.PIDs)
			}
			return nil
		},
	}
}

func topCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "top",
		Short: "Real-time container resource monitoring",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTUI()
		},
	}
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fGB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}
