package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

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
	var watch bool
	var sortBy string

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List all LXC containers",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := lxd.NewClient("")
			if err != nil {
				return err
			}

			if watch {
				return watchList(client, sortBy)
			}
			return printList(client, sortBy)
		},
	}

	cmd.Flags().BoolVarP(&watch, "watch", "w", false, "Auto-refresh every 2 seconds")
	cmd.Flags().StringVarP(&sortBy, "sort", "s", "name", "Sort by: name, cpu, mem, status")

	return cmd
}

func printList(client *lxd.Client, sortBy string) error {
	containers, err := client.ListContainers(context.Background())
	if err != nil {
		return err
	}

	sortContainers(containers, sortBy)

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
}

func watchList(client *lxd.Client, sortBy string) error {
	type prevData struct {
		cpuNs int64
		t     time.Time
	}
	prev := make(map[string]prevData)

	for {
		// Clear screen
		fmt.Print("\033[H\033[2J")

		containers, err := client.ListContainers(context.Background())
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			time.Sleep(2 * time.Second)
			continue
		}

		now := time.Now()
		cpuPcts := make(map[string]float64)

		for _, c := range containers {
			if c.Status == "Running" {
				if p, ok := prev[c.Name]; ok && !p.t.IsZero() {
					dt := now.Sub(p.t)
					if dt > 0 {
						dCPU := c.CPUUsage - p.cpuNs
						if dCPU < 0 {
							dCPU = 0
						}
						cpuPcts[c.Name] = float64(dCPU) / float64(dt.Nanoseconds()) * 100.0
					}
				}
				prev[c.Name] = prevData{cpuNs: c.CPUUsage, t: now}
			}
		}

		sortContainers(containers, sortBy)

		ts := now.UTC().Add(8 * time.Hour).Format("15:04:05")
		running := 0
		for _, c := range containers {
			if c.Status == "Running" {
				running++
			}
		}
		fmt.Printf("📡 cella watch  %d/%d running  %s  (Ctrl+C to quit)\n\n", running, len(containers), ts)

		fmt.Printf("%-20s %-10s %-7s %-18s %-10s %-6s\n",
			"NAME", "STATUS", "CPU%", "IP", "MEMORY", "PIDs")
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
			cpuStr := "-"
			if pct, ok := cpuPcts[c.Name]; ok {
				cpuStr = fmt.Sprintf("%.1f%%", pct)
			}
			fmt.Printf("%-20s %-10s %-7s %-18s %-10s %-6d\n",
				c.Name, c.Status, cpuStr, ip, mem, c.PIDs)
		}

		time.Sleep(2 * time.Second)
	}
}

func sortContainers(containers []lxd.ContainerInfo, sortBy string) {
	switch sortBy {
	case "mem":
		sort.Slice(containers, func(i, j int) bool {
			return containers[i].MemoryCur > containers[j].MemoryCur
		})
	case "status":
		sort.Slice(containers, func(i, j int) bool {
			return containers[i].Status < containers[j].Status
		})
	default: // name
		sort.Slice(containers, func(i, j int) bool {
			si := statusOrder(containers[i].Status)
			sj := statusOrder(containers[j].Status)
			if si != sj {
				return si < sj
			}
			return containers[i].Name < containers[j].Name
		})
	}
}

func statusOrder(s string) int {
	switch s {
	case "Running":
		return 0
	case "Frozen":
		return 1
	default:
		return 2
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
