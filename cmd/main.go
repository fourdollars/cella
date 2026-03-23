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
	"github.com/fourdoors/cella/internal/runtime"
	"github.com/fourdoors/cella/internal/tui"
	"github.com/spf13/cobra"
)

var version = "0.1.0-dev"

func main() {
	rootCmd := &cobra.Command{
		Use:   "cella",
		Short: "cella — container management TUI for LXD & Docker",
		Long: `cella (Latin: "small room") is a terminal UI for managing and
monitoring LXD and Docker containers with real-time metrics, syscall
tracing, disk I/O, network monitoring, and security policy management.`,
		Version: version,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTUI()
		},
	}

	rootCmd.AddCommand(listCmd())
	rootCmd.AddCommand(execCmd())

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

// initRuntimes detects available container runtimes and returns them
func initRuntimes() ([]runtime.Runtime, error) {
	var runtimes []runtime.Runtime

	// Try LXD
	client, err := lxd.NewClient("")
	if err == nil {
		runtimes = append(runtimes, runtime.NewLXDRuntime(client))
	}

	// Try Docker
	dockerClient, err := runtime.NewDockerClient("")
	if err == nil {
		runtimes = append(runtimes, dockerClient)
	}

	if len(runtimes) == 0 {
		return nil, fmt.Errorf("no container runtime detected (checked LXD socket + Docker socket)")
	}
	return runtimes, nil
}

func listCmd() *cobra.Command {
	var watch bool
	var sortBy string
	var filterRuntime string

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List all containers (LXD + Docker)",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimes, err := initRuntimes()
			if err != nil {
				return err
			}

			if watch {
				return watchList(runtimes, sortBy, filterRuntime)
			}
			return printList(runtimes, sortBy, filterRuntime)
		},
	}

	cmd.Flags().BoolVarP(&watch, "watch", "w", false, "Auto-refresh every 2 seconds")
	cmd.Flags().StringVarP(&sortBy, "sort", "s", "name", "Sort by: name, cpu, mem, status")
	cmd.Flags().StringVarP(&filterRuntime, "runtime", "r", "", "Filter by runtime: lxd, docker (default: all)")

	return cmd
}

func execCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "exec <container> -- <command...>",
		Short: "Execute a command in a container",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			containerName := args[0]

			// Find command after --
			command := []string{"/bin/sh"}
			dashIdx := cmd.ArgsLenAtDash()
			if dashIdx >= 0 && dashIdx < len(args) {
				command = args[dashIdx:]
			} else if len(args) > 1 {
				command = args[1:]
			}

			runtimes, err := initRuntimes()
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Try each runtime to find the container
			for _, rt := range runtimes {
				result, err := rt.ExecCommand(ctx, containerName, command)
				if err != nil {
					continue // container might be in another runtime
				}

				if result.Stdout != "" {
					fmt.Print(result.Stdout)
				}
				if result.Stderr != "" {
					fmt.Fprint(os.Stderr, result.Stderr)
				}

				if result.ExitCode != 0 {
					os.Exit(result.ExitCode)
				}
				return nil
			}

			return fmt.Errorf("container %q not found in any runtime", containerName)
		},
	}
}

func fetchAllContainers(runtimes []runtime.Runtime) ([]runtime.ContainerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var all []runtime.ContainerInfo
	for _, rt := range runtimes {
		containers, err := rt.ListContainers(ctx)
		if err != nil {
			continue
		}
		all = append(all, containers...)
	}
	return all, nil
}

func printList(runtimes []runtime.Runtime, sortBy, filterRuntime string) error {
	containers, err := fetchAllContainers(runtimes)
	if err != nil {
		return err
	}

	containers = filterByRuntime(containers, filterRuntime)
	sortRuntimeContainers(containers, sortBy)

	fmt.Printf("%-2s %-20s %-7s %-10s %-7s %-18s %-10s %-6s\n",
		"", "NAME", "RT", "STATUS", "CPU%", "IP", "MEMORY", "PIDs")
	fmt.Println(strings.Repeat("─", 85))

	for _, c := range containers {
		ip := c.IP
		if ip == "" {
			ip = "-"
		}
		mem := "-"
		if c.MemoryCur > 0 {
			mem = formatBytes(c.MemoryCur)
		}
		rtIcon := "🔷"
		if c.Runtime == "docker" {
			rtIcon = "🐳"
		}
		fmt.Printf("%s %-20s %-7s %-10s %-7s %-18s %-10s %-6d\n",
			rtIcon, truncate(c.Name, 20), c.Runtime, c.Status, "-", ip, mem, c.PIDs)
	}

	// Summary
	lxdCount, dockerCount, runningCount := 0, 0, 0
	for _, c := range containers {
		if c.Runtime == "lxd" {
			lxdCount++
		} else {
			dockerCount++
		}
		if c.Status == "Running" {
			runningCount++
		}
	}
	fmt.Printf("\n%d containers (%d running) — LXD: %d, Docker: %d\n",
		len(containers), runningCount, lxdCount, dockerCount)

	return nil
}

func watchList(runtimes []runtime.Runtime, sortBy, filterRuntime string) error {
	type prevData struct {
		cpuNs int64
		t     time.Time
	}
	prev := make(map[string]prevData)

	for {
		fmt.Print("\033[H\033[2J")

		containers, err := fetchAllContainers(runtimes)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			time.Sleep(2 * time.Second)
			continue
		}

		containers = filterByRuntime(containers, filterRuntime)

		now := time.Now()
		cpuPcts := make(map[string]float64)

		for _, c := range containers {
			key := c.Runtime + ":" + c.Name
			if c.Status == "Running" {
				if p, ok := prev[key]; ok && !p.t.IsZero() {
					dt := now.Sub(p.t)
					if dt > 0 {
						dCPU := c.CPUUsage - p.cpuNs
						if dCPU < 0 {
							dCPU = 0
						}
						cpuPcts[key] = float64(dCPU) / float64(dt.Nanoseconds()) * 100.0
					}
				}
				prev[key] = prevData{cpuNs: c.CPUUsage, t: now}
			}
		}

		sortRuntimeContainers(containers, sortBy)

		ts := now.UTC().Add(8 * time.Hour).Format("15:04:05")
		running := 0
		for _, c := range containers {
			if c.Status == "Running" {
				running++
			}
		}
		fmt.Printf("📡 cella watch  %d/%d running  %s  (Ctrl+C to quit)\n\n",
			running, len(containers), ts)

		fmt.Printf("%-2s %-20s %-7s %-10s %-7s %-18s %-10s %-6s\n",
			"", "NAME", "RT", "STATUS", "CPU%", "IP", "MEMORY", "PIDs")
		fmt.Println(strings.Repeat("─", 85))

		for _, c := range containers {
			ip := c.IP
			if ip == "" {
				ip = "-"
			}
			mem := "-"
			if c.MemoryCur > 0 {
				mem = formatBytes(c.MemoryCur)
			}
			key := c.Runtime + ":" + c.Name
			cpuStr := "-"
			if pct, ok := cpuPcts[key]; ok {
				cpuStr = fmt.Sprintf("%.1f%%", pct)
			}
			rtIcon := "🔷"
			if c.Runtime == "docker" {
				rtIcon = "🐳"
			}
			fmt.Printf("%s %-20s %-7s %-10s %-7s %-18s %-10s %-6d\n",
				rtIcon, truncate(c.Name, 20), c.Runtime, c.Status, cpuStr, ip, mem, c.PIDs)
		}

		time.Sleep(2 * time.Second)
	}
}

func filterByRuntime(containers []runtime.ContainerInfo, rt string) []runtime.ContainerInfo {
	if rt == "" {
		return containers
	}
	var result []runtime.ContainerInfo
	for _, c := range containers {
		if c.Runtime == rt {
			result = append(result, c)
		}
	}
	return result
}

func sortRuntimeContainers(containers []runtime.ContainerInfo, sortBy string) {
	switch sortBy {
	case "cpu":
		sort.Slice(containers, func(i, j int) bool {
			return containers[i].CPUUsage > containers[j].CPUUsage
		})
	case "mem":
		sort.Slice(containers, func(i, j int) bool {
			return containers[i].MemoryCur > containers[j].MemoryCur
		})
	case "status":
		sort.Slice(containers, func(i, j int) bool {
			return containers[i].Status < containers[j].Status
		})
	case "runtime":
		sort.Slice(containers, func(i, j int) bool {
			if containers[i].Runtime != containers[j].Runtime {
				return containers[i].Runtime < containers[j].Runtime
			}
			return containers[i].Name < containers[j].Name
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

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 2 {
		return s[:max]
	}
	return s[:max-2] + ".."
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
