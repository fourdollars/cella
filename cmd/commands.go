package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fourdoors/cella/internal/runtime"
	"github.com/spf13/cobra"
)

// ── helpers ──

func findRuntime(runtimes []runtime.Runtime, containerName string) (runtime.Runtime, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, rt := range runtimes {
		containers, err := rt.ListContainers(ctx)
		if err != nil {
			continue
		}
		for _, c := range containers {
			if c.Name == containerName {
				return rt, nil
			}
		}
	}
	return nil, fmt.Errorf("container %q not found in any runtime", containerName)
}

// ── start / stop / pause / unpause ──

func startCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start <container>",
		Short: "Start a stopped container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimes, err := initRuntimes()
			if err != nil {
				return err
			}
			rt, err := findRuntime(runtimes, args[0])
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := rt.StartContainer(ctx, args[0]); err != nil {
				return fmt.Errorf("start: %w", err)
			}
			fmt.Printf("✅ %s started\n", args[0])
			return nil
		},
	}
}

func stopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop <container>",
		Short: "Stop a running container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimes, err := initRuntimes()
			if err != nil {
				return err
			}
			rt, err := findRuntime(runtimes, args[0])
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := rt.StopContainer(ctx, args[0]); err != nil {
				return fmt.Errorf("stop: %w", err)
			}
			fmt.Printf("✅ %s stopped\n", args[0])
			return nil
		},
	}
}

func pauseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pause <container>",
		Short: "Pause (freeze) a running container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimes, err := initRuntimes()
			if err != nil {
				return err
			}
			rt, err := findRuntime(runtimes, args[0])
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := rt.PauseContainer(ctx, args[0]); err != nil {
				return fmt.Errorf("pause: %w", err)
			}
			fmt.Printf("⏸ %s paused\n", args[0])
			return nil
		},
	}
}

func unpauseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unpause <container>",
		Short: "Unpause (unfreeze) a paused container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimes, err := initRuntimes()
			if err != nil {
				return err
			}
			rt, err := findRuntime(runtimes, args[0])
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := rt.UnpauseContainer(ctx, args[0]); err != nil {
				return fmt.Errorf("unpause: %w", err)
			}
			fmt.Printf("▶ %s unpaused\n", args[0])
			return nil
		},
	}
}

// ── logs ──

func logsCmd() *cobra.Command {
	var lines int
	var follow bool

	cmd := &cobra.Command{
		Use:   "logs <container>",
		Short: "Fetch container logs (journalctl or /var/log/syslog)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimes, err := initRuntimes()
			if err != nil {
				return err
			}
			rt, err := findRuntime(runtimes, args[0])
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			var shellCmd string
			if follow {
				shellCmd = fmt.Sprintf(
					"journalctl -f -n %d 2>/dev/null || tail -f /var/log/syslog 2>/dev/null || tail -f /var/log/messages 2>/dev/null",
					lines,
				)
			} else {
				shellCmd = fmt.Sprintf(
					"journalctl --no-pager -n %d 2>/dev/null || tail -n %d /var/log/syslog 2>/dev/null || echo 'No logs available'",
					lines, lines,
				)
			}

			result, err := rt.ExecCommand(ctx, args[0], []string{"/bin/sh", "-c", shellCmd})
			if err != nil {
				return fmt.Errorf("logs: %w", err)
			}
			if result.Stdout != "" {
				fmt.Print(result.Stdout)
			}
			if result.Stderr != "" {
				fmt.Fprint(os.Stderr, result.Stderr)
			}
			return nil
		},
	}

	cmd.Flags().IntVarP(&lines, "lines", "n", 100, "Number of log lines to show")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output (tail -f)")
	return cmd
}

// ── snapshot ──

func snapshotCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "snapshot",
		Short:   "Manage container snapshots",
		Aliases: []string{"snap"},
	}

	// snapshot list
	listSnap := &cobra.Command{
		Use:     "list <container>",
		Short:   "List snapshots for a container",
		Aliases: []string{"ls"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimes, err := initRuntimes()
			if err != nil {
				return err
			}
			rt, err := findRuntime(runtimes, args[0])
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			snaps, err := rt.ListSnapshots(ctx, args[0])
			if err != nil {
				return fmt.Errorf("list snapshots: %w", err)
			}
			if len(snaps) == 0 {
				fmt.Printf("No snapshots for %s\n", args[0])
				return nil
			}
			fmt.Printf("%-32s  %-24s  %s\n", "NAME", "CREATED", "STATEFUL")
			fmt.Println(strings.Repeat("─", 65))
			for _, s := range snaps {
				stateful := "no"
				if s.Stateful {
					stateful = "yes"
				}
				fmt.Printf("%-32s  %-24s  %s\n",
					s.Name,
					s.CreatedAt,
					stateful,
				)
			}
			return nil
		},
	}

	// snapshot create
	createSnap := &cobra.Command{
		Use:   "create <container> [snapshot-name]",
		Short: "Create a snapshot (auto-names if omitted)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimes, err := initRuntimes()
			if err != nil {
				return err
			}
			rt, err := findRuntime(runtimes, args[0])
			if err != nil {
				return err
			}
			snapName := time.Now().Format("snap-20060102-1504")
			if len(args) == 2 {
				snapName = args[1]
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if err := rt.CreateSnapshot(ctx, args[0], snapName); err != nil {
				return fmt.Errorf("create snapshot: %w", err)
			}
			fmt.Printf("📸 Snapshot %q created for %s\n", snapName, args[0])
			return nil
		},
	}

	// snapshot delete
	deleteSnap := &cobra.Command{
		Use:     "delete <container> <snapshot>",
		Short:   "Delete a snapshot",
		Aliases: []string{"rm", "del"},
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimes, err := initRuntimes()
			if err != nil {
				return err
			}
			rt, err := findRuntime(runtimes, args[0])
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := rt.DeleteSnapshot(ctx, args[0], args[1]); err != nil {
				return fmt.Errorf("delete snapshot: %w", err)
			}
			fmt.Printf("🗑 Snapshot %q deleted from %s\n", args[1], args[0])
			return nil
		},
	}

	cmd.AddCommand(listSnap, createSnap, deleteSnap)
	return cmd
}

// ── clone ──

func cloneCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clone <source> <target>",
		Short: "Clone (copy) a container",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimes, err := initRuntimes()
			if err != nil {
				return err
			}
			rt, err := findRuntime(runtimes, args[0])
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			if err := rt.CopyContainer(ctx, args[0], args[1]); err != nil {
				return fmt.Errorf("clone: %w", err)
			}
			fmt.Printf("📋 Container %s cloned → %s\n", args[0], args[1])
			return nil
		},
	}
}

// ── info ──

func infoCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "info <container>",
		Short:   "Show detailed configuration for a container",
		Aliases: []string{"inspect"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimes, err := initRuntimes()
			if err != nil {
				return err
			}
			rt, err := findRuntime(runtimes, args[0])
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cfg, err := rt.GetConfig(ctx, args[0])
			if err != nil {
				return fmt.Errorf("info: %w", err)
			}

			fmt.Printf("Container: %s\n", args[0])
			fmt.Printf("Runtime:   %s\n", rt.Name())
			fmt.Printf("Image:     %s\n", cfg.Image)
			if len(cfg.Profiles) > 0 {
				fmt.Printf("Profiles:  %s\n", strings.Join(cfg.Profiles, ", "))
			}
			if len(cfg.Config) > 0 {
				fmt.Printf("\nConfiguration:\n")
				keys := make([]string, 0, len(cfg.Config))
				for k := range cfg.Config {
					keys = append(keys, k)
				}
				// sort keys
				for i := 0; i < len(keys)-1; i++ {
					for j := i + 1; j < len(keys); j++ {
						if keys[i] > keys[j] {
							keys[i], keys[j] = keys[j], keys[i]
						}
					}
				}
				for _, k := range keys {
					fmt.Printf("  %-32s = %s\n", k, cfg.Config[k])
				}
			}
			return nil
		},
	}
}

// ── create / delete ──

func createContainerCmd() *cobra.Command {
	var image string
	var configPairs []string

	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimes, err := initRuntimes()
			if err != nil {
				return err
			}
			// Default to first runtime (LXD preferred)
			if len(runtimes) == 0 {
				return fmt.Errorf("no runtimes available")
			}
			rt := runtimes[0]

			config := make(map[string]string)
			for _, pair := range configPairs {
				parts := strings.SplitN(pair, "=", 2)
				if len(parts) == 2 {
					config[parts[0]] = parts[1]
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			if err := rt.CreateContainer(ctx, args[0], image, config); err != nil {
				return fmt.Errorf("create: %w", err)
			}
			fmt.Printf("✅ Container %q created (image: %s)\n", args[0], image)
			return nil
		},
	}

	cmd.Flags().StringVarP(&image, "image", "i", "ubuntu:24.04", "Container image")
	cmd.Flags().StringArrayVarP(&configPairs, "config", "c", nil, "Config key=value pairs (repeatable)")
	return cmd
}

func deleteContainerCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:     "delete <container>",
		Short:   "Delete a container (must be stopped, use --force to stop first)",
		Aliases: []string{"rm", "del"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimes, err := initRuntimes()
			if err != nil {
				return err
			}
			rt, err := findRuntime(runtimes, args[0])
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			if force {
				// Best-effort stop before delete
				_ = rt.StopContainer(ctx, args[0])
				time.Sleep(2 * time.Second)
			}

			if err := rt.DeleteContainer(ctx, args[0]); err != nil {
				return fmt.Errorf("delete: %w", err)
			}
			fmt.Printf("🗑 Container %q deleted\n", args[0])
			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Stop container before deleting")
	return cmd
}
