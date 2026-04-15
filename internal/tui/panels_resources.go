package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fourdoors/cella/internal/lxd"
)

// formatSnapshotSize returns a human-readable size string.
// Returns "-" when the storage driver does not track snapshot sizes (e.g. dir).
func formatSnapshotSize(bytes int64) string {
	if bytes <= 0 {
		return "-"
	}
	const (
		KiB = 1024
		MiB = 1024 * KiB
		GiB = 1024 * MiB
	)
	switch {
	case bytes >= GiB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/GiB)
	case bytes >= MiB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/MiB)
	case bytes >= KiB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/KiB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// ── Resources panel handler ──

func (a App) handleResourcesPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if a.resEditing {
		switch msg.String() {
		case "esc":
			a.resEditing = false
			a.resInput = ""
			return a, nil
		case "enter":
			a.resEditing = false
			val := strings.TrimSpace(a.resInput)
			a.resInput = ""
			if val == "" {
				return a, nil
			}
			var configKey string
			switch a.resCursor {
			case 0:
				configKey = "limits.cpu"
			case 1:
				configKey = "limits.memory"
			}
			if configKey != "" {
				name := a.resTarget
				rt := a.runtimeFor(name)
				return a, func() tea.Msg {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if rt == nil {
						return asyncResultMsg{err: fmt.Errorf("no runtime for %s", name)}
					}
					err := rt.UpdateConfig(ctx, name, map[string]string{configKey: val})
					if err != nil {
						return asyncResultMsg{err: fmt.Errorf("set %s=%s: %w", configKey, val, err)}
					}
					return asyncResultMsg{text: fmt.Sprintf("%s set to %s for %s", configKey, val, name)}
				}
			}
			return a, nil
		case "backspace":
			if len(a.resInput) > 0 {
				a.resInput = a.resInput[:len(a.resInput)-1]
			}
			return a, nil
		default:
			if len(msg.String()) == 1 {
				a.resInput += msg.String()
			}
			return a, nil
		}
	}

	switch msg.String() {
	case "esc", "q":
		a.focus = a.prevFocus
		return a, nil
	case "up", "k":
		if a.resCursor > 0 {
			a.resCursor--
		}
	case "down", "j":
		if a.resCursor < 1 {
			a.resCursor++
		}
	case "enter":
		a.resEditing = true
		a.resInput = ""
	case "r":
		return a, fetchConfig(a.runtimeFor(a.resTarget), a.resTarget)
	}
	return a, nil
}

// ── Resources panel render ──

func (a App) renderResourcesPanel() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render(fmt.Sprintf("⚙ Resource Limits — %s ◆", a.resTarget)) + "\n")

	if a.resConfig == nil {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorYellow).
			Render("\n  ⏳ Loading configuration...\n"))
		return b.String()
	}

	// Host system info
	if a.hostRes != nil {
		hostStyle := lipgloss.NewStyle().Foreground(ColorSubtle)
		memFree := a.hostRes.MemoryTotal - a.hostRes.MemoryUsed
		memPct := float64(a.hostRes.MemoryUsed) / float64(a.hostRes.MemoryTotal) * 100
		b.WriteString(hostStyle.Render(fmt.Sprintf("  Host: %d CPUs │ RAM %s / %s (%.0f%% used, %s free)",
			a.hostRes.CPUTotal,
			formatBytes(a.hostRes.MemoryUsed), formatBytes(a.hostRes.MemoryTotal),
			memPct, formatBytes(memFree))) + "\n\n")
	}

	config := a.resConfig.Config

	type resRow struct {
		label   string
		key     string
		current string
		hint    string
	}

	cpuHint := "e.g. 2, 0-3, 200ms/100ms"
	memHint := "e.g. 256MB, 1GB, 2GiB"
	if a.hostRes != nil {
		cpuHint = fmt.Sprintf("max %d │ e.g. 2, 0-3, 200ms/100ms", a.hostRes.CPUTotal)
		memFree := a.hostRes.MemoryTotal - a.hostRes.MemoryUsed
		memHint = fmt.Sprintf("free %s │ e.g. 256MB, 1GB", formatBytes(memFree))
	}

	rows := []resRow{
		{
			label:   "CPU Limit",
			key:     "limits.cpu",
			current: config["limits.cpu"],
			hint:    cpuHint,
		},
		{
			label:   "Memory Limit",
			key:     "limits.memory",
			current: config["limits.memory"],
			hint:    memHint,
		},
	}

	b.WriteString("\n")
	for i, row := range rows {
		cursor := "  "
		style := lipgloss.NewStyle().Foreground(ColorText)
		if i == a.resCursor {
			cursor = "▸ "
			style = style.Foreground(ColorBlue).Bold(true)
		}

		val := row.current
		if val == "" {
			val = "(not set)"
		}

		b.WriteString(cursor + style.Render(fmt.Sprintf("%-14s", row.label)))

		if a.resEditing && i == a.resCursor {
			b.WriteString(lipgloss.NewStyle().Foreground(ColorGreen).Bold(true).
				Render(fmt.Sprintf("  → %s▌", a.resInput)))
			b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).
				Render(fmt.Sprintf("  (%s)", row.hint)))
		} else {
			b.WriteString(lipgloss.NewStyle().Foreground(ColorText).
				Render(fmt.Sprintf("  %s", val)))
		}
		b.WriteString("\n\n")
	}

	// Show other useful config values (read-only)
	b.WriteString(SectionHeaderStyle.Render("Current Usage") + "\n\n")

	barWidth := 30

	// Find container in our list for live metrics
	for _, c := range a.containers {
		if c.Name == a.resTarget {
			if m, ok := a.metrics[c.Name]; ok {
				// Check if CPU is pinned to specific cores
				cpuPins := parseCPUPins(config["limits.cpu"])

				if len(cpuPins) > 0 && len(a.perCPUUsage) > 0 {
					// Show per-CPU bars for pinned cores
					usageMap := make(map[int]float64)
					for _, u := range a.perCPUUsage {
						usageMap[u.ID] = u.Percent
					}
					for _, cpuID := range cpuPins {
						pct := usageMap[cpuID]
						bar := renderProgressBar(pct, 100.0, barWidth)
						b.WriteString(fmt.Sprintf("  CPU%-2d   %s  %.1f%%\n", cpuID, bar, pct))
					}
				} else {
					// Aggregate CPU bar
					cpuPct := m.CPUPercent
					cpuBar := renderProgressBar(cpuPct, 100.0, barWidth)
					b.WriteString(fmt.Sprintf("  CPU     %s  %.1f%%\n", cpuBar, cpuPct))
				}

				// Memory bar (container usage vs limit or host total)
				memLimit := c.MemoryMax
				if memLimit == 0 && a.hostRes != nil {
					memLimit = a.hostRes.MemoryTotal
				}
				memPct := 0.0
				if memLimit > 0 {
					memPct = float64(c.MemoryCur) / float64(memLimit) * 100
				}
				memBar := renderProgressBar(memPct, 100.0, barWidth)
				b.WriteString(fmt.Sprintf("  MEM     %s  %s / %s (%.0f%%)\n",
					memBar, formatBytes(c.MemoryCur), formatBytes(memLimit), memPct))

				// Disk I/O rate
				b.WriteString(fmt.Sprintf("  DISK    R %s/s  W %s/s\n",
					formatBytes(m.DiskReadRate), formatBytes(m.DiskWriteRate)))
				if c.DiskUsage > 0 {
					b.WriteString(fmt.Sprintf("          %s used\n", formatBytes(c.DiskUsage)))
				}

				b.WriteString(fmt.Sprintf("  PIDs    %d\n", c.PIDs))

				// Network rates
				b.WriteString(fmt.Sprintf("  NET     ↓ %s/s  ↑ %s/s\n",
					formatBytes(m.NetRxRate), formatBytes(m.NetTxRate)))
			}
			break
		}
	}

	// Host-level bar if available
	if a.hostRes != nil {
		b.WriteString("\n" + SectionHeaderStyle.Render("Host Overview") + "\n\n")
		hostMemPct := float64(a.hostRes.MemoryUsed) / float64(a.hostRes.MemoryTotal) * 100
		hostMemBar := renderProgressBar(hostMemPct, 100.0, barWidth)
		b.WriteString(fmt.Sprintf("  RAM     %s  %s / %s (%.0f%%)\n",
			hostMemBar,
			formatBytes(a.hostRes.MemoryUsed), formatBytes(a.hostRes.MemoryTotal), hostMemPct))
	}

	b.WriteString("\n" + SectionHeaderStyle.Render("Other Limits") + "\n\n")
	otherKeys := []string{"limits.cpu.allowance", "limits.cpu.priority",
		"limits.disk.priority", "limits.memory.swap", "limits.processes"}
	for _, k := range otherKeys {
		if v, ok := config[k]; ok {
			b.WriteString(fmt.Sprintf("  %-26s %s\n", k, v))
		}
	}

	return b.String()
}

// ── Snapshots panel handler ──

func (a App) handleSnapshotsPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Confirm mode — must be checked FIRST before any text-input / normal key handling
	if a.snapConfirmDelete || a.snapConfirmRestore {
		snapName := a.snapConfirmName
		name := a.snapTarget
		switch msg.String() {
		case "y", "Y":
			if a.snapConfirmDelete {
				a.snapConfirmDelete = false
				a.snapConfirmName = ""
				rt := a.runtimeFor(name)
				return a, func() tea.Msg {
					ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
					defer cancel()
					if rt == nil {
						return asyncResultMsg{err: fmt.Errorf("no runtime for %s", name)}
					}
					err := rt.DeleteSnapshot(ctx, name, snapName)
					if err != nil {
						return asyncResultMsg{err: fmt.Errorf("delete snapshot: %w", err)}
					}
					return asyncResultMsg{text: fmt.Sprintf("🗑 deleted snapshot '%s' from %s", snapName, name)}
				}
			}
			if a.snapConfirmRestore {
				a.snapConfirmRestore = false
				a.snapConfirmName = ""
				return a, func() tea.Msg {
					ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
					defer cancel()
					lxdClient, _ := lxd.NewClient("")
					if lxdClient != nil {
						err := lxdClient.RestoreSnapshot(ctx, name, snapName)
						if err != nil {
							return asyncResultMsg{err: fmt.Errorf("restore: %w", err)}
						}
					}
					return asyncResultMsg{text: fmt.Sprintf("⏪ restored %s to snapshot '%s'", name, snapName)}
				}
			}
		default:
			// Any other key cancels the confirmation
			a.snapConfirmDelete = false
			a.snapConfirmRestore = false
			a.snapConfirmName = ""
		}
		return a, nil
	}

	// Text input mode for naming/renaming/cloning
	if a.snapNaming || a.snapCloning || a.snapRenaming {
		switch msg.String() {
		case "esc":
			a.snapNaming = false
			a.snapCloning = false
			a.snapRenaming = false
			a.snapRenameOld = ""
			a.snapInput = ""
			return a, nil
		case "enter":
			val := strings.TrimSpace(a.snapInput)
			a.snapInput = ""
			if val == "" {
				a.snapNaming = false
				a.snapCloning = false
				a.snapRenaming = false
				return a, nil
			}
			name := a.snapTarget
			if a.snapNaming {
				a.snapNaming = false
				rt := a.runtimeFor(name)
				return a, func() tea.Msg {
					ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
					defer cancel()
					if rt == nil {
						return asyncResultMsg{err: fmt.Errorf("no runtime for %s", name)}
					}
					err := rt.CreateSnapshot(ctx, name, val)
					if err != nil {
						return asyncResultMsg{err: fmt.Errorf("snapshot: %w", err)}
					}
					return asyncResultMsg{text: fmt.Sprintf("📸 snapshot '%s' created for %s", val, name)}
				}
			}
			if a.snapRenaming {
				a.snapRenaming = false
				oldName := a.snapRenameOld
				a.snapRenameOld = ""
				rt := a.runtimeFor(name)
				return a, func() tea.Msg {
					ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
					defer cancel()
					if rt == nil {
						return asyncResultMsg{err: fmt.Errorf("no runtime for %s", name)}
					}
					err := rt.RenameSnapshot(ctx, name, oldName, val)
					if err != nil {
						return asyncResultMsg{err: fmt.Errorf("rename failed: %w", err)}
					}
					// Verify: re-fetch snapshot list and confirm new name exists
					snaps, verifyErr := rt.ListSnapshots(ctx, name)
					if verifyErr != nil {
						// API rename succeeded but can't verify — report both
						return asyncResultMsg{text: fmt.Sprintf("✏️ renamed '%s' → '%s' (verify failed: %v)", oldName, val, verifyErr)}
					}
					found := false
					for _, s := range snaps {
						if s.Name == val {
							found = true
							break
						}
					}
					if !found {
						return asyncResultMsg{err: fmt.Errorf("rename rejected by LXD: '%s' not found after rename (name may contain invalid characters like '.')", val)}
					}
					return asyncResultMsg{text: fmt.Sprintf("✏️ renamed '%s' → '%s'", oldName, val)}
				}
			}
			if a.snapCloning {
				a.snapCloning = false
				rt := a.runtimeFor(name)
				return a, func() tea.Msg {
					ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
					defer cancel()
					if rt == nil {
						return asyncResultMsg{err: fmt.Errorf("no runtime for %s", name)}
					}
					err := rt.CopyContainer(ctx, name, val)
					if err != nil {
						return asyncResultMsg{err: fmt.Errorf("clone: %w", err)}
					}
					// Verify: check the cloned container actually exists
					// (LXD rejects names containing '.' or other invalid chars)
					containers, verifyErr := rt.ListContainers(ctx)
					if verifyErr != nil {
						// Can't verify — report the ambiguity
						return asyncResultMsg{text: fmt.Sprintf("🐑 cloned %s → %s (verify failed: %v)", name, val, verifyErr)}
					}
					for _, c := range containers {
						if c.Name == val {
							return asyncResultMsg{text: fmt.Sprintf("🐑 cloned %s → %s", name, val)}
						}
					}
					return asyncResultMsg{err: fmt.Errorf("clone failed: '%s' not found after operation (name may contain invalid characters like '.')", val)}
				}
			}
			return a, nil
		case "backspace":
			if len(a.snapInput) > 0 {
				a.snapInput = a.snapInput[:len(a.snapInput)-1]
			}
			return a, nil
		default:
			if len(msg.String()) == 1 {
				ch := msg.String()
				// LXD rejects container/snapshot names containing '.'
				if ch == "." && a.snapCloning {
					return a, nil // silently drop '.' in clone name
				}
				a.snapInput += ch
			}
			return a, nil
		}
	}

	switch msg.String() {
	case "esc", "q":
		a.focus = a.prevFocus
		return a, nil
	case "up", "k":
		if a.snapCursor > 0 {
			a.snapCursor--
		}
	case "down", "j":
		if a.snapCursor < len(a.snapshots)-1 {
			a.snapCursor++
		}
	case "n":
		a.snapNaming = true
		a.snapInput = fmt.Sprintf("snap-%s", time.Now().Format("20060102-1504"))
	case "c":
		a.snapCloning = true
		// Sanitize: replace '.' with '-' so LXD won't reject the name
		sanitized := strings.ReplaceAll(a.snapTarget, ".", "-")
		a.snapInput = sanitized + "-clone"
	case "R":
		// Restore snapshot (LXD only) — ask for confirmation first
		if a.snapCursor < len(a.snapshots) {
			if a.containerRuntime(a.snapTarget) == "docker" {
				a.addEvent("⚠ Docker doesn't support snapshot restore")
				return a, nil
			}
			a.snapConfirmRestore = true
			a.snapConfirmName = a.snapshots[a.snapCursor].Name
		}
	case "D":
		// Delete snapshot — ask for confirmation first
		if a.snapCursor < len(a.snapshots) {
			a.snapConfirmDelete = true
			a.snapConfirmName = a.snapshots[a.snapCursor].Name
		}
	case "r":
		// Rename selected snapshot
		if a.snapCursor < len(a.snapshots) {
			snap := a.snapshots[a.snapCursor]
			a.snapRenaming = true
			a.snapRenameOld = snap.Name
			a.snapInput = snap.Name
			return a, nil
		}
	}
	return a, nil
}

// ── Snapshots panel render ──

// fmtSnapTime converts RFC3339 / arbitrary timestamp to "2006-01-02 15:04" for display.
func fmtSnapTime(s string) string {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Local().Format("2006-01-02 15:04")
		}
	}
	return s // fallback: show as-is
}

func (a App) renderSnapshotsPanel() string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e"))
	blue := lipgloss.NewStyle().Bold(true).Foreground(ColorBlue)
	sel := lipgloss.NewStyle().Bold(true).Foreground(ColorBlue).Background(lipgloss.Color("#1a2a3a"))
	purple := lipgloss.NewStyle().Foreground(lipgloss.Color("#8e44ad"))
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("#27ae60"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("#e74c3c")).Bold(true)
	orange := lipgloss.NewStyle().Foreground(lipgloss.Color("#e67e22")).Bold(true)

	var b strings.Builder
	b.WriteString(TitleStyle.Render(fmt.Sprintf("📸 Snapshots — %s ◆", a.snapTarget)) + "\n")

	if a.snapshots == nil {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorYellow).Render("\n  ⏳ Loading snapshots...\n"))
		return b.String()
	}

	// ── Layout: left list | right detail ──
	// Total usable width: a.width minus outer borders (~4) and sidebar
	totalW := a.width - 4
	if totalW < 60 {
		totalW = 60
	}
	listW := 36  // left column fixed width
	divW := 1    // │ divider
	detailW := totalW - listW - divW - 2
	if detailW < 20 {
		detailW = 20
	}

	// ── Left: snapshot list ──
	var listB strings.Builder
	if len(a.snapshots) == 0 {
		listB.WriteString(dim.Render("  No snapshots yet.") + "\n")
	} else {
		listB.WriteString(dim.Render(fmt.Sprintf("  %-24s  %s", "NAME", "CREATED")) + "\n")
		listB.WriteString(dim.Render("  " + strings.Repeat("─", listW-2)) + "\n")
		for i, snap := range a.snapshots {
			name := snap.Name
			if len(name) > 22 {
				name = name[:21] + "…"
			}
			created := fmtSnapTime(snap.CreatedAt)
			row := fmt.Sprintf("%-24s  %s", name, created)
			if i == a.snapCursor {
				listB.WriteString("▸ " + sel.Render(row) + "\n")
			} else {
				listB.WriteString("  " + row + "\n")
			}
		}
	}

	// ── Right: detail panel for focused snapshot ──
	var detailB strings.Builder
	if a.snapCursor >= 0 && a.snapCursor < len(a.snapshots) {
		snap := a.snapshots[a.snapCursor]

		detailRow := func(label, value string) string {
			return fmt.Sprintf(" %s  %s\n", dim.Render(fmt.Sprintf("%-14s", label)), value)
		}

		detailB.WriteString(blue.Render(snap.Name) + "\n")
		detailB.WriteString(dim.Render(strings.Repeat("─", detailW-1)) + "\n")

		// Size
		sizeStr := formatSnapshotSize(snap.Size)
		if sizeStr == "-" {
			sizeStr = dim.Render("unknown")
		}
		detailB.WriteString(detailRow("Size", sizeStr))

		// Stateful
		if snap.Stateful {
			detailB.WriteString(detailRow("Stateful", green.Render("✦ yes (with memory)")))
		} else {
			detailB.WriteString(detailRow("Stateful", dim.Render("no")))
		}

		// Profiles
		if len(snap.Profiles) > 0 {
			detailB.WriteString(detailRow("Profiles", purple.Render(strings.Join(snap.Profiles, ", "))))
		}

		// Config keys of interest
		keyConfigs := []struct{ key, label string }{
			{"limits.cpu", "CPU limit"},
			{"limits.memory", "Memory limit"},
			{"security.privileged", "Privileged"},
			{"security.nesting", "Nesting"},
			{"security.idmap.isolated", "ID map isolated"},
			{"image.os", "Image OS"},
			{"image.release", "Image release"},
			{"image.description", "Image desc"},
			{"cloud-init.user-data", "cloud-init"},
		}
		if len(snap.Config) > 0 {
			shown := 0
			for _, kv := range keyConfigs {
				if v, ok := snap.Config[kv.key]; ok && v != "" {
					if shown == 0 {
						detailB.WriteString(dim.Render(strings.Repeat("─", detailW-1)) + "\n")
					}
					// Truncate long values to fit column
					display := v
					maxV := detailW - 18
					if maxV < 10 {
						maxV = 10
					}
					if len(display) > maxV {
						display = display[:maxV-1] + "…"
					}
					detailB.WriteString(detailRow(kv.label, green.Render(display)))
					shown++
				}
			}
		}
	}

	// ── Join columns side by side ──
	leftLines := strings.Split(strings.TrimRight(listB.String(), "\n"), "\n")
	rightLines := strings.Split(strings.TrimRight(detailB.String(), "\n"), "\n")

	maxLines := len(leftLines)
	if len(rightLines) > maxLines {
		maxLines = len(rightLines)
	}

	b.WriteString("\n")
	for i := 0; i < maxLines; i++ {
		left := ""
		if i < len(leftLines) {
			left = leftLines[i]
		}
		right := ""
		if i < len(rightLines) {
			right = rightLines[i]
		}
		// Pad left column to fixed width (strip ANSI for padding calc is complex;
		// use lipgloss Width for visual width)
		padded := lipgloss.NewStyle().Width(listW).Render(left)
		b.WriteString(padded + dim.Render("│") + " " + right + "\n")
	}

	// ── Footer: count + input prompts + confirm ──
	b.WriteString(fmt.Sprintf("\n  %d snapshot(s)\n", len(a.snapshots)))

	if a.snapNaming {
		b.WriteString("\n" + lipgloss.NewStyle().Foreground(ColorGreen).Bold(true).
			Render(fmt.Sprintf("  New snapshot name: %s▌", a.snapInput)) + "\n")
	}
	if a.snapCloning {
		b.WriteString("\n" + lipgloss.NewStyle().Foreground(ColorGreen).Bold(true).
			Render(fmt.Sprintf("  Clone target name: %s▌", a.snapInput)) + "\n")
	}
	if a.snapRenaming {
		b.WriteString("\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("#e67e22")).Bold(true).
			Render(fmt.Sprintf("  Rename '%s' → %s▌", a.snapRenameOld, a.snapInput)) + "\n")
	}

	// Confirmation prompts — always at the very bottom
	if a.snapConfirmDelete {
		b.WriteString("\n" + red.
			Render(fmt.Sprintf("  ⚠  Delete snapshot '%s'?  [y] yes  [n] cancel", a.snapConfirmName)) + "\n")
	}
	if a.snapConfirmRestore {
		b.WriteString("\n" + orange.
			Render(fmt.Sprintf("  ⚠  Restore to '%s'? Container will stop.  [y] yes  [n] cancel", a.snapConfirmName)) + "\n")
	}

	return b.String()
}
