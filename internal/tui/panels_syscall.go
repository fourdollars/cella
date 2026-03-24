package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fourdoors/cella/internal/trace"
)

// ── Syscall panel handler ──

func (a App) handleSyscallPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		a.focus = a.prevFocus
		return a, nil
	case "up", "k":
		if a.selected > 0 {
			a.selected--
			a.ensureTracing()
		}
		return a, nil
	case "down", "j":
		if a.selected < len(a.containers)-1 {
			a.selected++
			a.ensureTracing()
		}
		return a, nil
	case "T":
		// Stop tracing for current container
		if a.selected < len(a.containers) {
			name := a.containers[a.selected].Name
			if t, ok := a.tracers[name]; ok {
				t.Stop()
				delete(a.tracers, name)
				a.addEvent(fmt.Sprintf("🔬 syscall tracing stopped for %s", name))
			}
			a.focus = a.prevFocus
		}
		return a, nil
	case "G":
		// Generate seccomp profile from syscall panel
		if a.selected < len(a.containers) {
			name := a.containers[a.selected].Name
			if tracer, ok := a.tracers[name]; ok {
				profile, err := trace.GenerateProfile(tracer, name)
				if err != nil {
					a.addEvent(fmt.Sprintf("⚠ seccomp gen: %v", err))
				} else {
					jsonStr, _ := trace.ProfileToJSON(profile)
					a.seccompJSON = jsonStr
					a.seccompSummary = trace.ProfileSummary(profile)
					a.seccompScroll = 0
					a.prevFocus = panelSyscall
					a.focus = panelSeccompGen
					a.addEvent(fmt.Sprintf("🛡 seccomp profile: %d syscalls for %s",
						len(profile.Syscalls[0].Names), name))
				}
			}
		}
		return a, nil
	case "tab":
		a.focus = panelSidebar
		return a, nil
	}
	return a, nil
}

// ── Syscall panel render ──

func (a App) renderSyscallPanel() string {
	if a.selected >= len(a.containers) {
		return ""
	}
	containerName := a.containers[a.selected].Name
	tracer, ok := a.tracers[containerName]

	var b strings.Builder

	b.WriteString(TitleStyle.Render(fmt.Sprintf("🔬 Syscall Trace — %s ◆", containerName)) + "\n")

	if !ok || !tracer.IsRunning() {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).
			Render("\n  Tracer not active. Press [t] on a running container to start.\n"))
		return b.String()
	}

	snap := tracer.GetSnapshot()
	if snap == nil {
		lastErr := tracer.LastError()
		msg := "⏳ Collecting first snapshot... (wait ~5 seconds)\n"
		if lastErr != "" {
			msg += fmt.Sprintf("\n  ⚠ %s\n", lastErr)
		}
		b.WriteString(lipgloss.NewStyle().Foreground(ColorYellow).
			Render("\n  " + msg))
		return b.String()
	}

	// Show error if present
	if snap.Error != "" && snap.Total == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorRed).
			Render(fmt.Sprintf("\n  ⚠ %s\n", snap.Error)))
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).
			Render("\n  Retrying every 5 seconds...\n"))
		return b.String()
	}

	// Summary line
	b.WriteString(lipgloss.NewStyle().Foreground(ColorText).
		Render(fmt.Sprintf("  Total: %d syscalls/sample  |  %s\n\n",
			snap.Total,
			snap.Timestamp.UTC().Add(8*time.Hour).Format("15:04:05"))))

	// Family breakdown with bars
	b.WriteString(SectionHeaderStyle.Render("By Family") + "\n")
	families := []struct {
		name  string
		key   trace.SyscallFamily
		color lipgloss.Color
	}{
		{"File    ", trace.FamilyFile, ColorGreen},
		{"Network ", trace.FamilyNetwork, ColorBlue},
		{"Process ", trace.FamilyProcess, ColorPurple},
		{"Memory  ", trace.FamilyMemory, ColorOrange},
		{"IPC/Sync", trace.FamilyIPC, ColorYellow},
		{"Signal  ", trace.FamilySignal, ColorRed},
		{"Other   ", trace.FamilyOther, ColorDim},
	}

	for _, f := range families {
		count := snap.ByFamily[f.key]
		if count == 0 && snap.Total > 0 {
			continue
		}
		pct := float64(0)
		if snap.Total > 0 {
			pct = float64(count) / float64(snap.Total) * 100
		}
		barWidth := 20
		filled := int(pct / 100 * float64(barWidth))
		if filled < 0 {
			filled = 0
		}
		bar := lipgloss.NewStyle().Foreground(f.color).Render(strings.Repeat("█", filled)) +
			lipgloss.NewStyle().Foreground(ColorDim).Render(strings.Repeat("░", barWidth-filled))
		b.WriteString(fmt.Sprintf("  %s %s %5.1f%% (%d)\n",
			lipgloss.NewStyle().Foreground(f.color).Render(f.name),
			bar, pct, count))
	}

	// Top syscalls table
	b.WriteString("\n" + SectionHeaderStyle.Render("Top Syscalls") + "\n")
	header := fmt.Sprintf("  %-4s %-18s %6s %6s %-10s", "NR", "NAME", "COUNT", "%", "FAMILY")
	b.WriteString(lipgloss.NewStyle().Foreground(ColorSubtle).Render(header) + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).Render("  " + strings.Repeat("─", 48)) + "\n")

	for i, sc := range snap.TopCalls {
		if i >= 12 {
			break
		}
		familyColor := ColorDim
		switch sc.Family {
		case trace.FamilyFile:
			familyColor = ColorGreen
		case trace.FamilyNetwork:
			familyColor = ColorBlue
		case trace.FamilyProcess:
			familyColor = ColorPurple
		case trace.FamilyMemory:
			familyColor = ColorOrange
		case trace.FamilyIPC:
			familyColor = ColorYellow
		case trace.FamilySignal:
			familyColor = ColorRed
		}

		pct := float64(0)
		if snap.Total > 0 {
			pct = float64(sc.Count) / float64(snap.Total) * 100
		}

		// Pad name to fixed width BEFORE applying ANSI style (otherwise escape codes break alignment)
		paddedName := fmt.Sprintf("%-18s", sc.Name)
		styledName := lipgloss.NewStyle().Foreground(ColorText).Render(paddedName)
		styledFamily := lipgloss.NewStyle().Foreground(familyColor).Render(string(sc.Family))

		b.WriteString(fmt.Sprintf("  %-4d %s %6d %5.1f%% %s\n",
			sc.ID,
			styledName,
			sc.Count,
			pct,
			styledFamily,
		))
	}

	// Sparkline history of total syscalls
	history := tracer.GetHistory()
	if len(history) > 1 {
		b.WriteString("\n" + SectionHeaderStyle.Render("Activity") + "\n")
		totals := make([]float64, len(history))
		for i, h := range history {
			totals[i] = float64(h.Total)
		}
		b.WriteString("  " + renderSparkline(totals, ColorOrange) + "\n")
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).
			Render(fmt.Sprintf("  ← %d samples (2s each) →\n", len(history))))
	}

	return b.String()
}

// ensureTracing starts tracing for the currently selected container if not already running
func (a *App) ensureTracing() {
	if a.selected >= len(a.containers) {
		return
	}
	c := a.containers[a.selected]
	if c.Status != "Running" {
		return
	}
	name := c.Name
	if _, exists := a.tracers[name]; !exists {
		cgroupPath := resolveCgroupPath(c)
		tracer := trace.NewTracer(name, cgroupPath)
		_ = tracer.Start(context.Background())
		a.tracers[name] = tracer
		a.addEvent(fmt.Sprintf("🔬 syscall tracing started for %s", name))
	}
}

// ── Seccomp panel handler ──

func (a App) handleSeccompPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		a.focus = a.prevFocus
		return a, nil
	case "up", "k":
		if a.seccompScroll > 0 {
			a.seccompScroll--
		}
	case "down", "j":
		lines := strings.Split(a.seccompJSON, "\n")
		maxScroll := len(lines) - (a.height - 14)
		if maxScroll < 0 {
			maxScroll = 0
		}
		if a.seccompScroll < maxScroll {
			a.seccompScroll++
		}
	case "S":
		// Save profile to file
		if a.seccompJSON != "" && a.selected < len(a.containers) {
			name := a.containers[a.selected].Name
			filename := fmt.Sprintf("/tmp/cella-seccomp-%s.json", name)
			if err := saveToFile(filename, a.seccompJSON); err != nil {
				a.addEvent(fmt.Sprintf("⚠ save failed: %v", err))
				return a, a.setFlash(fmt.Sprintf("❌ Save failed: %v", err))
			}
			a.addEvent(fmt.Sprintf("💾 saved to %s", filename))
			return a, a.setFlash(fmt.Sprintf("✅ Saved to %s", filename))
		}
	}
	return a, nil
}

// ── Seccomp panel render ──

func (a App) renderSeccompPanel() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("🛡 Generated Seccomp Profile ◆") + "\n")

	// Summary
	if a.seccompSummary != "" {
		lines := strings.Split(a.seccompSummary, "\n")
		for _, line := range lines {
			b.WriteString("  " + lipgloss.NewStyle().Foreground(ColorText).Render(line) + "\n")
		}
	}

	b.WriteString("\n" + SectionHeaderStyle.Render("JSON Profile") + "\n")

	// Scrollable JSON
	lines := strings.Split(a.seccompJSON, "\n")
	totalLines := len(lines)
	visibleH := a.height - 18
	if visibleH < 5 {
		visibleH = 5
	}

	start := a.seccompScroll
	end := start + visibleH
	if end > totalLines {
		end = totalLines
	}
	if start > totalLines {
		start = totalLines
	}

	if totalLines > visibleH {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).
			Render(fmt.Sprintf("  [%d-%d of %d lines]\n", start+1, end, totalLines)))
	}

	jsonStyle := lipgloss.NewStyle().Foreground(ColorGreen)
	for i := start; i < end; i++ {
		b.WriteString("  " + jsonStyle.Render(lines[i]) + "\n")
	}

	b.WriteString("\n" + lipgloss.NewStyle().Foreground(ColorYellow).Bold(true).
		Render("  Press S to save │ Esc to go back") + "\n")

	// Flash message
	if a.flashText != "" && time.Now().Before(a.flashExpiry) {
		b.WriteString("\n" + lipgloss.NewStyle().
			Foreground(lipgloss.Color("#0d1117")).
			Background(ColorGreen).
			Bold(true).
			Padding(0, 1).
			Render(a.flashText) + "\n")
	}

	return b.String()
}
