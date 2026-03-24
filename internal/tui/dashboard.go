package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ── Dashboard rendering ──

func (a App) renderDashboard() string {
	if len(a.containers) == 0 {
		return lipgloss.NewStyle().Foreground(ColorDim).Render("\n  No containers found\n")
	}

	c := a.containers[a.selected]
	m := a.getMetric(c.Name)
	var b strings.Builder

	rtIcon := "🔷"
	rtLabel := "LXD"
	if c.Runtime == "docker" {
		rtIcon = "🐳"
		rtLabel = "Docker"
	}

	focusIndicator := ""
	title := fmt.Sprintf("─ %s %s %s%s ", rtIcon, c.Name, rtLabel, focusIndicator)
	if c.Image != "" {
		title = fmt.Sprintf("─ %s %s (%s)%s ", rtIcon, c.Name, c.Image, focusIndicator)
	}
	b.WriteString(TitleStyle.Render(title) + "\n")

	if c.Status != "Running" {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).Render(
			fmt.Sprintf("\n  Container is %s\n\n  Press [s] to start", strings.ToLower(c.Status))))
		return b.String()
	}

	// CPU
	b.WriteString(SectionHeaderStyle.Render("CPU") + "\n")
	b.WriteString(renderBar("", m.CPUPercent, 100, ColorGreen, 30))
	b.WriteString(fmt.Sprintf("  %.2f%%\n", m.CPUPercent))
	if len(m.CPUHist) > 1 {
		b.WriteString("  " + renderSparkline(m.CPUHist, ColorGreen) + "\n")
	}

	// Memory
	b.WriteString(SectionHeaderStyle.Render("Memory") + "\n")
	memMax := c.MemoryMax
	if memMax <= 0 {
		memMax = 1 << 30
	}
	b.WriteString(renderBar("", m.MemPercent, 100, ColorBlue, 30))
	b.WriteString(fmt.Sprintf("  %s / %s (%.1f%%)\n", formatBytes(c.MemoryCur), formatBytes(memMax), m.MemPercent))
	if len(m.MemHist) > 1 {
		b.WriteString("  " + renderSparkline(m.MemHist, ColorBlue) + "\n")
	}

	// Network
	b.WriteString(SectionHeaderStyle.Render("Network") + "\n")
	b.WriteString(fmt.Sprintf("  ↑ %s/s  ↓ %s/s\n",
		formatBytes(m.NetTxRate), formatBytes(m.NetRxRate)))
	b.WriteString(fmt.Sprintf("  Total: ↑ %s  ↓ %s\n",
		formatBytes(c.NetTxBytes), formatBytes(c.NetRxBytes)))
	if len(m.NetRxHist) > 1 || len(m.NetTxHist) > 1 {
		b.WriteString("  ↓ " + renderSparkline(m.NetRxHist, ColorBlue) + "\n")
		b.WriteString("  ↑ " + renderSparkline(m.NetTxHist, ColorGreen) + "\n")
	}

	// Disk I/O
	b.WriteString(SectionHeaderStyle.Render("Disk I/O") + "\n")
	b.WriteString(fmt.Sprintf("  R %s/s  W %s/s\n",
		formatBytes(m.DiskReadRate), formatBytes(m.DiskWriteRate)))
	if c.DiskUsage > 0 {
		b.WriteString(fmt.Sprintf("  Usage: %s\n", formatBytes(c.DiskUsage)))
	}
	if len(m.DiskRHist) > 1 || len(m.DiskWHist) > 1 {
		b.WriteString("  R " + renderSparkline(m.DiskRHist, ColorGreen) + "\n")
		b.WriteString("  W " + renderSparkline(m.DiskWHist, ColorRed) + "\n")
	}

	// Info
	b.WriteString(SectionHeaderStyle.Render("Info") + "\n")
	b.WriteString(fmt.Sprintf("  IP: %s  PIDs: %d  Type: %s\n", c.IP, c.PIDs, c.Type))
	b.WriteString(fmt.Sprintf("  Profiles: %s  Created: %s\n",
		strings.Join(c.Profiles, ", "), c.CreatedAt))

	// Events
	if len(a.events) > 0 {
		b.WriteString(SectionHeaderStyle.Render("Events (live)") + "\n")
		start := len(a.events) - 6
		if start < 0 {
			start = 0
		}
		for _, ev := range a.events[start:] {
			style := EventNormalStyle
			if strings.Contains(ev.Text, "■") || strings.Contains(ev.Text, "✖") {
				style = EventErrorStyle
			} else if strings.Contains(ev.Text, "⚠") || strings.Contains(ev.Text, "⏸") {
				style = EventWarnStyle
			} else if strings.Contains(ev.Text, "▶") || strings.Contains(ev.Text, "✚") || strings.Contains(ev.Text, "🔬") {
				style = lipgloss.NewStyle().Foreground(ColorGreen)
			}
			ts := ev.Time.Format("15:04:05")
			b.WriteString("  " + lipgloss.NewStyle().Faint(true).Render(ts) + " " + style.Render(ev.Text) + "\n")
		}
	}

	return b.String()
}
