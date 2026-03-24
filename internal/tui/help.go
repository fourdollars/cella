package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ── Help overlay ──

func (a App) renderHelpOverlay() string {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorBlue).
		MarginBottom(1)

	sectionStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorYellow).
		MarginTop(1)

	keyStyle := HelpKeyStyle.Copy().Width(10)
	descStyle := HelpDescStyle

	var b strings.Builder
	b.WriteString(titleStyle.Render("  📖 cella — Keyboard Shortcuts") + "\n\n")

	b.WriteString(sectionStyle.Render("  Navigation") + "\n")
	navKeys := [][]string{
		{"↑/k", "Move up"},
		{"↓/j", "Move down"},
		{"1", "Sort by name"},
		{"2", "Sort by CPU"},
		{"3", "Sort by memory"},
	}
	for _, h := range navKeys {
		b.WriteString(fmt.Sprintf("  %s %s\n", keyStyle.Render(h[0]), descStyle.Render(h[1])))
	}

	b.WriteString(sectionStyle.Render("  Container Actions") + "\n")
	actionKeys := [][]string{
		{"s", "Start container"},
		{"x", "Stop container"},
		{"p", "Pause / Unpause"},
		{"e", "Execute command"},
		{"l", "View logs (streaming)"},
		{"+", "Create new container"},
		{"d", "Delete container (stopped only)"},
	}
	for _, h := range actionKeys {
		b.WriteString(fmt.Sprintf("  %s %s\n", keyStyle.Render(h[0]), descStyle.Render(h[1])))
	}

	b.WriteString(sectionStyle.Render("  Panels") + "\n")
	panelKeys := [][]string{
		{"w", "Network monitoring"},
		{"r", "Resource limits & usage"},
		{"n", "Snapshots & clone"},
		{"P", "Security policy (seccomp/egress)"},
		{"D", "DNS monitor (traffic/allow/deny)"},
		{"V", "Recent events log"},
		{"t", "Start syscall trace"},
		{"T", "Stop syscall trace"},
		{"G", "Generate seccomp profile"},
		{"S", "Save seccomp profile"},
	}
	for _, h := range panelKeys {
		b.WriteString(fmt.Sprintf("  %s %s\n", keyStyle.Render(h[0]), descStyle.Render(h[1])))
	}

	b.WriteString(sectionStyle.Render("  General") + "\n")
	generalKeys := [][]string{
		{"E", "Export container config (JSON)"},
		{"I", "Import config from file"},
		{"f", "Cycle runtime filter"},
		{"/", "Search containers by name"},
		{"g", "Goto container # (type number, Enter)"},
		{"?", "Show this help"},
		{"q", "Quit (with confirmation)"},
		{"esc", "Back / close panel"},
	}
	for _, h := range generalKeys {
		b.WriteString(fmt.Sprintf("  %s %s\n", keyStyle.Render(h[0]), descStyle.Render(h[1])))
	}

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).Italic(true).
		Render("  Press any key to close") + "\n")

	overlay := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBlue).
		Padding(1, 2).
		Width(50).
		Render(b.String())

	// Center the overlay
	return lipgloss.Place(a.width, a.height, lipgloss.Center, lipgloss.Center, overlay)
}
