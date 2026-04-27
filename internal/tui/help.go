package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ── Help overlay — rendered from keymap.go definitions ──

func (a App) renderHelpOverlay() string {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorBlue)

	secStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorYellow)

	keyStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorGreen).
		Width(6)

	descStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#c9d1d9"))

	renderSection := func(s HelpSection) string {
		var b strings.Builder
		b.WriteString(secStyle.Render(s.Title) + "\n")
		for _, e := range s.Entries {
			b.WriteString(fmt.Sprintf(" %s %s\n", keyStyle.Render(e.Key), descStyle.Render(e.Desc)))
		}
		return b.String()
	}

	cols := HelpColumns()
	var rendered [3]string
	for i, sections := range cols {
		var parts []string
		for _, s := range sections {
			parts = append(parts, renderSection(s))
		}
		rendered[i] = strings.Join(parts, "\n")
	}

	// Render columns side by side
	colWidth := (a.width - 12) / 3
	if colWidth < 24 {
		colWidth = 24
	}
	if colWidth > 32 {
		colWidth = 32
	}

	colStyle := lipgloss.NewStyle().Width(colWidth).PaddingRight(1)

	columns := lipgloss.JoinHorizontal(lipgloss.Top,
		colStyle.Render(rendered[0]),
		colStyle.Render(rendered[1]),
		colStyle.Render(rendered[2]),
	)

	title := titleStyle.Render("📖 cella — Keyboard Shortcuts")
	hint := lipgloss.NewStyle().Foreground(ColorDim).Italic(true).
		Render("Press any key to close")

	content := title + "\n\n" + columns + "\n" + hint

	overlay := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBlue).
		Padding(1, 2).
		Render(content)

	return lipgloss.Place(a.width, a.height, lipgloss.Center, lipgloss.Center, overlay)
}
