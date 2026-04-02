package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── Events panel handler ──

func (a App) handleEventsPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		a.focus = panelSidebar
		return a, nil
	case "up", "k":
		if a.eventScroll > 0 {
			a.eventScroll--
		}
		return a, nil
	case "down", "j":
		maxIdx := len(a.events) - 1
		if maxIdx < 0 {
			maxIdx = 0
		}
		if a.eventScroll < maxIdx {
			a.eventScroll++
		}
		return a, nil
	case "pgup":
		step := (a.height - 10) / 2
		if step < 1 {
			step = 1
		}
		if a.eventScroll > step {
			a.eventScroll -= step
		} else {
			a.eventScroll = 0
		}
		return a, nil
	case "pgdown":
		maxIdx := len(a.events) - 1
		if maxIdx < 0 {
			maxIdx = 0
		}
		step := (a.height - 10) / 2
		if step < 1 {
			step = 1
		}
		if a.eventScroll+step < maxIdx {
			a.eventScroll += step
		} else {
			a.eventScroll = maxIdx
		}
		return a, nil
	case "G":
		// Jump to latest
		a.eventScroll = len(a.events) - 1
		if a.eventScroll < 0 {
			a.eventScroll = 0
		}
		return a, nil
	case "g":
		// Jump to top
		a.eventScroll = 0
		return a, nil
	case "c":
		// Clear events
		a.events = nil
		a.eventScroll = 0
		return a, nil
	}
	return a, nil
}

// ── Events panel render ──

func (a App) renderEventsPanel() string {
	title := lipgloss.NewStyle().Bold(true)
	dim := lipgloss.NewStyle().Faint(true)
	warn := lipgloss.NewStyle().Foreground(lipgloss.Color("220"))

	var b strings.Builder

	b.WriteString(title.Render("📋 Recent Events"))
	b.WriteString(fmt.Sprintf("  %s", dim.Render(fmt.Sprintf("(%d total)", len(a.events)))))
	b.WriteString("\n\n")

	if len(a.events) == 0 {
		b.WriteString(dim.Render("  No events recorded yet."))
		b.WriteString("\n")
		b.WriteString(dim.Render("  Events from container operations, policy changes,"))
		b.WriteString("\n")
		b.WriteString(dim.Render("  and system notifications will appear here."))
		return b.String()
	}

	visibleRows := a.height - 10
	if visibleRows < 5 {
		visibleRows = 5
	}

	// Show events around eventScroll, latest at bottom
	endIdx := a.eventScroll + 1
	startIdx := endIdx - visibleRows
	if startIdx < 0 {
		startIdx = 0
	}
	if endIdx > len(a.events) {
		endIdx = len(a.events)
	}

	for i := startIdx; i < endIdx; i++ {
		e := a.events[i]
		ts := e.Time.Format("15:04:05")

		// Color based on content
		var line string
		if strings.Contains(e.Text, "⚠") || strings.Contains(e.Text, "error") || strings.Contains(e.Text, "fail") {
			line = fmt.Sprintf("  %s %s", dim.Render(ts), warn.Render(e.Text))
		} else {
			line = fmt.Sprintf("  %s %s", dim.Render(ts), e.Text)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}

	// Scroll indicators
	if startIdx > 0 {
		b.WriteString(dim.Render(fmt.Sprintf("\n  ▲ %d more above", startIdx)))
		b.WriteString("\n")
	}
	if endIdx < len(a.events) {
		b.WriteString(dim.Render(fmt.Sprintf("\n  ▼ %d more below", len(a.events)-endIdx)))
		b.WriteString("\n")
	}

	return b.String()
}
