package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── Exec input handler ──

func (a App) handleExecInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		a.focus = panelSidebar
		a.execInput = ""
		return a, nil
	case "enter":
		if a.execInput == "" {
			return a, nil
		}
		containerName := a.containers[a.selected].Name
		cmd := strings.TrimSpace(a.execInput)

		if cmd == "bash" || cmd == "sh" || cmd == "/bin/bash" || cmd == "/bin/sh" {
			a.focus = panelSidebar
			a.execInput = ""
			return a, enterShell(containerName)
		}

		a.execRunning = true
		a.execOutput = ""
		return a, runExecInContainer(a.runtimeFor(containerName), containerName, cmd)
	case "backspace":
		if len(a.execInput) > 0 {
			a.execInput = a.execInput[:len(a.execInput)-1]
		}
	case "ctrl+u":
		a.execInput = ""
	case "ctrl+w":
		input := strings.TrimRight(a.execInput, " ")
		idx := strings.LastIndex(input, " ")
		if idx >= 0 {
			a.execInput = input[:idx+1]
		} else {
			a.execInput = ""
		}
	default:
		r := msg.String()
		if len(r) == 1 && r[0] >= 32 && r[0] < 127 {
			a.execInput += r
		} else if r == " " {
			a.execInput += " "
		}
	}
	return a, nil
}

// ── Exec output handler ──

func (a App) handleExecOutput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		a.focus = panelSidebar
		a.execOutput = ""
		a.execScroll = 0
		return a, nil
	case "e":
		a.focus = panelExecInput
		a.execInput = ""
		a.execOutput = ""
		a.execScroll = 0
		return a, nil
	case "up", "k":
		if a.execScroll > 0 {
			a.execScroll--
		}
	case "down", "j":
		lines := strings.Split(a.execOutput, "\n")
		maxScroll := len(lines) - (a.height - 10)
		if maxScroll < 0 {
			maxScroll = 0
		}
		if a.execScroll < maxScroll {
			a.execScroll++
		}
	}
	return a, nil
}

// ── Exec input render ──

func (a App) renderExecInput() string {
	var b strings.Builder
	containerName := ""
	if a.selected < len(a.containers) {
		containerName = a.containers[a.selected].Name
	}

	b.WriteString(TitleStyle.Render(fmt.Sprintf("⚡ Exec in %s ◆", containerName)) + "\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(ColorSubtle).Render("  Type a command to execute inside the container.") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(ColorSubtle).Render("  Type 'bash' or 'sh' for interactive shell.") + "\n\n")

	prompt := lipgloss.NewStyle().Foreground(ColorGreen).Bold(true).Render(fmt.Sprintf("  %s $ ", containerName))
	cursor := lipgloss.NewStyle().Foreground(ColorBlue).Bold(true).Render("█")
	inputText := lipgloss.NewStyle().Foreground(ColorText).Render(a.execInput)
	b.WriteString(prompt + inputText + cursor + "\n")

	if a.execRunning {
		b.WriteString("\n" + lipgloss.NewStyle().Foreground(ColorYellow).Render("  ⏳ Running...") + "\n")
	}

	b.WriteString("\n" + SectionHeaderStyle.Render("Quick Commands") + "\n")
	suggestions := [][]string{
		{"bash", "Interactive shell"},
		{"ps aux", "Process list"},
		{"df -h", "Disk usage"},
		{"free -h", "Memory info"},
		{"ip addr", "Network config"},
	}
	for _, s := range suggestions {
		b.WriteString(fmt.Sprintf("  %s  %s\n",
			HelpKeyStyle.Render(s[0]),
			HelpDescStyle.Render(s[1]),
		))
	}

	return b.String()
}

// ── Exec output render ──

func (a App) renderExecOutput() string {
	var b strings.Builder
	containerName := ""
	if a.selected < len(a.containers) {
		containerName = a.containers[a.selected].Name
	}

	b.WriteString(TitleStyle.Render(fmt.Sprintf("⚡ Output — %s ◆", containerName)) + "\n")

	lines := strings.Split(a.execOutput, "\n")
	totalLines := len(lines)

	visibleH := a.height - 12
	if visibleH < 5 {
		visibleH = 5
	}

	start := a.execScroll
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

	outputStyle := lipgloss.NewStyle().Foreground(ColorText)
	for i := start; i < end; i++ {
		b.WriteString("  " + outputStyle.Render(lines[i]) + "\n")
	}

	return b.String()
}

// ── Logs panel handler ──

func (a App) handleLogsPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		// Stop log stream on exit
		if a.logCancel != nil {
			a.logCancel()
			a.logCancel = nil
		}
		a.logFollow = false
		a.focus = a.prevFocus
		return a, nil
	case "up", "k":
		a.logFollow = false // manual scroll disables follow
		if a.logScroll > 0 {
			a.logScroll--
		}
	case "down", "j":
		maxScroll := len(a.logLines) - (a.height - 10)
		if maxScroll < 0 {
			maxScroll = 0
		}
		if a.logScroll < maxScroll {
			a.logScroll++
		}
	case "g":
		a.logFollow = false
		a.logScroll = 0
	case "G":
		maxScroll := len(a.logLines) - (a.height - 10)
		if maxScroll < 0 {
			maxScroll = 0
		}
		a.logScroll = maxScroll
		a.logFollow = true // G = go to bottom + follow
	case "F":
		// Toggle follow mode
		a.logFollow = !a.logFollow
		if a.logFollow {
			maxScroll := len(a.logLines) - (a.height - 10)
			if maxScroll < 0 {
				maxScroll = 0
			}
			a.logScroll = maxScroll
		}
	case "r":
		// Refresh logs (non-streaming)
		if a.logTarget != "" {
			if a.logCancel != nil {
				a.logCancel()
				a.logCancel = nil
			}
			a.logFollow = false
			return a, fetchLogs(a.runtimeFor(a.logTarget), a.logTarget)
		}
	}
	return a, nil
}

// ── Logs panel render ──

func (a App) renderLogsPanel() string {
	var b strings.Builder

	followTag := ""
	if a.logFollow {
		followTag = lipgloss.NewStyle().Foreground(ColorGreen).Bold(true).Render(" 🔴 LIVE")
	}
	b.WriteString(TitleStyle.Render(fmt.Sprintf("📋 Logs — %s ◆", a.logTarget)) + followTag + "\n")

	if len(a.logLines) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorYellow).
			Render("\n  ⏳ Loading logs...\n"))
		return b.String()
	}

	totalLines := len(a.logLines)
	visibleH := a.height - 10
	if visibleH < 5 {
		visibleH = 5
	}

	start := a.logScroll
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

	logStyle := lipgloss.NewStyle().Foreground(ColorText)
	warnStyle := lipgloss.NewStyle().Foreground(ColorYellow)
	errStyle := lipgloss.NewStyle().Foreground(ColorRed)

	for i := start; i < end; i++ {
		line := a.logLines[i]
		style := logStyle
		lower := strings.ToLower(line)
		if strings.Contains(lower, "error") || strings.Contains(lower, "fatal") || strings.Contains(lower, "critical") {
			style = errStyle
		} else if strings.Contains(lower, "warn") || strings.Contains(lower, "timeout") {
			style = warnStyle
		}
		b.WriteString("  " + style.Render(line) + "\n")
	}

	return b.String()
}
