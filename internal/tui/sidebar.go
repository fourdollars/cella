package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ensureSidebarVisible adjusts sideScroll so selected item is visible
func (a *App) ensureSidebarVisible() {
	visibleH := a.sidebarVisibleRows()
	if visibleH <= 0 {
		return
	}
	if a.selected < a.sideScroll {
		a.sideScroll = a.selected
	}
	if a.selected >= a.sideScroll+visibleH {
		a.sideScroll = a.selected - visibleH + 1
	}
}

// calcSidebarWidth dynamically sizes sidebar based on longest container name.
// Layout per line (worst case):
//
//	"▸"(1) + "%2d"(2-3) + indicator●(2cells) + rtIcon🔷(2cells) + name + " "(1) + "100% 99.9G"(10)
//	= 19 cells + name length
func (a App) calcSidebarWidth() int {
	// Layout: "▸"(1) + "%2d"(2-3) + indicator●(2cells) + rtIcon🔷(2cells) + name + rightInfo(10: "%4s %5s")
	const overhead = 18 // prefix(~8 cells) + right column(10 cells)
	const minW = 32
	const maxW = 55

	maxName := 0
	for _, c := range a.containers {
		if len(c.Name) > maxName {
			maxName = len(c.Name)
		}
	}

	w := overhead + maxName
	if w < minW {
		w = minW
	}
	if w > maxW {
		w = maxW
	}
	// Don't let sidebar eat more than 40% of terminal width
	limit := a.width * 40 / 100
	if limit < minW {
		limit = minW
	}
	if w > limit {
		w = limit
	}
	return w
}

// sidebarNameMax returns how many chars of container name can fit in sidebar
func (a App) sidebarNameMax() int {
	const overhead = 18
	w := a.calcSidebarWidth()
	nameMax := w - overhead
	if nameMax < 8 {
		nameMax = 8
	}
	return nameMax
}

func (a App) sidebarVisibleRows() int {
	// contentH - title(2 lines) - footer hint(2 lines) - border padding
	h := a.height - 4 - 4
	if h < 3 {
		h = 3
	}
	return h
}

// ── Sidebar rendering ──

func (a App) renderSidebar() string {
	var b strings.Builder

	focusIndicator := ""
	if a.focus == panelSidebar {
		focusIndicator = " ◆"
	}
	title := "Containers" + focusIndicator
	b.WriteString(TitleStyle.Render(title) + "\n")

	// Search filter indicator
	if a.searchFilter != "" {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorYellow).Render(
			fmt.Sprintf("  🔍 filtered: %s", a.searchFilter)) + "\n")
	} else {
		b.WriteString("\n")
	}

	visibleH := a.sidebarVisibleRows()
	total := len(a.containers)

	// Clamp scroll
	maxScroll := total - visibleH
	if maxScroll < 0 {
		maxScroll = 0
	}
	scroll := a.sideScroll
	if scroll > maxScroll {
		scroll = maxScroll
	}

	// Scroll up indicator
	if scroll > 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).Render("  ▲ more") + "\n")
		visibleH-- // one line used for indicator
	}

	end := scroll + visibleH
	if end > total {
		end = total
	}

	// Need bottom indicator?
	needBottomIndicator := end < total

	if needBottomIndicator && end > scroll+1 {
		end-- // reserve one line for ▼ indicator
	}

	for i := scroll; i < end; i++ {
		c := a.containers[i]
		m := a.getMetric(c.Name)
		indicator := "○"
		style := StoppedContainerStyle
		if c.Status == "Running" {
			indicator = "●"
			style = ActiveContainerStyle
		} else if c.Status == "Frozen" {
			indicator = "◉"
			style = lipgloss.NewStyle().Foreground(ColorYellow)
		}

		// Runtime icon
		rtIcon := "🔷"
		if c.Runtime == "docker" {
			rtIcon = "🐳"
		}

		// Show trace indicator
		traceIcon := ""
		if _, ok := a.tracers[c.Name]; ok {
			traceIcon = "🔬"
		}

		// Show syscall blocking indicator (⛔ = security.syscalls.deny active)
		blockIcon := ""
		if a.syscallBlocked != nil && a.syscallBlocked[c.Name] {
			blockIcon = "⛔"
		}

		name := c.Name
		nameMax := a.sidebarNameMax()
		// 🔬 trace icon takes 2 terminal cells — shrink name to compensate
		if traceIcon != "" {
			nameMax -= 2
			if nameMax < 6 {
				nameMax = 6
			}
		}
		if len(name) > nameMax {
			name = name[:nameMax-2] + ".."
		}

		rightInfo := ""
		if c.Status == "Running" {
			cpu := fmt.Sprintf("%.0f%%", m.CPUPercent)
			mem := formatBytesShort(c.MemoryCur)
			rightInfo = fmt.Sprintf("%4s %5s", cpu, mem)
		} else {
			rightInfo = fmt.Sprintf("%10s", strings.ToLower(c.Status))
		}

		line := fmt.Sprintf("%2d%s%s%s%s%-*s%s", i, indicator, rtIcon, traceIcon, blockIcon, nameMax, name, rightInfo)

		if i == a.selected {
			line = SelectedContainerStyle.Render("▸" + line)
		} else {
			line = style.Render(" " + line)
		}

		b.WriteString(line + "\n")
	}

	// Scroll down indicator
	if needBottomIndicator {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).Render("  ▼ more") + "\n")
	}

	// Compact footer hint
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).Render(" [?] help") + "\n")

	return b.String()
}
