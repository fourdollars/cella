package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// ── Mouse handling ──

func (a App) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	e := tea.MouseEvent(msg)

	switch {
	case e.Button == tea.MouseButtonLeft && e.Action == tea.MouseActionPress:
		return a.handleMouseClick(e.X, e.Y)
	case e.Button == tea.MouseButtonWheelUp:
		return a.handleMouseWheel(-1)
	case e.Button == tea.MouseButtonWheelDown:
		return a.handleMouseWheel(1)
	}
	return a, nil
}

func (a App) handleMouseClick(x, y int) (tea.Model, tea.Cmd) {
	sideW := a.calcSidebarWidth()

	// Layout: row 0 = header, row 1 = top border, row 2+ = sidebar content
	// Sidebar content: line 0 = blank, line 1 = "Containers", line 2 = blank, line 3+ = entries
	// So first container entry is at screen Y = 1 (border) + 1 (blank) + 1 (title) + 1 (blank) + 1 = 5
	// But with the box border rendered by lipgloss, the exact offset may vary.
	// The sidebar box starts at X=0, ends at X=sideW+1 (including border).
	// Container entries start at Y offset = 5 (header + border + padding + title + blank)

	const sidebarContentStartY = 6 // header(1) + border(1) + padding(1) + title(1) + blank(1) + blank(1)

	if x <= sideW+2 {
		// Click inside sidebar area
		if y >= sidebarContentStartY {
			// Calculate which container was clicked
			scroll := a.sideScroll
			hasUpIndicator := scroll > 0
			entryOffset := y - sidebarContentStartY
			if hasUpIndicator {
				if entryOffset == 0 {
					// Clicked "▲ more" — scroll up
					if a.sideScroll > 0 {
						a.sideScroll--
					}
					return a, nil
				}
				entryOffset-- // account for the ▲ line
			}

			idx := scroll + entryOffset
			if idx >= 0 && idx < len(a.containers) {
				a.selected = idx
				a.ensureSidebarVisible()
				a.focus = panelSidebar
			}
		}
	} else {
		// Click inside main panel area — focus the current panel
		// (no-op for most panels, but useful to indicate focus)
	}

	return a, nil
}

func (a App) handleMouseWheel(delta int) (tea.Model, tea.Cmd) {
	switch a.focus {
	case panelSidebar, panelDashboard:
		// Scroll the sidebar container list
		newSel := a.selected + delta
		if newSel < 0 {
			newSel = 0
		}
		if newSel >= len(a.containers) {
			newSel = len(a.containers) - 1
		}
		a.selected = newSel
		a.ensureSidebarVisible()

	case panelExecOutput:
		a.execScroll += delta
		if a.execScroll < 0 {
			a.execScroll = 0
		}

	case panelLogs:
		// Scroll log view (disable follow mode on scroll up)
		if delta < 0 {
			a.logFollow = false
		}

	case panelDNS:
		entries := a.getDNSEntriesForSelected()
		maxIdx := len(entries) - 1
		if maxIdx < 0 {
			maxIdx = 0
		}
		a.dnsScroll += delta
		if a.dnsScroll < 0 {
			a.dnsScroll = 0
		}
		if a.dnsScroll > maxIdx {
			a.dnsScroll = maxIdx
		}

	case panelPolicy:
		a.policyScroll += delta
		if a.policyScroll < 0 {
			a.policyScroll = 0
		}

	case panelEvents:
		a.eventScroll += delta
		if a.eventScroll < 0 {
			a.eventScroll = 0
		}
		maxIdx := len(a.events) - 1
		if maxIdx < 0 {
			maxIdx = 0
		}
		if a.eventScroll > maxIdx {
			a.eventScroll = maxIdx
		}

	case panelSyscall:
		// Scroll syscall output if applicable
	}

	return a, nil
}
