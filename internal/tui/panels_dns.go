package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fourdoors/cella/internal/security"
)

// ── DNS panel handler ──

func (a App) handleDNSPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	entries := a.getDNSEntriesForSelected()
	maxIdx := len(entries) - 1
	if maxIdx < 0 {
		maxIdx = 0
	}

	switch key {
	case "esc", "q":
		a.focus = panelSidebar
		return a, nil
	case "up", "k":
		if a.dnsScroll > 0 {
			a.dnsScroll--
		}
		return a, nil
	case "down", "j":
		if a.dnsScroll < maxIdx {
			a.dnsScroll++
		}
		return a, nil
	case "pgup":
		step := (a.height - 16) / 2
		if step < 1 {
			step = 1
		}
		if a.dnsScroll > step {
			a.dnsScroll -= step
		} else {
			a.dnsScroll = 0
		}
		return a, nil
	case "pgdown":
		step := (a.height - 16) / 2
		if step < 1 {
			step = 1
		}
		if a.dnsScroll+step < maxIdx {
			a.dnsScroll += step
		} else {
			a.dnsScroll = maxIdx
		}
		return a, nil
	case "a":
		// Allow selected domain for the current container
		if a.dnsMonitor != nil && a.selected < len(a.containers) {
			entries := a.getDNSEntriesForSelected()
			idx := a.dnsScroll
			if idx < len(entries) {
				c := a.containers[a.selected]
				entry := entries[idx]
				for _, ip := range entry.IPs {
					_ = security.AddEgressAllow(c.Name, c.IP, ip, entry.Domain)
				}
				a.dnsMonitor.SetStatus(entry.Domain, "allow")
				a.addEvent(fmt.Sprintf("🟢 allow %s for %s", entry.Domain, c.Name))
			}
		}
		return a, nil
	case "x":
		// Deny: enable egress restriction (if not already) which blocks unlisted domains
		if a.dnsMonitor != nil && a.selected < len(a.containers) {
			entries := a.getDNSEntriesForSelected()
			idx := a.dnsScroll
			if idx < len(entries) {
				c := a.containers[a.selected]
				entry := entries[idx]
				// Ensure container has egress restriction (deny-all)
				if !security.HasEgressRestriction(c.Name) {
					// Get currently allowed IPs from allow-listed entries
					var allowIPs []string
					allEntries := a.getDNSEntriesForSelected()
					for _, e := range allEntries {
						if e.Status == "allow" {
							allowIPs = append(allowIPs, e.IPs...)
						}
					}
					rule := security.EgressRule{
						Container: c.Name,
						SrcIP:     c.IP,
						Allow:     allowIPs,
					}
					_ = security.ApplyEgressRules(rule)
				}
				a.dnsMonitor.SetStatus(entry.Domain, "deny")
				a.addEvent(fmt.Sprintf("🔴 deny %s for %s", entry.Domain, c.Name))
			}
		}
		return a, nil
	case "u":
		// Unset status
		if a.dnsMonitor != nil {
			entries := a.getDNSEntriesForSelected()
			idx := a.dnsScroll
			if idx < len(entries) {
				a.dnsMonitor.SetStatus(entries[idx].Domain, "")
			}
		}
		return a, nil
	}
	return a, nil
}

// ── Get DNS entries for selected container ──

func (a App) getDNSEntriesForSelected() []*security.DNSEntry {
	if a.dnsMonitor == nil || a.selected >= len(a.containers) {
		return nil
	}
	c := a.containers[a.selected]
	entries := a.dnsMonitor.EntriesForContainer(c.IP)
	// Sort by query count descending
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].QueryCount > entries[j].QueryCount
	})
	return entries
}

// ── DNS panel render ──

func (a App) renderDNSPanel() string {
	title := lipgloss.NewStyle().Bold(true)
	dim := lipgloss.NewStyle().Faint(true)
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	yellow := lipgloss.NewStyle().Foreground(lipgloss.Color("220"))

	var b strings.Builder

	containerName := "(none)"
	containerIP := ""
	if a.selected < len(a.containers) {
		c := a.containers[a.selected]
		containerName = c.Name
		containerIP = c.IP
	}

	b.WriteString(title.Render(fmt.Sprintf("🔍 DNS Monitor — %s (%s)", containerIP, containerName)))
	b.WriteString("\n\n")

	if a.dnsMonitor == nil || !a.dnsMonitor.IsRunning() {
		b.WriteString(dim.Render("  DNS monitor not started"))
		return b.String()
	}

	entries := a.getDNSEntriesForSelected()

	if len(entries) == 0 {
		b.WriteString(dim.Render("  Listening for DNS queries on lxdbr0..."))
		b.WriteString("\n")
		b.WriteString(dim.Render("  Generate traffic from the container to see domains here."))
		b.WriteString("\n\n")

		// Also show all entries across all containers
		allEntries := a.dnsMonitor.Entries()
		if len(allEntries) > 0 {
			b.WriteString(title.Render("  All containers:"))
			b.WriteString("\n")
			sort.Slice(allEntries, func(i, j int) bool {
				return allEntries[i].QueryCount > allEntries[j].QueryCount
			})
			for i, e := range allEntries {
				if i >= 15 {
					b.WriteString(fmt.Sprintf("  ... and %d more\n", len(allEntries)-15))
					break
				}
				ips := strings.Join(e.IPs, ", ")
				if len(ips) > 30 {
					ips = ips[:27] + "..."
				}
				// Resolve container IP to hostname
				srcLabel := e.SrcIP
				for _, c := range a.containers {
					if c.IP == e.SrcIP {
						srcLabel = fmt.Sprintf("%s (%s)", e.SrcIP, c.Name)
						break
					}
				}
				b.WriteString(fmt.Sprintf("  %-30s %3d queries  %s  %s\n",
					e.Domain, e.QueryCount, srcLabel, dim.Render(ips)))
			}
		}
		return b.String()
	}

	// Header
	hdr := fmt.Sprintf("  %-3s %-28s %5s  %-15s %-8s %s", "#", "DOMAIN", "QRY", "IPs", "STATUS", "SEEN")
	b.WriteString(dim.Render(hdr))
	b.WriteString("\n")
	b.WriteString(dim.Render("  " + strings.Repeat("─", 78)))
	b.WriteString("\n")

	// Clamp scroll for display
	maxScroll := len(entries) - 1
	if maxScroll < 0 {
		maxScroll = 0
	}
	scroll := a.dnsScroll
	if scroll > maxScroll {
		scroll = maxScroll
	}

	visibleRows := a.height - 16
	if visibleRows < 5 {
		visibleRows = 5
	}

	startIdx := 0
	if scroll > visibleRows/2 {
		startIdx = scroll - visibleRows/2
	}
	if startIdx+visibleRows > len(entries) {
		startIdx = len(entries) - visibleRows
	}
	if startIdx < 0 {
		startIdx = 0
	}

	for i := startIdx; i < len(entries) && i < startIdx+visibleRows; i++ {
		e := entries[i]

		// Status indicator
		var statusStr string
		switch e.Status {
		case "allow":
			statusStr = green.Render("🟢 ALLOW")
		case "deny":
			statusStr = red.Render("🔴 DENY")
		default:
			statusStr = yellow.Render("  ─")
		}

		// IPs (truncated)
		ips := strings.Join(e.IPs, ",")
		if len(ips) > 16 {
			ips = ips[:13] + "..."
		}

		// Last seen
		ago := time.Since(e.LastSeen)
		var lastSeen string
		if ago < time.Minute {
			lastSeen = fmt.Sprintf("%ds ago", int(ago.Seconds()))
		} else if ago < time.Hour {
			lastSeen = fmt.Sprintf("%dm ago", int(ago.Minutes()))
		} else {
			lastSeen = e.LastSeen.Format("15:04:05")
		}

		// Cursor
		cursor := "  "
		if i == scroll {
			cursor = "▸ "
		}

		domain := e.Domain
		if len(domain) > 30 {
			domain = domain[:27] + "..."
		}

		line := fmt.Sprintf("%s%-3d %-28s %5d  %-15s %-8s %s",
			cursor, i, domain, e.QueryCount, ips, statusStr, dim.Render(lastSeen))
		b.WriteString(line)
		b.WriteString("\n")
	}

	// Summary
	b.WriteString("\n")
	hasRestriction := false
	if a.selected < len(a.containers) {
		hasRestriction = security.HasEgressRestriction(a.containers[a.selected].Name)
	}
	if hasRestriction {
		b.WriteString(red.Render("  ⚠ Egress restricted — only allowed domains can be accessed"))
	} else {
		b.WriteString(dim.Render("  ℹ No egress restriction — all traffic allowed"))
	}
	b.WriteString("\n")

	return b.String()
}
