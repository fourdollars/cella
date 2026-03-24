package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fourdoors/cella/internal/proxy"
)

// approvalMsg wraps an incoming approval request from the proxy
type approvalMsg proxy.ApprovalRequest

// approvalDismissMsg signals the approval prompt should be dismissed
type approvalDismissMsg struct{}

// listenApprovals reads one approval request from the channel and returns it as a Msg
func listenApprovals(ch chan proxy.ApprovalRequest) tea.Cmd {
	return func() tea.Msg {
		req, ok := <-ch
		if !ok {
			return nil
		}
		return approvalMsg(req)
	}
}

// handleApprovalKey handles key presses during the approval prompt overlay
func (a *App) handleApprovalKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if a.pendingApproval == nil {
		return a, nil
	}

	switch msg.String() {
	case "y": // allow this time
		a.pendingApproval.ResponseCh <- proxy.ApprovalResponse{Approved: true, Permanent: false}
		a.addEvent(fmt.Sprintf("👤 approved (once): %s → %s", a.pendingApproval.Container, a.pendingApproval.Domain))
		a.pendingApproval = nil
		return a, a.listenApprovalsContinue()

	case "Y": // allow permanently
		a.pendingApproval.ResponseCh <- proxy.ApprovalResponse{Approved: true, Permanent: true}
		a.addEvent(fmt.Sprintf("👤+ approved (permanent): %s → %s", a.pendingApproval.Container, a.pendingApproval.Domain))
		a.pendingApproval = nil
		return a, a.listenApprovalsContinue()

	case "n", "N": // deny
		a.pendingApproval.ResponseCh <- proxy.ApprovalResponse{Approved: false}
		a.addEvent(fmt.Sprintf("⛔ denied: %s → %s", a.pendingApproval.Container, a.pendingApproval.Domain))
		a.pendingApproval = nil
		return a, a.listenApprovalsContinue()
	}

	return a, nil // ignore other keys while approval pending
}

// listenApprovalsContinue continues listening for approvals
func (a App) listenApprovalsContinue() tea.Cmd {
	if a.approvalCh == nil {
		return nil
	}
	return listenApprovals(a.approvalCh)
}

// renderApprovalOverlay draws the approval prompt at the bottom of the screen
func (a App) renderApprovalOverlay() string {
	if a.pendingApproval == nil {
		return ""
	}

	req := a.pendingApproval

	icon := "🔒"
	if req.Method == "CONNECT" {
		icon = "🔐"
	}

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#e74c3c")).
		Background(lipgloss.Color("#1a1a2e")).
		Padding(0, 1)

	domainStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#58a6ff"))

	containerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#e67e22"))

	optStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#8b949e"))

	keyStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#27ae60"))

	line1 := titleStyle.Render(fmt.Sprintf("%s APPROVAL REQUIRED", icon))
	line2 := fmt.Sprintf("  %s is trying to connect to %s",
		containerStyle.Render(req.Container),
		domainStyle.Render(req.Domain))
	if req.URL != "" && req.URL != req.Domain {
		line2 += fmt.Sprintf(" (%s %s)", req.Method, req.URL)
	}
	line3 := fmt.Sprintf("  %s %s  %s %s  %s %s",
		keyStyle.Render("[y]"), optStyle.Render("allow once"),
		keyStyle.Render("[Y]"), optStyle.Render("allow always"),
		keyStyle.Render("[n]"), optStyle.Render("deny"))

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#e74c3c")).
		Padding(0, 1).
		Width(a.width - 4).
		Render(strings.Join([]string{line1, line2, line3}, "\n"))

	return box
}

// ── Audit Panel (Phase 7b: filter + scroll + export) ──

// handleAuditPanel handles keypresses in the audit panel
func (a *App) handleAuditPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Filter input mode
	if a.auditFilterMode {
		switch msg.String() {
		case "enter":
			a.auditFilterText = a.auditFilterInput
			a.auditFilterMode = false
			a.auditFilterInput = ""
			a.auditScroll = 0
		case "esc":
			a.auditFilterMode = false
			a.auditFilterInput = ""
		case "backspace":
			if len(a.auditFilterInput) > 0 {
				a.auditFilterInput = a.auditFilterInput[:len(a.auditFilterInput)-1]
			}
		case "ctrl+u":
			a.auditFilterInput = ""
		default:
			k := msg.String()
			if len(k) == 1 && k[0] >= 32 && k[0] < 127 {
				a.auditFilterInput += k
			} else if k == " " {
				a.auditFilterInput += " "
			}
		}
		return a, nil
	}

	switch msg.String() {
	case "esc", "q":
		a.focus = panelSidebar
		return a, nil

	case "c":
		// Clear audit log
		if a.proxyServer != nil {
			a.proxyServer.Audit().Clear()
			a.addEvent("📋 audit log cleared")
		}
		return a, nil

	case "/":
		// Enter filter mode
		a.auditFilterMode = true
		a.auditFilterInput = ""
		return a, nil

	case "ctrl+l":
		// Clear filter
		a.auditFilterText = ""
		a.auditScroll = 0
		return a, nil

	case "f":
		// Cycle status filter: all → allowed → denied → approved → timeout → all
		switch a.auditStatusFilter {
		case "":
			a.auditStatusFilter = "allowed"
		case "allowed":
			a.auditStatusFilter = "denied"
		case "denied":
			a.auditStatusFilter = "approved"
		case "approved":
			a.auditStatusFilter = "timeout"
		default:
			a.auditStatusFilter = ""
		}
		a.auditScroll = 0
		return a, nil

	case "S":
		// Export audit log to JSON file
		if a.proxyServer != nil {
			entries := a.filterAuditEntries(a.proxyServer.Audit().All())
			return a, a.exportAuditJSON(entries)
		}
		return a, nil

	case "up", "k":
		if a.auditScroll > 0 {
			a.auditScroll--
		}
	case "down", "j":
		a.auditScroll++
	case "g":
		a.auditScroll = 0
	case "G":
		// Jump to bottom — handled in render (set to max)
		a.auditScroll = 99999
	}
	return a, nil
}

// filterAuditEntries applies text and status filters
func (a App) filterAuditEntries(entries []proxy.AuditEntry) []proxy.AuditEntry {
	if a.auditFilterText == "" && a.auditStatusFilter == "" {
		return entries
	}
	filterLower := strings.ToLower(a.auditFilterText)
	var result []proxy.AuditEntry
	for _, e := range entries {
		// Status filter
		if a.auditStatusFilter != "" {
			if a.auditStatusFilter == "denied" {
				if !strings.HasPrefix(e.Status, "denied") {
					continue
				}
			} else if a.auditStatusFilter == "approved" {
				if !strings.HasPrefix(e.Status, "approved") {
					continue
				}
			} else if e.Status != a.auditStatusFilter {
				continue
			}
		}
		// Text filter (matches container, domain, URL, method)
		if filterLower != "" {
			text := strings.ToLower(e.Container + " " + e.Domain + " " + e.URL + " " + e.Method)
			if !strings.Contains(text, filterLower) {
				continue
			}
		}
		result = append(result, e)
	}
	return result
}

// exportAuditJSON writes filtered audit entries to a JSON file
func (a *App) exportAuditJSON(entries []proxy.AuditEntry) tea.Cmd {
	return func() tea.Msg {
		type exportEntry struct {
			Time      string `json:"time"`
			Container string `json:"container"`
			Domain    string `json:"domain"`
			Method    string `json:"method"`
			URL       string `json:"url"`
			Status    string `json:"status"`
			LatencyMs int64  `json:"latency_ms"`
		}

		exported := make([]exportEntry, len(entries))
		for i, e := range entries {
			exported[i] = exportEntry{
				Time:      e.Time.Format(time.RFC3339),
				Container: e.Container,
				Domain:    e.Domain,
				Method:    e.Method,
				URL:       e.URL,
				Status:    e.Status,
				LatencyMs: e.Latency.Milliseconds(),
			}
		}

		data, err := json.MarshalIndent(exported, "", "  ")
		if err != nil {
			return asyncResultMsg{err: fmt.Errorf("audit export: %w", err)}
		}

		filename := fmt.Sprintf("cella-audit-%s.json", time.Now().Format("20060102-150405"))
		if err := os.WriteFile(filename, data, 0644); err != nil {
			return asyncResultMsg{err: fmt.Errorf("write %s: %w", filename, err)}
		}

		return asyncResultMsg{text: fmt.Sprintf("📋 Exported %d audit entries → %s (%d bytes)", len(entries), filename, len(data))}
	}
}

// renderAuditPanel renders the API audit log panel with filters
func (a App) renderAuditPanel() string {
	if a.proxyServer == nil {
		noProxyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e"))
		hintStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#e67e22"))
		return noProxyStyle.Render(" Proxy not running.\n\n") +
			noProxyStyle.Render(" Start cella with ") +
			hintStyle.Render("--proxy 9080") +
			noProxyStyle.Render(" to enable API interception.\n\n") +
			noProxyStyle.Render(" Then configure containers:\n") +
			hintStyle.Render("   lxc config set <name> environment.HTTP_PROXY=http://<host>:9080\n") +
			hintStyle.Render("   lxc config set <name> environment.HTTPS_PROXY=http://<host>:9080\n")
	}

	var b strings.Builder

	// Title
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#58a6ff")).
		Render("📋 API Audit Log ◆")
	portBadge := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#27ae60")).
		Render(fmt.Sprintf(" (proxy :%d)", a.proxyServer.Port()))
	b.WriteString(title + portBadge + "\n")

	// Stats bar
	stats := a.proxyServer.Audit().Stats()
	allowed := stats.ByStatus["allowed"]
	denied := stats.ByStatus["denied"] + stats.ByStatus["denied-queue-full"]
	approved := stats.ByStatus["approved"] + stats.ByStatus["approved-permanent"]
	timeouts := stats.ByStatus["timeout"]

	statStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e"))
	b.WriteString(statStyle.Render(fmt.Sprintf(
		"  Total: %d │ ✅ %d │ 👤 %d │ ⛔ %d │ ⏱ %d │ Domains: %d │ Containers: %d",
		stats.Total, allowed, approved, denied, timeouts,
		len(stats.ByDomain), len(stats.ByContainer))) + "\n")

	// Active filters indicator
	var filters []string
	if a.auditStatusFilter != "" {
		icon := "🔵"
		switch a.auditStatusFilter {
		case "allowed":
			icon = "✅"
		case "denied":
			icon = "⛔"
		case "approved":
			icon = "👤"
		case "timeout":
			icon = "⏱"
		}
		filters = append(filters, fmt.Sprintf("%s status:%s", icon, a.auditStatusFilter))
	}
	if a.auditFilterText != "" {
		filters = append(filters, fmt.Sprintf("🔍 \"%s\"", a.auditFilterText))
	}
	if len(filters) > 0 {
		filterLine := lipgloss.NewStyle().Foreground(lipgloss.Color("#e67e22")).Bold(true).
			Render("  Filters: " + strings.Join(filters, " │ "))
		b.WriteString(filterLine + "\n")
	}

	b.WriteString(strings.Repeat("─", 70) + "\n")

	// Top domains breakdown (compact)
	if len(stats.ByDomain) > 0 {
		type domCount struct {
			domain string
			count  int
		}
		var sorted []domCount
		for d, c := range stats.ByDomain {
			sorted = append(sorted, domCount{d, c})
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].count > sorted[j].count })

		domLine := "  Top: "
		max := 5
		if len(sorted) < max {
			max = len(sorted)
		}
		for i := 0; i < max; i++ {
			if i > 0 {
				domLine += " │ "
			}
			domLine += fmt.Sprintf("%s(%d)", sorted[i].domain, sorted[i].count)
		}
		if len(sorted) > max {
			domLine += fmt.Sprintf(" +%d more", len(sorted)-max)
		}
		b.WriteString(statStyle.Render(domLine) + "\n")
		b.WriteString(strings.Repeat("─", 70) + "\n")
	}

	// Get filtered entries
	allEntries := a.proxyServer.Audit().All()
	entries := a.filterAuditEntries(allEntries)

	if len(entries) == 0 {
		if len(allEntries) > 0 {
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#e67e22")).
				Render("  No entries match current filters. Press Ctrl+L to clear.\n"))
		} else {
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e")).
				Render("  No requests recorded yet. Waiting for container traffic...\n"))
		}
		return b.String()
	}

	// Filtered count
	if len(entries) != len(allEntries) {
		b.WriteString(statStyle.Render(fmt.Sprintf("  Showing %d / %d entries", len(entries), len(allEntries))) + "\n")
	}

	// Calculate visible area
	visibleH := a.height - 14 // header + stats + filters + separators
	if visibleH < 5 {
		visibleH = 5
	}

	// Clamp scroll
	maxScroll := len(entries) - visibleH
	if maxScroll < 0 {
		maxScroll = 0
	}
	scroll := a.auditScroll
	if scroll > maxScroll {
		scroll = maxScroll
	}

	// Render entries (newest first, with scroll)
	reversed := make([]proxy.AuditEntry, len(entries))
	for i, e := range entries {
		reversed[len(entries)-1-i] = e
	}

	start := scroll
	end := scroll + visibleH
	if end > len(reversed) {
		end = len(reversed)
	}

	// Scroll indicators
	if scroll > 0 {
		b.WriteString(statStyle.Render("  ▲ more") + "\n")
	}

	for i := start; i < end; i++ {
		e := reversed[i]
		line := proxy.FormatEntry(e)

		var style lipgloss.Style
		switch {
		case strings.HasPrefix(e.Status, "denied") || e.Status == "timeout":
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("#e74c3c"))
		case strings.HasPrefix(e.Status, "approved"):
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("#e67e22"))
		default:
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("#e6edf3"))
		}

		// Highlight search match
		if a.auditFilterText != "" {
			// Just render normally — highlight is expensive for TUI
		}

		b.WriteString("  " + style.Render(line) + "\n")
	}

	if end < len(reversed) {
		b.WriteString(statStyle.Render(fmt.Sprintf("  ▼ %d more", len(reversed)-end)) + "\n")
	}

	return b.String()
}
