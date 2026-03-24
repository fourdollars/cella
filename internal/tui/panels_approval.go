package tui

import (
	"fmt"
	"strings"

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

	elapsed := ""
	// No elapsed display needed—prompt just appeared

	icon := "🔒"
	if req.Method == "CONNECT" {
		icon = "🔐" // HTTPS
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

	line1 := titleStyle.Render(fmt.Sprintf("%s APPROVAL REQUIRED %s", icon, elapsed))
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

// renderAuditPanel renders the API audit log panel (press A)
func (a App) renderAuditPanel() string {
	if a.proxyServer == nil {
		return " Proxy not running. Start cella with --proxy to enable.\n"
	}

	var b strings.Builder
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#58a6ff")).
		Render("📋 API Audit Log ◆")
	b.WriteString(title + "\n\n")

	entries := a.proxyServer.Audit().Last(50)
	if len(entries) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e")).
			Render("  No requests recorded yet.\n  Proxy is listening on port ") +
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#e67e22")).
				Render(fmt.Sprintf("%d", a.proxyServer.Port())) +
			"\n")
		return b.String()
	}

	// Stats summary
	stats := a.proxyServer.Audit().Stats()
	allowed := stats.ByStatus["allowed"]
	denied := stats.ByStatus["denied"] + stats.ByStatus["denied-queue-full"]
	approved := stats.ByStatus["approved"] + stats.ByStatus["approved-permanent"]
	timeouts := stats.ByStatus["timeout"]

	statLine := fmt.Sprintf("  Total: %d │ ✅ %d │ 👤 %d │ ⛔ %d │ ⏱ %d │ Domains: %d\n",
		stats.Total, allowed, approved, denied, timeouts, len(stats.ByDomain))
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e")).Render(statLine))
	b.WriteString(strings.Repeat("─", 60) + "\n")

	// Recent entries (newest first)
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		line := proxy.FormatEntry(e)

		// Color by status
		var style lipgloss.Style
		switch {
		case strings.HasPrefix(e.Status, "denied") || e.Status == "timeout":
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("#e74c3c"))
		case strings.HasPrefix(e.Status, "approved"):
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("#e67e22"))
		default:
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("#e6edf3"))
		}
		b.WriteString("  " + style.Render(line) + "\n")
	}

	return b.String()
}

// handleAuditPanel handles keypresses in the audit panel
func (a *App) handleAuditPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		a.focus = panelSidebar
		return a, nil
	case "c":
		if a.proxyServer != nil {
			a.proxyServer.Audit().Clear()
			a.addEvent("📋 audit log cleared")
		}
		return a, nil
	case "up", "k":
		if a.auditScroll > 0 {
			a.auditScroll--
		}
	case "down", "j":
		a.auditScroll++
	}
	return a, nil
}
