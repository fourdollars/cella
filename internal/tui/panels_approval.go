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
	case "y":
		a.pendingApproval.ResponseCh <- proxy.ApprovalResponse{Approved: true, Permanent: false}
		a.addEvent(fmt.Sprintf("👤 approved (once): %s → %s", a.pendingApproval.Container, a.pendingApproval.Domain))
		a.pendingApproval = nil
		return a, a.listenApprovalsContinue()
	case "Y":
		a.pendingApproval.ResponseCh <- proxy.ApprovalResponse{Approved: true, Permanent: true}
		a.addEvent(fmt.Sprintf("👤+ approved (permanent): %s → %s", a.pendingApproval.Container, a.pendingApproval.Domain))
		a.pendingApproval = nil
		return a, a.listenApprovalsContinue()
	case "n", "N":
		a.pendingApproval.ResponseCh <- proxy.ApprovalResponse{Approved: false}
		a.addEvent(fmt.Sprintf("⛔ denied: %s → %s", a.pendingApproval.Container, a.pendingApproval.Domain))
		a.pendingApproval = nil
		return a, a.listenApprovalsContinue()
	}

	return a, nil
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

	connInfo := fmt.Sprintf("  %s is trying to connect to %s",
		containerStyle.Render(req.Container),
		domainStyle.Render(req.Domain))
	if req.URL != "" && req.URL != req.Domain {
		connInfo += fmt.Sprintf(" (%s %s)", req.Method, req.URL)
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
		Render(line1 + "\n" + connInfo + "\n" + line3)

	return box
}

// ── Audit Panel (Phase 7b+7c: filter + scroll + export + MITM) ──

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
		if a.proxyServer != nil {
			a.proxyServer.Audit().Clear()
			a.addEvent("📋 audit log cleared")
		}
		return a, nil
	case "/":
		a.auditFilterMode = true
		a.auditFilterInput = ""
		return a, nil
	case "ctrl+l":
		a.auditFilterText = ""
		a.auditStatusFilter = ""
		a.auditScroll = 0
		return a, nil
	case "f":
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
	case "p":
		// Auto-setup interception on selected container (lazy-starts listener)
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			if c.Runtime != "lxd" {
				a.addEvent(fmt.Sprintf("⚠ auto-setup only supports LXD containers (got %s)", c.Runtime))
				return a, a.setFlash("❌ Auto-setup only for LXD containers")
			}
			if c.Status != "Running" {
				a.addEvent(fmt.Sprintf("⚠ container %s is not running", c.Name))
				return a, a.setFlash("❌ Container must be running")
			}
			a.addEvent(fmt.Sprintf("🔧 setting up proxy on %s...", c.Name))
			return a, a.autoSetupProxy(c.Name)
		}
		return a, nil
	case "u":
		// Remove interception from selected container
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			if c.Runtime == "lxd" {
				a.addEvent(fmt.Sprintf("🔧 removing proxy from %s...", c.Name))
				return a, a.removeProxySetup(c.Name)
			}
			return a, a.setFlash("❌ Only LXD containers supported")
		}
		return a, nil
		case "S":
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
		if filterLower != "" {
			text := strings.ToLower(e.Container + " " + e.Domain + " " + e.URL + " " + e.Method + " " + e.Path)
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
			Path      string `json:"path,omitempty"`
			Status    string `json:"status"`
			RespCode  int    `json:"resp_code,omitempty"`
			TLS       bool   `json:"tls"`
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
				Path:      e.Path,
				Status:    e.Status,
				RespCode:  e.RespCode,
				TLS:       e.TLS,
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

// renderAuditPanel renders the API audit log panel
func (a App) renderAuditPanel() string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e"))
	bright := lipgloss.NewStyle().Foreground(lipgloss.Color("#e67e22"))
	blue := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#58a6ff"))
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("#27ae60"))

	if a.proxyServer == nil {
		var b strings.Builder
		b.WriteString("\n")
		b.WriteString(dim.Render("  Interception not active.") + "\n\n")
		selectedName := ""
		if a.selected < len(a.containers) {
			selectedName = a.containers[a.selected].Name
		}
		if selectedName != "" {
			b.WriteString(dim.Render("  Selected: ") + bright.Render(selectedName) + "\n\n")
		}
		b.WriteString(dim.Render("  Press ") + bright.Render("p") + dim.Render(" to start intercepting this container.") + "\n\n")
		b.WriteString(dim.Render("  What p does:") + "\n")
		b.WriteString(dim.Render("  1. nftables REDIRECT -- all port 80/443 traffic to cella") + "\n")
		b.WriteString(dim.Render("  2. CA cert inject -- enables HTTPS decryption") + "\n")
		b.WriteString(dim.Render("  3. Full audit -- domain + path + method + response code") + "\n\n")
		b.WriteString(dim.Render("  Press ") + bright.Render("u") + dim.Render(" to undo.") + "\n")
		return b.String()
	}

	var b strings.Builder

	// Title line
	b.WriteString(blue.Render("📋 API Audit Log ◆"))
	b.WriteString(green.Render(fmt.Sprintf(" (intercept :%d", 9081)))
	if a.proxyServer.MITMEnabled() {
		b.WriteString(bright.Render(" +MITM🔓"))
	}
	b.WriteString(green.Render(")"))
	b.WriteString("\n")

	// Stats
	stats := a.proxyServer.Audit().Stats()
	allowed := stats.ByStatus["allowed"]
	denied := stats.ByStatus["denied"] + stats.ByStatus["denied-queue-full"]
	approved := stats.ByStatus["approved"] + stats.ByStatus["approved-permanent"]
	timeouts := stats.ByStatus["timeout"]

	statsLine := fmt.Sprintf("  Total: %d │ ✅ %d │ 👤 %d │ ⛔ %d │ ⏱ %d",
		stats.Total, allowed, approved, denied, timeouts)
	if stats.TLSCount > 0 {
		statsLine += fmt.Sprintf(" │ 🔓 %d", stats.TLSCount)
	}
	statsLine += fmt.Sprintf(" │ Domains: %d", len(stats.ByDomain))
	b.WriteString(dim.Render(statsLine) + "\n")

	// Filters
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
		b.WriteString(bright.Render("  Filters: "+strings.Join(filters, " │ ")) + "\n")
	}

	b.WriteString(dim.Render(strings.Repeat("─", 70)) + "\n")

	// Top domains
	if len(stats.ByDomain) > 0 {
		type dc struct {
			d string
			c int
		}
		var sorted []dc
		for d, c := range stats.ByDomain {
			sorted = append(sorted, dc{d, c})
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].c > sorted[j].c })

		parts := make([]string, 0, 5)
		max := 5
		if len(sorted) < max {
			max = len(sorted)
		}
		for i := 0; i < max; i++ {
			parts = append(parts, fmt.Sprintf("%s(%d)", sorted[i].d, sorted[i].c))
		}
		domLine := "  Top: " + strings.Join(parts, " │ ")
		if len(sorted) > max {
			domLine += fmt.Sprintf(" +%d more", len(sorted)-max)
		}
		b.WriteString(dim.Render(domLine) + "\n")
		b.WriteString(dim.Render(strings.Repeat("─", 70)) + "\n")
	}

	// Entries
	allEntries := a.proxyServer.Audit().All()
	entries := a.filterAuditEntries(allEntries)

	if len(entries) == 0 {
		if len(allEntries) > 0 {
			b.WriteString(bright.Render("  No entries match current filters.") + dim.Render(" Press Ctrl+L to clear.") + "\n")
		} else {
			selectedName := ""
		if a.selected < len(a.containers) {
			selectedName = a.containers[a.selected].Name
		}
		b.WriteString(dim.Render("  No requests recorded yet.") + "\n\n")
		if selectedName != "" {
			b.WriteString(dim.Render("  Selected: ") + bright.Render(selectedName) + "\n")
			b.WriteString(dim.Render("  Press ") + bright.Render("p") + dim.Render(" to auto-configure proxy on this container") + "\n")
			b.WriteString(dim.Render("  Press ") + bright.Render("u") + dim.Render(" to remove proxy configuration") + "\n")
		}
		}
		return b.String()
	}

	if len(entries) != len(allEntries) {
		b.WriteString(dim.Render(fmt.Sprintf("  Showing %d / %d entries", len(entries), len(allEntries))) + "\n")
	}

	// Scroll calculation
	visibleH := a.height - 14
	if visibleH < 5 {
		visibleH = 5
	}

	maxScroll := len(entries) - visibleH
	if maxScroll < 0 {
		maxScroll = 0
	}
	scroll := a.auditScroll
	if scroll > maxScroll {
		scroll = maxScroll
	}

	// Reverse entries (newest first)
	reversed := make([]proxy.AuditEntry, len(entries))
	for i, e := range entries {
		reversed[len(entries)-1-i] = e
	}

	start := scroll
	end := scroll + visibleH
	if end > len(reversed) {
		end = len(reversed)
	}

	if scroll > 0 {
		b.WriteString(dim.Render("  ▲ more") + "\n")
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
		case strings.Contains(e.Status, "error"):
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("#e74c3c"))
		default:
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("#e6edf3"))
		}

		b.WriteString("  " + style.Render(line) + "\n")
	}

	if end < len(reversed) {
		b.WriteString(dim.Render(fmt.Sprintf("  ▼ %d more", len(reversed)-end)) + "\n")
	}

	return b.String()
}

// autoSetupProxy configures proxy env + CA cert on a container via LXD API
func (a *App) autoSetupProxy(container string) tea.Cmd {
	return func() tea.Msg {
		if a.client == nil {
			return asyncResultMsg{err: fmt.Errorf("LXD client not available")}
		}

		// Lazy-start: create Server + MITM + TransparentListener on first use
		if a.proxyServer == nil {
			approvalCh := make(chan proxy.ApprovalRequest, 10)
			srv := proxy.NewServer(9081, approvalCh)
			a.proxyServer = srv
			a.approvalCh = approvalCh

			// Always enable MITM (CA cert will be injected into container)
			dataDir := os.ExpandEnv("$HOME/.cella")
			mitmCfg, err := proxy.NewMITMConfig(dataDir)
			if err != nil {
				return asyncResultMsg{err: fmt.Errorf("generate CA: %w", err)}
			}
			srv.EnableMITM(mitmCfg)

			// Start transparent listener
			tl := proxy.NewTransparentListener(9081, srv)
			if err := tl.Start(); err != nil {
				return asyncResultMsg{err: fmt.Errorf("start listener :9081: %w", err)}
			}
			a.tproxyListener = tl
		}

		// Find container IP
		containerIP := ""
		for _, c := range a.allContainers {
			if c.Name == container && c.IP != "" {
				containerIP = c.IP
				break
			}
		}
		if containerIP == "" {
			return asyncResultMsg{err: fmt.Errorf("cannot find IP for %s", container)}
		}

		// 1. nftables REDIRECT (port 80/443 → :9081)
		if err := proxy.SetupTransparentRedirect(containerIP, 9081); err != nil {
			return asyncResultMsg{err: fmt.Errorf("nftables REDIRECT: %w", err)}
		}

		// 2. CA cert inject + update-ca-certificates
		socketPath := a.client.SocketPath()
		setup := &proxy.AutoSetup{
			MITMPem: a.proxyServer.MITMCAPem(),
		}
		if err := setup.SetupContainer(socketPath, container); err != nil {
			return asyncResultMsg{err: fmt.Errorf("CA cert: %w", err)}
		}

		// Update container IP mapping for the proxy
		ipMap := make(map[string]string)
		for _, c := range a.allContainers {
			if c.IP != "" {
				ipMap[c.IP] = c.Name
			}
		}
		a.proxyServer.UpdateContainerMap(ipMap)

		return asyncResultMsg{text: fmt.Sprintf("🔧 intercepting %s (%s) — REDIRECT :9081 + CA cert", container, containerIP)}
	}
}

// removeProxySetup removes proxy configuration from a container
func (a *App) removeProxySetup(container string) tea.Cmd {
	return func() tea.Msg {
		if a.proxyServer == nil || a.client == nil {
			return asyncResultMsg{err: fmt.Errorf("proxy or LXD client not available")}
		}

		setup := &proxy.AutoSetup{}
		socketPath := a.client.SocketPath()
		if err := setup.RemoveSetup(socketPath, container); err != nil {
			return asyncResultMsg{err: fmt.Errorf("remove proxy %s: %w", container, err)}
		}

		// Remove transparent redirect
		for _, c := range a.allContainers {
			if c.Name == container && c.IP != "" {
				_ = proxy.RemoveTransparentRedirect(c.IP)
				break
			}
		}

		return asyncResultMsg{text: fmt.Sprintf("🔧 proxy removed from %s", container)}
	}
}
