package tui

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/atotto/clipboard"
	"github.com/fourdoors/cella/internal/proxy"
)

// approvalMsg wraps an incoming approval request from the proxy
type approvalMsg proxy.ApprovalRequest

// approvalCancelMsg is sent when a proxy approval request times out
type approvalCancelMsg string // request ID

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
		select {
		case a.pendingApproval.ResponseCh <- proxy.ApprovalResponse{Approved: true, Permanent: false}:
		default: // proxy already timed out
		}
		a.addEvent(fmt.Sprintf("👤 approved (once): %s → %s", a.pendingApproval.Container, a.pendingApproval.Domain))
		a.flashText = fmt.Sprintf("👤 approved (once): %s", a.pendingApproval.Domain)
		a.pendingApproval = nil
		return a, a.listenApprovalsContinue()
	case "Y":
		select {
		case a.pendingApproval.ResponseCh <- proxy.ApprovalResponse{Approved: true, Permanent: true}:
		default:
		}
		a.addEvent(fmt.Sprintf("👤+ approved (permanent): %s → %s", a.pendingApproval.Container, a.pendingApproval.Domain))
		a.flashText = fmt.Sprintf("👤+ allow always: %s", a.pendingApproval.Domain)
		a.pendingApproval = nil
		return a, a.listenApprovalsContinue()
	case "n":
		select {
		case a.pendingApproval.ResponseCh <- proxy.ApprovalResponse{Approved: false, Permanent: false}:
		default:
		}
		a.addEvent(fmt.Sprintf("⛔ denied (once): %s → %s", a.pendingApproval.Container, a.pendingApproval.Domain))
		a.flashText = fmt.Sprintf("⛔ denied (once): %s", a.pendingApproval.Domain)
		a.pendingApproval = nil
		return a, a.listenApprovalsContinue()
	case "N":
		select {
		case a.pendingApproval.ResponseCh <- proxy.ApprovalResponse{Approved: false, Permanent: true}:
		default:
		}
		a.addEvent(fmt.Sprintf("🚫 denied (permanent): %s → %s", a.pendingApproval.Container, a.pendingApproval.Domain))
		a.flashText = fmt.Sprintf("🚫 deny always: %s", a.pendingApproval.Domain)
		a.pendingApproval = nil
		return a, a.listenApprovalsContinue()
	}

	return a, nil
}

// listenApprovalsContinue continues listening for approvals
func (a App) listenApprovalsContinue() tea.Cmd {
	if globalApprovalCh == nil {
		return nil
	}
	return listenApprovals(globalApprovalCh)
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

	line3 := fmt.Sprintf("  %s %s  %s %s  %s %s  %s %s",
		keyStyle.Render("[y]"), optStyle.Render("allow once"),
		keyStyle.Render("[Y]"), optStyle.Render("allow always"),
		keyStyle.Render("[n]"), optStyle.Render("deny once"),
		keyStyle.Render("[N]"), optStyle.Render("deny always"))

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

	// List-view mode: j/k/del/x navigate and remove entries
	if a.auditShowLists {
		items := a.buildListItems()
		max := len(items) - 1

				// ── add sub-mode ──
		if a.auditAddMode {
			runes := []rune(a.auditEditInput)
			switch msg.String() {
			case "esc":
				a.auditAddMode = false
				a.auditEditInput = ""
				a.auditEditCursor = 0
			case "enter":
				newDomain := strings.TrimSpace(strings.ToLower(a.auditEditInput))
				original := a.auditEditOriginal // used to know which container/kind to add to
				a.auditAddMode = false
				a.auditEditInput = ""
				a.auditEditCursor = 0
				if newDomain != "" {
					return a, a.addListItem(original.container, newDomain, original.kind)
				}
			case "left":
				if a.auditEditCursor > 0 {
					a.auditEditCursor--
				}
			case "right":
				if a.auditEditCursor < len(runes) {
					a.auditEditCursor++
				}
			case "backspace", "ctrl+h":
				if a.auditEditCursor > 0 {
					runes = append(runes[:a.auditEditCursor-1], runes[a.auditEditCursor:]...)
					a.auditEditCursor--
					a.auditEditInput = string(runes)
				}
			case "delete":
				if a.auditEditCursor < len(runes) {
					runes = append(runes[:a.auditEditCursor], runes[a.auditEditCursor+1:]...)
					a.auditEditInput = string(runes)
				}
			case "ctrl+v":
				text, err := clipboard.ReadAll()
				if err == nil {
					cleanText := strings.TrimSpace(text)
					if len(cleanText) > 0 {
						runes = append(runes[:a.auditEditCursor], append([]rune(cleanText), runes[a.auditEditCursor:]...)...)
						a.auditEditCursor += len([]rune(cleanText))
						a.auditEditInput = string(runes)
					}
				}

				if k := msg.String(); len(k) == 1 && k[0] >= 32 && k[0] < 127 {
					runes = append(runes[:a.auditEditCursor], append([]rune{rune(k[0])}, runes[a.auditEditCursor:]...)...)
					a.auditEditCursor++
					a.auditEditInput = string(runes)
				}
			}
			return a, nil
		}

// ── edit sub-mode ──
		if a.auditEditMode {
			runes := []rune(a.auditEditInput)
			switch msg.String() {
			case "esc":
				a.auditEditMode = false
				a.auditEditInput = ""
				a.auditEditCursor = 0
			case "enter":
				newDomain := strings.TrimSpace(strings.ToLower(a.auditEditInput))
				original := a.auditEditOriginal
				a.auditEditMode = false
				a.auditEditInput = ""
				a.auditEditCursor = 0
				if newDomain != "" && newDomain != original.domain {
					return a, a.editListItem(original, newDomain)
				}
			case "left":
				if a.auditEditCursor > 0 {
					a.auditEditCursor--
				}
			case "right":
				if a.auditEditCursor < len(runes) {
					a.auditEditCursor++
				}
			case "backspace", "ctrl+h":
				if a.auditEditCursor > 0 {
					runes = append(runes[:a.auditEditCursor-1], runes[a.auditEditCursor:]...)
					a.auditEditCursor--
					a.auditEditInput = string(runes)
				}
			case "delete":
				if a.auditEditCursor < len(runes) {
					runes = append(runes[:a.auditEditCursor], runes[a.auditEditCursor+1:]...)
					a.auditEditInput = string(runes)
				}
			case "ctrl+v":
				text, err := clipboard.ReadAll()
				if err == nil {
					cleanText := strings.TrimSpace(text)
					if len(cleanText) > 0 {
						runes = append(runes[:a.auditEditCursor], append([]rune(cleanText), runes[a.auditEditCursor:]...)...)
						a.auditEditCursor += len([]rune(cleanText))
						a.auditEditInput = string(runes)
					}
				}

			default:
				if k := msg.String(); len(k) == 1 && k[0] >= 32 && k[0] < 127 {
					runes = append(runes[:a.auditEditCursor], append([]rune{rune(k[0])}, runes[a.auditEditCursor:]...)...)
					a.auditEditCursor++
					a.auditEditInput = string(runes)
				}
			}
			return a, nil
		}

		// ── normal navigation ──
		switch msg.String() {
		case "esc", "q", "L":
			a.auditShowLists = false
			a.auditListCursor = 0
			return a, nil
		case "up", "k":
			if a.auditListCursor > 0 {
				a.auditListCursor--
			}
		case "down", "j":
			if a.auditListCursor < max {
				a.auditListCursor++
			}
		case "g":
			a.auditListCursor = 0
		case "G":
			if max >= 0 {
				a.auditListCursor = max
			}
		case "x", "delete":
			if a.auditListCursor >= 0 && a.auditListCursor < len(items) {
				return a, a.removeListItem(items[a.auditListCursor])
			}
		case "d":
			// Move allow → deny (no-op on deny entries)
			if a.auditListCursor >= 0 && a.auditListCursor < len(items) {
				it := items[a.auditListCursor]
				if it.kind == "allow" {
					return a, a.moveListItem(it, "deny")
				}
			}
		case "A":
			// Move deny → allow (no-op on allow entries)
			if a.auditListCursor >= 0 && a.auditListCursor < len(items) {
				it := items[a.auditListCursor]
				if it.kind == "deny" {
					return a, a.moveListItem(it, "allow")
				}
			}
				case "a": // Add new domain to the current list type (allow/deny)
			if a.auditListCursor >= 0 && a.auditListCursor < len(items) {
				it := items[a.auditListCursor]
				a.auditAddMode = true
				a.auditEditInput = ""
				a.auditEditCursor = 0
				a.auditEditOriginal.container = it.container
				a.auditEditOriginal.kind = it.kind
			}
		case "c", "y": // copy
			if a.auditListCursor >= 0 && a.auditListCursor < len(items) {
				it := items[a.auditListCursor]
				_ = clipboard.WriteAll(it.domain)
				a.flashText = "📋 Copied: " + it.domain
			}
		case "p": // paste (as new item)
			if a.auditListCursor >= 0 && a.auditListCursor < len(items) {
				it := items[a.auditListCursor]
				text, err := clipboard.ReadAll()
				if err == nil {
					cleanText := strings.TrimSpace(text)
					if cleanText != "" {
						return a, a.addListItem(it.container, cleanText, it.kind)
					}
				}
			}
		case "e":
			if a.auditListCursor >= 0 && a.auditListCursor < len(items) {
				it := items[a.auditListCursor]
				a.auditEditMode = true
				a.auditEditInput = it.domain
				a.auditEditCursor = len([]rune(it.domain))
				a.auditEditOriginal.container = it.container
				a.auditEditOriginal.domain = it.domain
				a.auditEditOriginal.kind = it.kind
			}
		}
		// clamp cursor
		if max >= 0 && a.auditListCursor > max {
			a.auditListCursor = max
		}
		// scroll is handled entirely by renderAllowDenyLists
		return a, nil
	}

	switch msg.String() {
	case "esc", "q":
		a.focus = panelSidebar
		return a, nil
	case "c":
		if globalProxyServer != nil {
			globalProxyServer.Audit().Clear()
			a.addEvent("📋 audit log cleared")
		a.flashText = "📋 audit log cleared"
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
			a.auditStatusFilter = "approved"
		case "approved":
			a.auditStatusFilter = "denied"
		case "denied":
			a.auditStatusFilter = "denied-permanent"
		case "denied-permanent":
			a.auditStatusFilter = "timeout"
		default:
			a.auditStatusFilter = ""
		}
		a.auditScroll = 0
		return a, nil
	case "p":
		// Auto-setup interception on selected container
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			if c.Runtime != "lxd" {
				return a, a.setFlash("❌ Auto-setup only for LXD containers")
			}
			if c.Status != "Running" {
				return a, a.setFlash("❌ Container must be running")
			}
			// Lazy-start: create Server + MITM + Listener SYNCHRONOUSLY (in Update)
			if globalProxyServer == nil {
				approvalCh := make(chan proxy.ApprovalRequest, 10)
				srv := proxy.NewServer(9081, approvalCh)
				dataDir := os.ExpandEnv("$HOME/.cella")
				mitmCfg, err := proxy.NewMITMConfig(dataDir)
				if err != nil {
					return a, a.setFlash(fmt.Sprintf("❌ CA gen: %v", err))
				}
				srv.EnableMITM(mitmCfg)
				// Load persisted allowlists from previous sessions
				if err := srv.LoadAllowlistsFromDir(dataDir); err != nil {
					a.addEvent(fmt.Sprintf("⚠ allowlist load: %v", err))
				}
				// Load persisted denylists from previous sessions
				if err := srv.LoadDenylistsFromDir(dataDir); err != nil {
					a.addEvent(fmt.Sprintf("⚠ denylist load: %v", err))
				}
				tl := proxy.NewTransparentListener(9081, srv)
				// Wire persistence callback: save allowlist on every [Y] allow always
				tl.SetOnPermanentAllow(func() {
					if err := srv.SaveAllowlistsToDir(dataDir); err != nil {
						// best-effort; log to stderr but don't crash TUI
						_ = err
					}
				})
				// Wire persistence callback: save denylist on every [N] deny always
				tl.SetOnPermanentDeny(func() {
					if err := srv.SaveDenylistsToDir(dataDir); err != nil {
						_ = err
					}
				})
				if err := tl.Start(); err != nil {
					return a, a.setFlash(fmt.Sprintf("❌ listener: %v", err))
				}
				globalProxyServer = srv
				globalApprovalCh = approvalCh
				globalTproxyListener = tl
			}
			a.addEvent(fmt.Sprintf("🔧 setting up interception on %s...", c.Name))
			return a, a.autoSetupProxy(c.Name, globalProxyServer, a.client.SocketPath())
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
		if globalProxyServer != nil {
			entries := a.filterAuditEntries(globalProxyServer.Audit().All())
			return a, a.exportAuditJSON(entries)
		}
		return a, nil
	case "L":
		// Toggle allow/deny list view
		a.auditShowLists = !a.auditShowLists
		a.auditListCursor = 0
		a.auditListScroll = 0
		a.auditScroll = 0
		return a, nil
	case "H":
		// Toggle host traffic interception (OUTPUT chain)
		return a, a.toggleHostInterception()
	case "up", "k":
		if a.auditScroll > 0 {
			a.auditScroll--
		}
	case "down", "j":
		a.auditScroll++
	case "pgup":
		step := (a.height - 14) / 2
		if step < 1 {
			step = 1
		}
		if a.auditScroll > step {
			a.auditScroll -= step
		} else {
			a.auditScroll = 0
		}
	case "pgdown":
		step := (a.height - 14) / 2
		if step < 1 {
			step = 1
		}
		a.auditScroll += step
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
				if e.Status != "denied" && e.Status != "denied-queue-full" {
					continue
				}
			} else if a.auditStatusFilter == "denied-permanent" {
				if e.Status != "denied-permanent" {
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

// listItem represents a single domain entry in the allow/deny list view
type listItem struct {
	container string
	domain    string
	kind      string // "allow" or "deny"
}

// buildListItems returns a flat ordered slice of all allow+deny entries
// (sorted by container, then allow before deny, then domain).
func (a App) buildListItems() []listItem {
	if globalProxyServer == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, e := range globalProxyServer.Audit().All() {
		seen[e.Container] = true
	}
	if a.selected < len(a.containers) {
		seen[a.containers[a.selected].Name] = true
	}
	containers := make([]string, 0, len(seen))
	for c := range seen {
		containers = append(containers, c)
	}
	sort.Strings(containers)

	var items []listItem
	for _, cname := range containers {
		al := globalProxyServer.GetAllowlist(cname)
		dl := globalProxyServer.GetDenylist(cname)
		for _, d := range al.UserDomains() {
			items = append(items, listItem{container: cname, domain: d, kind: "allow"})
		}
		for _, d := range dl.List() {
			items = append(items, listItem{container: cname, domain: d, kind: "deny"})
		}
	}
	return items
}

// listItemIndex returns the cursor index of a specific item in the flat list.
// Returns -1 if not found.
func (a App) listItemIndex(container, domain, kind string, items []listItem) int {
	for i, it := range items {
		if it.container == container && it.domain == domain && it.kind == kind {
			return i
		}
	}
	return -1
}

// removeListItem removes the domain from its allowlist or denylist and persists.
func (a *App) removeListItem(item listItem) tea.Cmd {
	return func() tea.Msg {
		if globalProxyServer == nil {
			return asyncResultMsg{err: fmt.Errorf("proxy not active")}
		}
		dataDir := os.ExpandEnv("$HOME/.cella")
		switch item.kind {
		case "allow":
			globalProxyServer.GetAllowlist(item.container).Remove(item.domain)
			if err := globalProxyServer.SaveAllowlistsToDir(dataDir); err != nil {
				return asyncResultMsg{err: fmt.Errorf("save allowlist: %w", err)}
			}
			return asyncResultMsg{text: fmt.Sprintf("✅ removed allow: %s → %s", item.container, item.domain)}
		case "deny":
			globalProxyServer.GetDenylist(item.container).Remove(item.domain)
			if err := globalProxyServer.SaveDenylistsToDir(dataDir); err != nil {
				return asyncResultMsg{err: fmt.Errorf("save denylist: %w", err)}
			}
			return asyncResultMsg{text: fmt.Sprintf("🚫 removed deny: %s → %s", item.container, item.domain)}
		}
		return nil
	}
}


// renderAllowDenyLists renders the allowlist and denylist for the current container
func (a *App) renderAllowDenyLists() string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e"))
	bright := lipgloss.NewStyle().Foreground(lipgloss.Color("#e67e22"))
	blue := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#58a6ff"))
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("#27ae60"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("#e74c3c"))

	items := a.buildListItems()

	var b strings.Builder
	b.WriteString(blue.Render("📋 Allow / Deny Lists") + "\n")
	b.WriteString(dim.Render("  ↑/↓ j/k: move  │  a: add  │  e: edit  │  c: copy  │  p: paste  │  d: →deny  │  A: →allow  │  x: del  │  L/Esc: back") + "\n")
	b.WriteString(dim.Render(strings.Repeat("─", 70)) + "\n")

	if globalProxyServer == nil {
		b.WriteString(dim.Render("  Proxy not active.") + "\n")
		return b.String()
	}

	// Determine selected container name
	selectedName := ""
	if a.selected < len(a.containers) {
		selectedName = a.containers[a.selected].Name
	}

	// Collect all containers that have entries, sorted by name
	seen := map[string]bool{}
	for _, e := range globalProxyServer.Audit().All() {
		seen[e.Container] = true
	}
	if selectedName != "" {
		seen[selectedName] = true
	}
	containers := make([]string, 0, len(seen))
	for cname := range seen {
		containers = append(containers, cname)
	}
	sort.Strings(containers)

	if len(containers) == 0 {
		b.WriteString(dim.Render("  No containers with proxy history.") + "\n")
		return b.String()
	}

	// Build all content lines into a slice first, then apply viewport scroll.
	type contentLine struct {
		s        string
		isCursor bool // true if this line has the cursor on it
	}
	var lines []contentLine
	addLine := func(s string) { lines = append(lines, contentLine{s: s}) }
	addCursorLine := func(s string) { lines = append(lines, contentLine{s: s, isCursor: true}) }

	for _, cname := range containers {
		al := globalProxyServer.GetAllowlist(cname)
		dl := globalProxyServer.GetDenylist(cname)
		allowDomains := al.UserDomains()
		denyDomains := dl.List()

		if len(allowDomains) == 0 && len(denyDomains) == 0 {
			continue
		}

		header := bright.Render("  📦 " + cname)
		if cname == selectedName {
			header += dim.Render(" ◀ selected")
		}
		addLine(header)

		if len(allowDomains) > 0 {
			addLine(green.Render("    ✅ Allowed (permanent):"))
			for _, d := range allowDomains {
				idx := a.listItemIndex(cname, d, "allow", items)
				if idx == a.auditListCursor {
					cursorStyle := lipgloss.NewStyle().Background(lipgloss.Color("#1a4a1a")).Foreground(lipgloss.Color("#7ee787")).Bold(true)
										if a.auditAddMode && a.auditEditOriginal.kind == "allow" {
						addStyle := lipgloss.NewStyle().Background(lipgloss.Color("#1a4a1a")).Foreground(lipgloss.Color("#7ee787")).Bold(true)
						eRunes := []rune(a.auditEditInput)
						before := string(eRunes[:a.auditEditCursor])
						cursorChar := "█"
						after := ""
						if a.auditEditCursor < len(eRunes) {
							cursorChar = string(eRunes[a.auditEditCursor])
							after = string(eRunes[a.auditEditCursor+1:])
						}
						cursorRender := lipgloss.NewStyle().Background(lipgloss.Color("#ffffff")).Foreground(lipgloss.Color("#000000")).Render(cursorChar)
						addCursorLine(addStyle.Render("    ✨ + "+before) + cursorRender + addStyle.Render(after) + "  " + dim.Render("Enter: add  Esc: cancel  Ctrl+V: paste"))
					} else if a.auditEditMode {
						editStyle := lipgloss.NewStyle().Background(lipgloss.Color("#1a3a5a")).Foreground(lipgloss.Color("#79c0ff")).Bold(true)
						eRunes := []rune(a.auditEditInput)
						before := string(eRunes[:a.auditEditCursor])
						cursorChar := "█"
						after := ""
						if a.auditEditCursor < len(eRunes) {
							cursorChar = string(eRunes[a.auditEditCursor])
							after = string(eRunes[a.auditEditCursor+1:])
						}
						cursorRender := lipgloss.NewStyle().Background(lipgloss.Color("#ffffff")).Foreground(lipgloss.Color("#000000")).Render(cursorChar)
						addCursorLine(editStyle.Render("    ✏ + "+before) + cursorRender + editStyle.Render(after) + "  " + dim.Render("Enter: confirm  Esc: cancel"))
					} else {
						addCursorLine(cursorStyle.Render("    ▶ + "+d) + "  " + dim.Render("[a] add  [e] edit  [c] copy  [p] paste  [d] →deny  [x] remove"))
					}
				} else {
					addLine(green.Render("      + " + d))
				}
			}
		}
		if len(denyDomains) > 0 {
			addLine(red.Render("    🚫 Denied (permanent):"))
			for _, d := range denyDomains {
				idx := a.listItemIndex(cname, d, "deny", items)
				if idx == a.auditListCursor {
					cursorStyle := lipgloss.NewStyle().Background(lipgloss.Color("#4a1a1a")).Foreground(lipgloss.Color("#f97316")).Bold(true)
										if a.auditAddMode && a.auditEditOriginal.kind == "deny" {
						addStyle := lipgloss.NewStyle().Background(lipgloss.Color("#4a1a1a")).Foreground(lipgloss.Color("#f97316")).Bold(true)
						eRunes := []rune(a.auditEditInput)
						before := string(eRunes[:a.auditEditCursor])
						cursorChar := "█"
						after := ""
						if a.auditEditCursor < len(eRunes) {
							cursorChar = string(eRunes[a.auditEditCursor])
							after = string(eRunes[a.auditEditCursor+1:])
						}
						cursorRender := lipgloss.NewStyle().Background(lipgloss.Color("#ffffff")).Foreground(lipgloss.Color("#000000")).Render(cursorChar)
						addCursorLine(addStyle.Render("    ✨ - "+before) + cursorRender + addStyle.Render(after) + "  " + dim.Render("Enter: add  Esc: cancel  Ctrl+V: paste"))
					} else if a.auditEditMode {
						editStyle := lipgloss.NewStyle().Background(lipgloss.Color("#2a1a3a")).Foreground(lipgloss.Color("#d2a8ff")).Bold(true)
						eRunes := []rune(a.auditEditInput)
						before := string(eRunes[:a.auditEditCursor])
						cursorChar := "█"
						after := ""
						if a.auditEditCursor < len(eRunes) {
							cursorChar = string(eRunes[a.auditEditCursor])
							after = string(eRunes[a.auditEditCursor+1:])
						}
						cursorRender := lipgloss.NewStyle().Background(lipgloss.Color("#ffffff")).Foreground(lipgloss.Color("#000000")).Render(cursorChar)
						addCursorLine(editStyle.Render("    ✏ - "+before) + cursorRender + editStyle.Render(after) + "  " + dim.Render("Enter: confirm  Esc: cancel"))
					} else {
						addCursorLine(cursorStyle.Render("    ▶ - "+d) + "  " + dim.Render("[a] add  [e] edit  [c] copy  [p] paste  [A] →allow  [x] remove"))
					}
				} else {
					addLine(red.Render("      - " + d))
				}
			}
		}

	}

	// ═══ Viewport with scroll-follow (single source of truth) ═══
	//
	// Step 1: Find which line the cursor is on
	cursorLineIdx := -1
	for i, l := range lines {
		if l.isCursor {
			cursorLineIdx = i
			break
		}
	}

	// Step 2: Calculate how many content lines we can show
	// Total vertical budget inside the panel (after border+padding):
	//   a.height - 4 (header+statusbar+border*2) - 2 (padding) = contentH
	// Minus fixed lines in this render:
	//   title(1) + hint(1) + sep(1) + footer sep(1) + footer path(1) = 5
	contentH := a.height - 6 - 5
	if contentH < 3 {
		contentH = 3
	}

	// Step 3: If everything fits, no scrolling needed
	if len(lines) <= contentH {
		for _, l := range lines {
			b.WriteString(l.s + "\n")
		}
	} else {
		// We need scrolling. Reserve 1 line each for ▲/▼ indicators.
		showable := contentH - 2 // lines available for actual content
		if showable < 1 {
			showable = 1
		}

		// Scroll-follow with scrolloff=2
		const scrolloff = 2
		scroll := a.auditListScroll

		// Ensure cursor is visible with scrolloff margin
		if cursorLineIdx >= 0 {
			if cursorLineIdx-scrolloff < scroll {
				scroll = cursorLineIdx - scrolloff
			}
			if cursorLineIdx+scrolloff >= scroll+showable {
				scroll = cursorLineIdx + scrolloff - showable + 1
			}
		}

		// Hard clamp
		maxScroll := len(lines) - showable
		if maxScroll < 0 {
			maxScroll = 0
		}
		if scroll > maxScroll {
			scroll = maxScroll
		}
		if scroll < 0 {
			scroll = 0
		}
		a.auditListScroll = scroll

		// Render
		if scroll > 0 {
			b.WriteString(dim.Render(fmt.Sprintf("  ▲ %d more", scroll)) + "\n")
		} else {
			b.WriteString("\n") // blank line to keep height consistent
		}
		end := scroll + showable
		if end > len(lines) {
			end = len(lines)
		}
		for _, l := range lines[scroll:end] {
			b.WriteString(l.s + "\n")
		}
		remaining := len(lines) - end
		if remaining > 0 {
			b.WriteString(dim.Render(fmt.Sprintf("  ▼ %d more", remaining)))
		}
	}

	// Show file paths
	dataDir := os.ExpandEnv("$HOME/.cella")
	b.WriteString(dim.Render(strings.Repeat("─", 70)) + "\n")
	b.WriteString(dim.Render(fmt.Sprintf("  Persisted: %s/allowlist.json  %s/denylist.json", dataDir, dataDir)))
	return b.String()
}

// moveListItem moves an entry from one list to the other (allow↔deny).
func (a *App) moveListItem(item listItem, toKind string) tea.Cmd {
	return func() tea.Msg {
		if globalProxyServer == nil {
			return asyncResultMsg{err: fmt.Errorf("proxy not active")}
		}
		dataDir := os.ExpandEnv("$HOME/.cella")
		// Remove from source list
		switch item.kind {
		case "allow":
			globalProxyServer.GetAllowlist(item.container).Remove(item.domain)
			if err := globalProxyServer.SaveAllowlistsToDir(dataDir); err != nil {
				return asyncResultMsg{err: fmt.Errorf("save allowlist: %w", err)}
			}
		case "deny":
			globalProxyServer.GetDenylist(item.container).Remove(item.domain)
			if err := globalProxyServer.SaveDenylistsToDir(dataDir); err != nil {
				return asyncResultMsg{err: fmt.Errorf("save denylist: %w", err)}
			}
		}
		// Add to destination list
		switch toKind {
		case "allow":
			globalProxyServer.GetAllowlist(item.container).Add(item.domain)
			if err := globalProxyServer.SaveAllowlistsToDir(dataDir); err != nil {
				return asyncResultMsg{err: fmt.Errorf("save allowlist: %w", err)}
			}
		case "deny":
			globalProxyServer.GetDenylist(item.container).Add(item.domain)
			if err := globalProxyServer.SaveDenylistsToDir(dataDir); err != nil {
				return asyncResultMsg{err: fmt.Errorf("save denylist: %w", err)}
			}
		}
		fromIcon := "✅"
		toIcon := "🚫"
		if toKind == "allow" {
			fromIcon, toIcon = "🚫", "✅"
		}
		return asyncResultMsg{
			text: fmt.Sprintf("%s→%s moved [%s] %s", fromIcon, toIcon, item.container, item.domain),
		}
	}
}


// editListItem replaces oldItem.domain with newDomain in its allow/deny list.
func (a *App) editListItem(old listItem, newDomain string) tea.Cmd {
	return func() tea.Msg {
		if globalProxyServer == nil {
			return asyncResultMsg{err: fmt.Errorf("proxy not active")}
		}
		dataDir := os.ExpandEnv("$HOME/.cella")
		switch old.kind {
		case "allow":
			al := globalProxyServer.GetAllowlist(old.container)
			al.Remove(old.domain)
			al.Add(newDomain)
			if err := globalProxyServer.SaveAllowlistsToDir(dataDir); err != nil {
				return asyncResultMsg{err: fmt.Errorf("save allowlist: %w", err)}
			}
		case "deny":
			dl := globalProxyServer.GetDenylist(old.container)
			dl.Remove(old.domain)
			dl.Add(newDomain)
			if err := globalProxyServer.SaveDenylistsToDir(dataDir); err != nil {
				return asyncResultMsg{err: fmt.Errorf("save denylist: %w", err)}
			}
		}
		kindIcon := "✅"
		if old.kind == "deny" {
			kindIcon = "🚫"
		}
		return asyncResultMsg{
			text: fmt.Sprintf("%s edited [%s] %s → %s", kindIcon, old.container, old.domain, newDomain),
		}
	}
}

// toggleHostInterception enables or removes nftables OUTPUT REDIRECT for the host.
func (a *App) toggleHostInterception() tea.Cmd {
	return func() tea.Msg {
		// Ensure proxy is running
		if globalProxyServer == nil {
			return asyncResultMsg{err: fmt.Errorf("proxy not active — press p first")}
		}
		// Determine current state via containerByIP or a flag stored on the server
		if globalProxyServer.HostInterceptionActive() {
			// Turn off
			if err := proxy.RemoveHostRedirect(); err != nil {
				return asyncResultMsg{err: fmt.Errorf("remove host redirect: %w", err)}
			}
			globalProxyServer.SetHostInterceptionActive(false)
			hostname, _ := os.Hostname()
			return asyncResultMsg{text: fmt.Sprintf("🖥 host interception OFF (%s)", hostname)}
		}
		// Turn on
		hostname, _ := os.Hostname()
		uid := os.Getuid()
		if err := proxy.SetupHostRedirect(9081, uid); err != nil {
			return asyncResultMsg{err: fmt.Errorf("host redirect: %w", err)}
		}
		// Register host IP in containerByIP so traffic is attributed to hostname
		ipMap := make(map[string]string)
		for _, c := range a.allContainers {
			if c.IP != "" && c.IP != "-" {
				ipMap[c.IP] = c.Name
			}
		}
		// 127.0.0.1 won't appear in REDIRECT (OUTPUT uses 127.0.0.1 as src),
		// so the PTR/resolveContainerName fallback will resolve from "juju-..." hostname.
		// Register a marker so it shows nicely.
		ipMap["127.0.0.1"] = hostname
		globalProxyServer.UpdateContainerMap(ipMap)
		globalProxyServer.SetHostInterceptionActive(true)
		return asyncResultMsg{text: fmt.Sprintf("🖥 host interception ON (%s, uid≠%d excluded)", hostname, uid)}
	}
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

	if globalProxyServer == nil {
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

	// Show allow/deny lists mode (L key)
	if a.auditShowLists {
		return a.renderAllowDenyLists()
	}

	// Title line
	b.WriteString(blue.Render("📋 API Audit Log ◆"))
	b.WriteString(green.Render(fmt.Sprintf(" (intercept :%d", 9081)))
	if globalProxyServer.MITMEnabled() {
		b.WriteString(bright.Render(" +MITM🔓"))
	}
	b.WriteString(green.Render(")"))
	b.WriteString("\n")

	// Stats
	stats := globalProxyServer.Audit().Stats()
	allowed := stats.ByStatus["allowed"]
	denied := stats.ByStatus["denied"] + stats.ByStatus["denied-queue-full"]
	approved := stats.ByStatus["approved"] + stats.ByStatus["approved-permanent"]
	timeouts := stats.ByStatus["timeout"]

	deniedPerm := stats.ByStatus["denied-permanent"]
	statsLine := fmt.Sprintf("  Total: %d │ ✅ %d │ 👤 %d │ ⛔ %d │ 🚫 %d │ ⏱ %d",
		stats.Total, allowed, approved, denied, deniedPerm, timeouts)
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
		case "denied-permanent":
			icon = "🚫"
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
	allEntries := globalProxyServer.Audit().All()
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
func (a *App) autoSetupProxy(container string, srv *proxy.Server, lxdSocket string) tea.Cmd {
	return func() tea.Msg {
		if a.client == nil {
			return asyncResultMsg{err: fmt.Errorf("LXD client not available")}
		}

		// Server/MITM/Listener already initialized by p key handler in Update()
		if srv == nil {
			return asyncResultMsg{err: fmt.Errorf("proxy not initialized")}
		}

		// Find container IP
		containerIP := ""
		for _, c := range a.allContainers {
			if c.Name == container && c.IP != "" {
				containerIP = c.IP
				break
			}
		}
		if containerIP == "" || containerIP == "-" || net.ParseIP(containerIP) == nil {
			return asyncResultMsg{err: fmt.Errorf("no valid IP for %s (got %q) — container may still be starting", container, containerIP)}
		}

		// 1. nftables REDIRECT (port 80/443 → :9081)
		// Always try to remove any stale rules for this container first
		// (handles IP change after container restart, or leftover rules).
		for _, oldIP := range func() []string {
			var ips []string
			if prev, ok := a.interceptedIPs[container]; ok && prev != containerIP {
				ips = append(ips, prev)
			}
			ips = append(ips, containerIP) // also clean current IP before re-adding
			return ips
		}() {
			_ = proxy.RemoveTransparentRedirect(oldIP) // best-effort cleanup
		}
		if err := proxy.SetupTransparentRedirect(containerIP, 9081); err != nil {
			return asyncResultMsg{err: fmt.Errorf("nftables REDIRECT for %s (%s): %w", container, containerIP, err)}
		}

		// 2. CA cert inject + update-ca-certificates
		socketPath := lxdSocket
		setup := &proxy.AutoSetup{
			MITMPem: srv.MITMCAPem(),
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
		srv.UpdateContainerMap(ipMap)

		return asyncResultMsg{
			text: fmt.Sprintf("🔧 intercepting %s (%s) — REDIRECT :9081 + CA cert", container, containerIP),
			// Attach IP so the caller can record it in interceptedIPs.
			extra: containerIP,
			extraKey: container,
		}
	}
}

// removeProxySetup removes proxy configuration from a container
func (a *App) removeProxySetup(container string) tea.Cmd {
	return func() tea.Msg {
		if globalProxyServer == nil || a.client == nil {
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

		return asyncResultMsg{
			text:     fmt.Sprintf("🔧 proxy removed from %s", container),
			extraKey: container, // signal removal: extra is empty string
		}
	}
}

// addListItem adds a domain to its allow/deny list.
func (a *App) addListItem(container, domain, kind string) tea.Cmd {
	return func() tea.Msg {
		if globalProxyServer == nil {
			return asyncResultMsg{err: fmt.Errorf("proxy not active")}
		}
		dataDir := os.ExpandEnv("$HOME/.cella")
		switch kind {
		case "allow":
			globalProxyServer.GetAllowlist(container).Add(domain)
			if err := globalProxyServer.SaveAllowlistsToDir(dataDir); err != nil {
				return asyncResultMsg{err: fmt.Errorf("save allowlist: %w", err)}
			}
			return asyncResultMsg{text: fmt.Sprintf("✅ added allow: %s → %s", container, domain)}
		case "deny":
			globalProxyServer.GetDenylist(container).Add(domain)
			if err := globalProxyServer.SaveDenylistsToDir(dataDir); err != nil {
				return asyncResultMsg{err: fmt.Errorf("save denylist: %w", err)}
			}
			return asyncResultMsg{text: fmt.Sprintf("🚫 added deny: %s → %s", container, domain)}
		}
		return nil
	}
}
