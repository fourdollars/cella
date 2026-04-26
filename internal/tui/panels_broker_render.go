package tui

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fourdoors/cella/internal/proxy"
	"sort"
	"strings"
)

func (a *App) handleBrokerPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	a.clampBrokerCursors()
	s := msg.String()

	if a.brokerEditMode {
		switch s {
		case "esc", "q":
			a.brokerResetEditState()
			a.addEvent("↩ broker inline token input canceled")
		case "enter":
			if done := a.brokerCommitEdit(); !done {
				return a, nil
			}
		case "backspace":
			r := []rune(a.brokerEditBuf)
			if len(r) > 0 {
				a.brokerEditBuf = string(r[:len(r)-1])
			}
		case "ctrl+u":
			a.brokerEditBuf = ""
		default:
			if msg.Type == tea.KeyRunes && len(msg.Runes) > 0 {
				a.brokerEditBuf += string(msg.Runes)
			}
		}
		return a, nil
	}

	if a.brokerClearGroupsConfirm {
		switch s {
		case "y", "Y":
			a.brokerGroups = nil
			a.brokerGroupCursor = 0
			a.brokerReconcilePoliciesAfterGroupChange()
			a.brokerDirty = true
			a.brokerClearGroupsConfirm = false
			a.addEvent("🧨 token broker groups cleared (0 groups)")
		case "n", "N", "esc", "q":
			a.brokerClearGroupsConfirm = false
			a.addEvent("↩ clear-all groups canceled")
		default:
			a.brokerClearGroupsConfirm = false
		}
		return a, nil
	}

	if a.brokerApplyConfirm {
		switch s {
		case "y", "Y":
			snap := a.captureBrokerSnapshot()
			a.brokerLastApplied = &snap
			a.brokerDirty = false
			a.brokerApplyConfirm = false
			a.brokerSyncRuntimeState()
			if err := a.saveBrokerState(); err != nil {
				a.addEvent(fmt.Sprintf("⚠ token broker applied but save failed: %v", err))
			} else {
				a.addEvent("✅ token broker draft applied + persisted")
			}
		case "n", "N", "esc", "q":
			a.brokerApplyConfirm = false
			a.addEvent("↩ token broker apply canceled")
		default:
			a.brokerApplyConfirm = false
		}
		return a, nil
	}

	switch s {
	case "esc", "q":
		a.focus = a.prevFocus
		return a, nil
	case "tab":
		a.brokerTab = (a.brokerTab + 1) % 6
		return a, nil
	case "shift+tab":
		a.brokerTab = (a.brokerTab + 5) % 6
		return a, nil
	case "1", "2", "3", "4", "5", "6":
		a.brokerTab = int(s[0] - '1')
		return a, nil
	case "P", "p":
		a.brokerPreviewLines = a.brokerBuildPreview()
		return a, nil
	case "R":
		a.brokerPreviewLines = a.brokerBuildRuntimePreview()
		return a, nil
	case "V", "v":
		a.brokerPreviewLines = a.brokerBuildRuntimeDrift()
		a.addEvent("🧭 broker runtime drift check refreshed")
		return a, nil
	case "W", "w":
		window := a.brokerCycleCounterWindow()
		a.brokerPreviewLines = a.brokerBuildRuntimePreview()
		a.addEvent(fmt.Sprintf("🪟 broker counter window switched to %s", window.Label))
		return a, nil
	case "C", "c":
		if globalProxyServer == nil {
			a.addEvent("ℹ proxy runtime not active; no counters to clear")
			return a, nil
		}
		globalProxyServer.ResetBrokerCounters()
		a.brokerPreviewLines = a.brokerBuildRuntimePreview()
		a.addEvent("🧹 broker runtime counters cleared")
		return a, nil
	case "S":
		if !a.brokerDirty {
			a.addEvent("ℹ no broker draft changes to apply")
			return a, nil
		}
		a.brokerClearGroupsConfirm = false
		a.brokerDiffLines = a.brokerBuildDiffAgainstApplied()
		a.brokerApplyConfirm = true
		return a, nil
	case "U":
		a.brokerApplyConfirm = false
		a.brokerClearGroupsConfirm = false
		if a.brokerLastApplied != nil {
			a.restoreBrokerSnapshot(*a.brokerLastApplied)
			a.brokerDirty = false
			a.brokerDiffLines = []string{"Rolled back to last applied snapshot."}
			a.addEvent("↩ token broker rolled back")
		}
		return a, nil
	}

	switch a.brokerTab {
	case 0, 3:
		switch s {
		case "up", "k":
			a.brokerGroupCursor--
		case "down", "j":
			a.brokerGroupCursor++
		case "left", "h":
			a.brokerCycleGroupPool(-1)
		case "right", "l", "enter":
			a.brokerCycleGroupPool(1)
		case "+", "=":
			if len(a.brokerGroups) > 0 {
				a.brokerGroups[a.brokerGroupCursor].Weight++
				a.brokerDirty = true
			}
		case "-", "_":
			if len(a.brokerGroups) > 0 && a.brokerGroups[a.brokerGroupCursor].Weight > 1 {
				a.brokerGroups[a.brokerGroupCursor].Weight--
				a.brokerDirty = true
			}
		case "n", "N":
			pool := ""
			if len(a.brokerPools) > 0 {
				pool = a.brokerPools[0].Name
			}
			groupID := fmt.Sprintf("group-%d", len(a.brokerGroups)+1)
			// Default match to selected container name for better UX
			matchRule := groupID
			if a.selected < len(a.containers) {
				matchRule = a.containers[a.selected].Name
			}
			a.brokerGroups = append(a.brokerGroups, BrokerGroup{ID: groupID, Name: groupID, Match: matchRule, Pool: pool, Weight: 1, RPHLimit: 1000})
			a.brokerGroupCursor = len(a.brokerGroups) - 1
			a.brokerReconcilePoliciesAfterGroupChange()
			a.brokerDirty = true
		case "d", "D":
			if len(a.brokerGroups) > 0 {
				i := a.brokerGroupCursor
				removedID := brokerGroupID(a.brokerGroups[i])
				a.brokerGroups = append(a.brokerGroups[:i], a.brokerGroups[i+1:]...)
				a.brokerReconcilePoliciesAfterGroupChange()
				a.brokerDirty = true
				a.addEvent(fmt.Sprintf("🗑 broker group removed: %s", removedID))
			}
		case "e", "E":
			if len(a.brokerGroups) > 0 {
				g := &a.brokerGroups[a.brokerGroupCursor]
				a.brokerApplyConfirm = false
				a.brokerClearGroupsConfirm = false
				a.brokerEditMode = true
				a.brokerEditKind = "group-edit-match"
				a.brokerEditBuf = g.Match
				a.brokerEditSecret = false
				a.addEvent(fmt.Sprintf("📝 editing match rule for group %s (current: %s)", brokerGroupID(*g), g.Match))
			}
		case "x", "X":
			if len(a.brokerGroups) == 0 {
				a.addEvent("ℹ no broker groups to clear")
				break
			}
			a.brokerApplyConfirm = false
			a.brokerClearGroupsConfirm = true
		}
	case 1, 4:
		pool := a.brokerCurrentPool()
		switch s {
		case "n", "N":
			newPool := a.brokerNextPoolName()
			a.brokerPools = append(a.brokerPools, BrokerPool{Name: newPool})
			if len(a.brokerGroups) > 0 {
				a.brokerGroups[a.brokerGroupCursor].Pool = newPool
			}
			a.brokerReconcileMappingsAfterPoolChange()
			a.brokerDirty = true
			a.addEvent(fmt.Sprintf("➕ broker pool added: %s", newPool))
			return a, nil
		case "z", "Z":
			if pool == nil {
				a.addEvent("ℹ no pool to remove")
				return a, nil
			}
			idx := a.brokerPoolIndexByName(pool.Name)
			if idx < 0 {
				return a, nil
			}
			removed := a.brokerPools[idx].Name
			a.brokerPools = append(a.brokerPools[:idx], a.brokerPools[idx+1:]...)
			a.brokerReconcileMappingsAfterPoolChange()
			a.brokerTokenCursor = 0
			a.brokerDirty = true
			a.addEvent(fmt.Sprintf("🗑 broker pool removed: %s", removed))
			return a, nil
		}
		if pool == nil {
			break
		}
		switch s {
		case "a", "A":
			a.brokerBeginTokenAddInput(pool.Name)
			return a, nil
		case "d", "D":
			if len(pool.Tokens) > 1 {
				i := a.brokerTokenCursor
				pool.Tokens = append(pool.Tokens[:i], pool.Tokens[i+1:]...)
				if a.brokerTokenCursor >= len(pool.Tokens) {
					a.brokerTokenCursor = len(pool.Tokens) - 1
				}
				a.brokerDirty = true
			}
			break
		}
		if len(pool.Tokens) == 0 {
			break
		}
		switch s {
		case "up", "k":
			a.brokerTokenCursor--
		case "down", "j":
			a.brokerTokenCursor++
		case "enter", "x", "X":
			t := &pool.Tokens[a.brokerTokenCursor]
			t.Enabled = !t.Enabled
			a.brokerDirty = true
		case "b", "B":
			t := &pool.Tokens[a.brokerTokenCursor]
			t.BreakerOpen = !t.BreakerOpen
			a.brokerDirty = true
		case "f", "F":
			t := &pool.Tokens[a.brokerTokenCursor]
			t.SessionState = "fresh"
			t.BreakerOpen = false
			if t.Health < 0.99 {
				t.Health += 0.05
			}
			a.brokerDirty = true
		case "e", "E":
			t := &pool.Tokens[a.brokerTokenCursor]
			t.PATEnv = brokerSuggestedPATEnv(t.ID)
			a.brokerDirty = true
		case "g", "G":
			t := &pool.Tokens[a.brokerTokenCursor]
			t.PATEnv = "CELLA_BROKER_TEST_PAT"
			a.brokerDirty = true
		case "t", "T":
			t := &pool.Tokens[a.brokerTokenCursor]
			a.brokerTestExchangeToken(t)
			a.brokerDirty = true
		case "i", "I":
			// Edit Kind for the selected token inline.
			t := &pool.Tokens[a.brokerTokenCursor]
			a.brokerEditTokenID = t.ID
			a.brokerEditPoolName = pool.Name
			a.brokerEditKind = "token-edit-kind"
			a.brokerEditBuf = t.Kind
			a.brokerEditMode = true
			a.addEvent(fmt.Sprintf("🔍 editing kind for %s [current: %s] — type copilot/gemini/openai or clear for auto", t.ID, brokerKindLabel(t.Kind)))
		case "u", "U":
			// Edit Endpoint for the selected token inline.
			t := &pool.Tokens[a.brokerTokenCursor]
			a.brokerEditTokenID = t.ID
			a.brokerEditPoolName = pool.Name
			a.brokerEditKind = "token-edit-endpoint"
			a.brokerEditBuf = t.Endpoint
			a.brokerEditMode = true
			a.addEvent(fmt.Sprintf("🌐 editing endpoint for %s [current: %s] — paste URL or clear for default", t.ID, func() string {
				if t.Endpoint == "" {
					return brokerDefaultEndpointForKind(t.Kind) + " (default)"
				}
				return t.Endpoint
			}()))
		}
	case 2:
		switch s {
		case "up", "k":
			a.brokerPolicyCursor--
		case "down", "j":
			a.brokerPolicyCursor++
		case "a", "A":
			group, poolName := "", ""
			if len(a.brokerPolicies) > 0 {
				cur := a.brokerPolicies[a.brokerPolicyCursor]
				group = strings.TrimSpace(cur.Group)
				poolName = strings.TrimSpace(cur.Pool)
			}
			if group == "" {
				ids := a.brokerGroupIDs()
				if len(ids) > 0 {
					group = ids[0]
				}
			}
			if strings.TrimSpace(group) == "" {
				a.addEvent("⚠ add group first (Groups tab: N)")
				break
			}
			if poolName == "" {
				names := a.brokerPoolNames()
				if len(names) > 0 {
					poolName = names[0]
				}
			}
			profile := brokerPolicyProfiles()[0]
			newName := a.brokerNextPolicyName()
			a.brokerPolicies = append(a.brokerPolicies, BrokerPolicy{
				Name:     newName,
				Group:    group,
				Pool:     poolName,
				Strategy: profile.Strategy,
				Sticky:   profile.Sticky,
				Retry:    profile.Retry,
			})
			a.brokerPolicyCursor = len(a.brokerPolicies) - 1
			a.brokerDirty = true
			a.addEvent(fmt.Sprintf("➕ broker policy added: %s", newName))
		case "d", "D":
			if len(a.brokerPolicies) > 1 {
				i := a.brokerPolicyCursor
				name := a.brokerPolicies[i].Name
				a.brokerPolicies = append(a.brokerPolicies[:i], a.brokerPolicies[i+1:]...)
				if a.brokerPolicyCursor >= len(a.brokerPolicies) {
					a.brokerPolicyCursor = len(a.brokerPolicies) - 1
				}
				a.brokerDirty = true
				a.addEvent(fmt.Sprintf("🗑 broker policy removed: %s", name))
			}
		case "left", "h":
			if a.brokerPolicyPoolCycle(a.brokerPolicyCursor, -1) {
				a.brokerDirty = true
			}
		case "right", "l":
			if a.brokerPolicyPoolCycle(a.brokerPolicyCursor, +1) {
				a.brokerDirty = true
			}
		case "g":
			if a.brokerPolicyGroupCycle(a.brokerPolicyCursor, +1) {
				a.brokerDirty = true
			}
		case "G":
			if a.brokerPolicyGroupCycle(a.brokerPolicyCursor, -1) {
				a.brokerDirty = true
			}
		case "o", "O":
			dir := +1
			if s == "O" {
				dir = -1
			}
			if profileName, changed := a.brokerPolicyProfileCycle(a.brokerPolicyCursor, dir); changed {
				a.brokerDirty = true
				if len(a.brokerPolicies) > 0 {
					a.addEvent(fmt.Sprintf("🎛 policy %s switched to profile %s", a.brokerPolicies[a.brokerPolicyCursor].Name, profileName))
				}
			}
		case "enter":
			if len(a.brokerPolicies) > 0 {
				strats := []string{"weighted_least_load", "round_robin", "least_error", "sticky_rr"}
				p := &a.brokerPolicies[a.brokerPolicyCursor]
				i := 0
				for x, v := range strats {
					if v == p.Strategy {
						i = x
						break
					}
				}
				p.Strategy = strats[(i+1)%len(strats)]
				a.brokerDirty = true
			}
		case "s":
			if len(a.brokerPolicies) > 0 {
				p := &a.brokerPolicies[a.brokerPolicyCursor]
				p.Sticky = !p.Sticky
				a.brokerDirty = true
			}
		case "r":
			if len(a.brokerPolicies) > 0 {
				p := &a.brokerPolicies[a.brokerPolicyCursor]
				p.Retry = (p.Retry + 1) % 3
				a.brokerDirty = true
			}
		}
	}
	a.clampBrokerCursors()
	return a, nil
}

func (a App) renderBrokerPanel() string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e"))
	blue := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#58a6ff"))
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("#27ae60"))
	yellow := lipgloss.NewStyle().Foreground(lipgloss.Color("#f1c40f"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("#e74c3c"))
	sel := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#c9d1d9")).Background(lipgloss.Color("#1f2f52"))

	var b strings.Builder
	title := "🧭 Token Broker ◆"
	if a.brokerDirty {
		title += yellow.Render(" draft modified")
	}
	b.WriteString(blue.Render(title) + "\n")

	tabs := []string{"1 Groups", "2 Pools", "3 Policy", "4 EEVDF", "5 Health", "6 Preview"}
	for i, t := range tabs {
		if i == a.brokerTab {
			b.WriteString(sel.Render(" " + t + " "))
		} else {
			b.WriteString(dim.Render(" " + t + " "))
		}
		if i < len(tabs)-1 {
			b.WriteString(" ")
		}
	}
	b.WriteString("\n\n")

	leftW, midW := 32, 40
	totalW := a.width - 8
	if totalW < 90 {
		totalW = 90
	}
	rightW := totalW - leftW - midW - 4
	if rightW < 24 {
		rightW = 24
	}

	var left strings.Builder
	left.WriteString("Groups\n")
	left.WriteString(dim.Render(strings.Repeat("─", leftW-1)) + "\n")
	for i, g := range a.brokerGroups {
		row := fmt.Sprintf("%s [%s] pool=%s w=%d", brokerGroupID(g), brokerGroupMatchRule(g), g.Pool, g.Weight)
		if len(row) > leftW-3 {
			row = row[:leftW-4] + "…"
		}
		if i == a.brokerGroupCursor {
			left.WriteString("▸ " + sel.Render(row) + "\n")
		} else {
			left.WriteString("  " + row + "\n")
		}
	}
	if len(a.brokerGroups) == 0 {
		left.WriteString(dim.Render("  (no groups) press N to add one") + "\n")
	}

	var mid strings.Builder
	pool := a.brokerCurrentPool()
	poolName := "-"
	if pool != nil {
		poolName = pool.Name
	}
	runtimeState, hasRuntime := a.brokerRuntimeSnapshot()
	runtimePool, hasRuntimePool := proxy.BrokerPoolState{}, false
	if hasRuntime && pool != nil {
		runtimePool, hasRuntimePool = brokerRuntimePoolByName(runtimeState, pool.Name)
	}
	mid.WriteString(fmt.Sprintf("Pool tokens (%s)\n", poolName))
	mid.WriteString(dim.Render(strings.Repeat("─", midW-1)) + "\n")
	if pool == nil || len(pool.Tokens) == 0 {
		mid.WriteString(dim.Render("  no tokens") + "\n")
	} else {
		for i, t := range pool.Tokens {
			state := "ok"
			if t.BreakerOpen {
				state = "breaker"
			}
			rt := ""
			if hasRuntimePool {
				if rtt, ok := brokerRuntimeTokenByID(runtimePool, t.ID); ok {
					rt = fmt.Sprintf(" rt=%.2f/%d", rtt.Health, rtt.RemainingRPH)
				}
			}
			row := fmt.Sprintf("%s h=%.2f rem=%d %s test=%s%s", t.ID, t.Health, t.RemainingRPH, state, t.LastTest, rt)
			if len(row) > midW-3 {
				row = row[:midW-4] + "…"
			}
			if i == a.brokerTokenCursor {
				mid.WriteString("▸ " + sel.Render(row) + "\n")
			} else {
				mid.WriteString("  " + row + "\n")
			}
		}
	}

	var right strings.Builder
	right.WriteString("Detail\n")
	right.WriteString(dim.Render(strings.Repeat("─", rightW-1)) + "\n")
	switch a.brokerTab {
	case 0:
		if len(a.brokerGroups) > 0 {
			g := a.brokerGroups[a.brokerGroupCursor]
			right.WriteString(fmt.Sprintf("Group ID: %s\nMatch rule: %s\nPool: %s\nWeight: %d\nRPH limit: %d\n", brokerGroupID(g), brokerGroupMatchRule(g), g.Pool, g.Weight, g.RPHLimit))
		} else {
			right.WriteString(dim.Render("No groups configured. Press N to create the first group.") + "\n")
		}
		right.WriteString("\nKeys: ←/→ pool, +/- weight, E edit-match, N add, D delete, X clear-all\n")
	case 1:
		endpoint := strings.TrimSpace(a.brokerExchangeEndpoint)
		if endpoint == "" {
			endpoint = brokerDefaultExchangeEndpoint()
		}
		right.WriteString(fmt.Sprintf("Exchange endpoint: %s\n\n", endpoint))
		if pool != nil && len(pool.Tokens) > 0 {
			t := pool.Tokens[a.brokerTokenCursor]
			flag := green.Render("enabled")
			if !t.Enabled {
				flag = red.Render("disabled")
			}
			ep := t.Endpoint
			if ep == "" {
				ep = brokerDefaultEndpointForKind(t.Kind) + " (default)"
			}
			right.WriteString(fmt.Sprintf("Token: %s\nKind: %s\nEndpoint: %s\nStatus: %s\nHealth: %.2f\nRemaining RPH: %d\nSession: %s\nLast test: %s\nPAT env: %s\nP95: %dms\n", t.ID, brokerKindLabel(t.Kind), ep, flag, t.Health, t.RemainingRPH, t.SessionState, t.LastTest, t.PATEnv, t.P95ms))
			if t.BreakerOpen {
				right.WriteString(red.Render("Breaker: open") + "\n")
			}
			if hasRuntimePool {
				if rt, ok := brokerRuntimeTokenByID(runtimePool, t.ID); ok {
					right.WriteString(dim.Render("Runtime snapshot:") + "\n")
					right.WriteString(fmt.Sprintf("  health=%.2f rem=%d session=%s test=%s p95=%dms\n", rt.Health, rt.RemainingRPH, rt.SessionState, rt.LastTest, rt.P95ms))
				}
			}
		} else if pool == nil {
			right.WriteString(dim.Render("No pools configured. Press N to add a pool first.") + "\n")
		}
		right.WriteString("\nKeys: N add-pool, Z del-pool, A add-token(ID+PAT), D del-token, Enter/X toggle, B breaker, F refresh, E set-token-env, G global-env, T test, R runtime-preview, V drift-check, W window, C clear-counters\n")
	case 2:
		for i, p := range a.brokerPolicies {
			row := fmt.Sprintf("%s: %s -> %s (%s/%s)", p.Name, p.Group, p.Pool, p.Strategy, brokerPolicyProfileLabel(p))
			if i == a.brokerPolicyCursor {
				right.WriteString("▸ " + sel.Render(row) + "\n")
			} else {
				right.WriteString("  " + row + "\n")
			}
		}
		if len(a.brokerPolicies) > 0 {
			p := a.brokerPolicies[a.brokerPolicyCursor]
			right.WriteString("\nSelected policy\n")
			right.WriteString(fmt.Sprintf("  name: %s\n  group: %s\n  pool: %s\n  profile: %s\n  strategy: %s\n  sticky: %t\n  retry: %d\n", p.Name, p.Group, p.Pool, brokerPolicyProfileLabel(p), p.Strategy, p.Sticky, p.Retry))
		}
		right.WriteString("\nKeys: A add, D delete, ←/→ pool, g/G group, O/o profile, Enter strategy, s sticky, r retry\n")
	case 3:
		for i, g := range a.brokerGroups {
			row := fmt.Sprintf("%s [%s] w=%d lag=%+.2f vdl=%.1f", brokerGroupID(g), brokerGroupMatchRule(g), g.Weight, g.Lag, g.VDL)
			if i == a.brokerGroupCursor {
				right.WriteString("▸ " + sel.Render(row) + "\n")
			} else {
				right.WriteString("  " + row + "\n")
			}
		}
		if len(a.brokerGroups) == 0 {
			right.WriteString(dim.Render("No groups configured. Press N to bootstrap.") + "\n")
		}
		right.WriteString("\nKeys: +/- weight, ←/→ pool mapping, X clear-all\n")
	case 4:
		right.WriteString("Draft pools:\n")
		for _, p := range a.brokerPools {
			right.WriteString(fmt.Sprintf("%s\n", p.Name))
			for _, t := range p.Tokens {
				s := green.Render("healthy")
				if t.BreakerOpen || t.Health < 0.7 {
					s = red.Render("risk")
				}
				right.WriteString(fmt.Sprintf("  - %-8s %s h=%.2f rem=%d\n", t.ID, s, t.Health, t.RemainingRPH))
			}
		}
		if hasRuntime {
			right.WriteString("\nRuntime pools (proxy):\n")
			for _, rp := range runtimeState.Pools {
				right.WriteString(fmt.Sprintf("%s\n", rp.Name))
				for _, rt := range rp.Tokens {
					rs := green.Render("healthy")
					if rt.BreakerOpen || rt.Health < 0.7 {
						rs = red.Render("risk")
					}
					right.WriteString(fmt.Sprintf("  - %-8s %s h=%.2f rem=%d state=%s\n", rt.ID, rs, rt.Health, rt.RemainingRPH, rt.SessionState))
				}
			}
			if counters, ok := a.brokerRuntimeCounters(); ok && len(counters) > 0 {
				right.WriteString("\nRuntime counters (all-time):\n")
				for _, line := range brokerTopCounters(counters, "", 8) {
					right.WriteString("  " + line + "\n")
				}
			}
			window := a.brokerActiveCounterWindow()
			if countersWindow, ok := a.brokerRuntimeCountersWindow(window.Duration); ok && len(countersWindow) > 0 {
				right.WriteString(fmt.Sprintf("Runtime counters (last %s):\n", window.Label))
				for _, line := range brokerTopCounters(countersWindow, "", 8) {
					right.WriteString("  " + line + "\n")
				}
				for _, line := range brokerTopCounters(countersWindow, "group.", 6) {
					right.WriteString("  " + line + "\n")
				}
			}
		} else {
			right.WriteString("\nRuntime pools (proxy): unavailable\n")
		}
	case 5:
		right.WriteString("Draft diff:\n")
		for _, l := range a.brokerDiffLines {
			right.WriteString("  • " + l + "\n")
		}
		right.WriteString("\nPreview:\n")
		for _, l := range a.brokerPreviewLines {
			right.WriteString("- " + l + "\n")
		}
		right.WriteString("\nPress P to refresh simulation, R for runtime preview, V for drift check, W to switch counter window, C to clear counters.\n")
	}

	// Live RPH summary from current inference stats (if proxy active)
	if globalProxyServer != nil {
		stats := globalProxyServer.InferenceStats()
		if stats != nil {
			models := stats.GetModelStats()
			if len(models) > 0 {
				sort.Slice(models, func(i, j int) bool { return models[i].RPH > models[j].RPH })
				right.WriteString("\n" + dim.Render(strings.Repeat("─", rightW-1)) + "\n")
				right.WriteString("Live model RPH:\n")
				maxShow := 4
				if len(models) < maxShow {
					maxShow = len(models)
				}
				for i := 0; i < maxShow; i++ {
					ms := models[i]
					limit := "-"
					if ms.RPHLimit > 0 {
						limit = fmt.Sprintf("/%d", ms.RPHLimit)
					}
					right.WriteString(fmt.Sprintf("  %s: %d%s\n", ms.Model, ms.RPH, limit))
				}
			}
		}
	}

	leftLines := strings.Split(strings.TrimRight(left.String(), "\n"), "\n")
	midLines := strings.Split(strings.TrimRight(mid.String(), "\n"), "\n")
	rightLines := strings.Split(strings.TrimRight(right.String(), "\n"), "\n")
	maxN := len(leftLines)
	if len(midLines) > maxN {
		maxN = len(midLines)
	}
	if len(rightLines) > maxN {
		maxN = len(rightLines)
	}
	for i := 0; i < maxN; i++ {
		l, m, r := "", "", ""
		if i < len(leftLines) {
			l = leftLines[i]
		}
		if i < len(midLines) {
			m = midLines[i]
		}
		if i < len(rightLines) {
			r = rightLines[i]
		}
		b.WriteString(lipgloss.NewStyle().Width(leftW).Render(l) + dim.Render("│") + " ")
		b.WriteString(lipgloss.NewStyle().Width(midW).Render(m) + dim.Render("│") + " ")
		b.WriteString(r + "\n")
	}

	b.WriteString("\n")
	if a.brokerApplyConfirm {
		b.WriteString(red.Render("⚠ Apply broker draft changes now? (y/n)") + "\n")
	}
	if a.brokerClearGroupsConfirm {
		b.WriteString(red.Render("⚠ Clear ALL groups now? Policies will be cleared too. (y/n)") + "\n")
	}
	if a.brokerDirty {
		b.WriteString(yellow.Render("⚠ Draft pending. Use P preview, S apply, or U rollback.") + "\n")
	} else {
		b.WriteString(green.Render("✓ Applied state is in sync.") + "\n")
	}
	return b.String()
}
