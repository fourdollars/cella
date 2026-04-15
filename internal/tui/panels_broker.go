package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type BrokerGroup struct {
	Name     string
	Pool     string
	Weight   int
	RPHLimit int
	Lag      float64
	VDL      float64
}

type BrokerToken struct {
	ID           string
	Enabled      bool
	Health       float64
	RemainingRPH int
	BreakerOpen  bool
	SessionState string
	P95ms        int
}

type BrokerPool struct {
	Name   string
	Tokens []BrokerToken
}

type BrokerPolicy struct {
	Name     string
	Group    string
	Pool     string
	Strategy string
	Sticky   bool
	Retry    int
}

type BrokerSnapshot struct {
	Groups   []BrokerGroup
	Pools    []BrokerPool
	Policies []BrokerPolicy
}

func (a *App) initBrokerDefaults() {
	if len(a.brokerGroups) > 0 {
		return
	}
	a.brokerGroups = []BrokerGroup{
		{Name: "team-a", Pool: "pool_alpha", Weight: 2, RPHLimit: 5000, Lag: -0.18, VDL: 12.4},
		{Name: "team-b", Pool: "pool_beta", Weight: 1, RPHLimit: 5000, Lag: +0.21, VDL: 10.1},
		{Name: "ci", Pool: "pool_ci", Weight: 1, RPHLimit: 1500, Lag: -0.03, VDL: 13.2},
	}
	a.brokerPools = []BrokerPool{
		{Name: "pool_alpha", Tokens: []BrokerToken{{ID: "tok_a1", Enabled: true, Health: 0.93, RemainingRPH: 880, SessionState: "fresh", P95ms: 320}, {ID: "tok_a2", Enabled: true, Health: 0.87, RemainingRPH: 740, SessionState: "fresh", P95ms: 350}, {ID: "tok_a3", Enabled: true, Health: 0.64, RemainingRPH: 210, BreakerOpen: true, SessionState: "stale", P95ms: 490}}},
		{Name: "pool_beta", Tokens: []BrokerToken{{ID: "tok_b1", Enabled: true, Health: 0.91, RemainingRPH: 920, SessionState: "fresh", P95ms: 300}, {ID: "tok_b2", Enabled: true, Health: 0.78, RemainingRPH: 510, SessionState: "fresh", P95ms: 370}}},
		{Name: "pool_ci", Tokens: []BrokerToken{{ID: "tok_ci1", Enabled: true, Health: 0.89, RemainingRPH: 420, SessionState: "fresh", P95ms: 330}}},
	}
	a.brokerPolicies = []BrokerPolicy{
		{Name: "policy_a", Group: "team-a", Pool: "pool_alpha", Strategy: "weighted_least_load", Sticky: true, Retry: 1},
		{Name: "policy_b", Group: "team-b", Pool: "pool_beta", Strategy: "weighted_least_load", Sticky: false, Retry: 1},
		{Name: "policy_ci", Group: "ci", Pool: "pool_ci", Strategy: "round_robin", Sticky: false, Retry: 0},
	}
	a.brokerPreviewLines = []string{"Preview not generated. Press P to simulate."}
	s := a.captureBrokerSnapshot()
	a.brokerLastApplied = &s
}

func (a *App) captureBrokerSnapshot() BrokerSnapshot {
	gs := append([]BrokerGroup(nil), a.brokerGroups...)
	ps := make([]BrokerPool, len(a.brokerPools))
	for i, p := range a.brokerPools {
		ps[i] = BrokerPool{Name: p.Name, Tokens: append([]BrokerToken(nil), p.Tokens...)}
	}
	pol := append([]BrokerPolicy(nil), a.brokerPolicies...)
	return BrokerSnapshot{Groups: gs, Pools: ps, Policies: pol}
}

func (a *App) restoreBrokerSnapshot(s BrokerSnapshot) {
	a.brokerGroups = append([]BrokerGroup(nil), s.Groups...)
	a.brokerPools = make([]BrokerPool, len(s.Pools))
	for i, p := range s.Pools {
		a.brokerPools[i] = BrokerPool{Name: p.Name, Tokens: append([]BrokerToken(nil), p.Tokens...)}
	}
	a.brokerPolicies = append([]BrokerPolicy(nil), s.Policies...)
	a.clampBrokerCursors()
}

func (a *App) clampBrokerCursors() {
	if len(a.brokerGroups) == 0 {
		a.brokerGroupCursor = 0
	} else {
		if a.brokerGroupCursor < 0 {
			a.brokerGroupCursor = 0
		}
		if a.brokerGroupCursor >= len(a.brokerGroups) {
			a.brokerGroupCursor = len(a.brokerGroups) - 1
		}
	}
	pool := a.brokerCurrentPool()
	if pool == nil || len(pool.Tokens) == 0 {
		a.brokerTokenCursor = 0
	} else {
		if a.brokerTokenCursor < 0 {
			a.brokerTokenCursor = 0
		}
		if a.brokerTokenCursor >= len(pool.Tokens) {
			a.brokerTokenCursor = len(pool.Tokens) - 1
		}
	}
	if len(a.brokerPolicies) == 0 {
		a.brokerPolicyCursor = 0
	} else {
		if a.brokerPolicyCursor < 0 {
			a.brokerPolicyCursor = 0
		}
		if a.brokerPolicyCursor >= len(a.brokerPolicies) {
			a.brokerPolicyCursor = len(a.brokerPolicies) - 1
		}
	}
}

func (a *App) brokerCurrentPool() *BrokerPool {
	if len(a.brokerGroups) == 0 {
		return nil
	}
	poolName := a.brokerGroups[a.brokerGroupCursor].Pool
	for i := range a.brokerPools {
		if a.brokerPools[i].Name == poolName {
			return &a.brokerPools[i]
		}
	}
	if len(a.brokerPools) == 0 {
		return nil
	}
	return &a.brokerPools[0]
}

func (a *App) brokerPoolIndexByName(name string) int {
	for i := range a.brokerPools {
		if a.brokerPools[i].Name == name {
			return i
		}
	}
	return -1
}

func (a *App) brokerCycleGroupPool(dir int) {
	if len(a.brokerGroups) == 0 || len(a.brokerPools) == 0 {
		return
	}
	g := &a.brokerGroups[a.brokerGroupCursor]
	i := a.brokerPoolIndexByName(g.Pool)
	if i < 0 {
		i = 0
	}
	i = (i + dir + len(a.brokerPools)) % len(a.brokerPools)
	g.Pool = a.brokerPools[i].Name
	a.brokerDirty = true
}

func (a *App) brokerBuildPreview() []string {
	lines := []string{"Impact preview (10m simulation):"}
	for _, g := range a.brokerGroups {
		delta := g.Weight*3 - 2
		sign := "+"
		if delta < 0 {
			sign = ""
		}
		lines = append(lines, fmt.Sprintf("- %s throughput %s%d%% (cap %d RPH, pool %s)", g.Name, sign, delta, g.RPHLimit, g.Pool))
	}
	if p := a.brokerCurrentPool(); p != nil {
		warn := 0
		for _, t := range p.Tokens {
			if t.BreakerOpen || t.Health < 0.7 || t.RemainingRPH < 200 {
				warn++
			}
		}
		lines = append(lines, fmt.Sprintf("- pool %s risk tokens: %d", p.Name, warn))
	}
	lines = append(lines, "Note: apply updates runtime broker state via TUI (no manual config editing).")
	return lines
}

func (a *App) handleBrokerPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	a.clampBrokerCursors()
	s := msg.String()
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
	case "S":
		snap := a.captureBrokerSnapshot()
		a.brokerLastApplied = &snap
		a.brokerDirty = false
		a.addEvent("✅ token broker draft applied")
		return a, nil
	case "U":
		if a.brokerLastApplied != nil {
			a.restoreBrokerSnapshot(*a.brokerLastApplied)
			a.brokerDirty = false
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
			a.brokerGroups = append(a.brokerGroups, BrokerGroup{Name: fmt.Sprintf("group-%d", len(a.brokerGroups)+1), Pool: pool, Weight: 1, RPHLimit: 1000})
			a.brokerGroupCursor = len(a.brokerGroups) - 1
			a.brokerDirty = true
		case "d", "D":
			if len(a.brokerGroups) > 1 {
				i := a.brokerGroupCursor
				a.brokerGroups = append(a.brokerGroups[:i], a.brokerGroups[i+1:]...)
				a.brokerDirty = true
			}
		}
	case 1, 4:
		pool := a.brokerCurrentPool()
		if pool == nil || len(pool.Tokens) == 0 {
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
		}
	case 2:
		switch s {
		case "up", "k":
			a.brokerPolicyCursor--
		case "down", "j":
			a.brokerPolicyCursor++
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
		case "r", "R":
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
		row := fmt.Sprintf("%s  pool=%s  w=%d", g.Name, g.Pool, g.Weight)
		if len(row) > leftW-3 {
			row = row[:leftW-4] + "…"
		}
		if i == a.brokerGroupCursor {
			left.WriteString("▸ " + sel.Render(row) + "\n")
		} else {
			left.WriteString("  " + row + "\n")
		}
	}

	var mid strings.Builder
	pool := a.brokerCurrentPool()
	poolName := "-"
	if pool != nil {
		poolName = pool.Name
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
			row := fmt.Sprintf("%s h=%.2f rem=%d %s", t.ID, t.Health, t.RemainingRPH, state)
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
			right.WriteString(fmt.Sprintf("Group: %s\nPool: %s\nWeight: %d\nRPH limit: %d\n", g.Name, g.Pool, g.Weight, g.RPHLimit))
		}
		right.WriteString("\nKeys: ←/→ pool, +/- weight, N add, D delete\n")
	case 1:
		if pool != nil && len(pool.Tokens) > 0 {
			t := pool.Tokens[a.brokerTokenCursor]
			flag := green.Render("enabled")
			if !t.Enabled {
				flag = red.Render("disabled")
			}
			right.WriteString(fmt.Sprintf("Token: %s\nStatus: %s\nHealth: %.2f\nRemaining RPH: %d\nSession: %s\nP95: %dms\n", t.ID, flag, t.Health, t.RemainingRPH, t.SessionState, t.P95ms))
			if t.BreakerOpen {
				right.WriteString(red.Render("Breaker: open") + "\n")
			}
		}
		right.WriteString("\nKeys: Enter/X toggle, B breaker, F refresh\n")
	case 2:
		for i, p := range a.brokerPolicies {
			row := fmt.Sprintf("%s: %s -> %s (%s)", p.Name, p.Group, p.Pool, p.Strategy)
			if i == a.brokerPolicyCursor {
				right.WriteString("▸ " + sel.Render(row) + "\n")
			} else {
				right.WriteString("  " + row + "\n")
			}
		}
		right.WriteString("\nKeys: Enter cycle strategy, s sticky, r retry\n")
	case 3:
		for i, g := range a.brokerGroups {
			row := fmt.Sprintf("%s w=%d lag=%+.2f vdl=%.1f", g.Name, g.Weight, g.Lag, g.VDL)
			if i == a.brokerGroupCursor {
				right.WriteString("▸ " + sel.Render(row) + "\n")
			} else {
				right.WriteString("  " + row + "\n")
			}
		}
		right.WriteString("\nKeys: +/- weight, ←/→ pool mapping\n")
	case 4:
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
	case 5:
		for _, l := range a.brokerPreviewLines {
			right.WriteString("- " + l + "\n")
		}
		right.WriteString("\nPress P to refresh simulation.\n")
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
	if a.brokerDirty {
		b.WriteString(yellow.Render("⚠ Draft pending. Use P preview, S apply, or U rollback.") + "\n")
	} else {
		b.WriteString(green.Render("✓ Applied state is in sync.") + "\n")
	}
	return b.String()
}
