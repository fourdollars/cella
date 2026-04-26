package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"github.com/fourdoors/cella/internal/proxy"
)

func (a *App) brokerBuildPreview() []string {
	lines := []string{"Impact preview (10m simulation):"}
	for _, g := range a.brokerGroups {
		delta := g.Weight*3 - 2
		sign := "+"
		if delta < 0 {
			sign = ""
		}
		lines = append(lines, fmt.Sprintf("- %s (match %s) throughput %s%d%% (cap %d RPH, pool %s)", brokerGroupID(g), brokerGroupMatchRule(g), sign, delta, g.RPHLimit, g.Pool))
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
	endpoint := strings.TrimSpace(a.brokerExchangeEndpoint)
	if endpoint == "" {
		endpoint = brokerDefaultExchangeEndpoint()
	}
	lines = append(lines, fmt.Sprintf("- exchange endpoint: %s", endpoint))
	lines = append(lines, "Note: apply updates runtime broker state via TUI (no manual config editing).")
	return lines
}

func (a *App) brokerBuildDiffAgainstApplied() []string {
	if a.brokerLastApplied == nil {
		return []string{"No applied baseline; first apply will create baseline."}
	}
	base := a.brokerLastApplied
	out := []string{}
	if len(a.brokerGroups) != len(base.Groups) {
		out = append(out, fmt.Sprintf("groups: %d -> %d", len(base.Groups), len(a.brokerGroups)))
	}
	for i := 0; i < len(a.brokerGroups) && i < len(base.Groups); i++ {
		cur, old := a.brokerGroups[i], base.Groups[i]
		curID, oldID := brokerGroupID(cur), brokerGroupID(old)
		curMatch, oldMatch := brokerGroupMatchRule(cur), brokerGroupMatchRule(old)
		if curID != oldID || curMatch != oldMatch || cur.Pool != old.Pool || cur.Weight != old.Weight || cur.RPHLimit != old.RPHLimit {
			out = append(out, fmt.Sprintf("group %s: match %s→%s, pool %s→%s, weight %d→%d, rph %d→%d",
				curID, oldMatch, curMatch, old.Pool, cur.Pool, old.Weight, cur.Weight, old.RPHLimit, cur.RPHLimit))
		}
	}
	if len(a.brokerPools) != len(base.Pools) {
		out = append(out, fmt.Sprintf("pools: %d -> %d", len(base.Pools), len(a.brokerPools)))
	}
	if len(a.brokerPolicies) != len(base.Policies) {
		out = append(out, fmt.Sprintf("policies: %d -> %d", len(base.Policies), len(a.brokerPolicies)))
	}
	for i := 0; i < len(a.brokerPolicies) && i < len(base.Policies); i++ {
		cur, old := a.brokerPolicies[i], base.Policies[i]
		if cur.Group != old.Group || cur.Strategy != old.Strategy || cur.Sticky != old.Sticky || cur.Retry != old.Retry || cur.Pool != old.Pool {
			out = append(out, fmt.Sprintf("policy %s: group %s→%s, strategy %s→%s, sticky %t→%t, retry %d→%d, pool %s→%s",
				cur.Name, old.Group, cur.Group, old.Strategy, cur.Strategy, old.Sticky, cur.Sticky, old.Retry, cur.Retry, old.Pool, cur.Pool))
		}
	}
	if len(out) == 0 {
		out = append(out, "No effective changes detected.")
	}
	return out
}

func brokerCounterWindowOptions() []brokerCounterWindowOption {
	return []brokerCounterWindowOption{
		{Label: "5m", Duration: 5 * time.Minute},
		{Label: "15m", Duration: 15 * time.Minute},
		{Label: "1h", Duration: 1 * time.Hour},
	}
}

func (a *App) brokerActiveCounterWindow() brokerCounterWindowOption {
	opts := brokerCounterWindowOptions()
	if len(opts) == 0 {
		return brokerCounterWindowOption{Label: "5m", Duration: 5 * time.Minute}
	}
	idx := a.brokerCounterWindowIdx
	if idx < 0 {
		idx = 0
	}
	idx = idx % len(opts)
	return opts[idx]
}

func (a *App) brokerCycleCounterWindow() brokerCounterWindowOption {
	opts := brokerCounterWindowOptions()
	if len(opts) == 0 {
		return brokerCounterWindowOption{Label: "5m", Duration: 5 * time.Minute}
	}
	a.brokerCounterWindowIdx = (a.brokerCounterWindowIdx + 1) % len(opts)
	return a.brokerActiveCounterWindow()
}

func brokerRuntimePoolByName(st proxy.BrokerState, poolName string) (proxy.BrokerPoolState, bool) {
	for _, p := range st.Pools {
		if p.Name == poolName {
			return p, true
		}
	}
	return proxy.BrokerPoolState{}, false
}

func brokerRuntimeTokenByID(p proxy.BrokerPoolState, tokenID string) (proxy.BrokerTokenState, bool) {
	for _, t := range p.Tokens {
		if t.ID == tokenID {
			return t, true
		}
	}
	return proxy.BrokerTokenState{}, false
}

func brokerTopCounters(counters map[string]int64, prefix string, maxShow int) []string {
	type kv struct {
		k string
		v int64
	}
	arr := make([]kv, 0, len(counters))
	for k, v := range counters {
		if strings.TrimSpace(prefix) != "" && !strings.HasPrefix(k, prefix) {
			continue
		}
		arr = append(arr, kv{k: k, v: v})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].v != arr[j].v {
			return arr[i].v > arr[j].v
		}
		return arr[i].k < arr[j].k
	})
	if maxShow > 0 && len(arr) > maxShow {
		arr = arr[:maxShow]
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		out = append(out, fmt.Sprintf("%s=%d", item.k, item.v))
	}
	return out
}

func (a *App) brokerBuildRuntimePreview() []string {
	st, ok := a.brokerRuntimeSnapshot()
	if !ok {
		return []string{"Runtime broker state unavailable (proxy not active)."}
	}
	lines := []string{fmt.Sprintf("Runtime broker state: groups=%d pools=%d", len(st.Groups), len(st.Pools))}
	if counters, ok := a.brokerRuntimeCounters(); ok {
		topAll := brokerTopCounters(counters, "", 6)
		if len(topAll) > 0 {
			lines = append(lines, "Runtime counters (all-time):")
			for _, line := range topAll {
				lines = append(lines, "- "+line)
			}
		}
		topGroup := brokerTopCounters(counters, "group.", 6)
		if len(topGroup) > 0 {
			lines = append(lines, "Group counters (all-time):")
			for _, line := range topGroup {
				lines = append(lines, "- "+line)
			}
		}
	}
	window := a.brokerActiveCounterWindow()
	if countersWindow, ok := a.brokerRuntimeCountersWindow(window.Duration); ok {
		topWindow := brokerTopCounters(countersWindow, "", 6)
		if len(topWindow) > 0 {
			lines = append(lines, fmt.Sprintf("Runtime counters (last %s):", window.Label))
			for _, line := range topWindow {
				lines = append(lines, "- "+line)
			}
		}
		topWindowGroup := brokerTopCounters(countersWindow, "group.", 6)
		if len(topWindowGroup) > 0 {
			lines = append(lines, fmt.Sprintf("Group counters (last %s):", window.Label))
			for _, line := range topWindowGroup {
				lines = append(lines, "- "+line)
			}
		}
	}
	pool := a.brokerCurrentPool()
	if pool == nil {
		return lines
	}
	rp, found := brokerRuntimePoolByName(st, pool.Name)
	if !found {
		lines = append(lines, fmt.Sprintf("Pool %s not found in runtime snapshot.", pool.Name))
		return lines
	}
	lines = append(lines, fmt.Sprintf("Pool %s runtime tokens: %d", rp.Name, len(rp.Tokens)))
	for i, t := range rp.Tokens {
		if i >= 4 {
			break
		}
		lines = append(lines, fmt.Sprintf("- %s h=%.2f rem=%d state=%s test=%s", t.ID, t.Health, t.RemainingRPH, t.SessionState, t.LastTest))
	}
	return lines
}

func (a *App) brokerBuildRuntimeDrift() []string {
	a.normalizeBrokerGroupsAndPolicies()
	st, ok := a.brokerRuntimeSnapshot()
	if !ok {
		return []string{"Runtime drift unavailable (proxy not active)."}
	}

	drift := []string{}
	draftEndpoint := strings.TrimSpace(a.brokerExchangeEndpoint)
	if draftEndpoint == "" {
		draftEndpoint = brokerDefaultExchangeEndpoint()
	}
	runtimeEndpoint := strings.TrimSpace(st.ExchangeEndpoint)
	if runtimeEndpoint == "" {
		runtimeEndpoint = brokerDefaultExchangeEndpoint()
	}
	if !strings.EqualFold(draftEndpoint, runtimeEndpoint) {
		drift = append(drift, fmt.Sprintf("exchange endpoint draft=%s runtime=%s", draftEndpoint, runtimeEndpoint))
	}

	draftGroups := make(map[string]BrokerGroup)
	for _, g := range a.brokerGroups {
		draftGroups[brokerGroupID(g)] = g
	}
	runtimeGroups := make(map[string]proxy.BrokerGroupState)
	for _, g := range st.Groups {
		runtimeGroups[brokerRuntimeGroupID(g)] = g
	}
	groupIDs := make([]string, 0, len(draftGroups)+len(runtimeGroups))
	seenGroup := make(map[string]bool)
	for id := range draftGroups {
		if id == "" {
			continue
		}
		groupIDs = append(groupIDs, id)
		seenGroup[id] = true
	}
	for id := range runtimeGroups {
		if id == "" || seenGroup[id] {
			continue
		}
		groupIDs = append(groupIDs, id)
	}
	sort.Strings(groupIDs)
	for _, id := range groupIDs {
		dg, dok := draftGroups[id]
		rg, rok := runtimeGroups[id]
		switch {
		case dok && !rok:
			drift = append(drift, fmt.Sprintf("group %s missing in runtime", id))
		case !dok && rok:
			drift = append(drift, fmt.Sprintf("group %s exists only in runtime", id))
		default:
			dMatch := brokerGroupMatchRule(dg)
			rMatch := brokerRuntimeGroupMatchRule(rg)
			if dMatch != rMatch || dg.Pool != rg.Pool || dg.Weight != rg.Weight || dg.RPHLimit != rg.RPHLimit {
				drift = append(drift, fmt.Sprintf("group %s draft(match=%s pool=%s w=%d rph=%d) runtime(match=%s pool=%s w=%d rph=%d)",
					id, dMatch, dg.Pool, dg.Weight, dg.RPHLimit, rMatch, rg.Pool, rg.Weight, rg.RPHLimit))
			}
		}
	}

	draftPools := make(map[string]BrokerPool)
	for _, p := range a.brokerPools {
		draftPools[p.Name] = p
	}
	runtimePools := make(map[string]proxy.BrokerPoolState)
	for _, p := range st.Pools {
		runtimePools[p.Name] = p
	}
	poolNames := make([]string, 0, len(draftPools)+len(runtimePools))
	seenPool := make(map[string]bool)
	for name := range draftPools {
		if strings.TrimSpace(name) == "" {
			continue
		}
		poolNames = append(poolNames, name)
		seenPool[name] = true
	}
	for name := range runtimePools {
		if strings.TrimSpace(name) == "" || seenPool[name] {
			continue
		}
		poolNames = append(poolNames, name)
	}
	sort.Strings(poolNames)
	for _, name := range poolNames {
		dp, dok := draftPools[name]
		rp, rok := runtimePools[name]
		switch {
		case dok && !rok:
			drift = append(drift, fmt.Sprintf("pool %s missing in runtime", name))
		case !dok && rok:
			drift = append(drift, fmt.Sprintf("pool %s exists only in runtime", name))
		default:
			dIDs := strings.Join(brokerSortedDraftTokenIDs(dp.Tokens), ",")
			rIDs := strings.Join(brokerSortedRuntimeTokenIDs(rp.Tokens), ",")
			if dIDs != rIDs {
				drift = append(drift, fmt.Sprintf("pool %s token-set draft=[%s] runtime=[%s]", name, dIDs, rIDs))
			}
		}
	}

	draftPolicies := make(map[string]BrokerPolicy)
	for _, p := range a.brokerPolicies {
		draftPolicies[p.Name] = p
	}
	runtimePolicies := make(map[string]proxy.BrokerPolicyState)
	for _, p := range st.Policies {
		runtimePolicies[p.Name] = p
	}
	policyNames := make([]string, 0, len(draftPolicies)+len(runtimePolicies))
	seenPolicy := make(map[string]bool)
	for name := range draftPolicies {
		if strings.TrimSpace(name) == "" {
			continue
		}
		policyNames = append(policyNames, name)
		seenPolicy[name] = true
	}
	for name := range runtimePolicies {
		if strings.TrimSpace(name) == "" || seenPolicy[name] {
			continue
		}
		policyNames = append(policyNames, name)
	}
	sort.Strings(policyNames)
	for _, name := range policyNames {
		dp, dok := draftPolicies[name]
		rp, rok := runtimePolicies[name]
		switch {
		case dok && !rok:
			drift = append(drift, fmt.Sprintf("policy %s missing in runtime", name))
		case !dok && rok:
			drift = append(drift, fmt.Sprintf("policy %s exists only in runtime", name))
		default:
			if dp.Group != rp.Group || dp.Pool != rp.Pool || dp.Strategy != rp.Strategy || dp.Sticky != rp.Sticky || dp.Retry != rp.Retry {
				drift = append(drift, fmt.Sprintf("policy %s draft(group=%s pool=%s strategy=%s sticky=%t retry=%d) runtime(group=%s pool=%s strategy=%s sticky=%t retry=%d)",
					name, dp.Group, dp.Pool, dp.Strategy, dp.Sticky, dp.Retry, rp.Group, rp.Pool, rp.Strategy, rp.Sticky, rp.Retry))
			}
		}
	}

	lines := []string{fmt.Sprintf("Runtime drift check: draft groups=%d runtime groups=%d", len(a.brokerGroups), len(st.Groups))}
	if len(drift) == 0 {
		lines = append(lines, "No drift detected between draft and runtime policy views.")
		return lines
	}
	lines = append(lines, fmt.Sprintf("Drift detected: %d item(s)", len(drift)))
	for _, d := range drift {
		lines = append(lines, "- "+d)
	}
	return lines
}
