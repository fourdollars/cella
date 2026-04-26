package tui

import (
	"encoding/json"
	"fmt"
	"github.com/fourdoors/cella/internal/proxy"
	"net/http"
	"os"
	"strings"
	"time"
)

func (a *App) brokerTestExchangeToken(t *BrokerToken) {
	a.brokerTestExchangeTokenReal(t)
}

func brokerSuggestedPATEnv(tokenID string) string {
	n := strings.ToUpper(tokenID)
	n = strings.ReplaceAll(n, "-", "_")
	n = strings.ReplaceAll(n, ".", "_")
	n = strings.ReplaceAll(n, " ", "_")
	if n == "" {
		n = "TOKEN"
	}
	return "CELLA_BROKER_PAT_" + n
}

// brokerDefaultEndpointForKind returns the default upstream endpoint for a token kind.

func brokerDefaultEndpointForKind(kind string) string {
	switch kind {
	case "gemini":
		return "https://generativelanguage.googleapis.com"
	case "openai":
		return "https://api.openai.com"
	default: // copilot
		return "https://api.github.com/copilot_internal/v2/token"
	}
}

// brokerDetectTokenKind infers the token kind from its value prefix.
// Returns "" (auto) if no prefix matches — proxy will also auto-detect at runtime.

func brokerDetectTokenKind(pat string) string {
	switch {
	case strings.HasPrefix(pat, "ghu_"):
		return "copilot"
	case strings.HasPrefix(pat, "AIza"):
		return "gemini"
	case strings.HasPrefix(pat, "sk-"):
		return "openai"
	default:
		return ""
	}
}

// brokerKindLabel returns a human-readable label for a token kind.

func brokerKindLabel(kind string) string {
	switch kind {
	case "copilot":
		return "Copilot (GitHub PAT → exchange)"
	case "gemini":
		return "Gemini (API key → x-goog-api-key)"
	case "openai":
		return "OpenAI-compat (API key → Bearer)"
	default:
		return "auto-detect"
	}
}

func (a *App) brokerResolvePAT(t *BrokerToken) (pat string, sourceEnv string) {
	if t != nil {
		key := strings.TrimSpace(t.PATEnv)
		if key != "" {
			if v := strings.TrimSpace(os.Getenv(key)); v != "" {
				return v, key
			}
			return "", key
		}
	}
	fallback := "CELLA_BROKER_TEST_PAT"
	return strings.TrimSpace(os.Getenv(fallback)), fallback
}

func (a *App) brokerTestExchangeTokenReal(t *BrokerToken) {
	if !t.Enabled {
		t.LastTest = "fail"
		t.SessionState = "disabled"
		a.addEvent(fmt.Sprintf("❌ real exchange test failed for %s: token disabled", t.ID))
		return
	}
	pat, sourceEnv := a.brokerResolvePAT(t)
	if pat == "" {
		t.LastTest = "fail"
		t.SessionState = "real-no-pat"
		a.addEvent(fmt.Sprintf("❌ real exchange test failed: PAT env %s is empty", sourceEnv))
		if t.Health > 0.05 {
			t.Health -= 0.05
		}
		return
	}
	if sourceEnv != "" {
		a.addEvent(fmt.Sprintf("🔑 real exchange using PAT from %s", sourceEnv))
	}
	endpoint := strings.TrimSpace(a.brokerExchangeEndpoint)
	if endpoint == "" {
		endpoint = brokerDefaultExchangeEndpoint()
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		t.LastTest = "fail"
		t.SessionState = "real-req-error"
		a.addEvent(fmt.Sprintf("❌ real exchange test req error: %v", err))
		return
	}
	req.Header.Set("Authorization", "Bearer "+pat)
	req.Header.Set("editor-version", "vscode/1.87.0")
	req.Header.Set("editor-plugin-version", "copilot/1.155.0")
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.LastTest = "fail"
		t.SessionState = "real-http-error"
		a.addEvent(fmt.Sprintf("❌ real exchange test http error: %v", err))
		if t.Health > 0.05 {
			t.Health -= 0.05
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.LastTest = "fail"
		t.SessionState = fmt.Sprintf("real-%d", resp.StatusCode)
		a.addEvent(fmt.Sprintf("❌ real exchange test failed: status %d", resp.StatusCode))
		if t.Health > 0.05 {
			t.Health -= 0.05
		}
		return
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.LastTest = "fail"
		t.SessionState = "real-decode-error"
		a.addEvent(fmt.Sprintf("❌ real exchange decode failed: %v", err))
		if t.Health > 0.05 {
			t.Health -= 0.05
		}
		return
	}
	tok, _ := payload["token"].(string)
	if strings.TrimSpace(tok) == "" {
		t.LastTest = "fail"
		t.SessionState = "real-empty-token"
		a.addEvent("❌ real exchange test failed: empty token in response")
		if t.Health > 0.05 {
			t.Health -= 0.05
		}
		return
	}
	t.LastTest = "ok"
	t.SessionState = "tested-ok-real"
	if t.Health < 0.98 {
		t.Health += 0.03
	}
	a.addEvent(fmt.Sprintf("✅ real exchange test passed for %s", t.ID))
}

func (a *App) brokerSyncRuntimeState() {
	if globalProxyServer == nil {
		a.addEvent("ℹ token broker applied (proxy runtime not active; sync skipped)")
		return
	}
	state := a.brokerRuntimeState()
	globalProxyServer.SetBrokerState(state)
	a.addEvent(fmt.Sprintf("✅ token broker runtime synced: groups=%d pools=%d", len(state.Groups), len(state.Pools)))
}

func (a *App) brokerRuntimeSnapshot() (proxy.BrokerState, bool) {
	if globalProxyServer == nil {
		return proxy.BrokerState{}, false
	}
	return globalProxyServer.BrokerState(), true
}

func (a *App) brokerRuntimeCounters() (map[string]int64, bool) {
	if globalProxyServer == nil {
		return nil, false
	}
	return globalProxyServer.BrokerCounters(), true
}

func (a *App) brokerRuntimeCountersWindow(window time.Duration) (map[string]int64, bool) {
	if globalProxyServer == nil {
		return nil, false
	}
	return globalProxyServer.BrokerCountersWindow(window), true
}

type brokerCounterWindowOption struct {
	Label    string
	Duration time.Duration
}

func (a *App) brokerRuntimeState() proxy.BrokerState {
	a.normalizeBrokerGroupsAndPolicies()
	state := proxy.BrokerState{
		AppliedAt:        time.Now().UTC(),
		ExchangeEndpoint: strings.TrimSpace(a.brokerExchangeEndpoint),
	}
	for _, g := range a.brokerGroups {
		groupID := brokerGroupID(g)
		state.Groups = append(state.Groups, proxy.BrokerGroupState{ID: groupID, Name: groupID, Match: brokerGroupMatchRule(g), Pool: g.Pool, Weight: g.Weight, RPHLimit: g.RPHLimit})
	}
	for _, p := range a.brokerPools {
		poolState := proxy.BrokerPoolState{Name: p.Name}
		for _, t := range p.Tokens {
			poolState.Tokens = append(poolState.Tokens, proxy.BrokerTokenState{
				ID:           t.ID,
				Kind:         t.Kind,
				Endpoint:     t.Endpoint,
				Enabled:      t.Enabled,
				Health:       t.Health,
				RemainingRPH: t.RemainingRPH,
				BreakerOpen:  t.BreakerOpen,
				SessionState: t.SessionState,
				LastTest:     t.LastTest,
				PATEnv:       t.PATEnv,
				P95ms:        t.P95ms,
			})
		}
		state.Pools = append(state.Pools, poolState)
	}
	for _, p := range a.brokerPolicies {
		state.Policies = append(state.Policies, proxy.BrokerPolicyState{
			Name:     p.Name,
			Group:    p.Group,
			Pool:     p.Pool,
			Strategy: p.Strategy,
			Sticky:   p.Sticky,
			Retry:    p.Retry,
		})
	}
	return state
}
