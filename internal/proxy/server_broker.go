package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (s *Server) SetBrokerState(st BrokerState) {
	normalizeBrokerState(&st)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.brokerState = cloneBrokerState(st)
}

// BrokerState returns a copy of the currently applied runtime broker snapshot.

func (s *Server) BrokerState() BrokerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneBrokerState(s.brokerState)
}

func (s *Server) bumpBrokerCounter(key string) {
	k := strings.TrimSpace(key)
	if k == "" {
		return
	}
	s.mu.Lock()
	s.brokerCounters[k]++
	s.brokerCounterEvents = append(s.brokerCounterEvents, brokerCounterEvent{At: time.Now(), Key: k})
	if s.brokerCounterEventCap > 0 && len(s.brokerCounterEvents) > s.brokerCounterEventCap {
		s.brokerCounterEvents = s.brokerCounterEvents[len(s.brokerCounterEvents)-s.brokerCounterEventCap:]
	}
	s.mu.Unlock()
}

// BrokerCounters returns a copy of runtime broker telemetry counters.

func (s *Server) BrokerCounters() map[string]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]int64, len(s.brokerCounters))
	for k, v := range s.brokerCounters {
		out[k] = v
	}
	return out
}

// BrokerCountersWindow returns counter totals observed within the given recent window.
// If window <= 0, it returns an empty map.

func (s *Server) BrokerCountersWindow(window time.Duration) map[string]int64 {
	if window <= 0 {
		return map[string]int64{}
	}
	cutoff := time.Now().Add(-window)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]int64)
	for _, ev := range s.brokerCounterEvents {
		if ev.At.Before(cutoff) {
			continue
		}
		out[ev.Key]++
	}
	return out
}

// ResetBrokerCounters clears runtime broker telemetry counters.

func (s *Server) ResetBrokerCounters() {
	s.mu.Lock()
	s.brokerCounters = make(map[string]int64)
	s.brokerCounterEvents = nil
	s.mu.Unlock()
}

func brokerSanitizeCounterGroupName(name string) string {
	n := strings.TrimSpace(strings.ToLower(name))
	repl := strings.NewReplacer(" ", "_", ":", "_", "/", "_", "\\", "_", "*", "_", "?", "_", "[", "_", "]", "_", "-", "_")
	n = repl.Replace(n)
	if n == "" {
		n = "unknown"
	}
	return n
}

func brokerGroupCounterKey(groupName, metric string) string {
	m := strings.TrimSpace(metric)
	if m == "" {
		m = "unknown"
	}
	return fmt.Sprintf("group.%s.%s", brokerSanitizeCounterGroupName(groupName), m)
}

func cloneBrokerState(st BrokerState) BrokerState {
	out := st
	out.Groups = append([]BrokerGroupState(nil), st.Groups...)
	out.Pools = make([]BrokerPoolState, len(st.Pools))
	for i, p := range st.Pools {
		out.Pools[i] = BrokerPoolState{Name: p.Name, Tokens: append([]BrokerTokenState(nil), p.Tokens...)}
	}
	out.Policies = append([]BrokerPolicyState(nil), st.Policies...)
	return out
}

func brokerGroupID(g BrokerGroupState) string {
	if v := strings.TrimSpace(g.ID); v != "" {
		return v
	}
	if v := strings.TrimSpace(g.Name); v != "" {
		return v
	}
	if v := strings.TrimSpace(g.Match); v != "" {
		return v
	}
	return ""
}

func brokerGroupMatchRule(g BrokerGroupState) string {
	if v := strings.TrimSpace(g.Match); v != "" {
		return v
	}
	if v := strings.TrimSpace(g.Name); v != "" {
		return v
	}
	if v := strings.TrimSpace(g.ID); v != "" {
		return v
	}
	return ""
}

func brokerGroupLabel(g BrokerGroupState) string {
	if v := brokerGroupID(g); v != "" {
		return v
	}
	if v := brokerGroupMatchRule(g); v != "" {
		return v
	}
	return "unknown"
}

func normalizeBrokerState(st *BrokerState) {
	if st == nil {
		return
	}
	legacyToID := make(map[string]string)
	for i := range st.Groups {
		g := &st.Groups[i]
		legacyName := strings.TrimSpace(g.Name)
		if strings.TrimSpace(g.ID) == "" {
			g.ID = legacyName
		}
		if strings.TrimSpace(g.ID) == "" {
			g.ID = fmt.Sprintf("group-%d", i+1)
		}
		if strings.TrimSpace(g.Match) == "" {
			if legacyName != "" {
				g.Match = legacyName
			} else {
				g.Match = g.ID
			}
		}
		if strings.TrimSpace(g.Name) == "" {
			g.Name = g.ID
		}
		legacyToID[strings.ToLower(strings.TrimSpace(g.ID))] = g.ID
		if legacyName != "" {
			legacyToID[strings.ToLower(legacyName)] = g.ID
		}
	}
	for i := range st.Policies {
		groupRef := strings.TrimSpace(st.Policies[i].Group)
		if groupRef == "" {
			continue
		}
		if id, ok := legacyToID[strings.ToLower(groupRef)]; ok {
			st.Policies[i].Group = id
		}
	}
}

func brokerGroupMatchScore(rule, container string) int {
	rule = strings.TrimSpace(rule)
	container = strings.TrimSpace(container)
	if rule == "" || container == "" {
		return -1
	}
	if strings.EqualFold(rule, container) {
		return 5000 + len(rule)
	}

	ruleLower := strings.ToLower(rule)
	containerLower := strings.ToLower(container)

	if strings.HasPrefix(ruleLower, "prefix:") {
		prefix := strings.TrimSpace(rule[len("prefix:"):])
		if prefix == "" {
			return -1
		}
		if strings.HasPrefix(containerLower, strings.ToLower(prefix)) {
			return 4000 + len(prefix)
		}
		return -1
	}

	if strings.HasPrefix(ruleLower, "contains:") {
		sub := strings.TrimSpace(rule[len("contains:"):])
		if sub == "" {
			return -1
		}
		if strings.Contains(containerLower, strings.ToLower(sub)) {
			return 3000 + len(sub)
		}
		return -1
	}

	if strings.ContainsAny(rule, "*?[]") {
		pattern := strings.ToLower(rule)
		ok, err := path.Match(pattern, containerLower)
		if err != nil || !ok {
			return -1
		}
		specificity := 0
		for _, ch := range pattern {
			switch ch {
			case '*', '?', '[', ']':
			default:
				specificity++
			}
		}
		return 2000 + specificity
	}

	return -1
}

func brokerResolveGroup(st BrokerState, container string) (BrokerGroupState, bool) {
	bestScore := -1
	bestIdx := -1
	for i := range st.Groups {
		score := brokerGroupMatchScore(brokerGroupMatchRule(st.Groups[i]), container)
		if score > bestScore {
			bestScore = score
			bestIdx = i
		}
	}
	if bestIdx >= 0 {
		return st.Groups[bestIdx], true
	}
	return BrokerGroupState{}, false
}

func brokerResolvePoolName(st BrokerState, g BrokerGroupState) string {
	poolName := strings.TrimSpace(g.Pool)
	groupID := strings.TrimSpace(brokerGroupID(g))
	legacyName := strings.TrimSpace(g.Name)
	matchRule := strings.TrimSpace(brokerGroupMatchRule(g))
	for _, p := range st.Policies {
		policyGroup := strings.TrimSpace(p.Group)
		if policyGroup == "" || strings.TrimSpace(p.Pool) == "" {
			continue
		}
		if strings.EqualFold(policyGroup, groupID) || strings.EqualFold(policyGroup, legacyName) || strings.EqualFold(policyGroup, matchRule) {
			poolName = strings.TrimSpace(p.Pool)
			break
		}
	}
	return poolName
}

func brokerResolvePool(st BrokerState, poolName string) (BrokerPoolState, bool) {
	for i := range st.Pools {
		if strings.EqualFold(strings.TrimSpace(st.Pools[i].Name), strings.TrimSpace(poolName)) {
			return st.Pools[i], true
		}
	}
	return BrokerPoolState{}, false
}

func brokerTokenHealthy(t BrokerTokenState) bool {
	if !t.Enabled || t.BreakerOpen {
		return false
	}
	if t.Health < 0.50 || t.RemainingRPH <= 0 {
		return false
	}
	return true
}

// brokerTokenMatchesDomain returns true if the token's kind is compatible with
// the target domain. This prevents cross-provider token mismatches (e.g. a
// Gemini API key being injected into a Copilot request).
//
// Rules:
//   - kind=gemini   → only matches generativelanguage.googleapis.com
//   - kind=openai   → only matches openai-like domains (api.openai.com, azure, etc.)
//   - kind=copilot  → only matches githubcopilot.com and api.github.com
//   - kind="" (auto) → matches any domain (legacy / single-provider pools)

func brokerTokenMatchesDomain(t BrokerTokenState, domain string) bool {
	kind := strings.TrimSpace(t.Kind)
	d := strings.ToLower(strings.TrimSpace(domain))

	// If the token has a custom Endpoint, match against that hostname first.
	// e.g. Endpoint="https://openrouter.ai" matches domain="openrouter.ai".
	if ep := strings.TrimSpace(t.Endpoint); ep != "" {
		// Strip scheme and path from endpoint to get hostname.
		epHost := ep
		if idx := strings.Index(ep, "://"); idx >= 0 {
			epHost = ep[idx+3:]
		}
		if idx := strings.Index(epHost, "/"); idx >= 0 {
			epHost = epHost[:idx]
		}
		epHost = strings.ToLower(strings.TrimSpace(epHost))
		if epHost != "" && strings.HasSuffix(d, epHost) {
			return true
		}
	}

	if kind == "" {
		// auto kind with no endpoint: only match if no other token in pool
		// would be a more specific match. We return true here and let the
		// caller's sort order prefer more specific (non-auto) tokens.
		return true
	}

	switch kind {
	case BrokerTokenKindGemini:
		return strings.Contains(d, "googleapis.com")
	case BrokerTokenKindOpenAI:
		// OpenAI-compatible: covers OpenAI, Azure OpenAI, and
		// OpenAI-compat providers (openrouter, together, etc.) that
		// have explicitly set Kind=openai. Domain filter is broad:
		// prefer Endpoint-based matching above for specific providers.
		return strings.Contains(d, "openai.com") ||
			strings.Contains(d, "azure.com") ||
			strings.Contains(d, "openrouter.ai") ||
			strings.Contains(d, "together.ai") ||
			strings.Contains(d, "togetherai.com")
	case BrokerTokenKindCopilot:
		return strings.Contains(d, "githubcopilot.com") ||
			strings.Contains(d, "api.github.com")
	default:
		return true
	}
}

func brokerTokenRankP95(t BrokerTokenState) int {
	if t.P95ms <= 0 {
		return 1 << 30
	}
	return t.P95ms
}

func clampBrokerHealth(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// SelectBrokerToken returns a token candidate for the container/model/domain.
// matched=false means this container is not broker-managed (opt-in behavior).
// matched=true and ok=false means broker applies and admission should be blocked.
// domain is used to filter tokens by kind: copilot tokens are only selected for
// Copilot domains; gemini tokens only for Gemini domains; etc.

func (s *Server) SelectBrokerToken(container, model, domain string) (token BrokerTokenState, matched bool, ok bool, reason string) {
	_ = model // model-aware selection is next phase
	s.bumpBrokerCounter("select_attempt")

	st := s.BrokerState()
	if len(st.Groups) == 0 || len(st.Pools) == 0 {
		s.bumpBrokerCounter("select_unmanaged")
		return BrokerTokenState{}, false, false, ""
	}

	g, matched := brokerResolveGroup(st, container)
	if !matched {
		s.bumpBrokerCounter("select_unmanaged")
		return BrokerTokenState{}, false, false, ""
	}

	groupLabel := brokerGroupLabel(g)
	poolName := brokerResolvePoolName(st, g)
	if poolName == "" {
		s.bumpBrokerCounter("block_broker_pool_unmapped")
		s.bumpBrokerCounter(brokerGroupCounterKey(groupLabel, "block_pool_unmapped"))
		return BrokerTokenState{}, true, false, "broker_pool_unmapped"
	}

	pool, found := brokerResolvePool(st, poolName)
	if !found {
		s.bumpBrokerCounter("block_broker_pool_missing")
		s.bumpBrokerCounter(brokerGroupCounterKey(groupLabel, "block_pool_missing"))
		return BrokerTokenState{}, true, false, "broker_pool_missing"
	}

	candidates := make([]BrokerTokenState, 0, len(pool.Tokens))
	for _, t := range pool.Tokens {
		if brokerTokenHealthy(t) && brokerTokenMatchesDomain(t, domain) {
			candidates = append(candidates, t)
		}
	}
	if len(candidates) == 0 {
		s.bumpBrokerCounter("block_broker_no_healthy_tokens")
		s.bumpBrokerCounter(brokerGroupCounterKey(groupLabel, "block_no_healthy_tokens"))
		return BrokerTokenState{}, true, false, "broker_no_healthy_tokens"
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].RemainingRPH != candidates[j].RemainingRPH {
			return candidates[i].RemainingRPH > candidates[j].RemainingRPH
		}
		if candidates[i].Health != candidates[j].Health {
			return candidates[i].Health > candidates[j].Health
		}
		if brokerTokenRankP95(candidates[i]) != brokerTokenRankP95(candidates[j]) {
			return brokerTokenRankP95(candidates[i]) < brokerTokenRankP95(candidates[j])
		}
		return candidates[i].ID < candidates[j].ID
	})

	s.bumpBrokerCounter("select_ok")
	s.bumpBrokerCounter(brokerGroupCounterKey(groupLabel, "select_ok"))
	return candidates[0], true, true, ""
}

// ShouldBlockByBroker evaluates current runtime broker state and reports whether
// a request should be rejected at admission time.

func (s *Server) ShouldBlockByBroker(container, model string) (blocked bool, reason string) {
	_, matched, ok, reason := s.SelectBrokerToken(container, model, "")
	if !matched {
		return false, ""
	}
	if !ok {
		return true, reason
	}
	return false, ""
}

func (s *Server) mutateBrokerToken(tokenID string, fn func(*BrokerTokenState)) bool {
	target := strings.TrimSpace(tokenID)
	if target == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for pi := range s.brokerState.Pools {
		for ti := range s.brokerState.Pools[pi].Tokens {
			tok := &s.brokerState.Pools[pi].Tokens[ti]
			if strings.EqualFold(strings.TrimSpace(tok.ID), target) {
				fn(tok)
				return true
			}
		}
	}
	return false
}

func (s *Server) MarkBrokerTokenExchangeResult(tokenID string, ok bool, source string) {
	if ok {
		s.bumpBrokerCounter("exchange_ok")
	} else {
		s.bumpBrokerCounter("exchange_fail")
	}
	s.mutateBrokerToken(tokenID, func(tok *BrokerTokenState) {
		if ok {
			tok.LastTest = "ok"
			tok.SessionState = "session:" + strings.TrimSpace(source)
			tok.Health = clampBrokerHealth(tok.Health + 0.02)
			return
		}
		tok.LastTest = "fail"
		failState := "exchange-fail"
		if src := strings.TrimSpace(source); src != "" {
			failState += ":" + src
		}
		tok.SessionState = failState
		tok.Health = clampBrokerHealth(tok.Health - 0.06)
		if tok.Health < 0.20 {
			tok.BreakerOpen = true
		}
	})
}

func (s *Server) MarkBrokerTokenRequestResult(tokenID string, statusCode int, latency time.Duration) {
	if statusCode >= 200 && statusCode < 400 {
		s.bumpBrokerCounter("request_ok")
	} else if statusCode == http.StatusTooManyRequests {
		s.bumpBrokerCounter("request_429")
	} else if statusCode >= 500 {
		s.bumpBrokerCounter("request_5xx")
	} else {
		s.bumpBrokerCounter("request_other")
	}
	s.mutateBrokerToken(tokenID, func(tok *BrokerTokenState) {
		if tok.RemainingRPH > 0 {
			tok.RemainingRPH--
		}
		latMs := int(latency.Milliseconds())
		if latMs > 0 && (tok.P95ms == 0 || latMs > tok.P95ms) {
			tok.P95ms = latMs
		}
		if statusCode >= 500 || statusCode == http.StatusTooManyRequests {
			tok.Health = clampBrokerHealth(tok.Health - 0.03)
			tok.SessionState = fmt.Sprintf("upstream-%d", statusCode)
			return
		}
		if statusCode >= 200 && statusCode < 400 {
			tok.Health = clampBrokerHealth(tok.Health + 0.01)
			tok.SessionState = "in-use"
		}
	})
}

// brokerDefaultEndpointForKind returns the default upstream endpoint for a given
// token kind. This is used when the token has no explicit Endpoint set.

func brokerDefaultEndpointForKind(kind BrokerTokenKind) string {
	switch kind {
	case BrokerTokenKindGemini:
		return "https://generativelanguage.googleapis.com"
	case BrokerTokenKindOpenAI:
		return "https://api.openai.com"
	default: // copilot
		return "https://api.github.com/copilot_internal/v2/token"
	}
}

// brokerTokenEndpoint returns the effective upstream endpoint for a token,
// falling back to the kind default, then the global exchange endpoint.

func brokerTokenEndpoint(tok BrokerTokenState, globalFallback string) string {
	if e := strings.TrimSpace(tok.Endpoint); e != "" {
		return e
	}
	if globalFallback != "" {
		// Only use global fallback for copilot (legacy); ignore for other kinds.
		if tok.Kind == BrokerTokenKindCopilot || tok.Kind == BrokerTokenKindAuto {
			return globalFallback
		}
	}
	return brokerDefaultEndpointForKind(tok.Kind)
}

// Deprecated: use brokerDefaultEndpointForKind(BrokerTokenKindCopilot) instead.

func brokerDefaultExchangeEndpoint() string {
	return brokerDefaultEndpointForKind(BrokerTokenKindCopilot)
}

func (s *Server) shouldUseBrokerSession(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	return strings.Contains(d, "githubcopilot.com")
}

func brokerSessionCacheKey(t BrokerTokenState) string {
	if strings.TrimSpace(t.ID) != "" {
		return strings.TrimSpace(t.ID)
	}
	if strings.TrimSpace(t.PATEnv) != "" {
		return "env:" + strings.TrimSpace(t.PATEnv)
	}
	return ""
}

// proxyDataDir returns the ~/.cella/ path for the real invoking user,
// handling the case where the process runs as root via sudo.

func proxyDataDir() string {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		if u, err := user.Lookup(sudoUser); err == nil {
			return filepath.Join(u.HomeDir, ".cella")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.ExpandEnv("$HOME")
	}
	return filepath.Join(home, ".cella")
}

// loadBrokerSecretsFile reads ~/.cella/token_broker_secrets.json and returns
// the key→value map. Returns an empty map on any error (non-fatal).

func loadBrokerSecretsFile() map[string]string {
	secretsPath := filepath.Join(proxyDataDir(), "token_broker_secrets.json")
	data, err := os.ReadFile(secretsPath)
	if err != nil {
		return map[string]string{}
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return map[string]string{}
	}
	return m
}

// resolveBrokerTokenKind returns the effective auth kind for a token.
// If Kind is set explicitly, it is used as-is.
// Otherwise the PAT value prefix is used for auto-detection:
//   ghu_  → copilot
//   AIza  → gemini
//   sk-   → openai
//   (else) → copilot (default)

func resolveBrokerTokenKind(tok BrokerTokenState, pat string) BrokerTokenKind {
	if k := strings.TrimSpace(tok.Kind); k != "" {
		return k
	}
	switch {
	case strings.HasPrefix(pat, "ghu_"):
		return BrokerTokenKindCopilot
	case strings.HasPrefix(pat, "AIza"):
		return BrokerTokenKindGemini
	case strings.HasPrefix(pat, "sk-"):
		return BrokerTokenKindOpenAI
	default:
		return BrokerTokenKindCopilot
	}
}

func (s *Server) resolveBrokerPAT(token BrokerTokenState) (pat string, sourceEnv string, err error) {
	env := strings.TrimSpace(token.PATEnv)
	if env == "" {
		env = "CELLA_BROKER_TEST_PAT"
	}

	// 1. Try env var first (allows CI/headless override via export).
	pat = strings.TrimSpace(os.Getenv(env))
	if pat != "" {
		return pat, env, nil
	}

	// 2. Fallback: read from ~/.cella/token_broker_secrets.json.
	//    PATEnv is used as the key name in the secrets file.
	secrets := loadBrokerSecretsFile()
	if val := strings.TrimSpace(secrets[env]); val != "" {
		return val, env, nil
	}

	return "", env, fmt.Errorf("broker PAT not found: env %s is empty and not in secrets file", env)
}

func parseBrokerTokenExpiry(payload map[string]any, now time.Time) time.Time {
	if v, ok := payload["expires_at"].(float64); ok && v > 0 {
		return time.Unix(int64(v), 0)
	}
	if v, ok := payload["expires_at"].(string); ok {
		if ts, err := time.Parse(time.RFC3339, strings.TrimSpace(v)); err == nil {
			return ts
		}
	}
	return now.Add(25 * time.Minute)
}

// AcquireBrokerSessionToken returns a short-lived session token for the selected
// broker PAT (with per-token cache).

func (s *Server) AcquireBrokerSessionToken(token BrokerTokenState) (session string, source string, err error) {
	s.bumpBrokerCounter("session_acquire_attempt")
	st := s.BrokerState()
	globalFallback := strings.TrimSpace(st.ExchangeEndpoint)
	endpoint := brokerTokenEndpoint(token, globalFallback)

	cacheKey := brokerSessionCacheKey(token)
	now := time.Now()
	if cacheKey != "" {
		s.mu.RLock()
		entry, ok := s.brokerSessions[cacheKey]
		s.mu.RUnlock()
		if ok && strings.TrimSpace(entry.SessionToken) != "" && entry.ExpiresAt.After(now.Add(2*time.Minute)) {
			s.bumpBrokerCounter("session_cache_hit")
			return entry.SessionToken, "cache:" + entry.SourceEnv, nil
		}
	}

	pat, sourceEnv, err := s.resolveBrokerPAT(token)
	if err != nil {
		s.bumpBrokerCounter("session_exchange_fail_pat")
		return "", sourceEnv, err
	}

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		s.bumpBrokerCounter("session_exchange_fail_req")
		return "", sourceEnv, err
	}
	req.Header.Set("Authorization", "Bearer "+pat)
	req.Header.Set("editor-version", "vscode/1.87.0")
	req.Header.Set("editor-plugin-version", "copilot/1.155.0")

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.bumpBrokerCounter("session_exchange_fail_http")
		return "", sourceEnv, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		s.bumpBrokerCounter("session_exchange_fail_status")
		return "", sourceEnv, fmt.Errorf("exchange status %d", resp.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		s.bumpBrokerCounter("session_exchange_fail_decode")
		return "", sourceEnv, err
	}
	session, _ = payload["token"].(string)
	session = strings.TrimSpace(session)
	if session == "" {
		s.bumpBrokerCounter("session_exchange_fail_empty")
		return "", sourceEnv, fmt.Errorf("empty session token in exchange response")
	}

	expiresAt := parseBrokerTokenExpiry(payload, now)
	if cacheKey != "" {
		s.mu.Lock()
		s.brokerSessions[cacheKey] = brokerSessionEntry{SessionToken: session, SourceEnv: sourceEnv, ExpiresAt: expiresAt}
		s.mu.Unlock()
	}
	s.bumpBrokerCounter("session_exchange_ok")
	return session, "exchange:" + sourceEnv, nil
}

// AllAllowlists returns a snapshot of the container→allowlist map for persistence.
