package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServerBrokerStateRoundTripAndCopyIsolation(t *testing.T) {
	s := NewServer(9081, make(chan ApprovalRequest, 1))
	in := BrokerState{
		AppliedAt:        time.Now().UTC(),
		ExchangeEndpoint: "https://api.github.com/copilot_internal/v2/token",
		Groups:           []BrokerGroupState{{Name: "team-a", Pool: "pool_alpha", Weight: 2, RPHLimit: 5000}},
		Pools: []BrokerPoolState{{
			Name:   "pool_alpha",
			Tokens: []BrokerTokenState{{ID: "tok_a1", Enabled: true, Health: 0.9, RemainingRPH: 800, LastTest: "ok"}},
		}},
		Policies: []BrokerPolicyState{{Name: "policy_a", Group: "team-a", Pool: "pool_alpha", Strategy: "weighted_least_load", Sticky: true, Retry: 1}},
	}

	s.SetBrokerState(in)
	got := s.BrokerState()
	if got.ExchangeEndpoint == "" {
		t.Fatalf("unexpected broker state headers: %+v", got)
	}
	if len(got.Groups) != 1 || len(got.Pools) != 1 || len(got.Policies) != 1 {
		t.Fatalf("unexpected broker state sizes: %+v", got)
	}

	// Mutate caller-side and getter-side copies; server copy should stay stable.
	in.Groups[0].Weight = 99
	got.Groups[0].Weight = 77
	got.Pools[0].Tokens[0].ID = "tampered"

	again := s.BrokerState()
	if again.Groups[0].Weight != 2 {
		t.Fatalf("expected stored weight=2, got %d", again.Groups[0].Weight)
	}
	if again.Pools[0].Tokens[0].ID != "tok_a1" {
		t.Fatalf("expected stored token id tok_a1, got %s", again.Pools[0].Tokens[0].ID)
	}
}

func TestShouldBlockByBroker_OptInOnlyByContainerMatch(t *testing.T) {
	s := NewServer(9081, make(chan ApprovalRequest, 1))
	s.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "team-a", Pool: "pool_alpha", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name:   "pool_alpha",
			Tokens: []BrokerTokenState{{ID: "tok1", Enabled: false, Health: 0.2, RemainingRPH: 0}},
		}},
	})

	blocked, reason := s.ShouldBlockByBroker("juju-eadd46-0", "gpt-5-mini")
	if blocked || reason != "" {
		t.Fatalf("expected opt-in allow when no group match, got blocked=%v reason=%q", blocked, reason)
	}
}

func TestShouldBlockByBroker_BlocksWhenMappedPoolHasNoHealthyToken(t *testing.T) {
	s := NewServer(9081, make(chan ApprovalRequest, 1))
	s.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "ci-runner-1", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name: "pool_ci",
			Tokens: []BrokerTokenState{
				{ID: "tok1", Enabled: false, Health: 0.9, RemainingRPH: 100},
				{ID: "tok2", Enabled: true, BreakerOpen: true, Health: 0.9, RemainingRPH: 100},
				{ID: "tok3", Enabled: true, Health: 0.2, RemainingRPH: 100},
				{ID: "tok4", Enabled: true, Health: 0.9, RemainingRPH: 0},
			},
		}},
	})

	blocked, reason := s.ShouldBlockByBroker("ci-runner-1", "gpt-5-mini")
	if !blocked || reason != "broker_no_healthy_tokens" {
		t.Fatalf("expected broker_no_healthy_tokens, got blocked=%v reason=%q", blocked, reason)
	}

	// Make one token healthy and verify it unblocks.
	s.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "ci-runner-1", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name: "pool_ci",
			Tokens: []BrokerTokenState{
				{ID: "tok5", Enabled: true, Health: 0.95, RemainingRPH: 123},
			},
		}},
	})
	blocked, reason = s.ShouldBlockByBroker("ci-runner-1", "gpt-5-mini")
	if blocked || reason != "" {
		t.Fatalf("expected allow with healthy token, got blocked=%v reason=%q", blocked, reason)
	}
}

func TestSelectBrokerToken_ChoosesBestHealthyCandidate(t *testing.T) {
	s := NewServer(9081, make(chan ApprovalRequest, 1))
	s.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "ci-runner-1", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name: "pool_ci",
			Tokens: []BrokerTokenState{
				{ID: "tok-low", Enabled: true, Health: 0.99, RemainingRPH: 10, P95ms: 50},
				{ID: "tok-mid", Enabled: true, Health: 0.90, RemainingRPH: 120, P95ms: 20},
				{ID: "tok-best", Enabled: true, Health: 0.92, RemainingRPH: 120, P95ms: 10, PATEnv: "PAT_BEST"},
				{ID: "tok-bad", Enabled: false, Health: 0.99, RemainingRPH: 999, P95ms: 1},
			},
		}},
	})

	tok, matched, ok, reason := s.SelectBrokerToken("ci-runner-1", "gpt-5-mini", "")
	if !matched || !ok || reason != "" {
		t.Fatalf("expected matched+ok, got matched=%v ok=%v reason=%q", matched, ok, reason)
	}
	if tok.ID != "tok-best" {
		t.Fatalf("expected tok-best selected, got %s", tok.ID)
	}
	if tok.PATEnv != "PAT_BEST" {
		t.Fatalf("expected PAT_BEST, got %s", tok.PATEnv)
	}
}

func TestSelectBrokerToken_UsesPolicyPoolOverride(t *testing.T) {
	s := NewServer(9081, make(chan ApprovalRequest, 1))
	s.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "team-a", Pool: "pool_alpha", Weight: 1}},
		Pools: []BrokerPoolState{
			{Name: "pool_alpha", Tokens: []BrokerTokenState{{ID: "tok-a", Enabled: true, Health: 0.9, RemainingRPH: 100}}},
			{Name: "pool_beta", Tokens: []BrokerTokenState{{ID: "tok-b", Enabled: true, Health: 0.9, RemainingRPH: 150}}},
		},
		Policies: []BrokerPolicyState{{Name: "policy-a", Group: "team-a", Pool: "pool_beta", Strategy: "weighted_least_load"}},
	})

	tok, matched, ok, reason := s.SelectBrokerToken("team-a", "gpt-5-mini", "")
	if !matched || !ok || reason != "" {
		t.Fatalf("expected matched+ok, got matched=%v ok=%v reason=%q", matched, ok, reason)
	}
	if tok.ID != "tok-b" {
		t.Fatalf("expected token from pool_beta, got %s", tok.ID)
	}
}

func TestSelectBrokerToken_GroupPrefixPatternMatch(t *testing.T) {
	s := NewServer(9081, make(chan ApprovalRequest, 1))
	s.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "prefix:ci-runner-", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name:   "pool_ci",
			Tokens: []BrokerTokenState{{ID: "tok-ci", Enabled: true, Health: 0.92, RemainingRPH: 222}},
		}},
	})

	tok, matched, ok, reason := s.SelectBrokerToken("ci-runner-17", "gpt-5-mini", "")
	if !matched || !ok || reason != "" {
		t.Fatalf("expected prefix pattern match, got matched=%v ok=%v reason=%q", matched, ok, reason)
	}
	if tok.ID != "tok-ci" {
		t.Fatalf("expected tok-ci, got %s", tok.ID)
	}
}

func TestSelectBrokerToken_GroupGlobPatternMatch(t *testing.T) {
	s := NewServer(9081, make(chan ApprovalRequest, 1))
	s.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "ci-*", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name:   "pool_ci",
			Tokens: []BrokerTokenState{{ID: "tok-ci", Enabled: true, Health: 0.90, RemainingRPH: 111}},
		}},
	})

	tok, matched, ok, reason := s.SelectBrokerToken("ci-runner-1", "gpt-5-mini", "")
	if !matched || !ok || reason != "" {
		t.Fatalf("expected glob pattern match, got matched=%v ok=%v reason=%q", matched, ok, reason)
	}
	if tok.ID != "tok-ci" {
		t.Fatalf("expected tok-ci, got %s", tok.ID)
	}
}

func TestSelectBrokerToken_ExactMatchBeatsWildcard(t *testing.T) {
	s := NewServer(9081, make(chan ApprovalRequest, 1))
	s.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{
			{Name: "ci-*", Pool: "pool_ci", Weight: 1},
			{Name: "ci-runner-1", Pool: "pool_exact", Weight: 1},
		},
		Pools: []BrokerPoolState{
			{Name: "pool_ci", Tokens: []BrokerTokenState{{ID: "tok-ci", Enabled: true, Health: 0.90, RemainingRPH: 111}}},
			{Name: "pool_exact", Tokens: []BrokerTokenState{{ID: "tok-exact", Enabled: true, Health: 0.95, RemainingRPH: 222}}},
		},
	})

	tok, matched, ok, reason := s.SelectBrokerToken("ci-runner-1", "gpt-5-mini", "")
	if !matched || !ok || reason != "" {
		t.Fatalf("expected exact match to win, got matched=%v ok=%v reason=%q", matched, ok, reason)
	}
	if tok.ID != "tok-exact" {
		t.Fatalf("expected tok-exact, got %s", tok.ID)
	}
}

func TestSelectBrokerToken_GroupIDAndMatchRuleSplit(t *testing.T) {
	s := NewServer(9081, make(chan ApprovalRequest, 1))
	s.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{ID: "ci-batch", Match: "prefix:ci-runner-", Pool: "pool_alpha", Weight: 1}},
		Pools: []BrokerPoolState{
			{Name: "pool_alpha", Tokens: []BrokerTokenState{{ID: "tok-a", Enabled: true, Health: 0.9, RemainingRPH: 100}}},
			{Name: "pool_beta", Tokens: []BrokerTokenState{{ID: "tok-b", Enabled: true, Health: 0.9, RemainingRPH: 150}}},
		},
		Policies: []BrokerPolicyState{{Name: "policy-ci", Group: "ci-batch", Pool: "pool_beta", Strategy: "weighted_least_load"}},
	})

	tok, matched, ok, reason := s.SelectBrokerToken("ci-runner-42", "gpt-5-mini", "")
	if !matched || !ok || reason != "" {
		t.Fatalf("expected matched+ok with split id/match rule, got matched=%v ok=%v reason=%q", matched, ok, reason)
	}
	if tok.ID != "tok-b" {
		t.Fatalf("expected policy override to pool_beta token, got %s", tok.ID)
	}
}

func TestSetBrokerState_NormalizesLegacyGroupAndPolicyRefs(t *testing.T) {
	s := NewServer(9081, make(chan ApprovalRequest, 1))
	s.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "prefix:ci-runner-", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name:   "pool_ci",
			Tokens: []BrokerTokenState{{ID: "tok-ci", Enabled: true, Health: 0.9, RemainingRPH: 100}},
		}},
		Policies: []BrokerPolicyState{{Name: "legacy", Group: "prefix:ci-runner-", Pool: "pool_ci"}},
	})

	st := s.BrokerState()
	if len(st.Groups) == 0 {
		t.Fatalf("expected normalized groups in state")
	}
	g := st.Groups[0]
	if strings.TrimSpace(g.ID) == "" {
		t.Fatalf("expected group ID to be normalized from legacy name")
	}
	if strings.TrimSpace(g.Match) == "" {
		t.Fatalf("expected group Match to be normalized from legacy name")
	}
	if len(st.Policies) == 0 || st.Policies[0].Group != g.ID {
		t.Fatalf("expected policy group ref normalized to %q, got %+v", g.ID, st.Policies)
	}
}

func TestAcquireBrokerSessionToken_ExchangesAndCaches(t *testing.T) {
	exchangeCalls := 0
	srvExchange := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchangeCalls++
		if r.Header.Get("Authorization") != "Bearer ghu_best_pat" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"bad auth"}`))
			return
		}
		_, _ = w.Write([]byte(`{"token":"session_abc"}`))
	}))
	defer srvExchange.Close()

	s := NewServer(9081, make(chan ApprovalRequest, 1))
	s.SetBrokerState(BrokerState{ExchangeEndpoint: srvExchange.URL})
	t.Setenv("PAT_BEST", "ghu_best_pat")

	tok := BrokerTokenState{ID: "tok-best", PATEnv: "PAT_BEST"}
	session1, src1, err := s.AcquireBrokerSessionToken(tok)
	if err != nil {
		t.Fatalf("exchange session1 failed: %v", err)
	}
	if session1 != "session_abc" || !strings.Contains(src1, "PAT_BEST") {
		t.Fatalf("unexpected session1/src1: %q / %q", session1, src1)
	}

	session2, src2, err := s.AcquireBrokerSessionToken(tok)
	if err != nil {
		t.Fatalf("exchange session2 failed: %v", err)
	}
	if session2 != "session_abc" || !strings.HasPrefix(src2, "cache:") {
		t.Fatalf("expected cached session on second call, got %q / %q", session2, src2)
	}
	if exchangeCalls != 1 {
		t.Fatalf("expected one exchange call due to cache, got %d", exchangeCalls)
	}
}

func TestAcquireBrokerSessionToken_FailsWhenPATMissing(t *testing.T) {
	s := NewServer(9081, make(chan ApprovalRequest, 1))
	tok := BrokerTokenState{ID: "tok-best", PATEnv: "MISSING_PAT_ENV"}
	_, _, err := s.AcquireBrokerSessionToken(tok)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected missing PAT error, got %v", err)
	}
}

func TestBrokerTokenFeedbackUpdatesRuntimeState(t *testing.T) {
	s := NewServer(9081, make(chan ApprovalRequest, 1))
	s.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "ci-runner-1", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name:   "pool_ci",
			Tokens: []BrokerTokenState{{ID: "tok-best", Enabled: true, Health: 0.80, RemainingRPH: 5, P95ms: 10, PATEnv: "PAT_BEST"}},
		}},
	})

	s.MarkBrokerTokenExchangeResult("tok-best", true, "exchange:PAT_BEST")
	s.MarkBrokerTokenRequestResult("tok-best", http.StatusOK, 250*time.Millisecond)

	st := s.BrokerState()
	tok := st.Pools[0].Tokens[0]
	if tok.LastTest != "ok" {
		t.Fatalf("expected LastTest=ok, got %s", tok.LastTest)
	}
	if tok.SessionState != "in-use" {
		t.Fatalf("expected SessionState=in-use after success request, got %s", tok.SessionState)
	}
	if tok.RemainingRPH != 4 {
		t.Fatalf("expected RemainingRPH=4, got %d", tok.RemainingRPH)
	}
	if tok.P95ms != 250 {
		t.Fatalf("expected P95ms=250, got %d", tok.P95ms)
	}
	if tok.Health <= 0.80 {
		t.Fatalf("expected Health increased, got %.2f", tok.Health)
	}
}

func TestBrokerTokenFeedbackOpensBreakerWhenHealthTooLow(t *testing.T) {
	s := NewServer(9081, make(chan ApprovalRequest, 1))
	s.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "ci-runner-1", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name:   "pool_ci",
			Tokens: []BrokerTokenState{{ID: "tok-low", Enabled: true, Health: 0.10, RemainingRPH: 5, P95ms: 10}},
		}},
	})

	s.MarkBrokerTokenExchangeResult("tok-low", false, "")

	st := s.BrokerState()
	tok := st.Pools[0].Tokens[0]
	if tok.LastTest != "fail" {
		t.Fatalf("expected LastTest=fail, got %s", tok.LastTest)
	}
	if tok.SessionState != "exchange-fail" {
		t.Fatalf("expected SessionState=exchange-fail, got %s", tok.SessionState)
	}
	if !tok.BreakerOpen {
		t.Fatalf("expected BreakerOpen=true when health too low, got false")
	}
}

func TestBrokerTokenFeedbackFailureKeepsSourceContext(t *testing.T) {
	s := NewServer(9081, make(chan ApprovalRequest, 1))
	s.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "ci-runner-1", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name:   "pool_ci",
			Tokens: []BrokerTokenState{{ID: "tok-mid", Enabled: true, Health: 0.50, RemainingRPH: 5, P95ms: 10}},
		}},
	})

	s.MarkBrokerTokenExchangeResult("tok-mid", false, "pat:PAT_MID")

	st := s.BrokerState()
	tok := st.Pools[0].Tokens[0]
	if tok.SessionState != "exchange-fail:pat:PAT_MID" {
		t.Fatalf("expected SessionState to include failure source, got %s", tok.SessionState)
	}
}

func TestBrokerCounters_SelectionAndSessionFlow(t *testing.T) {
	exchangeCalls := 0
	srvExchange := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchangeCalls++
		if r.Header.Get("Authorization") != "Bearer ghu_best_pat" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"bad auth"}`))
			return
		}
		_, _ = w.Write([]byte(`{"token":"session_abc"}`))
	}))
	defer srvExchange.Close()

	s := NewServer(9081, make(chan ApprovalRequest, 1))
	s.SetBrokerState(BrokerState{
		ExchangeEndpoint: srvExchange.URL,
		Groups:           []BrokerGroupState{{Name: "ci-*", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name:   "pool_ci",
			Tokens: []BrokerTokenState{{ID: "tok-ci", Enabled: true, Health: 0.9, RemainingRPH: 100, PATEnv: "PAT_BEST"}},
		}},
	})
	t.Setenv("PAT_BEST", "ghu_best_pat")

	tok, matched, ok, reason := s.SelectBrokerToken("ci-runner-9", "gpt-5-mini", "")
	if !matched || !ok || reason != "" {
		t.Fatalf("expected matched+ok, got matched=%v ok=%v reason=%q", matched, ok, reason)
	}
	if _, _, err := s.AcquireBrokerSessionToken(tok); err != nil {
		t.Fatalf("acquire session failed: %v", err)
	}
	// second acquire should be cache hit
	if _, _, err := s.AcquireBrokerSessionToken(tok); err != nil {
		t.Fatalf("second acquire failed: %v", err)
	}
	s.MarkBrokerTokenExchangeResult(tok.ID, true, "exchange:PAT_BEST")
	s.MarkBrokerTokenRequestResult(tok.ID, http.StatusOK, 120*time.Millisecond)

	c := s.BrokerCounters()
	if c["select_ok"] == 0 {
		t.Fatalf("expected select_ok counter > 0, got %v", c)
	}
	if c["session_exchange_ok"] == 0 {
		t.Fatalf("expected session_exchange_ok counter > 0, got %v", c)
	}
	if c["session_cache_hit"] == 0 {
		t.Fatalf("expected session_cache_hit counter > 0, got %v", c)
	}
	if c["exchange_ok"] == 0 {
		t.Fatalf("expected exchange_ok counter > 0, got %v", c)
	}
	if c["request_ok"] == 0 {
		t.Fatalf("expected request_ok counter > 0, got %v", c)
	}
	groupSelectFound := false
	for k, v := range c {
		if strings.HasPrefix(k, "group.") && strings.HasSuffix(k, ".select_ok") && v > 0 {
			groupSelectFound = true
			break
		}
	}
	if !groupSelectFound {
		t.Fatalf("expected per-group select_ok counter, got %v", c)
	}
	if exchangeCalls != 1 {
		t.Fatalf("expected one real exchange call, got %d", exchangeCalls)
	}

	w5m := s.BrokerCountersWindow(5 * time.Minute)
	if len(w5m) == 0 {
		t.Fatalf("expected non-empty 5m window counters, got %v", w5m)
	}
	if w5m["select_ok"] == 0 {
		t.Fatalf("expected select_ok in 5m window, got %v", w5m)
	}
	if w5m["request_ok"] == 0 {
		t.Fatalf("expected request_ok in 5m window, got %v", w5m)
	}

	s.ResetBrokerCounters()
	if got := s.BrokerCounters(); len(got) != 0 {
		t.Fatalf("expected counters reset to empty, got %v", got)
	}
	if got := s.BrokerCountersWindow(5 * time.Minute); len(got) != 0 {
		t.Fatalf("expected window counters reset to empty, got %v", got)
	}
}
