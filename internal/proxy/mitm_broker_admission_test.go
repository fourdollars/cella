package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMITMHandler_BlocksByBrokerAdmission(t *testing.T) {
	srv := NewServer(9081, make(chan ApprovalRequest, 1))
	srv.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "ci-runner-1", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name:   "pool_ci",
			Tokens: []BrokerTokenState{{ID: "tok1", Enabled: false, Health: 0.1, RemainingRPH: 0}},
		}},
	})

	h := &mitmHandler{
		domain:    "api.business.githubcopilot.com",
		container: "ci-runner-1",
		server:    srv,
		stats:     NewInferenceStats(),
		routes:    NewRouteTable(),
	}

	req := httptest.NewRequest(http.MethodPost, "https://api.business.githubcopilot.com/responses", strings.NewReader(`{"model":"gpt-5-mini","input":"hello"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "broker_no_healthy_tokens") {
		t.Fatalf("expected broker reason in body, got %s", string(body))
	}
}

func TestMITMHandler_BlocksByBrokerAdmission_GroupGlobPattern(t *testing.T) {
	srv := NewServer(9081, make(chan ApprovalRequest, 1))
	srv.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "ci-*", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name:   "pool_ci",
			Tokens: []BrokerTokenState{{ID: "tok1", Enabled: false, Health: 0.1, RemainingRPH: 0}},
		}},
	})

	h := &mitmHandler{
		domain:    "api.business.githubcopilot.com",
		container: "ci-runner-42",
		server:    srv,
		stats:     NewInferenceStats(),
		routes:    NewRouteTable(),
	}

	req := httptest.NewRequest(http.MethodPost, "https://api.business.githubcopilot.com/responses", strings.NewReader(`{"model":"gpt-5-mini","input":"hello"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 429 with glob-mapped group, got %d body=%s", resp.StatusCode, string(body))
	}
}

func TestMITMHandler_AllowsWhenNoGroupMatch_AndCanReachUpstreamRoute(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"gpt-5-mini","usage":{"prompt_tokens":1,"completion_tokens":2},"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer up.Close()

	backendHost := strings.TrimPrefix(up.URL, "http://")

	srv := NewServer(9081, make(chan ApprovalRequest, 1))
	srv.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "mapped-container", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name:   "pool_ci",
			Tokens: []BrokerTokenState{{ID: "tok1", Enabled: false, Health: 0.1, RemainingRPH: 0}},
		}},
	})
	rt := NewRouteTable()
	rt.Add(InferenceRoute{SourceDomain: "api.business.githubcopilot.com", BackendHost: backendHost, BackendScheme: "http", Enabled: true})

	h := &mitmHandler{
		domain:    "api.business.githubcopilot.com",
		container: "another-container", // no exact group match -> broker check should not block
		server:    srv,
		stats:     NewInferenceStats(),
		routes:    rt,
	}

	req := httptest.NewRequest(http.MethodPost, "https://api.business.githubcopilot.com/responses", strings.NewReader(`{"model":"gpt-5-mini","input":"hello"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, string(body))
	}
}

func TestMITMHandler_MappedContainerForwardsSelectedBrokerTokenHeader(t *testing.T) {
	gotTokenID := ""
	gotPATEnv := ""
	gotAuth := ""
	gotAuthSource := ""
	exchangeCalls := 0

	exchange := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchangeCalls++
		if r.Header.Get("Authorization") != "Bearer ghu_best_pat" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"bad auth"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"session_best"}`))
	}))
	defer exchange.Close()

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTokenID = r.Header.Get("X-Cella-Broker-Token-ID")
		gotPATEnv = r.Header.Get("X-Cella-Broker-PAT-Env")
		gotAuth = r.Header.Get("Authorization")
		gotAuthSource = r.Header.Get("X-Cella-Broker-Auth-Source")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"gpt-5-mini","usage":{"prompt_tokens":1,"completion_tokens":2},"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer up.Close()

	backendHost := strings.TrimPrefix(up.URL, "http://")
	t.Setenv("PAT_BEST", "ghu_best_pat")

	srv := NewServer(9081, make(chan ApprovalRequest, 1))
	srv.SetBrokerState(BrokerState{
		ExchangeEndpoint: exchange.URL,
		Groups:           []BrokerGroupState{{Name: "ci-runner-1", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name: "pool_ci",
			Tokens: []BrokerTokenState{
				{ID: "tok-small", Enabled: true, Health: 0.9, RemainingRPH: 50, P95ms: 20, PATEnv: "PAT_SMALL"},
				{ID: "tok-best", Enabled: true, Health: 0.95, RemainingRPH: 200, P95ms: 10, PATEnv: "PAT_BEST"},
			},
		}},
	})
	rt := NewRouteTable()
	rt.Add(InferenceRoute{SourceDomain: "api.business.githubcopilot.com", BackendHost: backendHost, BackendScheme: "http", Enabled: true})

	h := &mitmHandler{
		domain:    "api.business.githubcopilot.com",
		container: "ci-runner-1",
		server:    srv,
		stats:     NewInferenceStats(),
		routes:    rt,
	}

	// first request: should exchange and cache
	req1 := httptest.NewRequest(http.MethodPost, "https://api.business.githubcopilot.com/responses", strings.NewReader(`{"model":"gpt-5-mini","input":"hello"}`))
	req1.Header.Set("Content-Type", "application/json")
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	resp1 := rr1.Result()
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp1.Body)
		t.Fatalf("expected first request 200, got %d body=%s", resp1.StatusCode, string(body))
	}

	// second request: should hit cache (exchange call count remains 1)
	req2 := httptest.NewRequest(http.MethodPost, "https://api.business.githubcopilot.com/responses", strings.NewReader(`{"model":"gpt-5-mini","input":"hello again"}`))
	req2.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	resp2 := rr2.Result()
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("expected second request 200, got %d body=%s", resp2.StatusCode, string(body))
	}

	if gotTokenID != "tok-best" {
		t.Fatalf("expected selected token header tok-best, got %q", gotTokenID)
	}
	if gotPATEnv != "PAT_BEST" {
		t.Fatalf("expected selected PAT env header PAT_BEST, got %q", gotPATEnv)
	}
	if gotAuth != "Bearer session_best" {
		t.Fatalf("expected rewritten Authorization Bearer session_best, got %q", gotAuth)
	}
	if !strings.Contains(gotAuthSource, "PAT_BEST") {
		t.Fatalf("expected auth source to include PAT_BEST, got %q", gotAuthSource)
	}
	if exchangeCalls != 1 {
		t.Fatalf("expected one exchange call due to cache, got %d", exchangeCalls)
	}

	st := srv.BrokerState()
	if len(st.Pools) == 0 || len(st.Pools[0].Tokens) < 2 {
		t.Fatalf("unexpected broker state pools: %+v", st.Pools)
	}
	var tokBest BrokerTokenState
	for _, tkn := range st.Pools[0].Tokens {
		if tkn.ID == "tok-best" {
			tokBest = tkn
			break
		}
	}
	if tokBest.ID != "tok-best" {
		t.Fatalf("tok-best not found in runtime state")
	}
	if tokBest.RemainingRPH != 198 {
		t.Fatalf("expected RemainingRPH decreased to 198 after two requests, got %d", tokBest.RemainingRPH)
	}
	if tokBest.LastTest != "ok" {
		t.Fatalf("expected LastTest=ok after exchange, got %s", tokBest.LastTest)
	}
	if tokBest.SessionState != "in-use" {
		t.Fatalf("expected SessionState=in-use, got %s", tokBest.SessionState)
	}
}

func TestMITMHandler_CopilotExchangePathRewritesDummyAuthWithBrokerPAT(t *testing.T) {
	gotAuth := ""
	gotAuthSource := ""
	gotTokenID := ""

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAuthSource = r.Header.Get("X-Cella-Broker-Auth-Source")
		gotTokenID = r.Header.Get("X-Cella-Broker-Token-ID")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"session_from_github","expires_at":1893456000}`))
	}))
	defer up.Close()

	backendHost := strings.TrimPrefix(up.URL, "http://")
	t.Setenv("PAT_BEST", "ghu_best_pat")

	srv := NewServer(9081, make(chan ApprovalRequest, 1))
	srv.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "ci-runner-1", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name:   "pool_ci",
			Tokens: []BrokerTokenState{{ID: "tok-best", Enabled: true, Health: 0.90, RemainingRPH: 200, PATEnv: "PAT_BEST"}},
		}},
	})
	rt := NewRouteTable()
	rt.Add(InferenceRoute{SourceDomain: "api.github.com", BackendHost: backendHost, BackendScheme: "http", Enabled: true})

	h := &mitmHandler{
		domain:    "api.github.com",
		container: "ci-runner-1",
		server:    srv,
		stats:     NewInferenceStats(),
		routes:    rt,
	}

	req := httptest.NewRequest(http.MethodGet, "https://api.github.com/copilot_internal/v2/token", nil)
	req.Header.Set("Authorization", "Bearer dummy-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "session_from_github") {
		t.Fatalf("expected proxied exchange response body, got %s", string(body))
	}
	if gotAuth != "Bearer ghu_best_pat" {
		t.Fatalf("expected Authorization rewritten to broker PAT, got %q", gotAuth)
	}
	if gotTokenID != "tok-best" {
		t.Fatalf("expected selected token header tok-best, got %q", gotTokenID)
	}
	if gotAuthSource != "pat:PAT_BEST" {
		t.Fatalf("expected auth source pat:PAT_BEST, got %q", gotAuthSource)
	}
	auditEntries := srv.Audit().All()
	if len(auditEntries) == 0 {
		t.Fatalf("expected audit entries")
	}
	last := auditEntries[len(auditEntries)-1]
	if last.BrokerTokenID != "tok-best" {
		t.Fatalf("expected audit broker token tok-best, got %q", last.BrokerTokenID)
	}
	if last.BrokerAuthSource != "pat:PAT_BEST" {
		t.Fatalf("expected audit broker source pat:PAT_BEST, got %q", last.BrokerAuthSource)
	}

	st := srv.BrokerState()
	if len(st.Pools) == 0 || len(st.Pools[0].Tokens) == 0 {
		t.Fatalf("unexpected broker state pools: %+v", st.Pools)
	}
	tok := st.Pools[0].Tokens[0]
	if tok.LastTest != "ok" {
		t.Fatalf("expected LastTest=ok for exchange path rewrite, got %s", tok.LastTest)
	}
	if !strings.Contains(tok.SessionState, "direct:api.github.com") {
		t.Fatalf("expected SessionState to record direct exchange source, got %s", tok.SessionState)
	}
	if tok.RemainingRPH != 200 {
		t.Fatalf("expected RemainingRPH unchanged for exchange path, got %d", tok.RemainingRPH)
	}
}

func TestMITMHandler_BlocksWhenBrokerSessionExchangeFails(t *testing.T) {
	exchange := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer exchange.Close()

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()

	backendHost := strings.TrimPrefix(up.URL, "http://")
	t.Setenv("PAT_BEST", "ghu_best_pat")

	srv := NewServer(9081, make(chan ApprovalRequest, 1))
	srv.SetBrokerState(BrokerState{
		ExchangeEndpoint: exchange.URL,
		Groups:           []BrokerGroupState{{Name: "ci-runner-1", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name:   "pool_ci",
			Tokens: []BrokerTokenState{{ID: "tok-best", Enabled: true, Health: 0.95, RemainingRPH: 200, P95ms: 10, PATEnv: "PAT_BEST"}},
		}},
	})
	rt := NewRouteTable()
	rt.Add(InferenceRoute{SourceDomain: "api.business.githubcopilot.com", BackendHost: backendHost, BackendScheme: "http", Enabled: true})

	h := &mitmHandler{
		domain:    "api.business.githubcopilot.com",
		container: "ci-runner-1",
		server:    srv,
		stats:     NewInferenceStats(),
		routes:    rt,
	}

	req := httptest.NewRequest(http.MethodPost, "https://api.business.githubcopilot.com/responses", strings.NewReader(`{"model":"gpt-5-mini","input":"hello"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 429, got %d body=%s", resp.StatusCode, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "broker_exchange_failed") {
		t.Fatalf("expected broker_exchange_failed in body, got %s", string(body))
	}

	st := srv.BrokerState()
	if len(st.Pools) == 0 || len(st.Pools[0].Tokens) == 0 {
		t.Fatalf("unexpected broker state pools: %+v", st.Pools)
	}
	tok := st.Pools[0].Tokens[0]
	if tok.LastTest != "fail" {
		t.Fatalf("expected LastTest=fail after exchange failure, got %s", tok.LastTest)
	}
	if tok.SessionState != "exchange-fail:pat:PAT_BEST" {
		t.Fatalf("expected SessionState to include source, got %s", tok.SessionState)
	}
	if tok.Health >= 0.95 {
		t.Fatalf("expected Health to decrease after exchange failure, got %.2f", tok.Health)
	}
	auditEntries := srv.Audit().All()
	if len(auditEntries) == 0 {
		t.Fatalf("expected audit entries")
	}
	last := auditEntries[len(auditEntries)-1]
	if last.BrokerAuthSource != "pat:PAT_BEST" {
		t.Fatalf("expected audit broker source pat:PAT_BEST, got %q", last.BrokerAuthSource)
	}
}

func TestMITMHandler_CopilotExchangePath_PATResolveFailureCarriesAuditSource(t *testing.T) {
	srv := NewServer(9081, make(chan ApprovalRequest, 1))
	srv.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "ci-runner-1", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name:   "pool_ci",
			Tokens: []BrokerTokenState{{ID: "tok-missing", Enabled: true, Health: 0.90, RemainingRPH: 200, PATEnv: "MISSING_PAT"}},
		}},
	})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"should_not_hit"}`))
	}))
	defer up.Close()
	backendHost := strings.TrimPrefix(up.URL, "http://")
	rt := NewRouteTable()
	rt.Add(InferenceRoute{SourceDomain: "api.github.com", BackendHost: backendHost, BackendScheme: "http", Enabled: true})

	h := &mitmHandler{
		domain:    "api.github.com",
		container: "ci-runner-1",
		server:    srv,
		stats:     NewInferenceStats(),
		routes:    rt,
	}

	req := httptest.NewRequest(http.MethodGet, "https://api.github.com/copilot_internal/v2/token", nil)
	req.Header.Set("Authorization", "Bearer dummy-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 429, got %d body=%s", resp.StatusCode, string(body))
	}

	auditEntries := srv.Audit().All()
	if len(auditEntries) == 0 {
		t.Fatalf("expected audit entries")
	}
	last := auditEntries[len(auditEntries)-1]
	if last.BrokerAuthSource != "pat:MISSING_PAT" {
		t.Fatalf("expected audit broker source pat:MISSING_PAT, got %q", last.BrokerAuthSource)
	}

	st := srv.BrokerState()
	tok := st.Pools[0].Tokens[0]
	if tok.SessionState != "exchange-fail:pat:MISSING_PAT" {
		t.Fatalf("expected SessionState to include source on PAT resolve failure, got %s", tok.SessionState)
	}
}

func TestMITMHandler_CopilotExchangePath_Upstream401KeepsSourceContext(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghu_best_pat" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"bad-auth"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"pat-rejected"}`))
	}))
	defer up.Close()

	backendHost := strings.TrimPrefix(up.URL, "http://")
	t.Setenv("PAT_BEST", "ghu_best_pat")

	srv := NewServer(9081, make(chan ApprovalRequest, 1))
	srv.SetBrokerState(BrokerState{
		Groups: []BrokerGroupState{{Name: "ci-runner-1", Pool: "pool_ci", Weight: 1}},
		Pools: []BrokerPoolState{{
			Name:   "pool_ci",
			Tokens: []BrokerTokenState{{ID: "tok-best", Enabled: true, Health: 0.95, RemainingRPH: 200, PATEnv: "PAT_BEST"}},
		}},
	})
	rt := NewRouteTable()
	rt.Add(InferenceRoute{SourceDomain: "api.github.com", BackendHost: backendHost, BackendScheme: "http", Enabled: true})

	h := &mitmHandler{
		domain:    "api.github.com",
		container: "ci-runner-1",
		server:    srv,
		stats:     NewInferenceStats(),
		routes:    rt,
	}

	req := httptest.NewRequest(http.MethodGet, "https://api.github.com/copilot_internal/v2/token", nil)
	req.Header.Set("Authorization", "Bearer dummy-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	resp := rr.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 passthrough, got %d body=%s", resp.StatusCode, string(body))
	}

	auditEntries := srv.Audit().All()
	if len(auditEntries) == 0 {
		t.Fatalf("expected audit entries")
	}
	last := auditEntries[len(auditEntries)-1]
	if last.RespCode != http.StatusUnauthorized {
		t.Fatalf("expected audit resp code 401, got %d", last.RespCode)
	}
	if last.BrokerAuthSource != "pat:PAT_BEST" {
		t.Fatalf("expected audit broker source pat:PAT_BEST, got %q", last.BrokerAuthSource)
	}

	st := srv.BrokerState()
	tok := st.Pools[0].Tokens[0]
	if tok.LastTest != "fail" {
		t.Fatalf("expected LastTest=fail after upstream 401, got %s", tok.LastTest)
	}
	if tok.SessionState != "exchange-fail:direct:api.github.com|pat:PAT_BEST" {
		t.Fatalf("expected SessionState to include direct+pat source, got %s", tok.SessionState)
	}
}
