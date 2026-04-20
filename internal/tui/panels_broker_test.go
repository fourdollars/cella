package tui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/fourdoors/cella/internal/proxy"
)

func keyRune(r rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
}

func keyEnter() tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyEnter}
}

func keyBackspace() tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyBackspace}
}

func seedBrokerTestData(a *App) {
	if len(a.brokerPools) == 0 {
		a.brokerPools = []BrokerPool{{
			Name: "pool_test",
			Tokens: []BrokerToken{{
				ID:           "tok_test_1",
				Enabled:      true,
				Health:       0.90,
				RemainingRPH: 300,
				SessionState: "fresh",
				LastTest:     "ok",
				PATEnv:       "CELLA_BROKER_TEST_PAT",
				P95ms:        120,
			}},
		}}
	}
	if len(a.brokerGroups) == 0 {
		a.brokerGroups = []BrokerGroup{{
			ID:       "team-a",
			Name:     "team-a",
			Match:    "team-a",
			Pool:     a.brokerPools[0].Name,
			Weight:   1,
			RPHLimit: 1000,
		}}
	}
	if len(a.brokerPolicies) == 0 {
		a.brokerPolicies = []BrokerPolicy{{
			Name:     "policy_a",
			Group:    a.brokerGroups[0].ID,
			Pool:     a.brokerPools[0].Name,
			Strategy: "weighted_least_load",
			Sticky:   true,
			Retry:    1,
		}}
	}
	if a.brokerExchangeMode == "" {
		a.brokerExchangeMode = "mock"
	}
	if a.brokerExchangeEndpoint == "" {
		a.brokerExchangeEndpoint = brokerDefaultExchangeEndpoint()
	}
	a.normalizeBrokerGroupsAndPolicies()
	a.clampBrokerCursors()
	s := a.captureBrokerSnapshot()
	a.brokerLastApplied = &s
}

func newBrokerTestApp(t *testing.T, isolateHome bool) App {
	t.Helper()
	// Always isolate HOME in tests to prevent host ~/.cella/ pollution
	t.Setenv("HOME", t.TempDir())
	a := App{width: 140}
	a.initBrokerDefaults()
	seedBrokerTestData(&a)
	return a
}

func TestBrokerInitDefaultsEmptyWhenNoState(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	a := App{width: 140}
	a.initBrokerDefaults()
	if len(a.brokerGroups) != 0 || len(a.brokerPools) != 0 || len(a.brokerPolicies) != 0 {
		t.Fatalf("expected empty bootstrap defaults, got groups=%d pools=%d policies=%d", len(a.brokerGroups), len(a.brokerPools), len(a.brokerPolicies))
	}
	if a.brokerExchangeMode != "mock" || a.brokerExchangeEndpoint == "" {
		t.Fatalf("expected exchange defaults set, mode=%s endpoint=%s", a.brokerExchangeMode, a.brokerExchangeEndpoint)
	}
}

func TestBrokerDefaultsAndRender(t *testing.T) {
	a := newBrokerTestApp(t, false)
	if len(a.brokerGroups) == 0 || len(a.brokerPools) == 0 || len(a.brokerPolicies) == 0 {
		t.Fatalf("broker seeded test data not initialized")
	}
	if a.brokerExchangeMode == "" || a.brokerExchangeEndpoint == "" {
		t.Fatalf("exchange defaults not initialized")
	}
	out := a.renderBrokerPanel()
	if out == "" {
		t.Fatalf("unexpected empty render output")
	}
}

func TestBrokerSnapshotRollback(t *testing.T) {
	a := newBrokerTestApp(t, false)
	orig := a.captureBrokerSnapshot()
	a.brokerGroups[0].Weight = 99
	a.brokerGroups[0].Pool = "pool_ci"
	a.restoreBrokerSnapshot(orig)
	if a.brokerGroups[0].Weight == 99 || a.brokerGroups[0].Pool == "pool_ci" {
		t.Fatalf("rollback failed: %+v", a.brokerGroups[0])
	}
}

func TestBrokerApplyConfirmFlow(t *testing.T) {
	a := newBrokerTestApp(t, true)
	a.brokerGroups[0].Weight++
	a.brokerDirty = true
	a.handleBrokerPanel(keyRune('S'))
	if !a.brokerApplyConfirm {
		t.Fatalf("expected brokerApplyConfirm=true after S")
	}
	a.handleBrokerPanel(keyRune('y'))
	if a.brokerApplyConfirm || a.brokerDirty {
		t.Fatalf("expected clean state after confirm apply")
	}
	if a.brokerLastApplied == nil {
		t.Fatalf("expected last applied snapshot")
	}
}

func TestBrokerApplyCancelFlow(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.brokerGroups[0].Weight++
	a.brokerDirty = true
	a.handleBrokerPanel(keyRune('S'))
	if !a.brokerApplyConfirm {
		t.Fatalf("expected confirm mode")
	}
	a.handleBrokerPanel(keyRune('n'))
	if a.brokerApplyConfirm {
		t.Fatalf("expected confirm canceled")
	}
	if !a.brokerDirty {
		t.Fatalf("cancel should keep dirty state")
	}
}

func TestBrokerGroupClearAllConfirmFlow(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('1')) // Groups tab

	if len(a.brokerGroups) == 0 {
		t.Fatalf("expected default groups")
	}
	a.handleBrokerPanel(keyRune('x'))
	if !a.brokerClearGroupsConfirm {
		t.Fatalf("expected clear-all confirm mode")
	}
	a.handleBrokerPanel(keyRune('y'))
	if a.brokerClearGroupsConfirm {
		t.Fatalf("expected clear-all confirm ended")
	}
	if len(a.brokerGroups) != 0 {
		t.Fatalf("expected all groups cleared, got %d", len(a.brokerGroups))
	}
	if len(a.brokerPolicies) != 0 {
		t.Fatalf("expected policies cleared after all groups removed, got %d", len(a.brokerPolicies))
	}
	if !a.brokerDirty {
		t.Fatalf("expected draft dirty after clear-all")
	}
	out := a.renderBrokerPanel()
	if !strings.Contains(out, "No groups configured") {
		t.Fatalf("expected empty-group hint in render, got: %s", out)
	}
}

func TestBrokerGroupClearAllCancelFlow(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('1')) // Groups tab

	beforeGroups := len(a.brokerGroups)
	a.handleBrokerPanel(keyRune('x'))
	if !a.brokerClearGroupsConfirm {
		t.Fatalf("expected clear-all confirm mode")
	}
	a.handleBrokerPanel(keyRune('n'))
	if a.brokerClearGroupsConfirm {
		t.Fatalf("expected clear-all confirm canceled")
	}
	if len(a.brokerGroups) != beforeGroups {
		t.Fatalf("expected groups unchanged after cancel")
	}
}

func TestBrokerPolicyAddBlockedWhenNoGroup(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('1'))
	a.handleBrokerPanel(keyRune('x'))
	a.handleBrokerPanel(keyRune('y'))

	a.handleBrokerPanel(keyRune('3')) // Policy tab
	before := len(a.brokerPolicies)
	a.handleBrokerPanel(keyRune('a'))
	if len(a.brokerPolicies) != before {
		t.Fatalf("expected add policy blocked when no groups, before=%d after=%d", before, len(a.brokerPolicies))
	}
}

func TestBrokerPoolAddDeleteKeys(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('2'))

	beforePools := len(a.brokerPools)
	a.handleBrokerPanel(keyRune('n'))
	if len(a.brokerPools) != beforePools+1 {
		t.Fatalf("expected pool count %d, got %d", beforePools+1, len(a.brokerPools))
	}
	addedName := a.brokerPools[len(a.brokerPools)-1].Name
	if !strings.HasPrefix(addedName, "pool_") {
		t.Fatalf("expected generated pool name, got %s", addedName)
	}

	// Remove current pool via Z
	a.handleBrokerPanel(keyRune('z'))
	if len(a.brokerPools) != beforePools {
		t.Fatalf("expected pool count back to %d, got %d", beforePools, len(a.brokerPools))
	}
}

func TestBrokerPoolAddDeleteTokenKeys(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('2'))
	pool := a.brokerCurrentPool()
	if pool == nil {
		t.Fatalf("expected pool")
	}
	before := len(pool.Tokens)
	a.handleBrokerPanel(keyRune('a'))
	if !a.brokerEditMode {
		t.Fatalf("expected broker edit mode after A")
	}
	if a.brokerEditKind != "token-add-id" {
		t.Fatalf("expected token-add-id mode, got %s", a.brokerEditKind)
	}
	for _, r := range "tok_manual_1" {
		a.handleBrokerPanel(keyRune(r))
	}
	a.handleBrokerPanel(keyEnter())
	if !a.brokerEditMode || a.brokerEditKind != "token-add-pat" {
		t.Fatalf("expected transition to token-add-pat mode")
	}
	for _, r := range "ghu_pat" {
		a.handleBrokerPanel(keyRune(r))
	}
	a.handleBrokerPanel(keyEnter())

	pool = a.brokerCurrentPool()
	if len(pool.Tokens) != before+1 {
		t.Fatalf("expected token count %d, got %d", before+1, len(pool.Tokens))
	}
	added := pool.Tokens[len(pool.Tokens)-1]
	if added.ID != "tok_manual_1" {
		t.Fatalf("expected manual token id tok_manual_1, got %s", added.ID)
	}
	if added.PATEnv == "" {
		t.Fatalf("expected PAT env assigned for added token")
	}
	if got := os.Getenv(added.PATEnv); got != "ghu_pat" {
		t.Fatalf("expected PAT stored in env %s, got %q", added.PATEnv, got)
	}

	a.handleBrokerPanel(keyRune('d'))
	pool = a.brokerCurrentPool()
	if len(pool.Tokens) != before {
		t.Fatalf("expected token count back to %d, got %d", before, len(pool.Tokens))
	}
}

func TestBrokerPoolAddTokenRequiresPATInput(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('2'))
	pool := a.brokerCurrentPool()
	if pool == nil {
		t.Fatalf("expected pool")
	}
	before := len(pool.Tokens)

	a.handleBrokerPanel(keyRune('a'))
	if !a.brokerEditMode || a.brokerEditKind != "token-add-id" {
		t.Fatalf("expected token-add-id edit mode")
	}
	a.handleBrokerPanel(keyEnter()) // empty token id
	if !a.brokerEditMode || a.brokerEditKind != "token-add-id" {
		t.Fatalf("expected stay in token-add-id mode when ID empty")
	}
	pool = a.brokerCurrentPool()
	if len(pool.Tokens) != before {
		t.Fatalf("expected token count unchanged when ID empty")
	}
	for _, r := range "tokx" {
		a.handleBrokerPanel(keyRune(r))
	}
	a.handleBrokerPanel(keyEnter())
	if !a.brokerEditMode || a.brokerEditKind != "token-add-pat" {
		t.Fatalf("expected transition to token-add-pat mode")
	}
	a.handleBrokerPanel(keyEnter()) // empty PAT
	if !a.brokerEditMode || a.brokerEditKind != "token-add-pat" {
		t.Fatalf("expected stay in token-add-pat mode when PAT empty")
	}
	pool = a.brokerCurrentPool()
	if len(pool.Tokens) != before {
		t.Fatalf("expected token count unchanged when PAT empty")
	}
	a.handleBrokerPanel(keyRune('x'))
	a.handleBrokerPanel(keyBackspace())
	a.handleBrokerPanel(keyRune('y'))
	a.handleBrokerPanel(keyEnter())
	pool = a.brokerCurrentPool()
	if len(pool.Tokens) != before+1 {
		t.Fatalf("expected token added after ID+PAT input, before=%d after=%d", before, len(pool.Tokens))
	}
}

func TestBrokerPoolAddTokenRequiresUniqueID(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('2'))
	pool := a.brokerCurrentPool()
	if pool == nil || len(pool.Tokens) == 0 {
		t.Fatalf("expected pool tokens")
	}
	before := len(pool.Tokens)
	existingID := pool.Tokens[0].ID

	a.handleBrokerPanel(keyRune('a'))
	if !a.brokerEditMode || a.brokerEditKind != "token-add-id" {
		t.Fatalf("expected token-add-id edit mode")
	}
	for _, r := range existingID {
		a.handleBrokerPanel(keyRune(r))
	}
	a.handleBrokerPanel(keyEnter())
	if !a.brokerEditMode || a.brokerEditKind != "token-add-id" {
		t.Fatalf("expected duplicate ID to stay in token-add-id mode")
	}
	pool = a.brokerCurrentPool()
	if len(pool.Tokens) != before {
		t.Fatalf("expected token count unchanged on duplicate ID")
	}
}

func TestBrokerExchangeModeToggleKey(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('2'))
	initial := a.brokerExchangeMode
	a.handleBrokerPanel(keyRune('m'))
	if a.brokerExchangeMode == initial {
		t.Fatalf("expected mode toggled")
	}
	a.handleBrokerPanel(keyRune('m'))
	if a.brokerExchangeMode != initial {
		t.Fatalf("expected mode toggled back")
	}
}

func TestBrokerTokenExchangeTestKeyMock(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('2'))
	pool := a.brokerCurrentPool()
	if pool == nil || len(pool.Tokens) < 1 {
		t.Fatalf("expected pool token")
	}

	pool.Tokens[a.brokerTokenCursor].BreakerOpen = true
	a.handleBrokerPanel(keyRune('t'))
	if pool.Tokens[a.brokerTokenCursor].LastTest != "fail" {
		t.Fatalf("expected failed exchange test")
	}

	pool.Tokens[a.brokerTokenCursor].BreakerOpen = false
	a.handleBrokerPanel(keyRune('t'))
	if pool.Tokens[a.brokerTokenCursor].LastTest != "ok" {
		t.Fatalf("expected successful exchange test")
	}
}

func TestBrokerTokenExchangeTestKeyRealSuccess(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('2'))
	a.brokerExchangeMode = "real"
	pool := a.brokerCurrentPool()
	if pool == nil || len(pool.Tokens) == 0 {
		t.Fatalf("expected pool token")
	}
	token := &pool.Tokens[a.brokerTokenCursor]
	if token.PATEnv == "" {
		token.PATEnv = "CELLA_BROKER_TEST_PAT"
	}
	t.Setenv(token.PATEnv, "ghu_test_pat")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer ghu_test_pat" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "bad auth"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "session_ok"})
	}))
	defer srv.Close()
	a.brokerExchangeEndpoint = srv.URL
	a.handleBrokerPanel(keyRune('t'))
	if token.LastTest != "ok" {
		t.Fatalf("expected real exchange test ok, got %s", token.LastTest)
	}
	if token.SessionState != "tested-ok-real" {
		t.Fatalf("expected tested-ok-real, got %s", token.SessionState)
	}
}

func TestBrokerTokenExchangeTestKeyRealNoPAT(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('2'))
	a.brokerExchangeMode = "real"
	a.brokerExchangeEndpoint = "http://127.0.0.1:1/unreachable"

	pool := a.brokerCurrentPool()
	a.handleBrokerPanel(keyRune('t'))
	if pool.Tokens[a.brokerTokenCursor].LastTest != "fail" {
		t.Fatalf("expected real exchange test fail when no PAT")
	}
	if pool.Tokens[a.brokerTokenCursor].SessionState != "real-no-pat" {
		t.Fatalf("expected real-no-pat, got %s", pool.Tokens[a.brokerTokenCursor].SessionState)
	}
}

func TestBrokerStatePersistRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	a := App{width: 140}
	a.initBrokerDefaults()
	a.brokerGroups = []BrokerGroup{{ID: "team-a", Name: "team-a", Match: "team-a", Pool: "pool_1", Weight: 7, RPHLimit: 2000}}
	a.brokerPools = []BrokerPool{{Name: "pool_1", Tokens: []BrokerToken{{ID: "tok_1", Enabled: true, Health: 0.9, RemainingRPH: 100}}}}
	a.brokerPolicies = []BrokerPolicy{{Name: "policy_1", Group: "team-a", Pool: "pool_1", Strategy: "weighted_least_load", Sticky: true, Retry: 1}}
	a.brokerExchangeMode = "real"
	a.brokerExchangeEndpoint = "http://example.local/token"
	if err := a.saveBrokerState(); err != nil {
		t.Fatalf("save broker state: %v", err)
	}

	b := App{width: 140}
	b.initBrokerDefaults() // load from persisted first
	if len(b.brokerGroups) == 0 || b.brokerGroups[0].Weight != 7 {
		t.Fatalf("unexpected loaded state: %+v", b.brokerGroups)
	}
	if len(b.brokerPools) != 1 || b.brokerPools[0].Name != "pool_1" {
		t.Fatalf("unexpected loaded pools: %+v", b.brokerPools)
	}
	if b.brokerExchangeMode != "real" || b.brokerExchangeEndpoint != "http://example.local/token" {
		t.Fatalf("unexpected exchange persisted state: mode=%s endpoint=%s", b.brokerExchangeMode, b.brokerExchangeEndpoint)
	}
}

func TestBrokerRuntimeStateIncludesGroupIDAndMatch(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.brokerGroups[0].ID = "group-ci"
	a.brokerGroups[0].Name = "legacy-ci"
	a.brokerGroups[0].Match = "prefix:ci-runner-"
	a.brokerPolicies[0].Group = "legacy-ci"

	st := a.brokerRuntimeState()
	if len(st.Groups) == 0 {
		t.Fatalf("expected runtime groups")
	}
	if st.Groups[0].ID != "group-ci" {
		t.Fatalf("expected runtime group id=group-ci, got %q", st.Groups[0].ID)
	}
	if st.Groups[0].Match != "prefix:ci-runner-" {
		t.Fatalf("expected runtime match rule preserved, got %q", st.Groups[0].Match)
	}
	if len(st.Policies) == 0 || st.Policies[0].Group != "group-ci" {
		t.Fatalf("expected policy group normalized to stable id, got %+v", st.Policies)
	}
}

func TestBrokerLoadEmptyStateDoesNotFallbackToTemplates(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	path := home + "/.cella/token_broker_state.json"
	if err := os.MkdirAll(home+"/.cella", 0o755); err != nil {
		t.Fatalf("mkdir .cella: %v", err)
	}
	emptyState := `{"groups":[],"pools":[],"policies":[],"exchange_mode":"mock"}`
	if err := os.WriteFile(path, []byte(emptyState), 0o644); err != nil {
		t.Fatalf("write empty state: %v", err)
	}

	a := App{width: 140}
	a.initBrokerDefaults()
	if len(a.brokerGroups) != 0 || len(a.brokerPools) != 0 || len(a.brokerPolicies) != 0 {
		t.Fatalf("expected empty state preserved, got groups=%d pools=%d policies=%d", len(a.brokerGroups), len(a.brokerPools), len(a.brokerPolicies))
	}
}

func TestBrokerLoadLegacyStateNormalizesGroupSchema(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	path := home + "/.cella/token_broker_state.json"
	if err := os.MkdirAll(home+"/.cella", 0o755); err != nil {
		t.Fatalf("mkdir .cella: %v", err)
	}
	legacy := `{
  "groups": [{"name":"prefix:ci-runner-","pool":"pool_ci","weight":1,"rph_limit":1200}],
  "pools": [{"name":"pool_ci","tokens":[{"id":"tok-ci","enabled":true,"health":0.9,"remaining_rph":100}]}],
  "policies": [{"name":"policy-ci","group":"prefix:ci-runner-","pool":"pool_ci","strategy":"weighted_least_load"}],
  "exchange_mode": "mock"
}`
	if err := os.WriteFile(path, []byte(legacy), 0o644); err != nil {
		t.Fatalf("write legacy state: %v", err)
	}

	a := App{width: 140}
	a.initBrokerDefaults()
	if len(a.brokerGroups) == 0 {
		t.Fatalf("expected loaded legacy group")
	}
	g := a.brokerGroups[0]
	if g.ID == "" || g.Match == "" {
		t.Fatalf("expected normalized id/match, got %+v", g)
	}
	if len(a.brokerPolicies) == 0 || a.brokerPolicies[0].Group != g.ID {
		t.Fatalf("expected policy normalized to group id %q, got %+v", g.ID, a.brokerPolicies)
	}
}

func TestBrokerKeySequenceOperation(t *testing.T) {
	a := newBrokerTestApp(t, true)
	a.focus = panelBroker

	a.handleBrokerPanel(keyRune('2'))
	pool := a.brokerCurrentPool()
	if pool == nil || len(pool.Tokens) == 0 {
		t.Fatalf("expected pool tokens")
	}
	beforeEnabled := pool.Tokens[a.brokerTokenCursor].Enabled
	a.handleBrokerPanel(keyRune('x'))
	afterEnabled := pool.Tokens[a.brokerTokenCursor].Enabled
	if beforeEnabled == afterEnabled {
		t.Fatalf("token toggle did not apply")
	}

	a.handleBrokerPanel(keyRune('p'))
	if len(a.brokerPreviewLines) == 0 {
		t.Fatalf("preview not generated")
	}

	a.handleBrokerPanel(keyRune('v'))
	if len(a.brokerPreviewLines) == 0 {
		t.Fatalf("drift preview not generated")
	}

	a.handleBrokerPanel(keyRune('S'))
	if !a.brokerApplyConfirm {
		t.Fatalf("expected apply confirm")
	}
	a.handleBrokerPanel(keyRune('y'))
	if a.brokerApplyConfirm || a.brokerDirty {
		t.Fatalf("expected applied clean state")
	}

	pool = a.brokerCurrentPool()
	pool.Tokens[a.brokerTokenCursor].BreakerOpen = !pool.Tokens[a.brokerTokenCursor].BreakerOpen
	a.brokerDirty = true
	a.handleBrokerPanel(keyRune('U'))
	if a.brokerDirty {
		t.Fatalf("expected rollback clean state")
	}
}

func TestBrokerPolicyKeyAddDeleteAndCycleMappings(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('3')) // Policy tab

	if len(a.brokerPolicies) == 0 {
		t.Fatalf("expected default policies")
	}
	baseCount := len(a.brokerPolicies)
	orig := a.brokerPolicies[a.brokerPolicyCursor]

	// ensure cycle keys have multiple targets
	a.brokerPools = append(a.brokerPools, BrokerPool{Name: "pool_alt", Tokens: []BrokerToken{{ID: "tok_alt_1", Enabled: true, Health: 0.9, RemainingRPH: 100, PATEnv: "CELLA_BROKER_TEST_PAT"}}})
	a.brokerGroups = append(a.brokerGroups, BrokerGroup{ID: "team-b", Name: "team-b", Match: "team-b", Pool: "pool_alt", Weight: 1, RPHLimit: 1000})
	a.normalizeBrokerGroupsAndPolicies()

	a.handleBrokerPanel(keyRune('a'))
	if len(a.brokerPolicies) != baseCount+1 {
		t.Fatalf("expected add policy count=%d, got %d", baseCount+1, len(a.brokerPolicies))
	}
	added := a.brokerPolicies[a.brokerPolicyCursor]
	if added.Name == "" {
		t.Fatalf("expected generated policy name")
	}
	if added.Group == "" || added.Pool == "" {
		t.Fatalf("expected generated policy mapping, got %+v", added)
	}

	beforePool := added.Pool
	a.handleBrokerPanel(keyRune('l'))
	afterPool := a.brokerPolicies[a.brokerPolicyCursor].Pool
	if beforePool == afterPool {
		t.Fatalf("expected pool cycle via l key")
	}

	beforeGroup := a.brokerPolicies[a.brokerPolicyCursor].Group
	a.handleBrokerPanel(keyRune('g'))
	afterGroup := a.brokerPolicies[a.brokerPolicyCursor].Group
	if beforeGroup == afterGroup {
		t.Fatalf("expected group cycle via g key")
	}

	a.handleBrokerPanel(keyRune('d'))
	if len(a.brokerPolicies) != baseCount {
		t.Fatalf("expected delete policy count=%d, got %d", baseCount, len(a.brokerPolicies))
	}
	if a.brokerPolicies[0].Name != orig.Name {
		t.Fatalf("expected original policy still present after add/delete flow")
	}
}

func TestBrokerPolicyProfileCycleKey(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('3')) // Policy tab

	if len(a.brokerPolicies) == 0 {
		t.Fatalf("expected policies")
	}
	p := a.brokerPolicies[a.brokerPolicyCursor]
	beforeProfile := brokerPolicyProfileLabel(p)
	beforeStrategy := p.Strategy
	beforeSticky := p.Sticky
	beforeRetry := p.Retry

	a.handleBrokerPanel(keyRune('o'))
	p = a.brokerPolicies[a.brokerPolicyCursor]
	afterProfile := brokerPolicyProfileLabel(p)
	if beforeProfile == afterProfile {
		t.Fatalf("expected profile label changed, still %s", afterProfile)
	}
	if p.Strategy == beforeStrategy && p.Sticky == beforeSticky && p.Retry == beforeRetry {
		t.Fatalf("expected profile key to change policy tuple")
	}
}

func TestBrokerPATEnvKeyAssignment(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('2'))
	pool := a.brokerCurrentPool()
	if pool == nil || len(pool.Tokens) == 0 {
		t.Fatalf("expected pool token")
	}

	a.handleBrokerPanel(keyRune('e'))
	if pool.Tokens[a.brokerTokenCursor].PATEnv == "" || pool.Tokens[a.brokerTokenCursor].PATEnv == "CELLA_BROKER_TEST_PAT" {
		t.Fatalf("expected token-specific PAT env after E key, got %q", pool.Tokens[a.brokerTokenCursor].PATEnv)
	}

	a.handleBrokerPanel(keyRune('g'))
	if pool.Tokens[a.brokerTokenCursor].PATEnv != "CELLA_BROKER_TEST_PAT" {
		t.Fatalf("expected global PAT env after G key, got %q", pool.Tokens[a.brokerTokenCursor].PATEnv)
	}
}

func TestBrokerTokenExchangeRealUsesTokenSpecificPATEnv(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('2'))
	a.brokerExchangeMode = "real"

	pool := a.brokerCurrentPool()
	if pool == nil || len(pool.Tokens) == 0 {
		t.Fatalf("expected pool token")
	}

	// Set different values: token-specific env should win over global env
	pool.Tokens[a.brokerTokenCursor].PATEnv = "CELLA_BROKER_PAT_TOKENX"
	t.Setenv("CELLA_BROKER_PAT_TOKENX", "ghu_token_specific")
	t.Setenv("CELLA_BROKER_TEST_PAT", "ghu_global_fallback")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer ghu_token_specific" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "wrong auth"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "session_ok"})
	}))
	defer srv.Close()
	a.brokerExchangeEndpoint = srv.URL

	a.handleBrokerPanel(keyRune('t'))
	if pool.Tokens[a.brokerTokenCursor].LastTest != "ok" {
		t.Fatalf("expected real exchange to use token-specific PAT env")
	}
}

func TestBrokerApplySyncsRuntimeStateToProxyServer(t *testing.T) {
	a := newBrokerTestApp(t, true)
	a.focus = panelBroker

	oldProxy := globalProxyServer
	globalProxyServer = proxy.NewServer(19081, make(chan proxy.ApprovalRequest, 1))
	defer func() { globalProxyServer = oldProxy }()

	a.brokerExchangeMode = "real"
	a.brokerExchangeEndpoint = "https://example.test/token"
	a.brokerGroups[0].Weight = 5
	a.brokerDirty = true

	a.handleBrokerPanel(keyRune('S'))
	if !a.brokerApplyConfirm {
		t.Fatalf("expected apply confirm")
	}
	a.handleBrokerPanel(keyRune('y'))

	st := globalProxyServer.BrokerState()
	if st.ExchangeMode != "real" || st.ExchangeEndpoint != "https://example.test/token" {
		t.Fatalf("unexpected runtime exchange state: %+v", st)
	}
	if len(st.Groups) == 0 || st.Groups[0].Weight != 5 {
		t.Fatalf("unexpected runtime group state: %+v", st.Groups)
	}
}

func TestBrokerRenderShowsExchangeModeAndEndpoint(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('2')) // Pools tab
	a.brokerExchangeMode = "real"
	a.brokerExchangeEndpoint = "https://example.test/token"

	out := a.renderBrokerPanel()
	if !strings.Contains(out, "Exchange mode: real") {
		t.Fatalf("render should show exchange mode, got: %s", out)
	}
	if !strings.Contains(out, "https://example.test/token") {
		t.Fatalf("render should show exchange endpoint, got: %s", out)
	}
}

func TestBrokerRuntimePreviewKey(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker

	oldProxy := globalProxyServer
	globalProxyServer = proxy.NewServer(19082, make(chan proxy.ApprovalRequest, 1))
	defer func() { globalProxyServer = oldProxy }()

	globalProxyServer.SetBrokerState(proxy.BrokerState{
		ExchangeMode: "real",
		Groups:       []proxy.BrokerGroupState{{Name: "team-a", Pool: "pool_alpha", Weight: 1}},
		Pools: []proxy.BrokerPoolState{{
			Name:   "pool_alpha",
			Tokens: []proxy.BrokerTokenState{{ID: "tok_a1", Enabled: true, Health: 0.91, RemainingRPH: 321, SessionState: "in-use", LastTest: "ok"}},
		}},
	})

	a.handleBrokerPanel(keyRune('R'))
	if len(a.brokerPreviewLines) == 0 {
		t.Fatalf("expected runtime preview lines")
	}
	if !strings.Contains(strings.Join(a.brokerPreviewLines, "\n"), "Runtime broker state") {
		t.Fatalf("expected runtime preview text, got: %v", a.brokerPreviewLines)
	}
}

func TestBrokerRuntimeDriftKeyDetectsChanges(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker

	oldProxy := globalProxyServer
	globalProxyServer = proxy.NewServer(19086, make(chan proxy.ApprovalRequest, 1))
	defer func() { globalProxyServer = oldProxy }()

	globalProxyServer.SetBrokerState(proxy.BrokerState{
		ExchangeMode:     "real",
		ExchangeEndpoint: "https://example.runtime/token",
		Groups: []proxy.BrokerGroupState{{
			ID: "team-a", Match: "prefix:team-a-", Pool: "pool_beta", Weight: 9, RPHLimit: 9999,
		}},
		Pools: []proxy.BrokerPoolState{{
			Name:   "pool_beta",
			Tokens: []proxy.BrokerTokenState{{ID: "tok_runtime_only", Enabled: true, Health: 0.95, RemainingRPH: 200}},
		}},
		Policies: []proxy.BrokerPolicyState{{Name: "policy_a", Group: "team-a", Pool: "pool_beta", Strategy: "round_robin", Sticky: false, Retry: 2}},
	})

	a.handleBrokerPanel(keyRune('V'))
	preview := strings.Join(a.brokerPreviewLines, "\n")
	if !strings.Contains(preview, "Drift detected:") {
		t.Fatalf("expected drift detection output, got: %s", preview)
	}
	if !strings.Contains(preview, "exchange mode") {
		t.Fatalf("expected exchange mode drift detail, got: %s", preview)
	}
	if !strings.Contains(preview, "group team-a") {
		t.Fatalf("expected group drift detail, got: %s", preview)
	}
}

func TestBrokerRuntimeDriftKeyNoDriftAfterSync(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker

	oldProxy := globalProxyServer
	globalProxyServer = proxy.NewServer(19087, make(chan proxy.ApprovalRequest, 1))
	defer func() { globalProxyServer = oldProxy }()

	a.brokerSyncRuntimeState()
	a.handleBrokerPanel(keyRune('V'))
	preview := strings.Join(a.brokerPreviewLines, "\n")
	if !strings.Contains(preview, "No drift detected") {
		t.Fatalf("expected no drift after sync, got: %s", preview)
	}
}

func TestBrokerRenderShowsRuntimePoolSnapshot(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker
	a.handleBrokerPanel(keyRune('5')) // Health tab

	oldProxy := globalProxyServer
	globalProxyServer = proxy.NewServer(19083, make(chan proxy.ApprovalRequest, 1))
	defer func() { globalProxyServer = oldProxy }()

	globalProxyServer.SetBrokerState(proxy.BrokerState{
		ExchangeMode: "real",
		Pools: []proxy.BrokerPoolState{{
			Name:   "pool_alpha",
			Tokens: []proxy.BrokerTokenState{{ID: "tok_a1", Enabled: true, Health: 0.95, RemainingRPH: 222, SessionState: "in-use", LastTest: "ok"}},
		}},
	})
	globalProxyServer.MarkBrokerTokenRequestResult("tok_a1", 200, 150)

	out := a.renderBrokerPanel()
	if !strings.Contains(out, "Runtime pools (proxy):") {
		t.Fatalf("expected runtime pools section in render, got: %s", out)
	}
	if !strings.Contains(out, "state=in-use") {
		t.Fatalf("expected runtime token state in render, got: %s", out)
	}
	if !strings.Contains(out, "Runtime counters (all-time):") {
		t.Fatalf("expected runtime counters section in render, got: %s", out)
	}
}

func TestBrokerRuntimePreviewShowsCounters(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker

	oldProxy := globalProxyServer
	globalProxyServer = proxy.NewServer(19084, make(chan proxy.ApprovalRequest, 1))
	defer func() { globalProxyServer = oldProxy }()

	globalProxyServer.SetBrokerState(proxy.BrokerState{
		ExchangeMode: "real",
		Groups:       []proxy.BrokerGroupState{{Name: "team-a", Pool: "pool_alpha", Weight: 1}},
		Pools: []proxy.BrokerPoolState{{
			Name:   "pool_alpha",
			Tokens: []proxy.BrokerTokenState{{ID: "tok_a1", Enabled: true, Health: 0.90, RemainingRPH: 300, SessionState: "fresh", LastTest: "ok"}},
		}},
	})
	globalProxyServer.SelectBrokerToken("unknown", "gpt-5-mini") // unmanaged
	globalProxyServer.SelectBrokerToken("team-a", "gpt-5-mini")  // grouped
	globalProxyServer.MarkBrokerTokenRequestResult("tok_a1", 200, 100)

	a.handleBrokerPanel(keyRune('R'))
	preview := strings.Join(a.brokerPreviewLines, "\n")
	if !strings.Contains(preview, "Runtime counters (all-time):") {
		t.Fatalf("expected runtime counters in preview, got: %s", preview)
	}
	if !strings.Contains(preview, "Group counters (all-time):") {
		t.Fatalf("expected group counters in preview, got: %s", preview)
	}
	if !strings.Contains(preview, "Runtime counters (last 5m):") {
		t.Fatalf("expected 5m runtime counters in preview, got: %s", preview)
	}
}

func TestBrokerClearCountersKey(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker

	oldProxy := globalProxyServer
	globalProxyServer = proxy.NewServer(19085, make(chan proxy.ApprovalRequest, 1))
	defer func() { globalProxyServer = oldProxy }()

	globalProxyServer.SetBrokerState(proxy.BrokerState{
		Groups: []proxy.BrokerGroupState{{Name: "team-a", Pool: "pool_alpha", Weight: 1}},
		Pools: []proxy.BrokerPoolState{{
			Name:   "pool_alpha",
			Tokens: []proxy.BrokerTokenState{{ID: "tok_a1", Enabled: true, Health: 0.9, RemainingRPH: 100}},
		}},
	})
	globalProxyServer.SelectBrokerToken("team-a", "gpt-5-mini")
	if len(globalProxyServer.BrokerCounters()) == 0 {
		t.Fatalf("expected counters before clear")
	}

	a.handleBrokerPanel(keyRune('C'))
	if got := globalProxyServer.BrokerCounters(); len(got) != 0 {
		t.Fatalf("expected counters cleared by C key, got %v", got)
	}
}

func TestBrokerCounterWindowCycleKey(t *testing.T) {
	a := newBrokerTestApp(t, false)
	a.focus = panelBroker

	if a.brokerCounterWindowIdx != 0 {
		t.Fatalf("expected default brokerCounterWindowIdx=0, got %d", a.brokerCounterWindowIdx)
	}
	a.handleBrokerPanel(keyRune('W'))
	if a.brokerCounterWindowIdx != 1 {
		t.Fatalf("expected brokerCounterWindowIdx=1 after first W, got %d", a.brokerCounterWindowIdx)
	}
	a.handleBrokerPanel(keyRune('W'))
	if a.brokerCounterWindowIdx != 2 {
		t.Fatalf("expected brokerCounterWindowIdx=2 after second W, got %d", a.brokerCounterWindowIdx)
	}
	a.handleBrokerPanel(keyRune('W'))
	if a.brokerCounterWindowIdx != 0 {
		t.Fatalf("expected brokerCounterWindowIdx wraps to 0 after third W, got %d", a.brokerCounterWindowIdx)
	}
}
