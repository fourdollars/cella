package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fourdoors/cella/internal/proxy"
)

type BrokerGroup struct {
	ID       string
	Name     string // legacy alias of ID (for backward-compatible state files)
	Match    string
	Pool     string
	Weight   int
	RPHLimit int
	Lag      float64
	VDL      float64
}

type BrokerToken struct {
	ID           string
	Kind         string // "" = auto, "copilot", "gemini", "openai"
	Endpoint     string // per-token upstream endpoint; "" = use kind default
	Enabled      bool
	Health       float64
	RemainingRPH int
	BreakerOpen  bool
	SessionState string
	LastTest     string
	PATEnv       string
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

type brokerPersistState struct {
	Groups           []BrokerGroup  `json:"groups"`
	Pools            []BrokerPool   `json:"pools"`
	Policies         []BrokerPolicy `json:"policies"`
	ExchangeEndpoint string         `json:"exchange_endpoint,omitempty"`
}

func brokerDefaultExchangeEndpoint() string {
	return "https://api.github.com/copilot_internal/v2/token"
}

func brokerStatePath() (string, error) {
	home, err := cellaUserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".cella")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "token_broker_state.json"), nil
}

func brokerSecretsPath() (string, error) {
	home, err := cellaUserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".cella")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "token_broker_secrets.json"), nil
}

func loadBrokerSecrets() (map[string]string, error) {
	path, err := brokerSecretsPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]string), nil
		}
		return nil, err
	}
	var secrets map[string]string
	if err := json.Unmarshal(data, &secrets); err != nil {
		return nil, err
	}
	return secrets, nil
}

func saveBrokerSecrets(secrets map[string]string) error {
	path, err := brokerSecretsPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func injectBrokerSecrets(secrets map[string]string) {
	for k, v := range secrets {
		if strings.TrimSpace(k) != "" && strings.TrimSpace(v) != "" {
			_ = os.Setenv(k, v)
		}
	}
}

func brokerGroupID(g BrokerGroup) string {
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

func brokerGroupMatchRule(g BrokerGroup) string {
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

func brokerRuntimeGroupID(g proxy.BrokerGroupState) string {
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

func brokerRuntimeGroupMatchRule(g proxy.BrokerGroupState) string {
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

func brokerSortedDraftTokenIDs(tokens []BrokerToken) []string {
	ids := make([]string, 0, len(tokens))
	for _, t := range tokens {
		id := strings.TrimSpace(t.ID)
		if id == "" {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func brokerSortedRuntimeTokenIDs(tokens []proxy.BrokerTokenState) []string {
	ids := make([]string, 0, len(tokens))
	for _, t := range tokens {
		id := strings.TrimSpace(t.ID)
		if id == "" {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

type brokerPolicyProfile struct {
	Name     string
	Strategy string
	Sticky   bool
	Retry    int
}

func brokerPolicyProfiles() []brokerPolicyProfile {
	return []brokerPolicyProfile{
		{Name: "sticky-balanced", Strategy: "weighted_least_load", Sticky: true, Retry: 1},
		{Name: "balanced", Strategy: "weighted_least_load", Sticky: false, Retry: 1},
		{Name: "throughput", Strategy: "round_robin", Sticky: false, Retry: 0},
		{Name: "resilient", Strategy: "least_error", Sticky: true, Retry: 2},
	}
}

func brokerPolicyProfileLabel(p BrokerPolicy) string {
	for _, profile := range brokerPolicyProfiles() {
		if p.Strategy == profile.Strategy && p.Sticky == profile.Sticky && p.Retry == profile.Retry {
			return profile.Name
		}
	}
	return "custom"
}

func brokerCycleStringOption(options []string, current string, dir int) string {
	if len(options) == 0 {
		return ""
	}
	idx := 0
	for i, opt := range options {
		if opt == current {
			idx = i
			break
		}
	}
	idx = (idx + dir + len(options)) % len(options)
	return options[idx]
}

func (a *App) brokerGroupIDs() []string {
	ids := make([]string, 0, len(a.brokerGroups))
	for _, g := range a.brokerGroups {
		id := strings.TrimSpace(brokerGroupID(g))
		if id == "" {
			continue
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return ids
	}
	uniq := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if uniq[id] {
			continue
		}
		uniq[id] = true
		out = append(out, id)
	}
	return out
}

func (a *App) brokerPoolNames() []string {
	names := make([]string, 0, len(a.brokerPools))
	for _, p := range a.brokerPools {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return names
	}
	uniq := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		if uniq[name] {
			continue
		}
		uniq[name] = true
		out = append(out, name)
	}
	return out
}

func (a *App) brokerNextPolicyName() string {
	maxN := 0
	for _, p := range a.brokerPolicies {
		name := strings.TrimSpace(strings.ToLower(p.Name))
		if !strings.HasPrefix(name, "policy_") {
			continue
		}
		suffix := strings.TrimPrefix(name, "policy_")
		n := 0
		for _, ch := range suffix {
			if ch < '0' || ch > '9' {
				n = 0
				break
			}
			n = n*10 + int(ch-'0')
		}
		if n > maxN {
			maxN = n
		}
	}
	return fmt.Sprintf("policy_%d", maxN+1)
}

func (a *App) brokerPolicyGroupCycle(idx int, dir int) bool {
	if len(a.brokerPolicies) == 0 || idx < 0 || idx >= len(a.brokerPolicies) {
		return false
	}
	groups := a.brokerGroupIDs()
	if len(groups) == 0 {
		return false
	}
	p := &a.brokerPolicies[idx]
	next := brokerCycleStringOption(groups, p.Group, dir)
	if next == "" || next == p.Group {
		return false
	}
	p.Group = next
	return true
}

func (a *App) brokerPolicyPoolCycle(idx int, dir int) bool {
	if len(a.brokerPolicies) == 0 || idx < 0 || idx >= len(a.brokerPolicies) {
		return false
	}
	pools := a.brokerPoolNames()
	if len(pools) == 0 {
		return false
	}
	p := &a.brokerPolicies[idx]
	next := brokerCycleStringOption(pools, p.Pool, dir)
	if next == "" || next == p.Pool {
		return false
	}
	p.Pool = next
	return true
}

func (a *App) brokerPolicyProfileCycle(idx int, dir int) (string, bool) {
	if len(a.brokerPolicies) == 0 || idx < 0 || idx >= len(a.brokerPolicies) {
		return "", false
	}
	profiles := brokerPolicyProfiles()
	if len(profiles) == 0 {
		return "", false
	}
	p := &a.brokerPolicies[idx]
	curIdx := -1
	for i, profile := range profiles {
		if p.Strategy == profile.Strategy && p.Sticky == profile.Sticky && p.Retry == profile.Retry {
			curIdx = i
			break
		}
	}
	if curIdx < 0 {
		if dir > 0 {
			curIdx = 0
		} else {
			curIdx = len(profiles) - 1
		}
	} else {
		curIdx = (curIdx + dir + len(profiles)) % len(profiles)
	}
	next := profiles[curIdx]
	if p.Strategy == next.Strategy && p.Sticky == next.Sticky && p.Retry == next.Retry {
		return next.Name, false
	}
	p.Strategy = next.Strategy
	p.Sticky = next.Sticky
	p.Retry = next.Retry
	return next.Name, true
}

func (a *App) normalizeBrokerGroupsAndPolicies() {
	if len(a.brokerGroups) == 0 {
		for i := range a.brokerPolicies {
			a.brokerPolicies[i].Group = ""
		}
		return
	}
	legacyToID := make(map[string]string)
	for i := range a.brokerGroups {
		g := &a.brokerGroups[i]
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
	for i := range a.brokerPolicies {
		groupRef := strings.TrimSpace(a.brokerPolicies[i].Group)
		if groupRef == "" {
			continue
		}
		if id, ok := legacyToID[strings.ToLower(groupRef)]; ok {
			a.brokerPolicies[i].Group = id
		}
	}
}

func (a *App) brokerReconcilePoliciesAfterGroupChange() {
	a.normalizeBrokerGroupsAndPolicies()
	if len(a.brokerGroups) == 0 {
		if len(a.brokerPolicies) > 0 {
			a.brokerPolicies = nil
			a.brokerPolicyCursor = 0
			a.addEvent("🧹 all groups removed; policies cleared")
		}
		return
	}
	valid := make(map[string]bool, len(a.brokerGroups))
	for _, g := range a.brokerGroups {
		id := strings.TrimSpace(brokerGroupID(g))
		if id != "" {
			valid[id] = true
		}
	}
	fallback := strings.TrimSpace(brokerGroupID(a.brokerGroups[0]))
	for i := range a.brokerPolicies {
		groupID := strings.TrimSpace(a.brokerPolicies[i].Group)
		if groupID == "" || !valid[groupID] {
			a.brokerPolicies[i].Group = fallback
		}
	}
}

func (a *App) loadBrokerState() error {
	path, err := brokerStatePath()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var st brokerPersistState
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	a.brokerGroups = append([]BrokerGroup(nil), st.Groups...)
	a.brokerPools = make([]BrokerPool, len(st.Pools))
	for i, p := range st.Pools {
		a.brokerPools[i] = BrokerPool{Name: p.Name, Tokens: append([]BrokerToken(nil), p.Tokens...)}
	}
	a.brokerPolicies = append([]BrokerPolicy(nil), st.Policies...)
	a.brokerExchangeEndpoint = st.ExchangeEndpoint
	if a.brokerExchangeEndpoint == "" {
		a.brokerExchangeEndpoint = brokerDefaultExchangeEndpoint()
	}
	a.normalizeBrokerGroupsAndPolicies()

	// Load and inject persisted secrets so proxy can resolve PATs
	secrets, err := loadBrokerSecrets()
	if err == nil && len(secrets) > 0 {
		injectBrokerSecrets(secrets)
	}
	return nil
}

func (a *App) saveBrokerState() error {
	a.normalizeBrokerGroupsAndPolicies()
	path, err := brokerStatePath()
	if err != nil {
		return err
	}
	st := brokerPersistState{Groups: a.brokerGroups, Pools: a.brokerPools, Policies: a.brokerPolicies, ExchangeEndpoint: a.brokerExchangeEndpoint}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (a *App) initBrokerDefaults() {
	if len(a.brokerGroups) > 0 || len(a.brokerPools) > 0 || len(a.brokerPolicies) > 0 {
		if a.brokerExchangeEndpoint == "" {
			a.brokerExchangeEndpoint = brokerDefaultExchangeEndpoint()
		}
		if len(a.brokerPreviewLines) == 0 {
			a.brokerPreviewLines = []string{"Preview not generated. Press P to simulate."}
		}
		if len(a.brokerDiffLines) == 0 {
			a.brokerDiffLines = []string{"No draft changes."}
		}
		s := a.captureBrokerSnapshot()
		a.brokerLastApplied = &s
		return
	}
	if err := a.loadBrokerState(); err == nil {
		a.brokerPreviewLines = []string{"Loaded broker state from ~/.cella/token_broker_state.json"}
		a.brokerDiffLines = []string{"No draft changes."}
		s := a.captureBrokerSnapshot()
		a.brokerLastApplied = &s
		return
	}
	a.brokerGroups = nil
	a.brokerPools = nil
	a.brokerPolicies = nil
	a.brokerExchangeEndpoint = brokerDefaultExchangeEndpoint()
	a.brokerPreviewLines = []string{"Broker draft is empty. Add pool/group/token to start."}
	a.brokerDiffLines = []string{"No draft changes."}
	s := a.captureBrokerSnapshot()
	a.brokerLastApplied = &s
}

func (a *App) captureBrokerSnapshot() BrokerSnapshot {
	a.normalizeBrokerGroupsAndPolicies()
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
	a.normalizeBrokerGroupsAndPolicies()
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
		if len(a.brokerPools) == 0 {
			return nil
		}
		return &a.brokerPools[0]
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

func (a *App) brokerNextPoolName() string {
	maxN := 0
	for _, p := range a.brokerPools {
		name := strings.TrimSpace(strings.ToLower(p.Name))
		if !strings.HasPrefix(name, "pool_") {
			continue
		}
		suffix := strings.TrimPrefix(name, "pool_")
		n := 0
		for _, ch := range suffix {
			if ch < '0' || ch > '9' {
				n = 0
				break
			}
			n = n*10 + int(ch-'0')
		}
		if n > maxN {
			maxN = n
		}
	}
	return fmt.Sprintf("pool_%d", maxN+1)
}

func (a *App) brokerReconcileMappingsAfterPoolChange() {
	valid := make(map[string]bool, len(a.brokerPools))
	for _, p := range a.brokerPools {
		name := strings.TrimSpace(p.Name)
		if name != "" {
			valid[name] = true
		}
	}
	fallback := ""
	if len(a.brokerPools) > 0 {
		fallback = strings.TrimSpace(a.brokerPools[0].Name)
	}
	for i := range a.brokerGroups {
		poolName := strings.TrimSpace(a.brokerGroups[i].Pool)
		if poolName == "" || !valid[poolName] {
			a.brokerGroups[i].Pool = fallback
		}
	}
	for i := range a.brokerPolicies {
		poolName := strings.TrimSpace(a.brokerPolicies[i].Pool)
		if poolName == "" || !valid[poolName] {
			a.brokerPolicies[i].Pool = fallback
		}
	}
}

func (a *App) brokerResetEditState() {
	a.brokerEditMode = false
	a.brokerEditBuf = ""
	a.brokerEditKind = ""
	a.brokerEditPoolName = ""
	a.brokerEditTokenID = ""
	a.brokerEditSecret = false
	a.brokerEditPAT = ""
	a.brokerEditPATEnv = ""
	a.brokerEditTokenKind = ""
}

func brokerTokenIDExists(pool BrokerPool, tokenID string) bool {
	id := strings.TrimSpace(tokenID)
	if id == "" {
		return false
	}
	for _, t := range pool.Tokens {
		if strings.EqualFold(strings.TrimSpace(t.ID), id) {
			return true
		}
	}
	return false
}

func (a *App) brokerBeginTokenAddInput(poolName string) {
	a.brokerApplyConfirm = false
	a.brokerClearGroupsConfirm = false
	a.brokerEditMode = true
	a.brokerEditKind = "token-add-id"
	a.brokerEditPoolName = poolName
	a.brokerEditTokenID = ""
	a.brokerEditBuf = ""
	a.brokerEditSecret = false
	a.addEvent(fmt.Sprintf("📝 enter new token ID for pool %s", poolName))
}

func (a *App) brokerCommitEdit() bool {
	kind := strings.TrimSpace(a.brokerEditKind)
	switch kind {
	case "group-edit-match":
		newMatch := strings.TrimSpace(a.brokerEditBuf)
		if newMatch == "" {
			a.addEvent("⚠ match rule cannot be empty")
			return false
		}
		if a.brokerGroupCursor < len(a.brokerGroups) {
			g := &a.brokerGroups[a.brokerGroupCursor]
			old := g.Match
			g.Match = newMatch
			a.brokerDirty = true
			a.addEvent(fmt.Sprintf("✅ group %s match updated: %s → %s", brokerGroupID(*g), old, newMatch))
		}
		a.brokerResetEditState()
		return true
	case "token-add-id":
		poolName := strings.TrimSpace(a.brokerEditPoolName)
		tokenID := strings.TrimSpace(a.brokerEditBuf)
		if poolName == "" {
			a.addEvent("❌ token add failed: invalid pool context")
			a.brokerResetEditState()
			return true
		}
		if tokenID == "" {
			a.addEvent("⚠ token ID cannot be empty")
			return false
		}
		if strings.ContainsAny(tokenID, " \t\n\r") {
			a.addEvent("⚠ token ID cannot contain whitespace")
			return false
		}
		idx := a.brokerPoolIndexByName(poolName)
		if idx < 0 {
			a.addEvent(fmt.Sprintf("❌ token add failed: pool %s not found", poolName))
			a.brokerResetEditState()
			return true
		}
		if brokerTokenIDExists(a.brokerPools[idx], tokenID) {
			a.addEvent(fmt.Sprintf("⚠ token ID %s already exists in %s", tokenID, poolName))
			return false
		}
		a.brokerEditTokenID = tokenID
		a.brokerEditKind = "token-add-pat"
		a.brokerEditBuf = ""
		a.brokerEditSecret = true
		a.addEvent(fmt.Sprintf("🔐 enter PAT/API key for %s (%s), then Enter", tokenID, poolName))
		return false
	case "token-add-pat":
		poolName := strings.TrimSpace(a.brokerEditPoolName)
		tokenID := strings.TrimSpace(a.brokerEditTokenID)
		pat := strings.TrimSpace(a.brokerEditBuf)
		if poolName == "" || tokenID == "" {
			a.addEvent("❌ token add failed: invalid edit context")
			a.brokerResetEditState()
			return true
		}
		if pat == "" {
			a.addEvent("⚠ PAT/API key cannot be empty")
			return false
		}
		if brokerTokenIDExists(a.brokerPools[a.brokerPoolIndexByName(poolName)], tokenID) {
			a.addEvent(fmt.Sprintf("⚠ token ID %s already exists in %s", tokenID, poolName))
			a.brokerResetEditState()
			return true
		}
		// Persist PAT/key to secrets file before moving to kind step.
		patEnv := brokerSuggestedPATEnv(tokenID)
		_ = os.Setenv(patEnv, pat)
		secrets, _ := loadBrokerSecrets()
		if secrets == nil {
			secrets = make(map[string]string)
		}
		secrets[patEnv] = pat
		if err := saveBrokerSecrets(secrets); err != nil {
			a.addEvent(fmt.Sprintf("⚠ PAT secret save failed: %v", err))
		} else {
			a.addEvent(fmt.Sprintf("🔐 key persisted (key=%s)", patEnv))
		}
		a.brokerEditPATEnv = patEnv
		a.brokerEditPAT = pat
		a.brokerEditKind = "token-add-kind"
		a.brokerEditBuf = ""
		a.brokerEditSecret = false
		// Auto-detect kind from PAT prefix and show as default.
		detected := brokerDetectTokenKind(pat)
		a.addEvent(fmt.Sprintf("🔎 detected kind: %s — enter to confirm, or type copilot/gemini/openai to override", brokerKindLabel(detected)))
		return false
	case "token-add-kind":
		poolName := strings.TrimSpace(a.brokerEditPoolName)
		tokenID := strings.TrimSpace(a.brokerEditTokenID)
		if poolName == "" || tokenID == "" {
			a.addEvent("❌ token add failed: invalid edit context")
			a.brokerResetEditState()
			return true
		}
		if a.brokerPoolIndexByName(poolName) < 0 {
			a.addEvent(fmt.Sprintf("❌ token add failed: pool %s not found", poolName))
			a.brokerResetEditState()
			return true
		}
		// Accept user input or fall back to auto-detected kind.
		kindInput := strings.ToLower(strings.TrimSpace(a.brokerEditBuf))
		pat := a.brokerEditPAT
		var kind string
		switch kindInput {
		case "copilot", "gemini", "openai":
			kind = kindInput
		default:
			kind = brokerDetectTokenKind(pat) // auto
		}
		a.brokerEditTokenKind = kind
		a.brokerEditKind = "token-add-endpoint"
		a.brokerEditBuf = ""
		a.brokerEditSecret = false
		defaultEP := brokerDefaultEndpointForKind(kind)
		a.addEvent(fmt.Sprintf("🌐 default endpoint: %s — Enter to accept, or paste custom URL", defaultEP))
		return false
	case "token-add-endpoint":
		poolName := strings.TrimSpace(a.brokerEditPoolName)
		tokenID := strings.TrimSpace(a.brokerEditTokenID)
		if poolName == "" || tokenID == "" {
			a.addEvent("❌ token add failed: invalid edit context")
			a.brokerResetEditState()
			return true
		}
		idx := a.brokerPoolIndexByName(poolName)
		if idx < 0 {
			a.addEvent(fmt.Sprintf("❌ token add failed: pool %s not found", poolName))
			a.brokerResetEditState()
			return true
		}
		// Empty = use default for kind (stored as "", resolved at runtime).
		endpoint := strings.TrimSpace(a.brokerEditBuf)
		kind := a.brokerEditTokenKind
		patEnv := a.brokerEditPATEnv
		a.brokerPools[idx].Tokens = append(a.brokerPools[idx].Tokens, BrokerToken{
			ID:           tokenID,
			Kind:         kind,
			Endpoint:     endpoint, // "" = proxy uses brokerDefaultEndpointForKind at runtime
			Enabled:      true,
			Health:       0.85,
			RemainingRPH: 600,
			SessionState: "new",
			LastTest:     "na",
			PATEnv:       patEnv,
			P95ms:        0,
		})
		if pool := a.brokerCurrentPool(); pool != nil && pool.Name == poolName {
			a.brokerTokenCursor = len(pool.Tokens) - 1
		}
		a.brokerDirty = true
		ep := endpoint
		if ep == "" {
			ep = brokerDefaultEndpointForKind(kind) + " (default)"
		}
		a.addEvent(fmt.Sprintf("✅ token %s (%s) → %s added to %s", tokenID, brokerKindLabel(kind), ep, poolName))
		a.brokerResetEditState()
		return true
	case "token-edit-kind":
		// Edit Kind of an existing token.
		poolName := strings.TrimSpace(a.brokerEditPoolName)
		tokenID := strings.TrimSpace(a.brokerEditTokenID)
		idx := a.brokerPoolIndexByName(poolName)
		if idx < 0 || tokenID == "" {
			a.addEvent("❌ kind edit failed: invalid context")
			a.brokerResetEditState()
			return true
		}
		kindInput := strings.ToLower(strings.TrimSpace(a.brokerEditBuf))
		var newKind string
		switch kindInput {
		case "copilot", "gemini", "openai":
			newKind = kindInput
		default:
			newKind = "" // clear = auto-detect
		}
		for i := range a.brokerPools[idx].Tokens {
			if a.brokerPools[idx].Tokens[i].ID == tokenID {
				a.brokerPools[idx].Tokens[i].Kind = newKind
				break
			}
		}
		a.brokerDirty = true
		a.addEvent(fmt.Sprintf("✅ %s kind set to: %s", tokenID, brokerKindLabel(newKind)))
		a.brokerResetEditState()
		return true
	case "token-edit-endpoint":
		// Edit Endpoint of an existing token.
		poolName := strings.TrimSpace(a.brokerEditPoolName)
		tokenID := strings.TrimSpace(a.brokerEditTokenID)
		idx := a.brokerPoolIndexByName(poolName)
		if idx < 0 || tokenID == "" {
			a.addEvent("❌ endpoint edit failed: invalid context")
			a.brokerResetEditState()
			return true
		}
		newEndpoint := strings.TrimSpace(a.brokerEditBuf)
		for i := range a.brokerPools[idx].Tokens {
			if a.brokerPools[idx].Tokens[i].ID == tokenID {
				a.brokerPools[idx].Tokens[i].Endpoint = newEndpoint
				break
			}
		}
		a.brokerDirty = true
		ep := newEndpoint
		if ep == "" {
			kind := ""
			for _, t := range a.brokerPools[idx].Tokens {
				if t.ID == tokenID {
					kind = t.Kind
					break
				}
			}
			ep = brokerDefaultEndpointForKind(kind) + " (default)"
		}
		a.addEvent(fmt.Sprintf("✅ %s endpoint set to: %s", tokenID, ep))
		a.brokerResetEditState()
		return true
	default:
		a.brokerResetEditState()
		return true
	}
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
