package tui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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
	ExchangeMode     string         `json:"exchange_mode,omitempty"`
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
	a.brokerExchangeMode = st.ExchangeMode
	if a.brokerExchangeMode == "" {
		a.brokerExchangeMode = "mock"
	}
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
	st := brokerPersistState{Groups: a.brokerGroups, Pools: a.brokerPools, Policies: a.brokerPolicies, ExchangeMode: a.brokerExchangeMode, ExchangeEndpoint: a.brokerExchangeEndpoint}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (a *App) initBrokerDefaults() {
	if len(a.brokerGroups) > 0 || len(a.brokerPools) > 0 || len(a.brokerPolicies) > 0 {
		if a.brokerExchangeMode == "" {
			a.brokerExchangeMode = "mock"
		}
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
	a.brokerExchangeMode = "mock"
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

func (a *App) brokerNextTokenID(poolName string) string {
	idx := a.brokerPoolIndexByName(poolName)
	if idx < 0 {
		return "tok_new1"
	}
	tokens := a.brokerPools[idx].Tokens
	maxN := 0
	for _, t := range tokens {
		parts := strings.Split(t.ID, "_")
		if len(parts) == 0 {
			continue
		}
		last := parts[len(parts)-1]
		n := 0
		for _, ch := range last {
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
	prefix := "tok"
	if strings.Contains(poolName, "alpha") {
		prefix = "tok_a"
	} else if strings.Contains(poolName, "beta") {
		prefix = "tok_b"
	} else if strings.Contains(poolName, "ci") {
		prefix = "tok_ci"
	}
	return fmt.Sprintf("%s%d", prefix, maxN+1)
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
		a.addEvent(fmt.Sprintf("🔐 enter PAT for %s (%s), then Enter to add", tokenID, poolName))
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
			a.addEvent("⚠ PAT cannot be empty")
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
			a.brokerResetEditState()
			return true
		}
		patEnv := brokerSuggestedPATEnv(tokenID)
		_ = os.Setenv(patEnv, pat)
		// Persist PAT to secrets file
		secrets, _ := loadBrokerSecrets()
		if secrets == nil {
			secrets = make(map[string]string)
		}
		secrets[patEnv] = pat
		if err := saveBrokerSecrets(secrets); err != nil {
			a.addEvent(fmt.Sprintf("⚠ PAT secret save failed: %v", err))
		} else {
			a.addEvent(fmt.Sprintf("🔐 PAT persisted to ~/.cella/token_broker_secrets.json (key=%s)", patEnv))
		}
		a.brokerPools[idx].Tokens = append(a.brokerPools[idx].Tokens, BrokerToken{
			ID:           tokenID,
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
		a.addEvent(fmt.Sprintf("✅ token %s added to %s (ID+PAT captured via inline input)", tokenID, poolName))
		a.brokerResetEditState()
		return true
	default:
		a.brokerResetEditState()
		return true
	}
}

func (a *App) brokerTestExchangeToken(t *BrokerToken) {
	if a.brokerExchangeMode == "real" {
		a.brokerTestExchangeTokenReal(t)
		return
	}
	a.brokerTestExchangeTokenMock(t)
}

func (a *App) brokerTestExchangeTokenMock(t *BrokerToken) {
	if !t.Enabled {
		t.LastTest = "fail"
		t.SessionState = "disabled"
		a.addEvent(fmt.Sprintf("❌ exchange test failed for %s: token disabled", t.ID))
		if t.Health > 0.05 {
			t.Health -= 0.05
		}
		return
	}
	if t.BreakerOpen || strings.Contains(strings.ToLower(t.ID), "bad") {
		t.LastTest = "fail"
		t.SessionState = "test-fail"
		a.addEvent(fmt.Sprintf("❌ exchange test failed for %s", t.ID))
		if t.Health > 0.05 {
			t.Health -= 0.05
		}
		return
	}
	t.LastTest = "ok"
	t.SessionState = "tested-ok-mock"
	if t.Health < 0.98 {
		t.Health += 0.03
	}
	a.addEvent(fmt.Sprintf("✅ mock exchange test passed for %s", t.ID))
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
	lines = append(lines, fmt.Sprintf("- exchange mode: %s", a.brokerExchangeMode))
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

func (a *App) brokerRuntimeState() proxy.BrokerState {
	a.normalizeBrokerGroupsAndPolicies()
	state := proxy.BrokerState{
		AppliedAt:        time.Now().UTC(),
		ExchangeMode:     a.brokerExchangeMode,
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

func (a *App) brokerSyncRuntimeState() {
	if globalProxyServer == nil {
		a.addEvent("ℹ token broker applied (proxy runtime not active; sync skipped)")
		return
	}
	state := a.brokerRuntimeState()
	globalProxyServer.SetBrokerState(state)
	a.addEvent(fmt.Sprintf("✅ token broker runtime synced: groups=%d pools=%d mode=%s", len(state.Groups), len(state.Pools), state.ExchangeMode))
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
	lines := []string{fmt.Sprintf("Runtime broker state: groups=%d pools=%d mode=%s", len(st.Groups), len(st.Pools), st.ExchangeMode)}
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
	if strings.TrimSpace(a.brokerExchangeMode) != strings.TrimSpace(st.ExchangeMode) {
		drift = append(drift, fmt.Sprintf("exchange mode draft=%s runtime=%s", a.brokerExchangeMode, st.ExchangeMode))
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
			a.brokerGroups = append(a.brokerGroups, BrokerGroup{ID: groupID, Name: groupID, Match: groupID, Pool: pool, Weight: 1, RPHLimit: 1000})
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
		case "m", "M":
			if a.brokerExchangeMode == "real" {
				a.brokerExchangeMode = "mock"
			} else {
				a.brokerExchangeMode = "real"
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
		right.WriteString("\nKeys: ←/→ pool, +/- weight, N add, D delete, X clear-all\n")
	case 1:
		endpoint := strings.TrimSpace(a.brokerExchangeEndpoint)
		if endpoint == "" {
			endpoint = brokerDefaultExchangeEndpoint()
		}
		right.WriteString(fmt.Sprintf("Exchange mode: %s\nExchange endpoint: %s\n\n", a.brokerExchangeMode, endpoint))
		if pool != nil && len(pool.Tokens) > 0 {
			t := pool.Tokens[a.brokerTokenCursor]
			flag := green.Render("enabled")
			if !t.Enabled {
				flag = red.Render("disabled")
			}
			right.WriteString(fmt.Sprintf("Token: %s\nStatus: %s\nHealth: %.2f\nRemaining RPH: %d\nSession: %s\nLast test: %s\nPAT env: %s\nP95: %dms\n", t.ID, flag, t.Health, t.RemainingRPH, t.SessionState, t.LastTest, t.PATEnv, t.P95ms))
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
		right.WriteString("\nKeys: N add-pool, Z del-pool, A add-token(ID+PAT), D del-token, Enter/X toggle, B breaker, F refresh, M mode, E set-token-env, G global-env, T test, R runtime-preview, V drift-check, W window, C clear-counters\n")
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
