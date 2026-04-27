package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ── Seccomp profile tests ──

func TestPredefinedProfiles_Valid(t *testing.T) {
	profiles := []SeccompProfile{StrictProfile, ModerateProfile, PermissiveProfile}
	for _, p := range profiles {
		if p.Name == "" {
			t.Fatal("profile name is empty")
		}
		if p.DefaultAction == "" {
			t.Fatalf("profile %s has empty defaultAction", p.Name)
		}
	}
}

func TestStrictProfile_HasDangerousSyscalls(t *testing.T) {
	if len(StrictProfile.Syscalls) == 0 {
		t.Fatal("strict profile should have syscall rules")
	}
	rule := StrictProfile.Syscalls[0]
	if rule.Action != "SCMP_ACT_NOTIFY" {
		t.Fatalf("strict profile first rule should be NOTIFY, got %s", rule.Action)
	}
	// Check that all dangerous syscalls are present
	nameSet := make(map[string]bool)
	for _, n := range rule.Names {
		nameSet[n] = true
	}
	for _, ds := range DangerousSyscalls {
		if !nameSet[ds] {
			t.Errorf("strict profile missing dangerous syscall: %s", ds)
		}
	}
}

func TestModerateProfile_BlocksDangerous(t *testing.T) {
	if len(ModerateProfile.Syscalls) == 0 {
		t.Fatal("moderate profile should have syscall rules")
	}
	rule := ModerateProfile.Syscalls[0]
	if rule.Action != "SCMP_ACT_ERRNO" {
		t.Fatalf("moderate profile should use ERRNO, got %s", rule.Action)
	}
}

func TestPermissiveProfile_LogOnly(t *testing.T) {
	if PermissiveProfile.DefaultAction != "SCMP_ACT_LOG" {
		t.Fatalf("permissive profile should be LOG, got %s", PermissiveProfile.DefaultAction)
	}
	if len(PermissiveProfile.Syscalls) != 0 {
		t.Fatal("permissive profile should have no explicit rules")
	}
}

func TestSaveAndLoadProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-profile.json")

	profile := &SeccompProfile{
		Name:          "test",
		Description:   "test profile",
		DefaultAction: "SCMP_ACT_ALLOW",
		Syscalls: []Rule{
			{Names: []string{"mount", "ptrace"}, Action: "SCMP_ACT_ERRNO"},
		},
	}

	if err := SaveProfile(path, profile); err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}

	loaded, err := LoadProfile(path)
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}

	if loaded.Name != "test" {
		t.Fatalf("expected name=test, got %s", loaded.Name)
	}
	if loaded.DefaultAction != "SCMP_ACT_ALLOW" {
		t.Fatalf("expected SCMP_ACT_ALLOW, got %s", loaded.DefaultAction)
	}
	if len(loaded.Syscalls) != 1 || len(loaded.Syscalls[0].Names) != 2 {
		t.Fatal("syscall rules not preserved")
	}
}

func TestLoadProfile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("{invalid json"), 0644)

	_, err := LoadProfile(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadProfile_NotFound(t *testing.T) {
	_, err := LoadProfile("/nonexistent/profile.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ── AppArmor tests ──

func TestMatchAppArmorProfile_Default(t *testing.T) {
	if name := MatchAppArmorProfile(""); name != "default" {
		t.Fatalf("expected 'default', got '%s'", name)
	}
}

func TestMatchAppArmorProfile_Hardened(t *testing.T) {
	raw := strings.Join(AppArmorHardened.Rules, "\n")
	if name := MatchAppArmorProfile(raw); name != "hardened" {
		t.Fatalf("expected 'hardened', got '%s'", name)
	}
}

func TestMatchAppArmorProfile_NetRestricted(t *testing.T) {
	raw := strings.Join(AppArmorNetRestricted.Rules, "\n")
	if name := MatchAppArmorProfile(raw); name != "net-restricted" {
		t.Fatalf("expected 'net-restricted', got '%s'", name)
	}
}

func TestMatchAppArmorProfile_ReadOnly(t *testing.T) {
	raw := strings.Join(AppArmorReadOnly.Rules, "\n")
	if name := MatchAppArmorProfile(raw); name != "read-only" {
		t.Fatalf("expected 'read-only', got '%s'", name)
	}
}

func TestMatchAppArmorProfile_Custom(t *testing.T) {
	if name := MatchAppArmorProfile("deny something arbitrary,"); name != "custom" {
		t.Fatalf("expected 'custom', got '%s'", name)
	}
}

func TestAllAppArmorProfiles_Count(t *testing.T) {
	if len(AllAppArmorProfiles) != 4 {
		t.Fatalf("expected 4 AppArmor profiles, got %d", len(AllAppArmorProfiles))
	}
}

// ── Policy struct tests ──

func TestContainerPolicy_JSONRoundtrip(t *testing.T) {
	policy := ContainerPolicy{
		Version:   "1",
		Container: "test-container",
		Seccomp:   PolicySeccomp{Profile: "strict"},
		AppArmor:  PolicyAppArmor{Profile: "hardened"},
		Egress:    PolicyEgress{Restricted: true, Allow: []string{"1.1.1.1", "8.8.8.8"}, DenyAll: true},
		Flags:     PolicyFlags{Privileged: false, Nesting: true},
	}

	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		t.Fatalf("JSON marshal: %v", err)
	}

	var loaded ContainerPolicy
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("JSON unmarshal: %v", err)
	}

	if loaded.Container != "test-container" {
		t.Fatalf("container name lost")
	}
	if loaded.Seccomp.Profile != "strict" {
		t.Fatalf("seccomp profile lost")
	}
	if !loaded.Flags.Nesting {
		t.Fatal("nesting flag lost")
	}
	if len(loaded.Egress.Allow) != 2 {
		t.Fatalf("expected 2 egress rules, got %d", len(loaded.Egress.Allow))
	}
}

func TestContainerPolicy_YAMLRoundtrip(t *testing.T) {
	policy := ContainerPolicy{
		Version:   "1",
		Container: "yaml-test",
		Seccomp:   PolicySeccomp{Profile: "moderate"},
		AppArmor:  PolicyAppArmor{Profile: "default"},
		Egress:    PolicyEgress{Restricted: false},
	}

	data, err := yaml.Marshal(policy)
	if err != nil {
		t.Fatalf("YAML marshal: %v", err)
	}

	var loaded ContainerPolicy
	if err := yaml.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("YAML unmarshal: %v", err)
	}

	if loaded.Container != "yaml-test" {
		t.Fatalf("container name lost in YAML roundtrip")
	}
	if loaded.Seccomp.Profile != "moderate" {
		t.Fatalf("seccomp profile lost in YAML roundtrip")
	}
}

func TestContainerPolicy_WithCustomSeccomp(t *testing.T) {
	custom := &SeccompProfile{
		Name:          "my-custom",
		DefaultAction: "SCMP_ACT_ALLOW",
		Syscalls: []Rule{
			{Names: []string{"mount"}, Action: "SCMP_ACT_ERRNO"},
		},
	}

	policy := ContainerPolicy{
		Version:   "1",
		Container: "custom-seccomp",
		Seccomp:   PolicySeccomp{Profile: "custom", Custom: custom},
	}

	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}

	var loaded ContainerPolicy
	json.Unmarshal(data, &loaded)

	if loaded.Seccomp.Custom == nil {
		t.Fatal("custom seccomp profile lost")
	}
	if loaded.Seccomp.Custom.Name != "my-custom" {
		t.Fatalf("expected my-custom, got %s", loaded.Seccomp.Custom.Name)
	}
}

// ── Egress helper tests ──

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"my-container", "my_container"},
		{"simple", "simple"},
		{"test.with.dots", "test_with_dots"},
		{"UPPER123", "UPPER123"},
		{"a@b#c$d", "a_b_c_d"},
		{"", ""},
	}
	for _, tt := range tests {
		got := sanitizeName(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeName(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// ── DNS Monitor unit tests ──

func TestDNSMonitor_NewAndEmpty(t *testing.T) {
	m := NewDNSMonitor()
	if m.IsRunning() {
		t.Fatal("new monitor should not be running")
	}
	entries := m.Entries()
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestDNSMonitor_SetStatus(t *testing.T) {
	m := NewDNSMonitor()
	// Manually add an entry
	m.mu.Lock()
	m.entries["example.com"] = &DNSEntry{Domain: "example.com", SrcIP: "10.0.0.2"}
	m.mu.Unlock()

	m.SetStatus("example.com", "allow")

	entries := m.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Status != "allow" {
		t.Fatalf("expected status 'allow', got '%s'", entries[0].Status)
	}
}

func TestDNSMonitor_EntriesForContainer(t *testing.T) {
	m := NewDNSMonitor()
	m.mu.Lock()
	m.entries["a.com"] = &DNSEntry{Domain: "a.com", SrcIP: "10.0.0.2"}
	m.entries["b.com"] = &DNSEntry{Domain: "b.com", SrcIP: "10.0.0.3"}
	m.entries["c.com"] = &DNSEntry{Domain: "c.com", SrcIP: "10.0.0.2"}
	m.mu.Unlock()

	got := m.EntriesForContainer("10.0.0.2")
	if len(got) != 2 {
		t.Fatalf("expected 2 entries for 10.0.0.2, got %d", len(got))
	}
}

func TestDNSMonitor_LookupDomain(t *testing.T) {
	m := NewDNSMonitor()
	m.mu.Lock()
	m.ipMap["1.2.3.4"] = "example.com"
	m.mu.Unlock()

	if domain := m.LookupDomain("1.2.3.4"); domain != "example.com" {
		t.Fatalf("expected example.com, got %s", domain)
	}
	if domain := m.LookupDomain("5.6.7.8"); domain != "" {
		t.Fatalf("expected empty for unknown IP, got %s", domain)
	}
}

func TestDNSMonitor_EntriesAreCopies(t *testing.T) {
	m := NewDNSMonitor()
	m.mu.Lock()
	m.entries["test.com"] = &DNSEntry{
		Domain: "test.com",
		IPs:    []string{"1.1.1.1"},
	}
	m.mu.Unlock()

	entries := m.Entries()
	// Mutate the copy
	entries[0].IPs = append(entries[0].IPs, "2.2.2.2")

	// Original should be unchanged
	m.mu.RLock()
	orig := m.entries["test.com"]
	m.mu.RUnlock()
	if len(orig.IPs) != 1 {
		t.Fatal("Entries() should return copies, but original was mutated")
	}
}

func TestDNSMonitor_StartStop(t *testing.T) {
	m := NewDNSMonitor()
	// Start will fail because no tcpdump, but the state should still toggle
	// The goroutine will retry and eventually the context gets cancelled
	_ = m.Start()
	if !m.IsRunning() {
		t.Fatal("expected running after Start()")
	}
	m.Stop()
	if m.IsRunning() {
		t.Fatal("expected not running after Stop()")
	}
}

// ── DangerousSyscalls sanity ──

func TestDangerousSyscalls_NotEmpty(t *testing.T) {
	if len(DangerousSyscalls) < 10 {
		t.Fatalf("expected at least 10 dangerous syscalls, got %d", len(DangerousSyscalls))
	}
	// Check some critical ones are present
	found := map[string]bool{"ptrace": false, "mount": false, "bpf": false}
	for _, s := range DangerousSyscalls {
		if _, ok := found[s]; ok {
			found[s] = true
		}
	}
	for name, ok := range found {
		if !ok {
			t.Errorf("missing critical dangerous syscall: %s", name)
		}
	}
}
