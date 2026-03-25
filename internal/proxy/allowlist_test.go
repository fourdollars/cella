package proxy

import (
	"sort"
	"testing"
)

// ── NewAllowlist ──

func TestNewAllowlist_NotEmpty(t *testing.T) {
	al := NewAllowlist()
	if al.Count() == 0 {
		t.Error("expected global defaults to pre-populate the allowlist")
	}
}

// ── Add / IsAllowed (exact match) ──

func TestAllowlist_ExactMatch(t *testing.T) {
	al := &Allowlist{domains: make(map[string]bool)}
	al.Add("api.openai.com")
	if !al.IsAllowed("api.openai.com") {
		t.Error("expected api.openai.com to be allowed")
	}
	if al.IsAllowed("api.anthropic.com") {
		t.Error("expected api.anthropic.com to be denied")
	}
}

func TestAllowlist_CaseInsensitive(t *testing.T) {
	al := &Allowlist{domains: make(map[string]bool)}
	al.Add("API.OpenAI.Com")
	if !al.IsAllowed("api.openai.com") {
		t.Error("expected case-insensitive match")
	}
}

// ── Wildcard matching ──

func TestAllowlist_WildcardMatch(t *testing.T) {
	al := &Allowlist{domains: make(map[string]bool)}
	al.Add("*.openai.com")

	cases := []struct {
		domain string
		want   bool
	}{
		{"api.openai.com", true},
		{"cdn.openai.com", true},
		{"openai.com", false},         // wildcard doesn't match apex
		{"api.notopen.com", false},
	}
	for _, c := range cases {
		got := al.IsAllowed(c.domain)
		if got != c.want {
			t.Errorf("IsAllowed(%q) = %v, want %v", c.domain, got, c.want)
		}
	}
}

// ── Parent domain match ──

func TestAllowlist_ParentDomainMatch(t *testing.T) {
	al := &Allowlist{domains: make(map[string]bool)}
	al.Add("openai.com")

	if !al.IsAllowed("api.openai.com") {
		t.Error("expected subdomain to match parent entry")
	}
	if !al.IsAllowed("deep.sub.openai.com") {
		t.Error("expected deep subdomain to match parent entry")
	}
	if al.IsAllowed("notopen.com") {
		t.Error("expected unrelated domain to be denied")
	}
}

// ── Remove ──

func TestAllowlist_Remove(t *testing.T) {
	al := &Allowlist{domains: make(map[string]bool)}
	al.Add("example.com")
	al.Remove("example.com")
	if al.IsAllowed("example.com") {
		t.Error("expected example.com to be denied after Remove")
	}
}

// ── SetFromList ──

func TestAllowlist_SetFromList(t *testing.T) {
	al := NewAllowlist()
	al.SetFromList([]string{"custom.example.com"})
	if !al.IsAllowed("custom.example.com") {
		t.Error("expected custom.example.com after SetFromList")
	}
	// Global defaults should still be present
	list := al.List()
	if len(list) == 0 {
		t.Error("expected non-empty list after SetFromList")
	}
}

// ── List ──

func TestAllowlist_List(t *testing.T) {
	al := &Allowlist{domains: make(map[string]bool)}
	al.Add("a.com")
	al.Add("b.com")
	al.Add("c.com")
	list := al.List()
	if len(list) != 3 {
		t.Errorf("List() len = %d, want 3", len(list))
	}
	sort.Strings(list)
	for i, want := range []string{"a.com", "b.com", "c.com"} {
		if list[i] != want {
			t.Errorf("list[%d] = %q, want %q", i, list[i], want)
		}
	}
}

// ── Count ──

func TestAllowlist_Count(t *testing.T) {
	al := &Allowlist{domains: make(map[string]bool)}
	if al.Count() != 0 {
		t.Errorf("initial Count = %d, want 0", al.Count())
	}
	al.Add("x.com")
	if al.Count() != 1 {
		t.Errorf("Count after Add = %d, want 1", al.Count())
	}
	al.Remove("x.com")
	if al.Count() != 0 {
		t.Errorf("Count after Remove = %d, want 0", al.Count())
	}
}

// ── Concurrency safety ──

func TestAllowlist_Concurrent(t *testing.T) {
	al := NewAllowlist()
	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func(n int) {
			al.Add("domain" + string(rune('a'+n)) + ".com")
			al.IsAllowed("api.openai.com")
			al.Count()
			done <- struct{}{}
		}(i % 26)
	}
	for i := 0; i < 20; i++ {
		<-done
	}
}
