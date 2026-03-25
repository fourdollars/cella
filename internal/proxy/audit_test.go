package proxy

import (
	"strings"
	"testing"
	"time"
)

// helper to make a test AuditEntry
func makeEntry(domain, status, container, method string, tls bool) AuditEntry {
	return AuditEntry{
		Time:      time.Now(),
		Domain:    domain,
		Status:    status,
		Container: container,
		Method:    method,
		TLS:       tls,
		Latency:   50 * time.Millisecond,
	}
}

// ── NewAuditLog ──

func TestNewAuditLog_Empty(t *testing.T) {
	al := NewAuditLog(100)
	if al.Count() != 0 {
		t.Errorf("initial Count = %d, want 0", al.Count())
	}
}

// ── Add / Count / Last ──

func TestAuditLog_AddAndCount(t *testing.T) {
	al := NewAuditLog(10)
	al.Add(makeEntry("api.openai.com", "allowed", "agent1", "CONNECT", true))
	al.Add(makeEntry("api.anthropic.com", "denied", "agent2", "CONNECT", true))
	if al.Count() != 2 {
		t.Errorf("Count = %d, want 2", al.Count())
	}
}

func TestAuditLog_RingBufferEviction(t *testing.T) {
	al := NewAuditLog(3)
	for i := 0; i < 5; i++ {
		al.Add(makeEntry("domain.com", "allowed", "c", "GET", false))
	}
	if al.Count() != 3 {
		t.Errorf("Count = %d, want 3 (ring buffer max)", al.Count())
	}
}

func TestAuditLog_Last(t *testing.T) {
	al := NewAuditLog(100)
	for _, d := range []string{"a.com", "b.com", "c.com", "d.com", "e.com"} {
		al.Add(makeEntry(d, "allowed", "c", "GET", false))
	}
	last2 := al.Last(2)
	if len(last2) != 2 {
		t.Fatalf("Last(2) len = %d, want 2", len(last2))
	}
	if last2[0].Domain != "d.com" || last2[1].Domain != "e.com" {
		t.Errorf("Last(2) = [%s, %s], want [d.com, e.com]", last2[0].Domain, last2[1].Domain)
	}
}

func TestAuditLog_LastBeyondSize(t *testing.T) {
	al := NewAuditLog(100)
	al.Add(makeEntry("x.com", "allowed", "c", "GET", false))
	got := al.Last(50)
	if len(got) != 1 {
		t.Errorf("Last(50) len = %d, want 1", len(got))
	}
}

// ── All ──

func TestAuditLog_All(t *testing.T) {
	al := NewAuditLog(100)
	al.Add(makeEntry("a.com", "allowed", "c1", "GET", false))
	al.Add(makeEntry("b.com", "denied", "c2", "GET", false))
	all := al.All()
	if len(all) != 2 {
		t.Fatalf("All() len = %d, want 2", len(all))
	}
}

// ── Clear ──

func TestAuditLog_Clear(t *testing.T) {
	al := NewAuditLog(100)
	al.Add(makeEntry("a.com", "allowed", "c", "GET", false))
	al.Clear()
	if al.Count() != 0 {
		t.Errorf("Count after Clear = %d, want 0", al.Count())
	}
}

// ── Stats ──

func TestAuditLog_Stats(t *testing.T) {
	al := NewAuditLog(100)
	al.Add(makeEntry("api.openai.com", "allowed", "agent1", "CONNECT", true))
	al.Add(makeEntry("api.openai.com", "denied", "agent1", "CONNECT", false))
	al.Add(makeEntry("api.anthropic.com", "allowed", "agent2", "CONNECT", true))

	stats := al.Stats()
	if stats.Total != 3 {
		t.Errorf("Stats.Total = %d, want 3", stats.Total)
	}
	if stats.TLSCount != 2 {
		t.Errorf("Stats.TLSCount = %d, want 2", stats.TLSCount)
	}
	if stats.ByDomain["api.openai.com"] != 2 {
		t.Errorf("ByDomain[api.openai.com] = %d, want 2", stats.ByDomain["api.openai.com"])
	}
	if stats.ByStatus["allowed"] != 2 {
		t.Errorf("ByStatus[allowed] = %d, want 2", stats.ByStatus["allowed"])
	}
	if stats.ByContainer["agent2"] != 1 {
		t.Errorf("ByContainer[agent2] = %d, want 1", stats.ByContainer["agent2"])
	}
}

// ── FormatEntry ──

func TestFormatEntry_AllowedTLS(t *testing.T) {
	e := makeEntry("api.openai.com", "allowed", "mycontainer", "CONNECT", true)
	s := FormatEntry(e)
	if !strings.Contains(s, "api.openai.com") {
		t.Error("FormatEntry missing domain")
	}
	if !strings.Contains(s, "mycontainer") {
		t.Error("FormatEntry missing container")
	}
	if !strings.Contains(s, "🔓") {
		t.Error("FormatEntry missing TLS indicator")
	}
}

func TestFormatEntry_Denied(t *testing.T) {
	e := makeEntry("evil.com", "denied", "sandbox", "CONNECT", false)
	s := FormatEntry(e)
	if !strings.Contains(s, "⛔") {
		t.Error("FormatEntry denied missing ⛔")
	}
}

func TestFormatEntry_WithPath(t *testing.T) {
	e := makeEntry("api.openai.com", "allowed", "c", "POST", true)
	e.Path = "/v1/chat/completions"
	e.RespCode = 200
	s := FormatEntry(e)
	if !strings.Contains(s, "/v1/chat/completions") {
		t.Errorf("FormatEntry missing path, got: %s", s)
	}
	if !strings.Contains(s, "[200]") {
		t.Errorf("FormatEntry missing resp code, got: %s", s)
	}
}

func TestFormatEntry_LongPathTruncated(t *testing.T) {
	e := makeEntry("api.openai.com", "allowed", "c", "GET", false)
	e.Path = "/" + strings.Repeat("a", 60)
	s := FormatEntry(e)
	if strings.Contains(s, strings.Repeat("a", 60)) {
		t.Error("expected long path to be truncated")
	}
	if !strings.Contains(s, "...") {
		t.Error("expected truncated path to have ...")
	}
}

// ── Concurrency safety ──

func TestAuditLog_Concurrent(t *testing.T) {
	al := NewAuditLog(50)
	done := make(chan struct{})
	for i := 0; i < 30; i++ {
		go func(n int) {
			al.Add(makeEntry("a.com", "allowed", "c", "GET", false))
			al.Last(5)
			al.Stats()
			al.Count()
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 30; i++ {
		<-done
	}
}
