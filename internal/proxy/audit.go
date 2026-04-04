package proxy

import (
	"fmt"
	"sync"
	"time"
)

// AuditLog keeps a ring buffer of recent proxy requests
type AuditLog struct {
	entries []AuditEntry
	maxSize int
	mu      sync.RWMutex
}

// NewAuditLog creates an audit log with a fixed capacity
func NewAuditLog(maxSize int) *AuditLog {
	return &AuditLog{
		entries: make([]AuditEntry, 0, maxSize),
		maxSize: maxSize,
	}
}

// Add appends an entry, evicting the oldest if at capacity
func (a *AuditLog) Add(entry AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.entries) >= a.maxSize {
		a.entries = a.entries[1:]
	}
	a.entries = append(a.entries, entry)
}

// Last returns the most recent n entries
func (a *AuditLog) Last(n int) []AuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if n > len(a.entries) {
		n = len(a.entries)
	}
	start := len(a.entries) - n
	result := make([]AuditEntry, n)
	copy(result, a.entries[start:])
	return result
}

// All returns all entries
func (a *AuditLog) All() []AuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]AuditEntry, len(a.entries))
	copy(result, a.entries)
	return result
}

// Clear removes all entries
func (a *AuditLog) Clear() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = a.entries[:0]
}

// Count returns the number of entries
func (a *AuditLog) Count() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.entries)
}

// Stats returns summary statistics
func (a *AuditLog) Stats() AuditStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	stats := AuditStats{
		Total:       len(a.entries),
		ByStatus:    make(map[string]int),
		ByDomain:    make(map[string]int),
		ByContainer: make(map[string]int),
	}
	for _, e := range a.entries {
		stats.ByStatus[e.Status]++
		stats.ByDomain[e.Domain]++
		stats.ByContainer[e.Container]++
		if e.TLS {
			stats.TLSCount++
		}
	}
	return stats
}

// AuditStats holds aggregated stats
type AuditStats struct {
	Total       int
	TLSCount    int
	ByStatus    map[string]int
	ByDomain    map[string]int
	ByContainer map[string]int
}

// FormatEntry formats an audit entry for display
func FormatEntry(e AuditEntry) string {
	statusIcon := "✅"
	switch {
	case e.Status == "denied-permanent":
		statusIcon = "🚫"
	case e.Status == "denied" || e.Status == "denied-queue-full":
		statusIcon = "⛔"
	case e.Status == "timeout":
		statusIcon = "⏱"
	case e.Status == "approved":
		statusIcon = "👤"
	case e.Status == "approved-permanent":
		statusIcon = "👤+"
	case e.Status == "error-cert" || e.Status == "error-handshake" || e.Status == "error-upstream":
		statusIcon = "💥"
	}

	// TLS indicator
	tlsTag := ""
	if e.TLS {
		tlsTag = "🔓"
	}

	// Path info (MITM mode gives us the full path)
	pathInfo := ""
	if e.Path != "" && e.Path != "/" {
		path := e.Path
		if len(path) > 40 {
			path = path[:37] + "..."
		}
		pathInfo = " " + path
	}

	// Response code
	respInfo := ""
	if e.RespCode > 0 {
		respInfo = fmt.Sprintf(" [%d]", e.RespCode)
	}

	return fmt.Sprintf("%s %s%s %s %s → %s%s%s (%s)",
		e.Time.Format("15:04:05"),
		statusIcon,
		tlsTag,
		e.Container,
		e.Method,
		e.Domain,
		pathInfo,
		respInfo,
		e.Latency.Truncate(time.Millisecond),
	)
}
