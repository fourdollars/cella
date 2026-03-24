package proxy

import (
	"strings"
	"sync"
)

// Allowlist holds per-container allowed domains
type Allowlist struct {
	domains map[string]bool // exact match or wildcard (*.example.com)
	mu      sync.RWMutex
}

// NewAllowlist creates an empty allowlist
func NewAllowlist() *Allowlist {
	al := &Allowlist{
		domains: make(map[string]bool),
	}
	// Add global defaults
	for _, d := range GlobalAllowlist() {
		al.domains[d] = true
	}
	return al
}

// Add adds a domain to the allowlist
func (a *Allowlist) Add(domain string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.domains[strings.ToLower(domain)] = true
}

// Remove removes a domain from the allowlist
func (a *Allowlist) Remove(domain string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.domains, strings.ToLower(domain))
}

// IsAllowed checks if a domain is allowed (supports *.example.com wildcards)
func (a *Allowlist) IsAllowed(domain string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	domain = strings.ToLower(domain)

	// Exact match
	if a.domains[domain] {
		return true
	}

	// Check wildcard patterns: *.example.com matches sub.example.com
	for pattern := range a.domains {
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".example.com"
			if strings.HasSuffix(domain, suffix) {
				return true
			}
		}
	}

	// Check if any allowed domain is a parent (e.g., "example.com" allows "sub.example.com")
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if a.domains[parent] {
			return true
		}
	}

	return false
}

// List returns all domains in the allowlist
func (a *Allowlist) List() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]string, 0, len(a.domains))
	for d := range a.domains {
		result = append(result, d)
	}
	return result
}

// SetFromList replaces the allowlist with a new set of domains
func (a *Allowlist) SetFromList(domains []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.domains = make(map[string]bool)
	for _, d := range GlobalAllowlist() {
		a.domains[d] = true
	}
	for _, d := range domains {
		a.domains[strings.ToLower(d)] = true
	}
}

// Count returns the number of entries
func (a *Allowlist) Count() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.domains)
}
