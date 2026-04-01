package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

// UserDomains returns only user-added domains (excludes global defaults).
func (a *Allowlist) UserDomains() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	globals := make(map[string]bool)
	for _, d := range GlobalAllowlist() {
		globals[d] = true
	}
	var result []string
	for d := range a.domains {
		if !globals[d] {
			result = append(result, d)
		}
	}
	sort.Strings(result)
	return result
}

// ── Persistence ─────────────────────────────────────────────────────────────

// allowlistFile is the on-disk format: a JSON object mapping container name
// to its user-added domain list (global defaults are excluded).
type allowlistFile struct {
	Containers map[string][]string `json:"containers"`
}

// SaveAllowlists writes all per-container allowlists to
// <dataDir>/allowlist.json, excluding global default entries.
func SaveAllowlists(dataDir string, allowlists map[string]*Allowlist) error {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("allowlist mkdir: %w", err)
	}
	f := allowlistFile{Containers: make(map[string][]string)}
	for container, al := range allowlists {
		userDomains := al.UserDomains()
		if len(userDomains) > 0 {
			f.Containers[container] = userDomains
		}
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("allowlist marshal: %w", err)
	}
	tmp := filepath.Join(dataDir, "allowlist.json.tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("allowlist write: %w", err)
	}
	return os.Rename(tmp, filepath.Join(dataDir, "allowlist.json"))
}

// LoadAllowlists reads <dataDir>/allowlist.json and returns a map of
// container name → Allowlist. Missing file returns an empty map (not an error).
func LoadAllowlists(dataDir string) (map[string]*Allowlist, error) {
	path := filepath.Join(dataDir, "allowlist.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return make(map[string]*Allowlist), nil
	}
	if err != nil {
		return nil, fmt.Errorf("allowlist read: %w", err)
	}
	var f allowlistFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("allowlist parse: %w", err)
	}
	result := make(map[string]*Allowlist, len(f.Containers))
	for container, domains := range f.Containers {
		al := NewAllowlist()
		for _, d := range domains {
			al.Add(d)
		}
		result[container] = al
	}
	return result, nil
}
