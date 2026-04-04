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

// Denylist holds per-container permanently denied domains.
// IsDenied must be checked before IsAllowed in the proxy path.
type Denylist struct {
	domains map[string]bool
	mu      sync.RWMutex
}

// NewDenylist creates an empty denylist.
func NewDenylist() *Denylist {
	return &Denylist{domains: make(map[string]bool)}
}

// Add adds a domain to the denylist.
func (d *Denylist) Add(domain string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.domains[strings.ToLower(domain)] = true
}

// Remove removes a domain from the denylist.
func (d *Denylist) Remove(domain string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.domains, strings.ToLower(domain))
}

// IsDenied returns true if the domain matches a denylist entry.
// Supports exact match, *.example.com wildcards, and parent-domain match.
func (d *Denylist) IsDenied(domain string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	domain = strings.ToLower(domain)
	if d.domains[domain] {
		return true
	}
	for pattern := range d.domains {
		if strings.HasPrefix(pattern, "*.") {
			if strings.HasSuffix(domain, pattern[1:]) {
				return true
			}
		}
	}
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		if d.domains[strings.Join(parts[i:], ".")] {
			return true
		}
	}
	return false
}

// List returns all denied domains, sorted.
func (d *Denylist) List() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	result := make([]string, 0, len(d.domains))
	for dom := range d.domains {
		result = append(result, dom)
	}
	sort.Strings(result)
	return result
}

// Count returns the number of entries.
func (d *Denylist) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.domains)
}

// ── Persistence ─────────────────────────────────────────────────────────────

type denylistFile struct {
	Containers map[string][]string `json:"containers"`
}

// SaveDenylists writes all per-container denylists to <dataDir>/denylist.json.
func SaveDenylists(dataDir string, denylists map[string]*Denylist) error {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("denylist mkdir: %w", err)
	}
	f := denylistFile{Containers: make(map[string][]string)}
	for container, dl := range denylists {
		domains := dl.List()
		if len(domains) > 0 {
			f.Containers[container] = domains
		}
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("denylist marshal: %w", err)
	}
	tmp := filepath.Join(dataDir, "denylist.json.tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("denylist write: %w", err)
	}
	return os.Rename(tmp, filepath.Join(dataDir, "denylist.json"))
}

// LoadDenylists reads <dataDir>/denylist.json. Missing file → empty map.
func LoadDenylists(dataDir string) (map[string]*Denylist, error) {
	path := filepath.Join(dataDir, "denylist.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return make(map[string]*Denylist), nil
	}
	if err != nil {
		return nil, fmt.Errorf("denylist read: %w", err)
	}
	var f denylistFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("denylist parse: %w", err)
	}
	result := make(map[string]*Denylist, len(f.Containers))
	for container, domains := range f.Containers {
		dl := NewDenylist()
		for _, dom := range domains {
			dl.Add(dom)
		}
		result[container] = dl
	}
	return result, nil
}
