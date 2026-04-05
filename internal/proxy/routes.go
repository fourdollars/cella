package proxy

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
)

// InferenceRoute defines how to forward inference API calls for a domain
type InferenceRoute struct {
	// Source: the original target domain (e.g., "api.openai.com")
	SourceDomain string `json:"source_domain"`
	// Backend: the actual upstream to forward to (e.g., "localhost:11434")
	BackendHost string `json:"backend_host"`
	// BackendScheme: "https" (default) or "http" (for local Ollama etc.)
	BackendScheme string `json:"backend_scheme,omitempty"`
	// PathPrefix: optional path prefix to add (e.g., "/v1" for Ollama)
	PathPrefix string `json:"path_prefix,omitempty"`
	// ModelOverride: if set, replace the model field in the request body
	ModelOverride string `json:"model_override,omitempty"`
	// Adapter: API format adapter to apply ("anthropic", "gemini", or empty)
	Adapter AdapterKind `json:"adapter,omitempty"`
	// Note: human-readable description
	Note string `json:"note,omitempty"`
	// Enabled: whether this route is active
	Enabled bool `json:"enabled"`
}

// RouteTable manages inference routing rules
type RouteTable struct {
	mu     sync.RWMutex
	routes map[string]*InferenceRoute // source domain → route
}

// NewRouteTable creates an empty route table
func NewRouteTable() *RouteTable {
	return &RouteTable{
		routes: make(map[string]*InferenceRoute),
	}
}

// Add adds or replaces a route
func (rt *RouteTable) Add(route InferenceRoute) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.routes[route.SourceDomain] = &route
}

// Remove removes a route
func (rt *RouteTable) Remove(domain string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	delete(rt.routes, domain)
}

// Get returns the route for a domain (nil if none or disabled)
func (rt *RouteTable) Get(domain string) *InferenceRoute {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	// Exact match
	if r, ok := rt.routes[domain]; ok && r.Enabled {
		return r
	}

	// Suffix match: route for "openai.com" matches "api.openai.com"
	domainLower := strings.ToLower(domain)
	for src, r := range rt.routes {
		if !r.Enabled {
			continue
		}
		if strings.HasSuffix(domainLower, strings.ToLower(src)) {
			return r
		}
	}
	return nil
}

// List returns all routes sorted by source domain
func (rt *RouteTable) List() []InferenceRoute {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	result := make([]InferenceRoute, 0, len(rt.routes))
	for _, r := range rt.routes {
		result = append(result, *r)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].SourceDomain < result[j].SourceDomain
	})
	return result
}

// BackendURL returns the full backend URL for a request
func (r *InferenceRoute) BackendURL(path string) string {
	scheme := r.BackendScheme
	if scheme == "" {
		scheme = "https"
	}
	prefix := r.PathPrefix
	return scheme + "://" + r.BackendHost + prefix + path
}

// SaveToFile serializes routes to JSON
func (rt *RouteTable) SaveToFile(path string) error {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	data, err := json.MarshalIndent(rt.routes, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadFromFile loads routes from JSON
func (rt *RouteTable) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return json.Unmarshal(data, &rt.routes)
}

// PresetRoutes returns common preset routes for quick configuration
func PresetRoutes() []InferenceRoute {
	return []InferenceRoute{
		{
			SourceDomain:  "api.openai.com",
			BackendHost:   "localhost:11434",
			BackendScheme: "http",
			PathPrefix:    "/v1",
			Note:          "OpenAI → local Ollama",
			Enabled:       false,
		},
		{
			SourceDomain:  "api.anthropic.com",
			BackendHost:   "localhost:11434",
			BackendScheme: "http",
			Adapter:       AdapterAnthropic,
			Note:          "Anthropic → local Ollama (via format adapter)",
			Enabled:       false,
		},
		{
			SourceDomain:  "api.business.githubcopilot.com",
			BackendHost:   "localhost:11434",
			BackendScheme: "http",
			PathPrefix:    "/v1",
			Note:          "GitHub Copilot → local Ollama",
			Enabled:       false,
		},
		{
			SourceDomain:  "generativelanguage.googleapis.com",
			BackendHost:   "localhost:11434",
			BackendScheme: "http",
			Adapter:       AdapterGemini,
			Note:          "Gemini → local Ollama (via format adapter)",
			Enabled:       false,
		},
	}
}
