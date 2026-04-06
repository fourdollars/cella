package proxy

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// ApprovalRequest represents a pending operator approval
type ApprovalRequest struct {
	ID         string
	Container  string // container name (resolved from source IP)
	Domain     string // target domain (e.g., "api.openai.com")
	Port       string // target port
	Method     string // HTTP method or "CONNECT"
	URL        string // full URL (HTTP) or host:port (CONNECT)
	Path       string // URL path (populated in MITM mode)
	Time       time.Time
	ResponseCh chan ApprovalResponse // send response here to unblock proxy
	CancelCh   chan struct{}          // closed by proxy when request times out
}

// ApprovalResponse carries the operator's decision
type ApprovalResponse struct {
	Approved  bool
	Permanent bool // true = add to allowlist/denylist permanently
}

// AuditEntry records a proxied request
type AuditEntry struct {
	Time      time.Time
	Container string
	Domain    string
	Method    string
	URL       string
	Path      string // URL path (populated in MITM mode)
	Status    string // "allowed", "denied", "approved", "timeout", "denied-permanent"
	RespCode  int    // HTTP response code (MITM mode)
	Latency   time.Duration
	TLS       bool // true = decrypted HTTPS via MITM
}

// Server is the HTTP/CONNECT proxy with operator approval
type Server struct {
	port           int
	allowlists     map[string]*Allowlist // container name → allowlist
	denylists      map[string]*Denylist  // container name → denylist
	containerByIP  map[string]string     // source IP → container name
	approvalCh     chan ApprovalRequest  // → TUI for approval
	audit          *AuditLog
	inferenceStats *InferenceStats
	routes         *RouteTable
	mitm                  *MITMConfig // nil = tunnel mode, non-nil = MITM mode
	hostInterceptionActive bool
	mu                    sync.RWMutex
	nextID         int
	timeout        time.Duration // approval timeout
}

// NewServer creates a proxy server
func NewServer(port int, approvalCh chan ApprovalRequest) *Server {
	return &Server{
		port:           port,
		allowlists:     make(map[string]*Allowlist),
		denylists:      make(map[string]*Denylist),
		containerByIP:  make(map[string]string),
		approvalCh:     approvalCh,
		audit:          NewAuditLog(500),
		inferenceStats: NewInferenceStats(),
		routes:         NewRouteTable(),
		timeout:        30 * time.Second,
	}
}

// HostInterceptionActive returns whether host OUTPUT redirect is enabled.
func (s *Server) HostInterceptionActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hostInterceptionActive
}

// SetHostInterceptionActive sets the host interception state flag.
func (s *Server) SetHostInterceptionActive(active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostInterceptionActive = active
}

// EnableMITM activates TLS interception with the given config
func (s *Server) EnableMITM(cfg *MITMConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mitm = cfg
}

// MITMEnabled returns true if MITM mode is active
func (s *Server) MITMEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mitm != nil
}

// MITMCAPem returns the CA certificate PEM for container injection
func (s *Server) MITMCAPem() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.mitm == nil {
		return nil
	}
	return s.mitm.CACertPEM()
}

// Port returns the listening port
func (s *Server) Port() int { return s.port }

// UpdateContainerMap refreshes the IP → container mapping
func (s *Server) UpdateContainerMap(mapping map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.containerByIP = mapping
}

// GetAllowlist returns the allowlist for a container (creates if needed)
func (s *Server) GetAllowlist(container string) *Allowlist {
	s.mu.Lock()
	defer s.mu.Unlock()
	if al, ok := s.allowlists[container]; ok {
		return al
	}
	al := NewAllowlist()
	s.allowlists[container] = al
	return al
}

// GetDenylist returns the denylist for a container (creates if needed)
func (s *Server) GetDenylist(container string) *Denylist {
	s.mu.Lock()
	defer s.mu.Unlock()
	if dl, ok := s.denylists[container]; ok {
		return dl
	}
	dl := NewDenylist()
	s.denylists[container] = dl
	return dl
}

// Audit returns the audit log
func (s *Server) Audit() *AuditLog { return s.audit }

func (s *Server) InferenceStats() *InferenceStats { return s.inferenceStats }

// AllAllowlists returns a snapshot of the container→allowlist map for persistence.
func (s *Server) AllAllowlists() map[string]*Allowlist {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]*Allowlist, len(s.allowlists))
	for k, v := range s.allowlists {
		result[k] = v
	}
	return result
}

// AllDenylists returns a snapshot of the container→denylist map for persistence.
func (s *Server) AllDenylists() map[string]*Denylist {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]*Denylist, len(s.denylists))
	for k, v := range s.denylists {
		result[k] = v
	}
	return result
}

// LoadAllowlistsFromDir loads persisted allowlists into the server.
// Existing in-memory entries are kept; persisted domains are merged in.
func (s *Server) LoadAllowlistsFromDir(dataDir string) error {
	loaded, err := LoadAllowlists(dataDir)
	if err != nil {
		return err
	}
	for container, al := range loaded {
		for _, d := range al.UserDomains() {
			s.GetAllowlist(container).Add(d)
		}
	}
	return nil
}

// SaveAllowlistsToDir persists all per-container allowlists to dataDir.
func (s *Server) SaveAllowlistsToDir(dataDir string) error {
	return SaveAllowlists(dataDir, s.AllAllowlists())
}

// LoadDenylistsFromDir loads persisted denylists into the server.
func (s *Server) LoadDenylistsFromDir(dataDir string) error {
	loaded, err := LoadDenylists(dataDir)
	if err != nil {
		return err
	}
	for container, dl := range loaded {
		for _, d := range dl.List() {
			s.GetDenylist(container).Add(d)
		}
	}
	return nil
}

// SaveDenylistsToDir persists all per-container denylists to dataDir.
func (s *Server) SaveDenylistsToDir(dataDir string) error {
	return SaveDenylists(dataDir, s.AllDenylists())
}

func (s *Server) Routes() *RouteTable { return s.routes }

func (s *Server) requestApproval(container, domain, method, url, path string) string {
	s.mu.Lock()
	s.nextID++
	id := fmt.Sprintf("req-%d", s.nextID)
	s.mu.Unlock()

	responseCh := make(chan ApprovalResponse, 1)
	cancelCh := make(chan struct{})
	req := ApprovalRequest{
		ID:         id,
		Container:  container,
		Domain:     domain,
		Method:     method,
		URL:        url,
		Path:       path,
		Time:       time.Now(),
		ResponseCh: responseCh,
		CancelCh:   cancelCh,
	}

	select {
	case s.approvalCh <- req:
	case <-time.After(2 * time.Second):
		return "denied-queue-full"
	}

	select {
	case resp := <-responseCh:
		if resp.Approved {
			if resp.Permanent {
				return "approved-permanent"
			}
			return "approved"
		}
		if resp.Permanent {
			return "denied-permanent"
		}
		return "denied"
	case <-time.After(s.timeout):
		close(cancelCh) // signal TUI that this request has expired
		return "timeout"
	}
}

// ── Helpers ──

func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func extractDomain(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}

func splitHostPort(hostport string) (string, string) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, ""
	}
	return host, port
}

func removeHopByHopHeaders(h http.Header) {
	hopByHop := []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailers",
		"Transfer-Encoding", "Upgrade", "Proxy-Connection",
	}
	for _, hdr := range hopByHop {
		h.Del(hdr)
	}
}

// GlobalAllowlist returns domains that should always be allowed
func GlobalAllowlist() []string {
	return []string{
		"dns.google",
		"1.1.1.1",
		"1.0.0.1",
		"8.8.8.8",
		"8.8.4.4",
	}
}
