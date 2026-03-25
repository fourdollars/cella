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
}

// ApprovalResponse carries the operator's decision
type ApprovalResponse struct {
	Approved  bool
	Permanent bool // true = add to allowlist permanently
}

// AuditEntry records a proxied request
type AuditEntry struct {
	Time      time.Time
	Container string
	Domain    string
	Method    string
	URL       string
	Path      string // URL path (populated in MITM mode)
	Status    string // "allowed", "denied", "approved", "timeout"
	RespCode  int    // HTTP response code (MITM mode)
	Latency   time.Duration
	TLS       bool   // true = decrypted HTTPS via MITM
}

// Server is the HTTP/CONNECT proxy with operator approval
type Server struct {
	port          int
	allowlists    map[string]*Allowlist // container name → allowlist
	containerByIP map[string]string     // source IP → container name
	approvalCh    chan ApprovalRequest   // → TUI for approval
	audit          *AuditLog
	inferenceStats *InferenceStats
	routes         *RouteTable
	mitm          *MITMConfig           // nil = tunnel mode, non-nil = MITM mode
	mu            sync.RWMutex
	nextID        int
	timeout       time.Duration // approval timeout
}

// NewServer creates a proxy server
func NewServer(port int, approvalCh chan ApprovalRequest) *Server {
	return &Server{
		port:          port,
		allowlists:    make(map[string]*Allowlist),
		containerByIP: make(map[string]string),
		approvalCh:    approvalCh,
		audit:          NewAuditLog(500),
		inferenceStats: NewInferenceStats(),
		routes:         NewRouteTable(),
		timeout:       30 * time.Second,
	}
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

// Audit returns the audit log
func (s *Server) Audit() *AuditLog { return s.audit }

func (s *Server) InferenceStats() *InferenceStats { return s.inferenceStats }

func (s *Server) Routes() *RouteTable { return s.routes }






func (s *Server) requestApproval(container, domain, method, url, path string) string {
	s.mu.Lock()
	s.nextID++
	id := fmt.Sprintf("req-%d", s.nextID)
	s.mu.Unlock()

	responseCh := make(chan ApprovalResponse, 1)
	req := ApprovalRequest{
		ID:         id,
		Container:  container,
		Domain:     domain,
		Method:     method,
		URL:        url,
		Path:       path,
		Time:       time.Now(),
		ResponseCh: responseCh,
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
		return "denied"
	case <-time.After(s.timeout):
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
