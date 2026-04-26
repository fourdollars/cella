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
	CancelCh   chan struct{}         // closed by proxy when request times out
}

// ApprovalResponse carries the operator's decision
type ApprovalResponse struct {
	Approved  bool
	Permanent bool // true = add to allowlist/denylist permanently
}

// AuditEntry records a proxied request
type AuditEntry struct {
	Time             time.Time
	Container        string
	Domain           string
	Method           string
	URL              string
	Path             string // URL path (populated in MITM mode)
	Status           string // "allowed", "denied", "approved", "timeout", "denied-permanent"
	RespCode         int    // HTTP response code (MITM mode)
	Latency          time.Duration
	TLS              bool   // true = decrypted HTTPS via MITM
	BrokerTokenID    string // selected broker token id (if any)
	BrokerAuthSource string // broker auth source, e.g. pat:PAT_ENV or exchanged:PAT_ENV
}

// Broker*State is a runtime snapshot of token broker policy staged/applied from TUI.
type BrokerGroupState struct {
	ID       string
	Name     string // legacy alias of ID (kept for backward compatibility)
	Match    string // container match rule: exact / prefix: / contains: / glob
	Pool     string
	Weight   int
	RPHLimit int
}

// BrokerTokenKind identifies the auth strategy for a broker token.
// ""        → auto-detect from PAT value prefix.
// "copilot" → GitHub PAT (ghu_...) exchanged for a Copilot session token.
// "gemini"  → Google Gemini API key injected as x-goog-api-key header.
// "openai"  → OpenAI-compatible API key injected as Authorization: Bearer.
type BrokerTokenKind = string

const (
	BrokerTokenKindAuto    BrokerTokenKind = ""
	BrokerTokenKindCopilot BrokerTokenKind = "copilot"
	BrokerTokenKindGemini  BrokerTokenKind = "gemini"
	BrokerTokenKindOpenAI  BrokerTokenKind = "openai"
)

type BrokerTokenState struct {
	ID           string
	Kind         BrokerTokenKind // auth strategy; "" = auto-detect from PAT prefix
	Endpoint     string          // per-token upstream endpoint; "" = use kind default
	Enabled      bool
	Health       float64
	RemainingRPH int
	BreakerOpen  bool
	SessionState string
	LastTest     string
	PATEnv       string
	P95ms        int
}

type BrokerPoolState struct {
	Name   string
	Tokens []BrokerTokenState
}

type BrokerPolicyState struct {
	Name     string
	Group    string
	Pool     string
	Strategy string
	Sticky   bool
	Retry    int
}

type BrokerState struct {
	AppliedAt        time.Time
	ExchangeEndpoint string
	Groups           []BrokerGroupState
	Pools            []BrokerPoolState
	Policies         []BrokerPolicyState
}

type brokerSessionEntry struct {
	SessionToken string
	SourceEnv    string
	ExpiresAt    time.Time
}

type brokerCounterEvent struct {
	At  time.Time
	Key string
}

// Server is the HTTP/CONNECT proxy with operator approval
type Server struct {
	port                   int
	allowlists             map[string]*Allowlist // container name → allowlist
	denylists              map[string]*Denylist  // container name → denylist
	containerByIP          map[string]string     // source IP → container name
	approvalCh             chan ApprovalRequest  // → TUI for approval
	audit                  *AuditLog
	inferenceStats         *InferenceStats
	routes                 *RouteTable
	brokerState            BrokerState
	brokerSessions         map[string]brokerSessionEntry
	brokerCounters         map[string]int64
	brokerCounterEvents    []brokerCounterEvent
	brokerCounterEventCap  int
	mitm                   *MITMConfig // nil = tunnel mode, non-nil = MITM mode
	hostInterceptionActive bool
	mu                     sync.RWMutex
	nextID                 int
	timeout                time.Duration // approval timeout
}

// NewServer creates a proxy server
func NewServer(port int, approvalCh chan ApprovalRequest) *Server {
	return &Server{
		port:                  port,
		allowlists:            make(map[string]*Allowlist),
		denylists:             make(map[string]*Denylist),
		containerByIP:         make(map[string]string),
		approvalCh:            approvalCh,
		audit:                 NewAuditLog(500),
		inferenceStats:        NewInferenceStats(),
		routes:                NewRouteTable(),
		brokerSessions:        make(map[string]brokerSessionEntry),
		brokerCounters:        make(map[string]int64),
		brokerCounterEventCap: 4096,
		timeout:               30 * time.Second,
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

// SetBrokerState stores a runtime broker snapshot that can later be consumed by
// admission/scheduler logic.

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
