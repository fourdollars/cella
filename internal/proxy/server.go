package proxy

import (
	"context"
	"fmt"
	"io"
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
	Status    string // "allowed", "denied", "approved", "timeout"
	Latency   time.Duration
}

// Server is the HTTP/CONNECT proxy with operator approval
type Server struct {
	port          int
	listener      net.Listener
	allowlists    map[string]*Allowlist // container name → allowlist
	containerByIP map[string]string     // source IP → container name
	approvalCh    chan ApprovalRequest   // → TUI for approval
	audit         *AuditLog
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
		audit:         NewAuditLog(500),
		timeout:       30 * time.Second,
	}
}

// Start begins listening. Call in a goroutine.
func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("proxy listen %s: %w", addr, err)
	}
	s.listener = ln

	srv := &http.Server{
		Handler:      s,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	return srv.Serve(ln)
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

// ServeHTTP handles both regular HTTP and CONNECT (HTTPS tunnel) requests
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handleHTTP(w, r)
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	srcIP := extractIP(r.RemoteAddr)

	s.mu.RLock()
	container := s.containerByIP[srcIP]
	s.mu.RUnlock()

	if container == "" {
		container = srcIP // fallback: show IP if unknown
	}

	domain := extractDomain(r.Host)

	// Check allowlist
	al := s.GetAllowlist(container)
	if al.IsAllowed(domain) {
		// Forward directly
		s.forwardHTTP(w, r)
		s.audit.Add(AuditEntry{
			Time: start, Container: container, Domain: domain,
			Method: r.Method, URL: r.URL.String(), Status: "allowed",
			Latency: time.Since(start),
		})
		return
	}

	// Need operator approval
	status := s.requestApproval(container, domain, r.Method, r.URL.String())
	if status == "approved" || status == "approved-permanent" {
		if status == "approved-permanent" {
			al.Add(domain)
		}
		s.forwardHTTP(w, r)
	} else {
		http.Error(w, fmt.Sprintf("Blocked by cella policy (%s)", status), http.StatusForbidden)
	}
	s.audit.Add(AuditEntry{
		Time: start, Container: container, Domain: domain,
		Method: r.Method, URL: r.URL.String(), Status: status,
		Latency: time.Since(start),
	})
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	srcIP := extractIP(r.RemoteAddr)

	s.mu.RLock()
	container := s.containerByIP[srcIP]
	s.mu.RUnlock()

	if container == "" {
		container = srcIP
	}

	host, port := splitHostPort(r.Host)
	domain := host

	// Check allowlist
	al := s.GetAllowlist(container)
	if !al.IsAllowed(domain) {
		status := s.requestApproval(container, domain, "CONNECT", r.Host)
		if status == "approved-permanent" {
			al.Add(domain)
		} else if status != "approved" {
			http.Error(w, fmt.Sprintf("Blocked by cella policy (%s)", status), http.StatusForbidden)
			s.audit.Add(AuditEntry{
				Time: start, Container: container, Domain: domain,
				Method: "CONNECT", URL: r.Host, Status: status,
				Latency: time.Since(start),
			})
			return
		}
	}

	// Establish tunnel
	targetAddr := r.Host
	if port == "" {
		targetAddr = host + ":443"
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		http.Error(w, fmt.Sprintf("Tunnel dial failed: %v", err), http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		targetConn.Close()
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Bidirectional copy
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(targetConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, targetConn)
		done <- struct{}{}
	}()
	<-done

	clientConn.Close()
	targetConn.Close()

	s.audit.Add(AuditEntry{
		Time: start, Container: container, Domain: domain,
		Method: "CONNECT", URL: r.Host, Status: "allowed",
		Latency: time.Since(start),
	})
}

func (s *Server) forwardHTTP(w http.ResponseWriter, r *http.Request) {
	// Remove proxy-specific headers
	r.RequestURI = ""
	removeHopByHopHeaders(r.Header)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *Server) requestApproval(container, domain, method, url string) string {
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
		Time:       time.Now(),
		ResponseCh: responseCh,
	}

	// Send to TUI (non-blocking with timeout)
	select {
	case s.approvalCh <- req:
	case <-time.After(2 * time.Second):
		return "denied-queue-full"
	}

	// Wait for operator response
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
		return host // no port
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

// GlobalAllowlist returns domains that should always be allowed (DNS, NTP, etc.)
func GlobalAllowlist() []string {
	return []string{
		// Common infrastructure
		"dns.google",
		"1.1.1.1",
		"1.0.0.1",
		"8.8.8.8",
		"8.8.4.4",
	}
}
