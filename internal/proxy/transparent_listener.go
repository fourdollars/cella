package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const mitmRetryBackoff = 5 * time.Second

// TransparentListener handles connections redirected by nftables REDIRECT/DNAT.
// These are raw TCP connections (not HTTP CONNECT), so we need to:
// 1. Peek the TLS ClientHello to extract SNI (domain name)
// 2. Check allowlist / request approval
// 3. Forward to upstream or MITM-intercept
type TransparentListener struct {
	port             int
	server           *Server
	listener         net.Listener
	pendingApprovals map[string]chan bool // domain → result channel (dedup concurrent approvals)
	mitmFailedUntil  map[string]time.Time // domain → temporarily bypass MITM until this time
	infraBypass      map[string]bool      // domains that should always use tunnel passthrough (no MITM)
	mu               sync.RWMutex
	// onPermanentAllow is called whenever a domain is permanently added to an
	// allowlist (i.e. operator pressed [Y]). Use it to persist the allowlist.
	onPermanentAllow func()
	// onPermanentDeny is called whenever a domain is permanently added to a
	// denylist (i.e. operator pressed [N]). Use it to persist the denylist.
	onPermanentDeny func()
}

// NewTransparentListener creates a transparent proxy listener
func NewTransparentListener(port int, server *Server) *TransparentListener {
	return &TransparentListener{
		port:             port,
		server:           server,
		pendingApprovals: make(map[string]chan bool),
		mitmFailedUntil:  make(map[string]time.Time),
		infraBypass:      defaultInfraBypass(),
	}
}

// SetOnPermanentAllow registers a callback invoked after every permanent
// allowlist addition. Typically used to persist the updated allowlist.
func (t *TransparentListener) SetOnPermanentAllow(fn func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onPermanentAllow = fn
}

// SetOnPermanentDeny registers a callback invoked after every permanent
// denylist addition. Typically used to persist the updated denylist.
func (t *TransparentListener) SetOnPermanentDeny(fn func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onPermanentDeny = fn
}

// Start begins accepting redirected connections
func (t *TransparentListener) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", t.port))
	if err != nil {
		return fmt.Errorf("transparent listen :%d: %w", t.port, err)
	}
	t.listener = ln

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go t.handleConn(conn)
		}
	}()

	return nil
}

// Port returns the listening port
func (t *TransparentListener) Port() int { return t.port }

// Stop closes the listener
func (t *TransparentListener) Stop() {
	if t.listener != nil {
		t.listener.Close()
	}
}

func (t *TransparentListener) handleConn(clientConn net.Conn) {
	defer clientConn.Close()
	start := time.Now()

	// Resolve source container
	srcIP := extractIP(clientConn.RemoteAddr().String())
	t.server.mu.RLock()
	container := t.server.containerByIP[srcIP]
	mitmCfg := t.server.mitm
	t.server.mu.RUnlock()
	if container == "" {
		// containerByIP not yet populated for this IP — try reverse DNS.
		// LXD containers typically have PTR records like "name.lxd".
		container = resolveContainerName(srcIP)
	}

	// Peek the first bytes to detect TLS and extract SNI
	peekReader := bufio.NewReaderSize(clientConn, 4096)
	peeked, err := peekReader.Peek(5)
	if err != nil {
		return
	}

	// Check if this is TLS (ContentType=22, handshake)
	isTLS := peeked[0] == 0x16 && peeked[1] == 0x03

	if isTLS {
		t.handleTLS(clientConn, peekReader, container, srcIP, mitmCfg, start)
	} else {
		t.handlePlainHTTP(clientConn, peekReader, container, srcIP, start)
	}
}

func (t *TransparentListener) handleTLS(
	clientConn net.Conn,
	reader *bufio.Reader,
	container, srcIP string,
	mitmCfg *MITMConfig,
	start time.Time,
) {
	// Extract SNI from TLS ClientHello
	// We need to read the full ClientHello to get the SNI
	domain := extractSNI(reader)
	if domain == "" {
		// No SNI — try to determine the original destination via reverse DNS.
		// nftables REDIRECT keeps the original dst in SO_ORIGINAL_DST but that
		// requires a syscall; instead we do a best-effort PTR lookup on the
		// destination IP we can infer from the connection context.
		// For now fall back to the source IP label so the operator at least
		// sees something actionable.
		domain = "unknown"
	} else {
		// SNI present but may be a raw IP (some clients do this) — resolve it
		domain = resolveHost(domain)
	}

	// Check denylist first — permanently denied domains are blocked immediately
	dl := t.server.GetDenylist(container)
	if dl.IsDenied(domain) {
		t.server.audit.Add(AuditEntry{
			Time: start, Container: container, Domain: domain,
			Method: "TPROXY", Status: "denied-permanent", TLS: true,
			Latency: time.Since(start),
		})
		return
	}

	// Check allowlist (with dedup for concurrent connections)
	al := t.server.GetAllowlist(container)
	if !al.IsAllowed(domain) {
		// Check if another goroutine is already requesting approval for this domain
		approvalKey := container + ":" + domain
		t.mu.Lock()
		if ch, pending := t.pendingApprovals[approvalKey]; pending {
			t.mu.Unlock()
			// Wait for the other goroutine's result
			approved := <-ch
			if !approved {
				return
			}
		} else {
			// First request for this domain — we do the approval
			resultCh := make(chan bool, 10)
			t.pendingApprovals[approvalKey] = resultCh
			t.mu.Unlock()

			status := t.server.requestApproval(container, domain, "CONNECT", domain+":443", "")
			approved := status == "approved-permanent" || status == "approved"

			if status == "approved-permanent" {
				al.Add(domain)
				t.mu.RLock()
				cb := t.onPermanentAllow
				t.mu.RUnlock()
				if cb != nil {
					go cb()
				}
			} else if status == "denied-permanent" {
				dl.Add(domain)
				t.mu.RLock()
				cb := t.onPermanentDeny
				t.mu.RUnlock()
				if cb != nil {
					go cb()
				}
			}

			// Notify all waiting goroutines
			t.mu.Lock()
			delete(t.pendingApprovals, approvalKey)
			t.mu.Unlock()
			// Send result to all waiters (buffered channel, non-blocking)
			for i := 0; i < 10; i++ {
				select {
				case resultCh <- approved:
				default:
				}
			}

			if !approved {
				t.server.audit.Add(AuditEntry{
					Time: start, Container: container, Domain: domain,
					Method: "TPROXY", Status: status, TLS: true,
					Latency: time.Since(start),
				})
				return
			}
		}
	}

	// Log the approval
	t.server.audit.Add(AuditEntry{
		Time: start, Container: container, Domain: domain,
		Method: "TPROXY", URL: domain + ":443",
		Status: "allowed", TLS: true,
		Latency: time.Since(start),
	})

	// Wrap reader back into a net.Conn
	bufferedConn := &bufferedConn{Conn: clientConn, reader: reader}

	// Infrastructure bypass: domains that use cert pinning or custom protocols
	// (e.g. Tailscale controlplane) always go through tunnel passthrough.
	t.mu.RLock()
	bypassed := t.infraBypass[domain]
	if !bypassed {
		// Also check suffix match (e.g. *.tailscale.com)
		for d := range t.infraBypass {
			if len(d) > 0 && d[0] == '.' && strings.HasSuffix(domain, d) {
				bypassed = true
				break
			}
		}
	}
	t.mu.RUnlock()
	if bypassed {
		t.tunnelPassthrough(clientConn, reader, container, domain, start)
		return
	}

	// MITM mode: intercept TLS (only for pre-allowed domains where CA cert is trusted)
	// On handshake failure we temporarily bypass MITM, then retry after backoff.
	if mitmCfg != nil && !t.shouldBypassMITM(domain) {
		t.handleMITMTransparent(bufferedConn, container, domain, mitmCfg, start)
		return
	}

	// Tunnel mode: connect to upstream and relay
	upstream, err := net.DialTimeout("tcp", domain+":443", 10*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, bufferedConn); done <- struct{}{} }()
	go func() { io.Copy(bufferedConn, upstream); done <- struct{}{} }()
	<-done

	t.server.audit.Add(AuditEntry{
		Time: start, Container: container, Domain: domain,
		Method: "TPROXY", URL: domain + ":443", Status: "allowed", TLS: true,
		Latency: time.Since(start),
	})
}

func (t *TransparentListener) handlePlainHTTP(
	clientConn net.Conn,
	reader *bufio.Reader,
	container, srcIP string,
	start time.Time,
) {
	// Read HTTP request
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	domain := req.Host
	if domain == "" {
		domain = "unknown"
	}
	domain = extractDomain(domain)
	domain = resolveHost(domain)

	// Check denylist first
	dl := t.server.GetDenylist(container)
	if dl.IsDenied(domain) {
		clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 28\r\n\r\nBlocked by cella proxy policy"))
		t.server.audit.Add(AuditEntry{
			Time: start, Container: container, Domain: domain,
			Method: req.Method, URL: req.URL.String(), Path: req.URL.Path,
			Status: "denied-permanent", Latency: time.Since(start),
		})
		return
	}

	al := t.server.GetAllowlist(container)
	if !al.IsAllowed(domain) {
		status := t.server.requestApproval(container, domain, req.Method, req.URL.String(), req.URL.Path)
		if status == "approved-permanent" {
			al.Add(domain)
			t.mu.RLock()
			cb := t.onPermanentAllow
			t.mu.RUnlock()
			if cb != nil {
				go cb()
			}
		} else if status == "denied-permanent" {
			dl.Add(domain)
			t.mu.RLock()
			cb := t.onPermanentDeny
			t.mu.RUnlock()
			if cb != nil {
				go cb()
			}
			clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 28\r\n\r\nBlocked by cella proxy policy"))
			t.server.audit.Add(AuditEntry{
				Time: start, Container: container, Domain: domain,
				Method: req.Method, URL: req.URL.String(), Path: req.URL.Path,
				Status: "denied-permanent", Latency: time.Since(start),
			})
			return
		} else if status != "approved" {
			clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 28\r\n\r\nBlocked by cella proxy policy"))
			t.server.audit.Add(AuditEntry{
				Time: start, Container: container, Domain: domain,
				Method: req.Method, URL: req.URL.String(), Path: req.URL.Path,
				Status: status, Latency: time.Since(start),
			})
			return
		}
	}

	// Forward to upstream
	targetAddr := req.Host
	if !hasPort(targetAddr) {
		targetAddr += ":80"
	}

	upstream, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()

	req.RequestURI = ""
	removeHopByHopHeaders(req.Header)
	req.Write(upstream)

	// Relay response
	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	t.server.audit.Add(AuditEntry{
		Time: start, Container: container, Domain: domain,
		Method: req.Method, URL: req.URL.String(), Path: req.URL.Path,
		Status: "allowed", RespCode: resp.StatusCode,
		Latency: time.Since(start),
	})

	resp.Write(clientConn)
}

func (t *TransparentListener) markMITMFailure(domain string) {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mitmFailedUntil[d] = time.Now().Add(mitmRetryBackoff)
}

func (t *TransparentListener) clearMITMFailure(domain string) {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.mitmFailedUntil, d)
}

func (t *TransparentListener) shouldBypassMITM(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return false
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	until, ok := t.mitmFailedUntil[d]
	if !ok {
		return false
	}
	if now.After(until) {
		delete(t.mitmFailedUntil, d)
		return false
	}
	return true
}

// resolveContainerName resolves a source IP to a container name.
// It attempts a PTR lookup and strips common suffixes (.lxd, .local, trailing dot).
// Falls back to the raw IP if resolution fails or times out.
func resolveContainerName(ip string) string {
	if ip == "" {
		return ip
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ip
	}
	name := strings.TrimSuffix(names[0], ".")
	// Strip common container DNS suffixes: .lxd .local
	for _, suffix := range []string{".lxd", ".local"} {
		if strings.HasSuffix(name, suffix) {
			name = name[:len(name)-len(suffix)]
			break
		}
	}
	if name == "" {
		return ip
	}
	return name
}

// ── resolveHost: try reverse DNS for bare IPs ──

// resolveHost returns the canonical hostname for addr.
// If addr is already a hostname it is returned as-is (lowercased).
// If addr looks like an IP, a reverse DNS (PTR) lookup is attempted;
// on success the first result (trimmed of trailing dot) is returned.
// Falls back to the original addr string if lookup fails or times out.
func resolveHost(addr string) string {
	if addr == "" {
		return addr
	}
	// Check if it's an IP address
	if net.ParseIP(addr) == nil {
		// Not an IP — already a hostname
		return strings.ToLower(addr)
	}
	// It's an IP — try reverse DNS with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, addr)
	if err != nil || len(names) == 0 {
		return addr // fallback to IP
	}
	// Trim trailing dot from PTR record (e.g. "host.example.com.")
	name := strings.TrimSuffix(names[0], ".")
	if name == "" {
		return addr
	}
	return name
}

// ── SNI extraction ──

func extractSNI(reader *bufio.Reader) string {
	// Read TLS record header (5 bytes)
	header, err := reader.Peek(5)
	if err != nil || header[0] != 0x16 { // not handshake
		return ""
	}

	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen > 16384 || recordLen < 42 {
		return ""
	}

	// Read full record
	buf, err := reader.Peek(5 + recordLen)
	if err != nil {
		return ""
	}

	// Parse ClientHello
	data := buf[5:]
	if len(data) < 42 || data[0] != 0x01 { // ClientHello
		return ""
	}

	// Skip: handshake header(4) + client_version(2) + random(32) = 38
	pos := 38

	// Session ID
	if pos >= len(data) {
		return ""
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Cipher suites
	if pos+2 > len(data) {
		return ""
	}
	cipherLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherLen

	// Compression methods
	if pos >= len(data) {
		return ""
	}
	compLen := int(data[pos])
	pos += 1 + compLen

	// Extensions
	if pos+2 > len(data) {
		return ""
	}
	extLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	end := pos + extLen
	if end > len(data) {
		end = len(data)
	}

	for pos+4 <= end {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extDataLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if extType == 0 { // server_name extension
			if pos+5 <= end && pos+extDataLen <= end {
				// SNI list length (2) + type (1) + name length (2) + name
				nameLen := int(data[pos+3])<<8 | int(data[pos+4])
				if pos+5+nameLen <= end {
					return string(data[pos+5 : pos+5+nameLen])
				}
			}
		}

		pos += extDataLen
	}

	return ""
}

// ── bufferedConn wraps a net.Conn with a bufio.Reader for already-peeked data ──

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (bc *bufferedConn) Read(b []byte) (int, error) {
	return bc.reader.Read(b)
}

func hasPort(addr string) bool {
	_, _, err := net.SplitHostPort(addr)
	return err == nil
}

// defaultInfraBypass returns the built-in set of domains that should
// always bypass MITM interception. These use cert pinning, custom
// protocols (Noise/DERP), or break when TLS is terminated by a proxy.
func defaultInfraBypass() map[string]bool {
	domains := []string{
		// Tailscale control plane (Noise protocol over /ts2021)
		"controlplane.tailscale.com",
		"login.tailscale.com",
		".tailscale.com",
		// DERP relay servers
		"derp1.tailscale.com",
		"derp2.tailscale.com",
		// Common cert-pinned services
		"mtalk.google.com", // FCM/GCM push
		"alt1-mtalk.google.com",
		"courier.push.apple.com", // APNs
	}
	m := make(map[string]bool, len(domains))
	for _, d := range domains {
		m[d] = true
	}
	return m
}

// tunnelPassthrough relays a TLS connection without MITM, logging it
// as a bypass. Used for infrastructure domains with cert pinning.
func (t *TransparentListener) tunnelPassthrough(
	clientConn net.Conn,
	reader *bufio.Reader,
	container, domain string,
	start time.Time,
) {
	bufferedConn := &bufferedConn{Conn: clientConn, reader: reader}

	upstream, err := net.DialTimeout("tcp", domain+":443", 10*time.Second)
	if err != nil {
		t.server.audit.Add(AuditEntry{
			Time: start, Container: container, Domain: domain,
			Method: "BYPASS", Status: "error-connect", TLS: true,
			Latency: time.Since(start),
		})
		return
	}
	defer upstream.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, bufferedConn); done <- struct{}{} }()
	go func() { io.Copy(bufferedConn, upstream); done <- struct{}{} }()
	<-done

	t.server.audit.Add(AuditEntry{
		Time: start, Container: container, Domain: domain,
		Method: "BYPASS", URL: domain + ":443", Status: "allowed", TLS: true,
		Latency: time.Since(start),
	})
}

// AddInfraBypass adds a domain to the infrastructure bypass list.
func (t *TransparentListener) AddInfraBypass(domain string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.infraBypass[domain] = true
}

// RemoveInfraBypass removes a domain from the infrastructure bypass list.
func (t *TransparentListener) RemoveInfraBypass(domain string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.infraBypass, domain)
}

// InfraBypassList returns a sorted list of bypassed domains.
func (t *TransparentListener) InfraBypassList() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var list []string
	for d := range t.infraBypass {
		list = append(list, d)
	}
	sort.Strings(list)
	return list
}
