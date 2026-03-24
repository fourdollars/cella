package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

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
	mitmFailed       map[string]bool     // domains where MITM handshake failed (cert pinning)
	mu               sync.RWMutex
}

// NewTransparentListener creates a transparent proxy listener
func NewTransparentListener(port int, server *Server) *TransparentListener {
	return &TransparentListener{
		port:             port,
		server:           server,
		pendingApprovals: make(map[string]chan bool),
		mitmFailed:       make(map[string]bool),
	}
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
		container = srcIP
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
		domain = "unknown"
	}

	// Check allowlist (with dedup for concurrent connections)
	justApproved := false
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
			justApproved = true
		} else {
			// First request for this domain — we do the approval
			resultCh := make(chan bool, 10)
			t.pendingApprovals[approvalKey] = resultCh
			t.mu.Unlock()

			status := t.server.requestApproval(container, domain, "CONNECT", domain+":443", "")
			approved := status == "approved-permanent" || status == "approved"

			if status == "approved-permanent" {
				al.Add(domain)
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
			justApproved = true
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

	// MITM mode: intercept TLS (only for pre-allowed domains where CA cert is trusted)
	// Freshly-approved connections use plain tunnel (CA cert may not be trusted yet)
	t.mu.RLock()
	mitmBlocked := t.mitmFailed[domain]
	t.mu.RUnlock()
	if mitmCfg != nil && !justApproved && !mitmBlocked {
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

func (t *TransparentListener) handleMITMTransparent(
	clientConn net.Conn,
	container, domain string,
	mitmCfg *MITMConfig,
	start time.Time,
) {
	defer clientConn.Close()

	cert, err := mitmCfg.GetCertForHost(domain)
	if err != nil {
		t.server.audit.Add(AuditEntry{
			Time: start, Container: container, Domain: domain,
			Method: "MITM", Status: "error-cert", TLS: true,
			Latency: time.Since(start),
		})
		return
	}

	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err := tlsConn.Handshake(); err != nil {
		// Remember this domain as cert-pinned — future connections skip MITM
		t.mu.Lock()
		t.mitmFailed[domain] = true
		t.mu.Unlock()
		t.server.audit.Add(AuditEntry{
			Time: start, Container: container, Domain: domain,
			Method: "MITM", Status: "pinned-fallback", TLS: true,
			Latency: time.Since(start),
		})
		return // client connection is broken, but next connection will tunnel
	}
	defer tlsConn.Close()

	// Use http.Client for upstream (handles HTTP/2, connection pooling)
	httpClient := &http.Client{Timeout: 30 * time.Second}

	// Read HTTP requests from decrypted client stream
	clientReader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			t.server.audit.Add(AuditEntry{
				Time: time.Now(), Container: container, Domain: domain,
				Method: "MITM", Status: "error-read",
				URL: err.Error(), TLS: true,
			})
			break
		}

		reqStart := time.Now()
		req.URL.Scheme = "https"
		req.URL.Host = domain
		req.RequestURI = ""
		removeHopByHopHeaders(req.Header)

		resp, err := httpClient.Do(req)
		if err != nil {
			t.server.audit.Add(AuditEntry{
				Time: reqStart, Container: container, Domain: domain,
				Method: req.Method, URL: req.URL.String(), Path: req.URL.Path,
				Status: "error-upstream", TLS: true,
				Latency: time.Since(reqStart),
			})
			break
		}

		t.server.audit.Add(AuditEntry{
			Time: reqStart, Container: container, Domain: domain,
			Method: req.Method, URL: req.URL.String(), Path: req.URL.Path,
			Status: "allowed", RespCode: resp.StatusCode, TLS: true,
			Latency: time.Since(reqStart),
		})

		removeHopByHopHeaders(resp.Header)
		if err := resp.Write(tlsConn); err != nil {
			resp.Body.Close()
			break
		}
		resp.Body.Close()

		if resp.Close || req.Close {
			break
		}
	}
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

	al := t.server.GetAllowlist(container)
	if !al.IsAllowed(domain) {
		status := t.server.requestApproval(container, domain, req.Method, req.URL.String(), req.URL.Path)
		if status == "approved-permanent" {
			al.Add(domain)
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
