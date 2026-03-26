package proxy

import (
	"bytes"
	"strings"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"golang.org/x/net/http2"
)

// handleMITMTransparent performs MITM interception supporting both HTTP/1.1 and HTTP/2
func (t *TransparentListener) handleMITMTransparent(
	clientConn net.Conn,
	container, domain string,
	mitmCfg *MITMConfig,
	start time.Time,
) {
	cert, err := mitmCfg.GetCertForHost(domain)
	if err != nil {
		t.server.audit.Add(AuditEntry{
			Time: start, Container: container, Domain: domain,
			Method: "MITM", Status: "error-cert", TLS: true,
			Latency: time.Since(start),
		})
		clientConn.Close()
		return
	}

	// TLS config supporting both h2 and http/1.1
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		t.mu.Lock()
		t.mitmFailed[domain] = true
		t.mu.Unlock()
		t.server.audit.Add(AuditEntry{
			Time: start, Container: container, Domain: domain,
			Method: "MITM", Status: "pinned-fallback", TLS: true,
			Latency: time.Since(start),
		})
		tlsConn.Close()
		clientConn.Close()
		return
	}

	// Create a reverse proxy handler that forwards to the real upstream
	handler := &mitmHandler{
		domain:    domain,
		container: container,
		server:    t.server,
		stats:     t.server.inferenceStats,
		routes:    t.server.routes,
	}

	// Detect protocol from ALPN negotiation
	negotiatedProto := tlsConn.ConnectionState().NegotiatedProtocol

	if negotiatedProto == "h2" {
		// HTTP/2: use http2.Server.ServeConn directly
		h2srv := &http2.Server{}
		h2srv.ServeConn(tlsConn, &http2.ServeConnOpts{
			Handler: handler,
		})
	} else {
		// HTTP/1.1: use http.Server on the single conn
		httpServer := &http.Server{
			Handler:      handler,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
		}
		httpServer.Serve(&singleConnListener{conn: tlsConn})
	}
}

// mitmHandler forwards intercepted requests to the real upstream
type mitmHandler struct {
	domain    string
	container string
	server    *Server
	stats     *InferenceStats
	routes    *RouteTable
}

func (h *mitmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqStart := time.Now()

	// Check route table for inference routing
	routed := false
	if h.routes != nil {
		if route := h.routes.Get(h.domain); route != nil {
			// Redirect to alternative backend
			scheme := route.BackendScheme
			if scheme == "" { scheme = "https" }
			r.URL.Scheme = scheme
			r.URL.Host = route.BackendHost
			if route.PathPrefix != "" && !strings.HasPrefix(r.URL.Path, route.PathPrefix) {
				r.URL.Path = route.PathPrefix + r.URL.Path
			}
			routed = true
		}
	}
	if !routed {
		r.URL.Scheme = "https"
		r.URL.Host = h.domain
	}
	r.RequestURI = ""
	removeHopByHopHeaders(r.Header)

	// Capture request body for inference parsing
	var reqBody []byte
	if r.Body != nil {
		reqBody, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
	}

	// Forward to real upstream
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(r)
	if err != nil {
		h.server.audit.Add(AuditEntry{
			Time: reqStart, Container: h.container, Domain: h.domain,
			Method: r.Method, URL: r.URL.String(), Path: r.URL.Path,
			Status: "error-upstream", TLS: true,
			Latency: time.Since(reqStart),
		})
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read response body for token usage parsing
	respBody, _ := io.ReadAll(resp.Body)

	// Parse inference stats (model, tokens)
	var model string
	var tokensIn, tokensOut int64
	if isInferencePath(r.URL.Path) {
		contentType := resp.Header.Get("Content-Type")
		if IsStreamingResponse(contentType) {
			// SSE streaming — scan event stream for usage chunks
			model, tokensIn, tokensOut = ParseSSETokens(respBody)
		} else {
			model, tokensIn, tokensOut = ParseInferenceResponse(respBody)
		}
		// Fall back to request body for model name if response didn't include it
		if model == "" && len(reqBody) > 0 {
			model = ParseInferenceRequest(reqBody)
		}
	}

	// Audit
	h.server.audit.Add(AuditEntry{
		Time: reqStart, Container: h.container, Domain: h.domain,
		Method: r.Method, URL: r.URL.String(), Path: r.URL.Path,
		Status: "allowed", RespCode: resp.StatusCode, TLS: true,
		Latency: time.Since(reqStart),
	})

	// Record inference stats
	if h.stats != nil && model != "" {
		h.stats.Record(InferenceRequest{
			Time:       reqStart,
			Container:  h.container,
			Domain:     h.domain,
			Model:      model,
			Path:       r.URL.Path,
			Method:     r.Method,
			TokensIn:   tokensIn,
			TokensOut:  tokensOut,
			Latency:    time.Since(reqStart),
			StatusCode: resp.StatusCode,
		})
	}

	// Write response back to client
	removeHopByHopHeaders(resp.Header)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// isInferencePath checks if the path is a known inference endpoint
func isInferencePath(path string) bool {
	switch path {
	case "/chat/completions",
		"/v1/chat/completions",
		"/v1/completions",
		"/v1/messages",         // Anthropic
		"/v1/embeddings",
		"/responses":         // GitHub Copilot
		return true
	}
	return false
}

// singleConnListener wraps a single net.Conn as a net.Listener
type singleConnListener struct {
	conn   net.Conn
	served bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.served {
		// Block until connection is closed
		select {}
	}
	l.served = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error {
	return l.conn.Close()
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// removeHopByHopHeadersMITM is a proxy-specific version
func removeHopByHopHeadersMITM(h http.Header) {
	for _, hdr := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailers",
		"Transfer-Encoding", "Upgrade", "Proxy-Connection",
	} {
		h.Del(hdr)
	}
}

// DumpRequest returns a summary of the request for debugging
func DumpRequest(r *http.Request) string {
	dump, _ := httputil.DumpRequest(r, false)
	return string(dump)
}
