package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
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
	var activeAdapter Adapter
	var activeRoute *InferenceRoute
	var origModel string
	routed := false

	if h.routes != nil {
		if route := h.routes.Get(h.domain); route != nil {
			scheme := route.BackendScheme
			if scheme == "" {
				scheme = "https"
			}
			r.URL.Scheme = scheme
			r.URL.Host = route.BackendHost
			if route.PathPrefix != "" && !strings.HasPrefix(r.URL.Path, route.PathPrefix) {
				r.URL.Path = route.PathPrefix + r.URL.Path
			}
			activeRoute = route
			activeAdapter = GetAdapter(route.Adapter)
			routed = true
		}
	}
	if !routed {
		r.URL.Scheme = "https"
		r.URL.Host = h.domain
	}
	r.RequestURI = ""
	removeHopByHopHeaders(r.Header)

	// Capture request body
	var reqBody []byte
	if r.Body != nil {
		reqBody, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
	}

	// Remember original model name (for response transformation)
	if len(reqBody) > 0 {
		origModel = ParseInferenceRequest(reqBody)
	}

	// Apply request adapter: rewrite body + path to OpenAI format
	if activeAdapter != nil && len(reqBody) > 0 {
		modelOverride := ""
		if activeRoute != nil {
			modelOverride = activeRoute.ModelOverride
		}
		newBody, newPath, err := activeAdapter.TransformRequest(r, reqBody, modelOverride)
		if err == nil {
			reqBody = newBody
			if newPath != "" {
				r.URL.Path = newPath
			}
			r.Body = io.NopCloser(bytes.NewReader(reqBody))
			r.ContentLength = int64(len(reqBody))
		}
	}

	// Forward to real upstream
	// Check RPH limit before forwarding
	if h.stats != nil && origModel != "" {
		if exceeded, cur, lim := h.stats.IsRPHExceeded(origModel); exceeded {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(w, "{\"error\":{\"message\":\"RPH limit exceeded (%d/%d)\",\"type\":\"rate_limit_error\",\"code\":\"rph_limit_exceeded\"}}", cur, lim)

			// Record as blocked
			h.stats.Record(InferenceRequest{
				Time:       reqStart,
				Container:  h.container,
				Domain:     h.domain,
				Model:      origModel,
				Path:       r.URL.Path,
				Method:     r.Method,
				StatusCode: http.StatusTooManyRequests,
				Error:      "rph_limit_exceeded",
				Latency:    time.Since(reqStart),
			})

			h.server.audit.Add(AuditEntry{
				Time: reqStart, Container: h.container, Domain: h.domain,
				Method: r.Method, URL: r.URL.String(), Path: r.URL.Path,
				Status: "blocked-rph", TLS: true,
				Latency: time.Since(reqStart),
			})
			return
		}
	}
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

	// Read response body
	respBody, _ := io.ReadAll(resp.Body)

	// Apply response adapter: rewrite Ollama response back to original provider format
	if activeAdapter != nil {
		contentType := resp.Header.Get("Content-Type")
		isStream := IsStreamingResponse(contentType)
		if converted, err := activeAdapter.TransformResponse(respBody, origModel, isStream); err == nil {
			respBody = converted
			// Update Content-Length after transformation
			resp.Header.Set("Content-Length", fmt.Sprint(len(respBody)))
			// Ensure streaming content-type is preserved
			if isStream {
				resp.Header.Set("Content-Type", "text/event-stream")
			}
		}
	}

	// Parse inference stats (model, tokens)
	// Model name priority: request > response > path
	// Upstream providers (e.g. Azure CAPI, GitHub Copilot) may return internal
	// deployment IDs (e.g. capi-noe-ptuc-h200-ib-gpt-5-mini-2025-08-07) in the
	// response "model" field. We prefer the user-facing model name from the
	// original request, and only fall back to the response model for token counts.
	var model string
	var tokensIn, tokensOut int64
	if isInferencePath(r.URL.Path) {
		contentType := resp.Header.Get("Content-Type")

		// Always parse response for token counts; also get response model as fallback
		var respModel string
		if IsStreamingResponse(contentType) {
			// SSE streaming — scan event stream for usage chunks
			respModel, tokensIn, tokensOut = ParseSSETokens(respBody)
		} else {
			respModel, tokensIn, tokensOut = ParseInferenceResponse(respBody)
		}

		// Use request model (origModel) as primary source — it reflects what the
		// client actually requested and avoids exposing provider-internal IDs.
		// Fall back to response model only if request didn't carry a model field.
		model = origModel
		if model == "" {
			model = respModel
		}
		// Last resort: extract from URL path (e.g. /models/<name>/chat/completions)
		if model == "" {
			model = extractModelFromPath(r.URL.Path)
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

// isInferencePath checks if the path is a known inference endpoint.
// Supports exact paths and suffix matching for versioned/model-namespaced paths
// e.g. /models/claude-sonnet-4.6/chat/completions
func isInferencePath(path string) bool {
	// Exact matches (fast path)
	switch path {
	case "/chat/completions",
		"/v1/chat/completions",
		"/v1/completions",
		"/v1/messages", // Anthropic
		"/v1/embeddings",
		"/responses": // GitHub Copilot
		return true
	}
	// Suffix matches: /models/<name>/chat/completions, /openai/v1/chat/completions, etc.
	for _, suffix := range []string{
		"/chat/completions",
		"/completions",
		"/messages",
		"/embeddings",
	} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

// extractModelFromPath tries to pull a model name from paths like:
//
//	/models/<model>/chat/completions
//	/openai/deployments/<model>/chat/completions  (Azure)
func extractModelFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, p := range parts {
		if (p == "models" || p == "deployments") && i+1 < len(parts) {
			candidate := parts[i+1]
			// Skip if it looks like a version string (v1, v2, beta...)
			if len(candidate) > 0 && candidate[0] != 'v' {
				return candidate
			}
		}
	}
	return ""
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
