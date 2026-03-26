package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// AutoSetup configures a container to use the cella transparent proxy.
//
// Architecture (Phase 7c onwards):
//   - nftables REDIRECT on the host intercepts outbound HTTPS from containers
//     and diverts it to the transparent listener (transparent.go / transparent_listener.go)
//   - AutoSetup handles only the per-container CA cert injection so that
//     containers trust the MITM CA for HTTPS interception
//   - No HTTP_PROXY / HTTPS_PROXY env vars are set — traffic is captured
//     transparently without changing container configuration (except the CA cert)
//
// Note: The struct comment previously said "Sets HTTP_PROXY/HTTPS_PROXY env vars"
// which referred to a Phase 7a design that was superseded by the transparent
// proxy in Phase 7c. That old mechanism has been removed.
type AutoSetup struct {
	ProxyHost string // host IP reachable from container (e.g., lxdbr0 gateway)
	ProxyPort int
	MITMPem   []byte // CA cert PEM (nil = skip MITM CA injection)
}

// SetupContainer injects the MITM CA cert into a container so that it trusts
// cella's transparent HTTPS proxy. The nftables REDIRECT rule is set up by
// the caller (transparent.go) before or after this call.
func (s *AutoSetup) SetupContainer(socketPath, container string) error {
	// 1. Inject CA cert so the container trusts our MITM TLS interception
	if len(s.MITMPem) > 0 {
		_ = lxdExec(socketPath, container, []string{
			"sh", "-c", "mkdir -p /usr/local/share/ca-certificates",
		})

		if err := lxdWriteFile(socketPath, container,
			"/usr/local/share/ca-certificates/cella-proxy.crt",
			s.MITMPem); err != nil {
			return fmt.Errorf("write CA cert: %w", err)
		}

		_ = lxdExec(socketPath, container, []string{
			"sh", "-c", "update-ca-certificates 2>/dev/null || true",
		})
	}

	// 2. Set NODE_EXTRA_CA_CERTS so Node.js trusts our CA
	//    (Node.js ignores the system CA store by default)
	if len(s.MITMPem) > 0 {
		certPath := "/usr/local/share/ca-certificates/cella-proxy.crt"
		config := map[string]interface{}{
			"config": map[string]string{
				"environment.NODE_EXTRA_CA_CERTS": certPath,
			},
		}
		body, _ := json.Marshal(config)
		_ = lxdAPIPatch(socketPath, fmt.Sprintf("/1.0/instances/%s", container), body)
	}

	// nftables REDIRECT is set up by the caller (transparent.go)
	return nil
}

// RemoveSetup removes the MITM CA cert from a container.
// The nftables REDIRECT rule is torn down by the caller (transparent.go).
func (s *AutoSetup) RemoveSetup(socketPath, container string) error {
	// Remove CA cert
	_ = lxdExec(socketPath, container, []string{
		"sh", "-c", "rm -f /usr/local/share/ca-certificates/cella-proxy.crt && update-ca-certificates 2>/dev/null || true",
	})

	// nftables REDIRECT removal is handled by the caller (transparent.go)
	return nil
}

// DetectBridgeIP finds the gateway IP of the LXD bridge (lxdbr0)
func DetectBridgeIP() string {
	iface, err := net.InterfaceByName("lxdbr0")
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}

// ── LXD API helpers (unix socket) ──

func lxdAPIPatch(socketPath, apiPath string, body []byte) error {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("PATCH", "http://unix"+apiPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("LXD API %s: %d %s", apiPath, resp.StatusCode, string(respBody))
	}
	return nil
}

func lxdExec(socketPath, container string, command []string) error {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 30 * time.Second,
	}

	execReq := map[string]interface{}{
		"command":            command,
		"wait-for-websocket": false,
		"record-output":      true,
	}
	body, _ := json.Marshal(execReq)

	apiPath := fmt.Sprintf("/1.0/instances/%s/exec", container)
	req, err := http.NewRequest("POST", "http://unix"+apiPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("exec in %s: %d %s", container, resp.StatusCode, string(respBody))
	}

	// Wait for operation to complete
	var lxdResp struct {
		Operation string `json:"operation"`
	}
	json.NewDecoder(resp.Body).Decode(&lxdResp)

	if lxdResp.Operation != "" {
		waitPath := lxdResp.Operation + "/wait"
		waitReq, _ := http.NewRequest("GET", "http://unix"+waitPath, nil)
		waitResp, err := client.Do(waitReq)
		if err == nil {
			waitResp.Body.Close()
		}
	}

	return nil
}

func lxdWriteFile(socketPath, container, filePath string, content []byte) error {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}

	// Use LXD file API: POST /1.0/instances/<name>/files?path=<path>
	apiPath := fmt.Sprintf("/1.0/instances/%s/files?path=%s", container, filePath)
	req, err := http.NewRequest("POST", "http://unix"+apiPath, bytes.NewReader(content))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-LXD-uid", "0")
	req.Header.Set("X-LXD-gid", "0")
	req.Header.Set("X-LXD-mode", "0644")
	req.Header.Set("X-LXD-type", "file")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("write file %s in %s: %d %s", filePath, container, resp.StatusCode, string(respBody))
	}
	return nil
}

// DetectLXDSocket returns the default LXD socket path
func DetectLXDSocket() string {
	candidates := []string{
		"/var/snap/lxd/common/lxd/unix.socket",
		"/var/lib/lxd/unix.socket",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// IsContainerProxied checks if a container already has cella's CA cert env var set.
// Note: cella uses transparent proxy (nftables REDIRECT), not HTTP_PROXY env vars.
// This check detects whether the CA cert has been injected by looking for
// environment.NODE_EXTRA_CA_CERTS pointing to our cert.
func IsContainerProxied(config map[string]string) bool {
	return strings.Contains(config["environment.NODE_EXTRA_CA_CERTS"], "cella") ||
		// Legacy check: old Phase 7a used HTTP_PROXY env vars (now removed)
		strings.Contains(config["environment.HTTP_PROXY"], "cella") ||
		strings.Contains(config["environment.http_proxy"], "cella")
}
