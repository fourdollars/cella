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

// AutoSetup configures a container to use the cella proxy.
// Sets HTTP_PROXY/HTTPS_PROXY env vars and optionally injects the MITM CA cert.
type AutoSetup struct {
	ProxyHost string // host IP reachable from container (e.g., lxdbr0 gateway)
	ProxyPort int
	MITMPem   []byte // CA cert PEM (nil = skip MITM setup)
}

// SetupContainer configures proxy env + CA cert for a single LXC container.
// Uses the LXD API via unix socket (same as cella's lxd.Client).
func (s *AutoSetup) SetupContainer(socketPath, container string) error {
	proxyURL := fmt.Sprintf("http://%s:%d", s.ProxyHost, s.ProxyPort)

	// 1. Set environment variables via LXD config PATCH
	config := map[string]interface{}{
		"config": map[string]string{
			"environment.HTTP_PROXY":  proxyURL,
			"environment.HTTPS_PROXY": proxyURL,
			"environment.http_proxy":  proxyURL,
			"environment.https_proxy": proxyURL,
			"environment.NO_PROXY":    "localhost,127.0.0.1",
			"environment.no_proxy":    "localhost,127.0.0.1",
		},
	}

	body, _ := json.Marshal(config)
	if err := lxdAPIPatch(socketPath, fmt.Sprintf("/1.0/instances/%s", container), body); err != nil {
		return fmt.Errorf("set proxy env: %w", err)
	}

	// 2. Inject CA cert if MITM enabled
	if len(s.MITMPem) > 0 {
		// Write CA cert via lxc file push (exec approach since LXD file API is complex)
		if err := lxdExec(socketPath, container, []string{
			"sh", "-c", "mkdir -p /usr/local/share/ca-certificates",
		}); err != nil {
			return fmt.Errorf("mkdir ca-certificates: %w", err)
		}

		// Write cert content via exec + stdin
		if err := lxdWriteFile(socketPath, container,
			"/usr/local/share/ca-certificates/cella-proxy.crt",
			s.MITMPem); err != nil {
			return fmt.Errorf("write CA cert: %w", err)
		}

		// Update CA store
		if err := lxdExec(socketPath, container, []string{
			"sh", "-c", "update-ca-certificates 2>/dev/null || true",
		}); err != nil {
			return fmt.Errorf("update-ca-certificates: %w", err)
		}
	}

	return nil
}

// RemoveSetup removes proxy configuration from a container
func (s *AutoSetup) RemoveSetup(socketPath, container string) error {
	config := map[string]interface{}{
		"config": map[string]string{
			"environment.HTTP_PROXY":  "",
			"environment.HTTPS_PROXY": "",
			"environment.http_proxy":  "",
			"environment.https_proxy": "",
			"environment.NO_PROXY":    "",
			"environment.no_proxy":    "",
		},
	}

	body, _ := json.Marshal(config)
	if err := lxdAPIPatch(socketPath, fmt.Sprintf("/1.0/instances/%s", container), body); err != nil {
		return fmt.Errorf("remove proxy env: %w", err)
	}

	// Remove CA cert
	_ = lxdExec(socketPath, container, []string{
		"sh", "-c", "rm -f /usr/local/share/ca-certificates/cella-proxy.crt && update-ca-certificates 2>/dev/null || true",
	})

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
		"command":      command,
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

// IsContainerProxied checks if a container already has proxy env set
func IsContainerProxied(config map[string]string) bool {
	return strings.Contains(config["environment.HTTP_PROXY"], "cella") ||
		strings.Contains(config["environment.http_proxy"], "cella") ||
		config["environment.HTTP_PROXY"] != "" ||
		config["environment.http_proxy"] != ""
}
