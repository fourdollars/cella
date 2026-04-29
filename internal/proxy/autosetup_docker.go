package proxy

import (
	"archive/tar"
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

// SetupDockerContainer injects the MITM CA cert into a Docker container so
// that it trusts cella's transparent HTTPS proxy.
// The nftables REDIRECT rule is set up by the caller (transparent.go).
func (s *AutoSetup) SetupDockerContainer(dockerSocket, container string) error {
	if dockerSocket == "" {
		dockerSocket = "/var/run/docker.sock"
	}

	if len(s.MITMPem) > 0 {
		// 1. Create the CA directory
		_ = dockerExec(dockerSocket, container, []string{
			"sh", "-c", "mkdir -p /usr/local/share/ca-certificates",
		})

		// 2. Write CA cert file via Docker archive PUT API
		if err := dockerWriteFile(dockerSocket, container,
			"/usr/local/share/ca-certificates/",
			"cella-proxy.crt",
			s.MITMPem); err != nil {
			return fmt.Errorf("write CA cert: %w", err)
		}

		// 3. Update CA certificates (best-effort — some images may not have it)
		_ = dockerExec(dockerSocket, container, []string{
			"sh", "-c", "update-ca-certificates 2>/dev/null || true",
		})

		// 4. Set NODE_EXTRA_CA_CERTS env var.
		// Docker doesn't support live env modification like LXD, so we
		// write a profile script that sets it for all shell sessions.
		envScript := []byte(
			"#!/bin/sh\nexport NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/cella-proxy.crt\n",
		)
		_ = dockerExec(dockerSocket, container, []string{
			"sh", "-c", "mkdir -p /etc/profile.d",
		})
		_ = dockerWriteFile(dockerSocket, container,
			"/etc/profile.d/",
			"cella-node-ca.sh",
			envScript)

		// 5. Append NODE_EXTRA_CA_CERTS to /etc/environment so it is
		//    available in non-login shells (docker exec, cron, systemd).
		//    /etc/environment is read by PAM on many distros and by
		//    Node.js when started from non-interactive contexts.
		certPath := "/usr/local/share/ca-certificates/cella-proxy.crt"
		envLine := "NODE_EXTRA_CA_CERTS=" + certPath + "\n"
		_ = dockerExec(dockerSocket, container, []string{
			"sh", "-c",
			"grep -q 'NODE_EXTRA_CA_CERTS.*cella' /etc/environment 2>/dev/null || printf '" + envLine + "' >> /etc/environment",
		})

		// 6. Configure npm to use our CA cert (npm has its own TLS
		//    handling and ignores NODE_EXTRA_CA_CERTS in many cases).
		//    Also set NODE_OPTIONS=--use-openssl-ca so Node.js reads
		//    the system CA store for all tools (not just npm).
		_ = dockerExec(dockerSocket, container, []string{
			"sh", "-c", "command -v npm >/dev/null 2>&1 && npm config set cafile " + certPath + " 2>/dev/null || true",
		})
		_ = dockerExec(dockerSocket, container, []string{
			"sh", "-c",
			"grep -q 'NODE_OPTIONS.*use-openssl-ca' /etc/environment 2>/dev/null || printf 'NODE_OPTIONS=--use-openssl-ca\n' >> /etc/environment",
		})
	}

	return nil
}

// RemoveDockerSetup removes the MITM CA cert from a Docker container.
// The nftables REDIRECT rule is torn down by the caller (transparent.go).
func (s *AutoSetup) RemoveDockerSetup(dockerSocket, container string) error {
	if dockerSocket == "" {
		dockerSocket = "/var/run/docker.sock"
	}

	_ = dockerExec(dockerSocket, container, []string{
		"sh", "-c", "rm -f /usr/local/share/ca-certificates/cella-proxy.crt /etc/profile.d/cella-node-ca.sh && sed -i '/NODE_EXTRA_CA_CERTS.*cella/d' /etc/environment 2>/dev/null; sed -i '/NODE_OPTIONS.*use-openssl-ca/d' /etc/environment 2>/dev/null; command -v npm >/dev/null 2>&1 && npm config delete cafile 2>/dev/null; update-ca-certificates 2>/dev/null || true",
	})

	return nil
}

// DetectDockerBridgeIP finds the gateway IP of the Docker bridge (docker0).
func DetectDockerBridgeIP() string {
	iface, err := net.InterfaceByName("docker0")
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

// DetectDockerSocket returns the default Docker socket path if it exists.
func DetectDockerSocket() string {
	candidates := []string{
		"/var/run/docker.sock",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ── Docker API helpers (unix socket) ──

func dockerExec(socketPath, container string, command []string) error {
	client := newDockerHTTPClient(socketPath)

	// Step 1: Create exec instance
	execReq := map[string]interface{}{
		"AttachStdout": true,
		"AttachStderr": true,
		"Cmd":          command,
	}
	body, _ := json.Marshal(execReq)

	req, err := http.NewRequest("POST",
		fmt.Sprintf("http://unix/v1.45/containers/%s/exec", container),
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("docker exec create: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("docker exec create in %s: %d %s", container, resp.StatusCode, string(respBody))
	}

	var execResp struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&execResp); err != nil {
		return fmt.Errorf("docker exec parse: %w", err)
	}

	// Step 2: Start exec (blocking, wait for completion)
	startReq, _ := http.NewRequest("POST",
		fmt.Sprintf("http://unix/v1.45/exec/%s/start", execResp.ID),
		strings.NewReader(`{"Detach":false,"Tty":false}`))
	startReq.Header.Set("Content-Type", "application/json")

	startResp, err := client.Do(startReq)
	if err != nil {
		return fmt.Errorf("docker exec start: %w", err)
	}
	defer startResp.Body.Close()
	io.Copy(io.Discard, startResp.Body) // drain

	return nil
}

// dockerWriteFile writes a single file into a Docker container using the
// PUT /containers/{id}/archive API (tar format).
func dockerWriteFile(socketPath, container, dir, filename string, content []byte) error {
	client := newDockerHTTPClient(socketPath)

	// Build an in-memory tar archive with the single file
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	hdr := &tar.Header{
		Name: filename,
		Mode: 0644,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("tar header: %w", err)
	}
	if _, err := tw.Write(content); err != nil {
		return fmt.Errorf("tar write: %w", err)
	}
	tw.Close()

	// PUT /containers/{id}/archive?path={dir}
	req, err := http.NewRequest("PUT",
		fmt.Sprintf("http://unix/v1.45/containers/%s/archive?path=%s", container, dir),
		&tarBuf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-tar")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("docker archive put: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("docker write file %s%s in %s: %d %s", dir, filename, container, resp.StatusCode, string(respBody))
	}
	return nil
}

func newDockerHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 30 * time.Second,
	}
}
