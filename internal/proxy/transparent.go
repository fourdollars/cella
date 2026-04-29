package proxy

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// TransparentRedirect configures iptables DNAT to force container traffic through the proxy.
// This works for ALL applications regardless of HTTP_PROXY support (Node.js, Go, etc.).
//
// Mechanism: On the host, redirect container's outbound port 80/443 to the proxy port.
// The proxy must handle this as a transparent proxy (original destination from SO_ORIGINAL_DST).
//
// For CONNECT-style proxying: we use nftables REDIRECT in the PREROUTING chain.
// Container → port 443 → host nftables REDIRECT → localhost:proxyPort → cella proxy
func SetupTransparentRedirect(containerIP string, proxyPort int) error {
	table := "cella_tproxy"
	chain := "prerouting"
	tag := fmt.Sprintf("cella_tproxy_%s", sanitizeName2(containerIP))

	// Remove any stale rules for this IP first (best-effort)
	_ = removeTransparentRules(table, chain, tag)

	// Build a single atomic batch:
	//   add table / add chain (idempotent) + add rules
	// NOTE: nft sometimes exits 0 even on rule errors, so we also
	// check the output for "Error:" strings.
	batch := fmt.Sprintf(
		"add table ip %s\n"+
			"add chain ip %s %s { type nat hook prerouting priority dstnat; policy accept; }\n"+
			"add rule ip %s %s ip saddr %s tcp dport 443 counter redirect to :%d comment \"%s_443\"\n"+
			"add rule ip %s %s ip saddr %s tcp dport 80  counter redirect to :%d comment \"%s_80\"",
		table,
		table, chain,
		table, chain, containerIP, proxyPort, tag,
		table, chain, containerIP, proxyPort, tag,
	)

	cmd := nftCmd2("-f", "-")
	cmd.Stdin = strings.NewReader(batch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("add tproxy rules: %s: %w", strings.TrimSpace(string(out)), err)
	}
	// nft exits 0 even on some errors — check output for "Error:"
	if strings.Contains(string(out), "Error:") {
		return fmt.Errorf("add tproxy rules: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// RemoveTransparentRedirect removes the DNAT rules for a container
func RemoveTransparentRedirect(containerIP string) error {
	table := "cella_tproxy"
	chain := "prerouting"
	tag := fmt.Sprintf("cella_tproxy_%s", sanitizeName2(containerIP))
	return removeTransparentRules(table, chain, tag)
}

func removeTransparentRules(table, chain, tag string) error {
	cmd := nftCmd2("--handle", "list", "chain", "ip", table, chain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil // table doesn't exist = nothing to remove
	}

	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, tag) {
			parts := strings.Split(line, "# handle ")
			if len(parts) == 2 {
				handle := strings.TrimSpace(parts[1])
				delCmd := nftCmd2("delete", "rule", "ip", table, chain, "handle", handle)
				delCmd.CombinedOutput() // best effort
			}
		}
	}
	return nil
}

// SetupHostRedirect adds an OUTPUT chain rule that redirects the host's own
// outbound port 80/443 traffic to the cella proxy.
//
// To prevent a redirect loop, traffic from uid is excluded (pass os.Getuid()).
// The container name "host" is used for audit/approval attribution.
func SetupHostRedirect(proxyPort, uid int) error {
	table := "cella_tproxy"
	chain := "output"
	tag := "cella_tproxy_host"

	// Remove stale rules first
	_ = removeTransparentRules(table, chain, tag)

	batch := fmt.Sprintf(
		"add table ip %s\n"+
			"add chain ip %s %s { type nat hook output priority dstnat; policy accept; }\n"+
			"add rule ip %s %s meta skuid != %d tcp dport 443 counter redirect to :%d comment \"%s_443\"\n"+
			"add rule ip %s %s meta skuid != %d tcp dport 80  counter redirect to :%d comment \"%s_80\"",
		table,
		table, chain,
		table, chain, uid, proxyPort, tag,
		table, chain, uid, proxyPort, tag,
	)

	cmd := nftCmd2("-f", "-")
	cmd.Stdin = strings.NewReader(batch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("add host output rules: %s: %w", strings.TrimSpace(string(out)), err)
	}
	if strings.Contains(string(out), "Error:") {
		return fmt.Errorf("add host output rules: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// RemoveHostRedirect removes the OUTPUT chain redirect rules for host traffic.
func RemoveHostRedirect() error {
	return removeTransparentRules("cella_tproxy", "output", "cella_tproxy_host")
}

// SetupDockerTransparentRedirect configures iptables DNAT inside a Docker
// container's network namespace so that outbound port 80/443 traffic is
// redirected to the cella proxy on the host.
//
// Unlike LXD containers whose bridge traffic traverses the host's PREROUTING
// chain, Docker default-bridge containers route packets via FORWARD and never
// hit host-side nftables REDIRECT rules. The workaround is to enter the
// container's network namespace with nsenter and add iptables OUTPUT DNAT
// rules there.
//
// dockerSocket may be empty (defaults to /var/run/docker.sock).
func SetupDockerTransparentRedirect(dockerSocket, containerName string, proxyPort int) error {
	if dockerSocket == "" {
		dockerSocket = "/var/run/docker.sock"
	}

	pid, err := dockerContainerPID(dockerSocket, containerName)
	if err != nil {
		return fmt.Errorf("get container PID: %w", err)
	}

	gatewayIP := DetectDockerBridgeIP()
	if gatewayIP == "" {
		gatewayIP = "172.17.0.1" // fallback
	}
	dest := fmt.Sprintf("%s:%d", gatewayIP, proxyPort)

	// Remove stale rules first (best-effort)
	_ = removeDockerNsRules(pid, dest)

	// Add OUTPUT DNAT rules for port 443 and 80
	for _, port := range []int{443, 80} {
		args := []string{
			"--target", pid, "--net",
			"iptables", "-t", "nat", "-A", "OUTPUT",
			"-p", "tcp", "--dport", fmt.Sprintf("%d", port),
			"-j", "DNAT", "--to-destination", dest,
			"-m", "comment", "--comment", "cella_tproxy",
		}
		cmd := nsenterCmd(args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nsenter iptables port %d: %s: %w", port, strings.TrimSpace(string(out)), err)
		}
	}
	return nil
}

// RemoveDockerTransparentRedirect removes the DNAT rules from a Docker
// container's network namespace.
func RemoveDockerTransparentRedirect(dockerSocket, containerName string) error {
	if dockerSocket == "" {
		dockerSocket = "/var/run/docker.sock"
	}

	pid, err := dockerContainerPID(dockerSocket, containerName)
	if err != nil {
		return nil // container may have stopped — nothing to clean up
	}

	gatewayIP := DetectDockerBridgeIP()
	if gatewayIP == "" {
		gatewayIP = "172.17.0.1"
	}
	dest := fmt.Sprintf("%s:%d", gatewayIP, 9081)

	return removeDockerNsRules(pid, dest)
}

// removeDockerNsRules removes all cella_tproxy iptables rules from a container netns.
func removeDockerNsRules(pid, dest string) error {
	// List rules and delete by comment match (best-effort, up to 10 passes)
	for i := 0; i < 10; i++ {
		listArgs := []string{
			"--target", pid, "--net",
			"iptables", "-t", "nat", "-L", "OUTPUT", "--line-numbers", "-n",
		}
		listCmd := nsenterCmd(listArgs...)
		out, err := listCmd.CombinedOutput()
		if err != nil {
			return nil // no iptables or container gone
		}
		// Find last line with our comment (delete from bottom to preserve line numbers)
		found := false
		lines := strings.Split(string(out), "\n")
		for j := len(lines) - 1; j >= 0; j-- {
			if strings.Contains(lines[j], "cella_tproxy") {
				parts := strings.Fields(lines[j])
				if len(parts) > 0 {
					lineNum := parts[0]
					delArgs := []string{
						"--target", pid, "--net",
						"iptables", "-t", "nat", "-D", "OUTPUT", lineNum,
					}
					delCmd := nsenterCmd(delArgs...)
					delCmd.CombinedOutput() // best-effort
					found = true
					break // re-list after delete (line numbers shift)
				}
			}
		}
		if !found {
			break
		}
	}
	return nil
}

// dockerContainerPID returns the host PID of a Docker container's init process.
func dockerContainerPID(socketPath, containerName string) (string, error) {
	cmd := exec.Command("docker", "inspect", containerName, "--format", "{{.State.Pid}}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker inspect %s: %s: %w", containerName, strings.TrimSpace(string(out)), err)
	}
	pid := strings.TrimSpace(string(out))
	if pid == "" || pid == "0" {
		return "", fmt.Errorf("container %s not running (pid=%s)", containerName, pid)
	}
	return pid, nil
}

func nsenterCmd(args ...string) *exec.Cmd {
	if os.Getuid() == 0 {
		return exec.Command("nsenter", args...)
	}
	full := append([]string{"-n", "nsenter"}, args...)
	return exec.Command("sudo", full...)
}

func nftCmd2(args ...string) *exec.Cmd {
	if os.Getuid() == 0 {
		return exec.Command("nft", args...)
	}
	full := append([]string{"-n", "nft"}, args...)
	return exec.Command("sudo", full...)
}

func sanitizeName2(name string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, name)
}
