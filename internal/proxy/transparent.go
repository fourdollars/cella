package proxy

import (
	"fmt"
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
	// We use nftables (consistent with egress.go)
	table := "cella_tproxy"
	chain := "prerouting"

	// Ensure table and chain exist
	ensureCmd := fmt.Sprintf(`table ip %s {
  chain %s {
    type nat hook prerouting priority dstnat; policy accept;
  }
}`, table, chain)

	// Check if table exists
	cmd := nftCmd2("list", "table", "ip", table)
	if err := cmd.Run(); err != nil {
		// Create table
		cmd = nftCmd2("-f", "-")
		cmd.Stdin = strings.NewReader(ensureCmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("create tproxy table: %s: %w", string(out), err)
		}
	}

	tag := fmt.Sprintf("cella_tproxy_%s", sanitizeName2(containerIP))

	// Remove existing rules for this IP
	removeTransparentRules(table, chain, tag)

	// Redirect HTTP (80) and HTTPS (443) from this container IP to proxy port
	rules := []string{
		// Redirect port 443 (HTTPS) to proxy
		fmt.Sprintf(`add rule ip %s %s ip saddr %s tcp dport 443 redirect to :%d comment "%s_443"`,
			table, chain, containerIP, proxyPort, tag),
		// Redirect port 80 (HTTP) to proxy
		fmt.Sprintf(`add rule ip %s %s ip saddr %s tcp dport 80 redirect to :%d comment "%s_80"`,
			table, chain, containerIP, proxyPort, tag),
	}

	batch := strings.Join(rules, "\n")
	cmd = nftCmd2("-f", "-")
	cmd.Stdin = strings.NewReader(batch)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("add tproxy rules: %s: %w", string(out), err)
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

func nftCmd2(args ...string) *exec.Cmd {
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
