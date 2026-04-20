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
	removeTransparentRules(table, chain, tag)

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
	removeTransparentRules(table, chain, tag)

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
