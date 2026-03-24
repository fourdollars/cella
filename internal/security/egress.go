package security

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	cellaTable = "cella"
	cellaChain = "forward"
	bridgeIf   = "lxdbr0"
)

// EgressRule defines a per-container network egress rule
type EgressRule struct {
	Container string
	SrcIP     string   // container's IP on the bridge
	Allow     []string // IP addresses/CIDRs to allow (with optional comment)
}

// nftCmd returns an *exec.Cmd that runs nft via "sudo -n" (non-interactive).
func nftCmd(args ...string) *exec.Cmd {
	if os.Getuid() == 0 {
		return exec.Command("nft", args...)
	}
	full := append([]string{"-n", "nft"}, args...)
	return exec.Command("sudo", full...)
}

// ensureCellaTable creates the cella nftables table and forward chain if they don't exist.
// Uses ip family (not inet) because LXD bridge traffic goes through the ip forward hook.
// Priority -5 so it runs before Docker's ip filter FORWARD (priority 0).
func ensureCellaTable() error {
	// Check if table exists
	cmd := nftCmd("list", "table", "ip", cellaTable)
	if err := cmd.Run(); err == nil {
		return nil // already exists
	}

	ruleset := fmt.Sprintf(`table ip %s {
  chain %s {
    type filter hook forward priority -5; policy accept;
    # Return traffic to containers: always accept
    oifname "%s" accept
  }
}`, cellaTable, cellaChain, bridgeIf)

	cmd = nftCmd("-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("create cella table: %s: %w", string(output), err)
	}
	return nil
}

// ApplyEgressRules creates deny-all + allow-list rules for a specific container.
// Rules are based on container's bridge IP (SrcIP), applied in the FORWARD chain.
func ApplyEgressRules(rule EgressRule) error {
	if rule.SrcIP == "" {
		return fmt.Errorf("container IP required for egress rules")
	}
	if err := ensureCellaTable(); err != nil {
		return err
	}

	// Remove existing rules for this container first
	if err := RemoveEgressRules(rule.Container, rule.SrcIP); err != nil {
		return err
	}

	// Build rules: for this container IP, allow DNS + established + specific IPs, then drop
	var cmds []string

	// Allow established/related connections
	cmds = append(cmds, fmt.Sprintf(
		`add rule ip %s %s iifname "%s" ip saddr %s ct state established,related accept comment "cella_%s_established"`,
		cellaTable, cellaChain, bridgeIf, rule.SrcIP, sanitizeName(rule.Container)))

	// Allow DNS
	cmds = append(cmds, fmt.Sprintf(
		`add rule ip %s %s iifname "%s" ip saddr %s udp dport 53 accept comment "cella_%s_dns"`,
		cellaTable, cellaChain, bridgeIf, rule.SrcIP, sanitizeName(rule.Container)))
	cmds = append(cmds, fmt.Sprintf(
		`add rule ip %s %s iifname "%s" ip saddr %s tcp dport 53 accept comment "cella_%s_dns"`,
		cellaTable, cellaChain, bridgeIf, rule.SrcIP, sanitizeName(rule.Container)))

	// Allow specific destinations
	for _, dest := range rule.Allow {
		cmds = append(cmds, fmt.Sprintf(
			`add rule ip %s %s iifname "%s" ip saddr %s ip daddr %s accept comment "cella_%s_allow"`,
			cellaTable, cellaChain, bridgeIf, rule.SrcIP, dest, sanitizeName(rule.Container)))
	}

	// Drop everything else from this container
	cmds = append(cmds, fmt.Sprintf(
		`add rule ip %s %s iifname "%s" ip saddr %s counter drop comment "cella_%s_deny-all"`,
		cellaTable, cellaChain, bridgeIf, rule.SrcIP, sanitizeName(rule.Container)))

	// Apply all rules as a single batch via nft -f -
	batch := strings.Join(cmds, "\n")
	cmd := nftCmd("-f", "-")
	cmd.Stdin = strings.NewReader(batch)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply failed: %s: %w", string(output), err)
	}

	return nil
}

// AddEgressAllow adds a single allow rule for a container (before the drop rule).
func AddEgressAllow(container, srcIP, dest, comment string) error {
	if err := ensureCellaTable(); err != nil {
		return err
	}

	tag := fmt.Sprintf("cella_%s_deny-all", sanitizeName(container))

	// Find the handle of the deny-all rule so we can insert before it
	cmd := nftCmd("--handle", "list", "chain", "ip", cellaTable, cellaChain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("list chain: %s: %w", string(output), err)
	}

	// Find the deny-all rule handle
	var denyHandle string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, tag) && strings.Contains(line, "drop") {
			// Extract handle number: "... # handle 42"
			parts := strings.Split(line, "# handle ")
			if len(parts) == 2 {
				denyHandle = strings.TrimSpace(parts[1])
			}
		}
	}

	ruleComment := fmt.Sprintf("cella_%s_allow", sanitizeName(container))
	if comment != "" {
		ruleComment = fmt.Sprintf("cella_%s_%s", sanitizeName(container), comment)
	}

	if denyHandle != "" {
		// Insert before the deny-all rule using nft -f -
		rule := fmt.Sprintf(`insert rule ip %s %s position %s iifname "%s" ip saddr %s ip daddr %s accept comment "%s"`,
			cellaTable, cellaChain, denyHandle, bridgeIf, srcIP, dest, ruleComment)
		cmd = nftCmd("-f", "-")
		cmd.Stdin = strings.NewReader(rule)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("insert allow rule: %s: %w", string(output), err)
		}
	} else {
		// No deny-all yet, just add
		rule := fmt.Sprintf(`add rule ip %s %s iifname "%s" ip saddr %s ip daddr %s accept comment "%s"`,
			cellaTable, cellaChain, bridgeIf, srcIP, dest, ruleComment)
		cmd = nftCmd("-f", "-")
		cmd.Stdin = strings.NewReader(rule)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("add allow rule: %s: %w", string(output), err)
		}
	}
	return nil
}

// RemoveEgressRules removes all cella rules for a specific container.
func RemoveEgressRules(container, srcIP string) error {
	tag := fmt.Sprintf("cella_%s_", sanitizeName(container))

	cmd := nftCmd("--handle", "list", "chain", "ip", cellaTable, cellaChain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Table/chain doesn't exist = nothing to remove
		if strings.Contains(string(output), "No such") {
			return nil
		}
		return fmt.Errorf("list chain: %s: %w", string(output), err)
	}

	// Find and delete all rules with our tag
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, tag) {
			parts := strings.Split(line, "# handle ")
			if len(parts) == 2 {
				handle := strings.TrimSpace(parts[1])
				delCmd := nftCmd("delete", "rule", "ip", cellaTable, cellaChain, "handle", handle)
				delCmd.CombinedOutput() // best effort
			}
		}
	}
	return nil
}

// ListEgressRules reads current nftables rules for a container
func ListEgressRules(container string) (string, error) {
	tag := fmt.Sprintf("cella_%s_", sanitizeName(container))

	cmd := nftCmd("list", "chain", "ip", cellaTable, cellaChain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "No such") {
			return "", nil
		}
		return "", fmt.Errorf("nft list: %s: %w", string(output), err)
	}

	// Filter to only this container's rules
	var lines []string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, tag) {
			lines = append(lines, strings.TrimSpace(line))
		}
	}

	if len(lines) == 0 {
		return "", nil
	}
	return strings.Join(lines, "\n"), nil
}

// ListAllowedIPs extracts the allowed IP destinations from a container's egress rules.
func ListAllowedIPs(container string) ([]string, error) {
	tag := fmt.Sprintf("cella_%s_", sanitizeName(container))
	allowTag := fmt.Sprintf("cella_%s_allow", sanitizeName(container))

	_ = tag
	cmd := nftCmd("list", "chain", "ip", cellaTable, cellaChain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, nil
	}

	var ips []string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, allowTag) || strings.Contains(line, ":allow") {
			// Extract "ip daddr X.X.X.X" from the rule
			if idx := strings.Index(line, "ip daddr "); idx >= 0 {
				rest := line[idx+9:]
				fields := strings.Fields(rest)
				if len(fields) > 0 {
					ips = append(ips, fields[0])
				}
			}
		}
	}
	return ips, nil
}

// HasEgressRestriction checks if a container has any egress restriction (deny-all rule).
func HasEgressRestriction(container string) bool {
	tag := fmt.Sprintf("cella_%s_deny-all", sanitizeName(container))
	cmd := nftCmd("list", "chain", "ip", cellaTable, cellaChain)
	output, _ := cmd.CombinedOutput()
	return strings.Contains(string(output), tag)
}

func sanitizeName(name string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, name)
}
