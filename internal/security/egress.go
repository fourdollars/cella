package security

import (
	"fmt"
	"os/exec"
	"strings"
)

// EgressRule defines a per-container network egress rule
type EgressRule struct {
	Container string
	Allow     []string // domain or IP patterns
	DenyAll   bool     // if true, deny all except Allow list
}

// ApplyEgressRules generates and applies nftables rules for a container
func ApplyEgressRules(rule EgressRule) error {
	if len(rule.Allow) == 0 && !rule.DenyAll {
		return nil // nothing to do
	}

	// Build nftables ruleset
	var rules []string
	tableName := fmt.Sprintf("cella_%s", sanitizeName(rule.Container))

	// Flush existing table
	rules = append(rules, fmt.Sprintf("table inet %s {", tableName))
	rules = append(rules, "  chain egress {")
	rules = append(rules, "    type filter hook output priority 0; policy drop;")

	// Allow DNS
	rules = append(rules, "    udp dport 53 accept")
	rules = append(rules, "    tcp dport 53 accept")

	// Allow loopback
	rules = append(rules, "    oif lo accept")

	// Allow established connections
	rules = append(rules, "    ct state established,related accept")

	// Allow listed destinations
	for _, dest := range rule.Allow {
		rules = append(rules, fmt.Sprintf("    ip daddr %s accept  # %s", dest, dest))
	}

	rules = append(rules, "  }")
	rules = append(rules, "}")

	ruleset := strings.Join(rules, "\n")

	// Apply via nft
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply failed: %s: %w", string(output), err)
	}

	return nil
}

// RemoveEgressRules removes nftables rules for a container
func RemoveEgressRules(container string) error {
	tableName := fmt.Sprintf("cella_%s", sanitizeName(container))
	cmd := exec.Command("nft", "delete", "table", "inet", tableName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Table might not exist, that's OK
		if strings.Contains(string(output), "No such file") {
			return nil
		}
		return fmt.Errorf("nft delete failed: %s: %w", string(output), err)
	}
	return nil
}

// ListEgressRules reads current nftables rules for a container
func ListEgressRules(container string) (string, error) {
	tableName := fmt.Sprintf("cella_%s", sanitizeName(container))
	cmd := exec.Command("nft", "list", "table", "inet", tableName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("nft list failed: %s: %w", string(output), err)
	}
	return string(output), nil
}

func sanitizeName(name string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, name)
}
