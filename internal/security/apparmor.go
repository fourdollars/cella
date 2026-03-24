package security

import (
	"fmt"
	"os/exec"
	"strings"
)

// AppArmorProfile represents an AppArmor profile template for containers.
type AppArmorProfile struct {
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description" yaml:"description"`
	Rules       []string `json:"rules" yaml:"rules"` // raw AppArmor rules appended to LXD default
}

// Predefined AppArmor profiles
var (
	AppArmorDefault = AppArmorProfile{
		Name:        "default",
		Description: "LXD default AppArmor profile (no custom rules)",
		Rules:       nil,
	}

	AppArmorHardened = AppArmorProfile{
		Name:        "hardened",
		Description: "Deny mount, ptrace, and raw network access",
		Rules: []string{
			"deny mount,",
			"deny ptrace,",
			"deny network raw,",
			"deny network packet,",
			"deny /proc/sys/kernel/** w,",
			"deny /sys/firmware/** r,",
		},
	}

	AppArmorNetRestricted = AppArmorProfile{
		Name:        "net-restricted",
		Description: "Deny raw/packet network, allow everything else",
		Rules: []string{
			"deny network raw,",
			"deny network packet,",
		},
	}

	AppArmorReadOnly = AppArmorProfile{
		Name:        "read-only",
		Description: "Deny all write operations to filesystem",
		Rules: []string{
			"deny /** w,",
			"allow /tmp/** w,",
			"allow /var/tmp/** w,",
			"allow /dev/null w,",
			"allow /dev/zero w,",
		},
	}

	// AllAppArmorProfiles is the list of built-in profiles for TUI selection.
	AllAppArmorProfiles = []AppArmorProfile{
		AppArmorDefault,
		AppArmorHardened,
		AppArmorNetRestricted,
		AppArmorReadOnly,
	}
)

// ApplyAppArmorProfile sets the raw.apparmor config on an LXD container.
// An empty rules slice clears the custom AppArmor rules (reverts to default).
func ApplyAppArmorProfile(containerName string, profile AppArmorProfile) error {
	value := strings.Join(profile.Rules, "\n")

	cmd := exec.Command("lxc", "config", "set", containerName, "raw.apparmor", value)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("set apparmor failed: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

// ReadAppArmorProfile reads the current raw.apparmor config from an LXD container.
func ReadAppArmorProfile(containerName string) (string, error) {
	cmd := exec.Command("lxc", "config", "get", containerName, "raw.apparmor")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("get apparmor failed: %s: %w", strings.TrimSpace(string(output)), err)
	}
	raw := strings.TrimSpace(string(output))
	if raw == "" {
		return "default", nil
	}

	// Try to match against known profiles
	for _, p := range AllAppArmorProfiles {
		if p.Name == "default" {
			continue
		}
		expected := strings.Join(p.Rules, "\n")
		if raw == expected {
			return p.Name, nil
		}
	}

	return "custom", nil
}

// MatchAppArmorProfile returns the profile name that matches the given raw rules.
func MatchAppArmorProfile(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "default"
	}
	for _, p := range AllAppArmorProfiles {
		if p.Name == "default" {
			continue
		}
		expected := strings.Join(p.Rules, "\n")
		if raw == expected {
			return p.Name
		}
	}
	return "custom"
}
