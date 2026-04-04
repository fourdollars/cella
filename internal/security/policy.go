package security

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
)

// ContainerPolicy represents the full security policy for a container.
// This is the format used for YAML export/import.
type ContainerPolicy struct {
	Version   string         `yaml:"version" json:"version"`
	Container string         `yaml:"container" json:"container"`
	Seccomp   PolicySeccomp  `yaml:"seccomp" json:"seccomp"`
	AppArmor  PolicyAppArmor `yaml:"apparmor" json:"apparmor"`
	Egress    PolicyEgress   `yaml:"egress" json:"egress"`
	Flags     PolicyFlags    `yaml:"flags,omitempty" json:"flags,omitempty"`
}

// PolicySeccomp represents seccomp policy configuration.
type PolicySeccomp struct {
	Profile string          `yaml:"profile" json:"profile"`                   // "strict", "moderate", "permissive", or "custom"
	Custom  *SeccompProfile `yaml:"custom,omitempty" json:"custom,omitempty"` // only if profile == "custom"
}

// PolicyAppArmor represents AppArmor policy configuration.
type PolicyAppArmor struct {
	Profile string   `yaml:"profile" json:"profile"`                 // "default", "hardened", "net-restricted", "read-only", or "custom"
	Rules   []string `yaml:"rules,omitempty" json:"rules,omitempty"` // custom rules (only if profile == "custom")
}

// PolicyEgress represents network egress policy.
type PolicyEgress struct {
	Restricted bool     `yaml:"restricted" json:"restricted"`           // whether egress restriction is active
	Allow      []string `yaml:"allow,omitempty" json:"allow,omitempty"` // allowed IPs/CIDRs
	DenyAll    bool     `yaml:"deny_all,omitempty" json:"deny_all,omitempty"`
}

// PolicyFlags represents container security flags.
type PolicyFlags struct {
	Privileged bool `yaml:"privileged,omitempty" json:"privileged,omitempty"`
	Nesting    bool `yaml:"nesting,omitempty" json:"nesting,omitempty"`
}

// ExportPolicy exports the current security policy for a container as YAML.
func ExportPolicy(containerName string) (*ContainerPolicy, error) {
	policy := &ContainerPolicy{
		Version:   "1",
		Container: containerName,
	}

	// Seccomp
	seccompRaw, err := readLXCConfig(containerName, "raw.lxc")
	if err == nil && strings.Contains(seccompRaw, "lxc.seccomp.profile") {
		// Extract seccomp profile path
		for _, line := range strings.Split(seccompRaw, "\n") {
			if strings.Contains(line, "lxc.seccomp.profile") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					path := strings.TrimSpace(parts[1])
					p, loadErr := LoadProfile(path)
					if loadErr == nil {
						policy.Seccomp.Profile = p.Name
						// If it's not a built-in, include the full profile
						if p.Name != "strict" && p.Name != "moderate" && p.Name != "permissive" {
							policy.Seccomp.Profile = "custom"
							policy.Seccomp.Custom = p
						}
					} else {
						policy.Seccomp.Profile = "unknown"
					}
				}
			}
		}
	}
	if policy.Seccomp.Profile == "" {
		policy.Seccomp.Profile = "none"
	}

	// AppArmor
	aaRaw, err := readLXCConfig(containerName, "raw.apparmor")
	if err == nil {
		profileName := MatchAppArmorProfile(aaRaw)
		policy.AppArmor.Profile = profileName
		if profileName == "custom" && aaRaw != "" {
			policy.AppArmor.Rules = strings.Split(aaRaw, "\n")
		}
	} else {
		policy.AppArmor.Profile = "default"
	}

	// Egress
	policy.Egress.Restricted = HasEgressRestriction(containerName)
	if policy.Egress.Restricted {
		ips, _ := ListAllowedIPs(containerName)
		policy.Egress.Allow = ips
		policy.Egress.DenyAll = true
	}

	// Flags
	priv, _ := readLXCConfig(containerName, "security.privileged")
	nest, _ := readLXCConfig(containerName, "security.nesting")
	policy.Flags.Privileged = strings.TrimSpace(priv) == "true"
	policy.Flags.Nesting = strings.TrimSpace(nest) == "true"

	return policy, nil
}

// ExportPolicyYAML exports policy as YAML bytes.
func ExportPolicyYAML(containerName string) ([]byte, error) {
	policy, err := ExportPolicy(containerName)
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(policy)
}

// ExportPolicyJSON exports policy as JSON bytes.
func ExportPolicyJSON(containerName string) ([]byte, error) {
	policy, err := ExportPolicy(containerName)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(policy, "", "  ")
}

// SavePolicyFile writes the policy to a file (YAML or JSON based on extension).
func SavePolicyFile(containerName, path string) error {
	var data []byte
	var err error

	if strings.HasSuffix(path, ".json") {
		data, err = ExportPolicyJSON(containerName)
	} else {
		data, err = ExportPolicyYAML(containerName)
	}
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ImportPolicy reads a policy file and applies it to a container.
func ImportPolicy(containerName, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}

	var policy ContainerPolicy

	if strings.HasSuffix(path, ".json") {
		err = json.Unmarshal(data, &policy)
	} else {
		err = yaml.Unmarshal(data, &policy)
	}
	if err != nil {
		return fmt.Errorf("parse policy file: %w", err)
	}

	return ApplyPolicy(containerName, &policy)
}

// ApplyPolicy applies a ContainerPolicy to a container.
func ApplyPolicy(containerName string, policy *ContainerPolicy) error {
	var errs []string

	// 1. Seccomp
	if policy.Seccomp.Profile != "" && policy.Seccomp.Profile != "none" {
		var profile *SeccompProfile
		switch policy.Seccomp.Profile {
		case "strict":
			profile = &StrictProfile
		case "moderate":
			profile = &ModerateProfile
		case "permissive":
			profile = &PermissiveProfile
		case "custom":
			if policy.Seccomp.Custom != nil {
				profile = policy.Seccomp.Custom
			}
		}
		if profile != nil {
			path := fmt.Sprintf("/tmp/cella-seccomp-%s.json", containerName)
			if err := SaveProfile(path, profile); err != nil {
				errs = append(errs, fmt.Sprintf("seccomp save: %v", err))
			} else {
				rawLxc := fmt.Sprintf("lxc.seccomp.profile = %s", path)
				if err := setLXCConfig(containerName, "raw.lxc", rawLxc); err != nil {
					errs = append(errs, fmt.Sprintf("seccomp apply: %v", err))
				}
			}
		}
	}

	// 2. AppArmor
	if policy.AppArmor.Profile != "" {
		var aaProfile *AppArmorProfile
		switch policy.AppArmor.Profile {
		case "default":
			aaProfile = &AppArmorDefault
		case "hardened":
			aaProfile = &AppArmorHardened
		case "net-restricted":
			aaProfile = &AppArmorNetRestricted
		case "read-only":
			aaProfile = &AppArmorReadOnly
		case "custom":
			aaProfile = &AppArmorProfile{
				Name:  "custom",
				Rules: policy.AppArmor.Rules,
			}
		}
		if aaProfile != nil {
			if err := ApplyAppArmorProfile(containerName, *aaProfile); err != nil {
				errs = append(errs, fmt.Sprintf("apparmor: %v", err))
			}
		}
	}

	// 3. Egress (requires container IP — caller should handle separately if needed)
	// Egress rules are IP-based and need the container's bridge IP,
	// which we don't have in this context. Log a note.
	if policy.Egress.Restricted && len(policy.Egress.Allow) > 0 {
		// Egress will need to be applied from TUI where container IP is available
		errs = append(errs, "egress: rules noted but require container IP to apply (use TUI)")
	}

	if len(errs) > 0 {
		return fmt.Errorf("partial apply: %s", strings.Join(errs, "; "))
	}
	return nil
}

// readLXCConfig reads a single LXD config key.
func readLXCConfig(container, key string) (string, error) {
	out, err := exec.Command("lxc", "config", "get", container, key).CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// setLXCConfig sets a single LXD config key.
func setLXCConfig(container, key, value string) error {
	out, err := exec.Command("lxc", "config", "set", container, key, value).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}
