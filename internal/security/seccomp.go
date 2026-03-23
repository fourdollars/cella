package security

import (
	"encoding/json"
	"fmt"
	"os"
)

// SeccompProfile represents a seccomp security profile
type SeccompProfile struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	DefaultAction string  `json:"defaultAction"` // SCMP_ACT_ALLOW, SCMP_ACT_LOG, etc.
	Syscalls     []Rule   `json:"syscalls"`
}

// Rule is a seccomp rule entry
type Rule struct {
	Names  []string `json:"names"`
	Action string   `json:"action"` // SCMP_ACT_ALLOW, SCMP_ACT_ERRNO, SCMP_ACT_NOTIFY
}

// PredefinedProfiles
var (
	StrictProfile = SeccompProfile{
		Name:          "strict",
		Description:   "Block dangerous syscalls, notify on file/net ops",
		DefaultAction: "SCMP_ACT_NOTIFY",
		Syscalls: []Rule{
			{Names: []string{"mount", "umount2", "reboot", "init_module", "delete_module", "ptrace", "kexec_load", "bpf"}, Action: "SCMP_ACT_ERRNO"},
			{Names: []string{"mmap", "mprotect", "brk", "futex", "clone", "clone3", "epoll_ctl", "epoll_wait", "poll", "select"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"sendmsg", "exit", "exit_group", "rt_sigreturn"}, Action: "SCMP_ACT_ALLOW"},
		},
	}

	ModerateProfile = SeccompProfile{
		Name:          "moderate",
		Description:   "Block dangerous syscalls, allow most others",
		DefaultAction: "SCMP_ACT_ALLOW",
		Syscalls: []Rule{
			{Names: []string{"mount", "umount2", "reboot", "init_module", "delete_module", "ptrace", "kexec_load", "bpf"}, Action: "SCMP_ACT_ERRNO"},
		},
	}

	PermissiveProfile = SeccompProfile{
		Name:          "permissive",
		Description:   "Log only, no blocking",
		DefaultAction: "SCMP_ACT_LOG",
		Syscalls:      []Rule{},
	}
)

// LoadProfile reads a seccomp profile from file
func LoadProfile(path string) (*SeccompProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile %s: %w", path, err)
	}
	var p SeccompProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse profile %s: %w", path, err)
	}
	return &p, nil
}

// SaveProfile writes a seccomp profile to file
func SaveProfile(path string, p *SeccompProfile) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
