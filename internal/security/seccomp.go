package security

import (
	"encoding/json"
	"fmt"
	"os"
)

// SeccompProfile represents a seccomp security profile
type SeccompProfile struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	DefaultAction string `json:"defaultAction"` // SCMP_ACT_ALLOW, SCMP_ACT_LOG, etc.
	Syscalls      []Rule `json:"syscalls"`
}

// Rule is a seccomp rule entry
type Rule struct {
	Names  []string `json:"names"`
	Action string   `json:"action"` // SCMP_ACT_ALLOW, SCMP_ACT_ERRNO, SCMP_ACT_NOTIFY
}

// DangerousSyscalls is the list of syscalls that trigger operator approval
// (SCMP_ACT_NOTIFY) when seccomp notify mode is enabled on a container.
// These are operations that could break container isolation or affect the host.
var DangerousSyscalls = []string{
	"ptrace",        // process tracing / debugging — can read/write other process memory
	"mount",         // filesystem mount — can access host paths
	"umount2",       // filesystem unmount
	"init_module",   // load kernel module
	"finit_module",  // load kernel module (fd-based)
	"delete_module", // unload kernel module
	"kexec_load",    // load new kernel — full host takeover
	"kexec_file_load",
	"bpf",             // eBPF — can hook into kernel, bypass security
	"perf_event_open", // kernel performance counters, side-channel risk
	"pivot_root",      // change root filesystem
	"unshare",         // create new namespaces (privilege escalation risk)
	"clone",           // with CLONE_NEWUSER flag = user namespace escape
}

// PredefinedProfiles
var (
	// StrictProfile: defaultAction = ALLOW, with targeted NOTIFY on dangerous syscalls.
	// Previously defaultAction was SCMP_ACT_NOTIFY (wrong — would freeze every syscall).
	// Corrected: only the DangerousSyscalls list triggers operator approval.
	StrictProfile = SeccompProfile{
		Name:          "strict",
		Description:   "Notify operator on dangerous syscalls; allow all others",
		DefaultAction: "SCMP_ACT_ALLOW",
		Syscalls: []Rule{
			// These dangerous syscalls pause the container and ask the operator
			{Names: DangerousSyscalls, Action: "SCMP_ACT_NOTIFY"},
		},
	}

	// ModerateProfile: block dangerous syscalls outright, allow everything else.
	// No operator approval — silent EPERM on dangerous ops.
	ModerateProfile = SeccompProfile{
		Name:          "moderate",
		Description:   "Block dangerous syscalls, allow most others",
		DefaultAction: "SCMP_ACT_ALLOW",
		Syscalls: []Rule{
			{Names: []string{
				"mount", "umount2", "reboot", "init_module", "finit_module",
				"delete_module", "ptrace", "kexec_load", "kexec_file_load",
				"bpf", "pivot_root",
			}, Action: "SCMP_ACT_ERRNO"},
		},
	}

	// PermissiveProfile: log only, no blocking, no approval needed.
	// Useful for profiling which syscalls a container actually uses.
	PermissiveProfile = SeccompProfile{
		Name:          "permissive",
		Description:   "Log only (SCMP_ACT_LOG), no blocking",
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
