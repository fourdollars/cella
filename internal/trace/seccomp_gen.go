package trace

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SeccompProfile represents an LXD-compatible seccomp profile
type SeccompProfile struct {
	Comment       string        `json:"comment"`
	DefaultAction string        `json:"defaultAction"`
	Architectures []string      `json:"architectures"`
	Syscalls      []SeccompRule `json:"syscalls"`
	Generated     time.Time     `json:"_generated"`
	Container     string        `json:"_container"`
	ObservedSec   int           `json:"_observedSeconds"`
	TotalSamples  int           `json:"_totalSamples"`
}

// SeccompRule is one entry in the seccomp profile
type SeccompRule struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

// GenerateProfile creates a minimal seccomp allow-list from tracer history.
// It collects all unique syscalls observed and builds a whitelist profile.
func GenerateProfile(tracer *Tracer, containerName string) (*SeccompProfile, error) {
	history := tracer.GetHistory()
	if len(history) == 0 {
		return nil, fmt.Errorf("no data collected yet — let the tracer run for at least 5 seconds")
	}

	// Collect all unique syscalls across all snapshots
	seen := make(map[int]int64)       // syscall NR → total count
	seenNames := make(map[int]string) // syscall NR → name
	var totalSyscalls int64

	for _, snap := range history {
		for _, sc := range snap.TopCalls {
			seen[sc.ID] += sc.Count
			seenNames[sc.ID] = sc.Name
			totalSyscalls += sc.Count
		}
	}

	if len(seen) == 0 {
		return nil, fmt.Errorf("no syscalls observed")
	}

	// Always include essential syscalls that may not appear in short traces
	// but are needed for basic container operation
	essentialSyscalls := []int{
		0,   // read
		1,   // write
		3,   // close
		9,   // mmap
		10,  // mprotect
		11,  // munmap
		12,  // brk
		13,  // rt_sigaction
		14,  // rt_sigprocmask
		15,  // rt_sigreturn
		21,  // access
		56,  // clone
		59,  // execve
		60,  // exit
		63,  // uname
		72,  // fcntl
		79,  // getcwd
		89,  // readlink
		95,  // umask
		96,  // gettimeofday
		97,  // getrlimit
		102, // getuid
		104, // getgid
		107, // geteuid
		108, // getegid
		110, // getppid
		131, // sigaltstack
		157, // prctl
		186, // gettid
		202, // futex
		218, // set_tid_address
		228, // clock_gettime
		231, // exit_group
		257, // openat
		262, // newfstatat
		302, // prlimit64
		334, // rseq
	}

	for _, nr := range essentialSyscalls {
		if _, exists := seen[nr]; !exists {
			seen[nr] = 0
			seenNames[nr] = SyscallName(nr)
		}
	}

	// Sort syscall names alphabetically for the profile
	names := make([]string, 0, len(seen))
	nameSet := make(map[string]bool)
	for nr := range seen {
		name := seenNames[nr]
		if name == "unknown" {
			name = fmt.Sprintf("syscall_%d", nr)
		}
		if !nameSet[name] {
			names = append(names, name)
			nameSet[name] = true
		}
	}
	sort.Strings(names)

	// Calculate observation duration
	observedSec := 0
	if len(history) > 1 {
		first := history[0].Timestamp
		last := history[len(history)-1].Timestamp
		observedSec = int(last.Sub(first).Seconds())
	}

	profile := &SeccompProfile{
		Comment:       fmt.Sprintf("Auto-generated minimal seccomp profile for %s", containerName),
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"},
		Syscalls: []SeccompRule{
			{
				Names:  names,
				Action: "SCMP_ACT_ALLOW",
			},
		},
		Generated:    time.Now(),
		Container:    containerName,
		ObservedSec:  observedSec,
		TotalSamples: len(history),
	}

	return profile, nil
}

// ProfileToJSON serializes the profile to indented JSON
func ProfileToJSON(profile *SeccompProfile) (string, error) {
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ProfileSummary returns a human-readable summary of the profile
func ProfileSummary(profile *SeccompProfile) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Container:     %s\n", profile.Container)
	fmt.Fprintf(&b, "Default:       %s (deny unlisted)\n", profile.DefaultAction)
	fmt.Fprintf(&b, "Allowed:       %d syscalls\n", len(profile.Syscalls[0].Names))
	fmt.Fprintf(&b, "Observed:      %ds (%d samples)\n", profile.ObservedSec, profile.TotalSamples)
	fmt.Fprintf(&b, "Generated:     %s\n", profile.Generated.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "\nSyscalls: %s\n", strings.Join(profile.Syscalls[0].Names, ", "))
	return b.String()
}
