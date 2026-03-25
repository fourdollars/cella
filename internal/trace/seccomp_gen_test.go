package trace

import (
	"strings"
	"testing"
)

// ── SyscallName ──

func TestSyscallName_Known(t *testing.T) {
	cases := []struct {
		nr   int
		want string
	}{
		{0, "read"},
		{1, "write"},
		{2, "open"},
		{3, "close"},
		{59, "execve"},
		{60, "exit"},
		{202, "futex"},
		{231, "exit_group"},
	}
	for _, c := range cases {
		got := SyscallName(c.nr)
		if got != c.want {
			t.Errorf("SyscallName(%d) = %q, want %q", c.nr, got, c.want)
		}
	}
}

func TestSyscallName_Unknown(t *testing.T) {
	got := SyscallName(99999)
	if got != "unknown" {
		t.Errorf("SyscallName(99999) = %q, want \"unknown\"", got)
	}
}

// ── SyscallFamilyOf ──

func TestSyscallFamilyOf_KnownFamilies(t *testing.T) {
	cases := []struct {
		nr     int
		family SyscallFamily
	}{
		{0, FamilyFile},      // read
		{1, FamilyFile},      // write
		{41, FamilyNetwork},  // socket
		{56, FamilyProcess},  // clone
		{9, FamilyMemory},    // mmap
		{202, FamilyIPC},     // futex
	}
	for _, c := range cases {
		got := SyscallFamilyOf(c.nr)
		if got != c.family {
			t.Errorf("SyscallFamilyOf(%d) = %v, want %v", c.nr, got, c.family)
		}
	}
}

func TestSyscallFamilyOf_Unknown(t *testing.T) {
	got := SyscallFamilyOf(99999)
	if got != FamilyOther {
		t.Errorf("SyscallFamilyOf(99999) = %v, want FamilyOther", got)
	}
}

// ── GenerateProfile (with mock tracer via injectSnapshot) ──

func TestGenerateProfile_Empty(t *testing.T) {
	tr := newTestTracer()
	_, err := GenerateProfile(tr, "test")
	if err == nil {
		t.Error("expected error for empty tracer, got nil")
	}
}

func TestGenerateProfile_ContainsEssentials(t *testing.T) {
	tr := newTestTracer()
	tr.injectSnapshot(Snapshot{
		TopCalls: []SyscallStats{
			{ID: 41, Name: "socket", Count: 5, Family: FamilyNetwork},
		},
	})

	prof, err := GenerateProfile(tr, "mycontainer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prof.Container != "mycontainer" {
		t.Errorf("Container = %q, want %q", prof.Container, "mycontainer")
	}
	if prof.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Errorf("DefaultAction = %q, want SCMP_ACT_ERRNO", prof.DefaultAction)
	}

	nameSet := make(map[string]bool)
	for _, n := range prof.Syscalls[0].Names {
		nameSet[n] = true
	}
	// observed syscall must be present
	if !nameSet["socket"] {
		t.Error("expected 'socket' in generated profile")
	}
	// essential syscalls must be present
	for _, essential := range []string{"read", "write", "close", "execve", "futex"} {
		if !nameSet[essential] {
			t.Errorf("essential syscall %q missing from profile", essential)
		}
	}
}

func TestGenerateProfile_NoDuplicates(t *testing.T) {
	tr := newTestTracer()
	for i := 0; i < 3; i++ {
		tr.injectSnapshot(Snapshot{
			TopCalls: []SyscallStats{
				{ID: 0, Name: "read", Count: 10, Family: FamilyFile},
				{ID: 1, Name: "write", Count: 8, Family: FamilyFile},
			},
		})
	}

	prof, err := GenerateProfile(tr, "dup-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seen := make(map[string]int)
	for _, n := range prof.Syscalls[0].Names {
		seen[n]++
		if seen[n] > 1 {
			t.Errorf("duplicate syscall %q in generated profile", n)
		}
	}
}

func TestGenerateProfile_SortedNames(t *testing.T) {
	tr := newTestTracer()
	tr.injectSnapshot(Snapshot{
		TopCalls: []SyscallStats{
			{ID: 2, Name: "open", Count: 3, Family: FamilyFile},
			{ID: 1, Name: "write", Count: 2, Family: FamilyFile},
			{ID: 0, Name: "read", Count: 1, Family: FamilyFile},
		},
	})

	prof, err := GenerateProfile(tr, "sort-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	names := prof.Syscalls[0].Names
	for i := 1; i < len(names); i++ {
		if strings.Compare(names[i-1], names[i]) > 0 {
			t.Errorf("profile syscalls not sorted: %q > %q at index %d", names[i-1], names[i], i)
		}
	}
}

// ── ProfileToJSON ──

func TestProfileToJSON_ValidJSON(t *testing.T) {
	tr := newTestTracer()
	tr.injectSnapshot(Snapshot{
		TopCalls: []SyscallStats{{ID: 0, Name: "read", Count: 1}},
	})
	prof, _ := GenerateProfile(tr, "json-test")
	jsonStr, err := ProfileToJSON(prof)
	if err != nil {
		t.Fatalf("ProfileToJSON error: %v", err)
	}
	if !strings.Contains(jsonStr, `"SCMP_ACT_ERRNO"`) {
		t.Error("JSON missing SCMP_ACT_ERRNO")
	}
	if !strings.Contains(jsonStr, `"json-test"`) {
		t.Error("JSON missing container name")
	}
}

// ── ProfileSummary ──

func TestProfileSummary_ContainsExpected(t *testing.T) {
	tr := newTestTracer()
	tr.injectSnapshot(Snapshot{
		TopCalls: []SyscallStats{{ID: 0, Name: "read", Count: 5}},
	})
	prof, _ := GenerateProfile(tr, "summary-test")
	summary := ProfileSummary(prof)
	if !strings.Contains(summary, "summary-test") {
		t.Error("summary missing container name")
	}
	if !strings.Contains(summary, "SCMP_ACT_ERRNO") {
		t.Error("summary missing default action")
	}
	if !strings.Contains(summary, "Allowed:") {
		t.Error("summary missing Allowed line")
	}
}
