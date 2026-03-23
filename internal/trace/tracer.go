package trace

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SyscallFamily categorizes syscalls
type SyscallFamily string

const (
	FamilyFile    SyscallFamily = "file"
	FamilyNetwork SyscallFamily = "network"
	FamilyProcess SyscallFamily = "process"
	FamilyMemory  SyscallFamily = "memory"
	FamilySignal  SyscallFamily = "signal"
	FamilyIPC     SyscallFamily = "ipc"
	FamilyOther   SyscallFamily = "other"
)

// SyscallStats holds aggregated syscall statistics
type SyscallStats struct {
	ID     int
	Name   string
	Count  int64
	Family SyscallFamily
}

// Snapshot is a point-in-time view of syscall activity
type Snapshot struct {
	Timestamp time.Time
	Total     int64
	ByFamily  map[SyscallFamily]int64
	TopCalls  []SyscallStats
	Error     string // non-empty if collection failed
}

// Tracer tracks syscall activity for a container using bpftrace
type Tracer struct {
	mu            sync.RWMutex
	containerName string
	cgroupPath    string
	pids          []int
	current       *Snapshot
	history       []Snapshot
	maxHistory    int
	cancel        context.CancelFunc
	running       bool
	lastError     string
}

// NewTracer creates a syscall tracer for a container
func NewTracer(containerName, cgroupPath string) *Tracer {
	return &Tracer{
		containerName: containerName,
		cgroupPath:    cgroupPath,
		maxHistory:    60,
	}
}

// Start begins tracing syscalls for the container
func (t *Tracer) Start(ctx context.Context) error {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return nil
	}
	t.running = true
	t.mu.Unlock()

	ctx, t.cancel = context.WithCancel(ctx)

	// Quick check: can we find PIDs?
	pids, err := t.findPIDs()
	if err != nil {
		t.mu.Lock()
		t.running = false
		t.mu.Unlock()
		return fmt.Errorf("find container PIDs: %w", err)
	}
	if len(pids) == 0 {
		t.mu.Lock()
		t.running = false
		t.mu.Unlock()
		return fmt.Errorf("no PIDs found in %s", t.cgroupPath)
	}
	t.mu.Lock()
	t.pids = pids
	t.mu.Unlock()

	// Collect first snapshot immediately (don't wait for ticker)
	go t.runLoop(ctx)
	return nil
}

// Stop stops the tracer
func (t *Tracer) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cancel != nil {
		t.cancel()
	}
	t.running = false
}

// IsRunning returns whether the tracer is active
func (t *Tracer) IsRunning() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.running
}

// GetSnapshot returns the latest snapshot
func (t *Tracer) GetSnapshot() *Snapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.current
}

// GetHistory returns historical snapshots
func (t *Tracer) GetHistory() []Snapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]Snapshot, len(t.history))
	copy(result, t.history)
	return result
}

// LastError returns the last error string (for debugging)
func (t *Tracer) LastError() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.lastError
}

// findPIDs reads all PIDs from the container's cgroup
func (t *Tracer) findPIDs() ([]int, error) {
	cmd := exec.Command("find", t.cgroupPath, "-name", "cgroup.procs", "-exec", "cat", "{}", ";")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var pids []int
	seen := make(map[int]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(line)
		if err == nil && !seen[pid] {
			pids = append(pids, pid)
			seen[pid] = true
		}
	}
	return pids, nil
}

// runLoop collects snapshots: first one immediately, then every 5 seconds
func (t *Tracer) runLoop(ctx context.Context) {
	// Collect first snapshot immediately
	t.doCollect(ctx)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.mu.Lock()
			t.running = false
			t.mu.Unlock()
			return
		case <-ticker.C:
			t.doCollect(ctx)
		}
	}
}

func (t *Tracer) doCollect(ctx context.Context) {
	// Refresh PIDs
	pids, err := t.findPIDs()
	if err != nil || len(pids) == 0 {
		t.mu.Lock()
		t.lastError = fmt.Sprintf("findPIDs: %v (count=%d)", err, len(pids))
		t.mu.Unlock()
		return
	}
	t.mu.Lock()
	t.pids = pids
	t.mu.Unlock()

	snap := t.collectSnapshot(ctx, pids)
	t.mu.Lock()
	if snap != nil {
		t.current = snap
		t.history = append(t.history, *snap)
		if len(t.history) > t.maxHistory {
			t.history = t.history[len(t.history)-t.maxHistory:]
		}
		t.lastError = ""
	}
	t.mu.Unlock()
}

// collectSnapshot uses `sudo timeout` + bpftrace to get a syscall sample.
// Key insight: we use `timeout --signal=INT 3 bpftrace ...` so bpftrace
// receives SIGINT and prints its aggregation maps before exiting.
// Using context.WithTimeout would SIGKILL bpftrace, losing all output.
func (t *Tracer) collectSnapshot(ctx context.Context, pids []int) *Snapshot {
	samplePIDs := pids
	if len(samplePIDs) > 20 {
		samplePIDs = samplePIDs[:20]
	}

	pidFilters := make([]string, len(samplePIDs))
	for i, pid := range samplePIDs {
		pidFilters[i] = fmt.Sprintf("pid == %d", pid)
	}
	filter := strings.Join(pidFilters, " || ")

	script := fmt.Sprintf(`tracepoint:raw_syscalls:sys_enter /%s/ { @[args.id] = count(); }`, filter)

	// Use `sudo timeout --signal=INT 3 bpftrace -e <script>`
	// timeout sends SIGINT after 3s → bpftrace prints aggregation → exits
	cmd := exec.CommandContext(ctx, "sudo", "timeout", "--signal=INT", "3", "bpftrace", "-e", script)
	out, err := cmd.CombinedOutput()

	outStr := string(out)

	// Parse output
	snap := &Snapshot{
		Timestamp: time.Now(),
		ByFamily:  make(map[SyscallFamily]int64),
	}

	// If bpftrace had an actual error (not just timeout exit code 124)
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() != 124 {
			// Real error, not timeout
			snap.Error = fmt.Sprintf("bpftrace: %v | output: %s", err, truncate(outStr, 200))
			t.mu.Lock()
			t.lastError = snap.Error
			t.mu.Unlock()
			return snap
		}
		// exit code 124 = timeout sent signal, which is expected
	}

	scanner := bufio.NewScanner(strings.NewReader(outStr))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "@[") {
			continue
		}

		// Parse @[232]: 69
		bracketEnd := strings.Index(line, "]")
		if bracketEnd < 0 {
			continue
		}
		nrStr := line[2:bracketEnd]
		nr, err := strconv.Atoi(nrStr)
		if err != nil {
			continue
		}

		colonIdx := strings.LastIndex(line, ":")
		if colonIdx < 0 {
			continue
		}
		countStr := strings.TrimSpace(line[colonIdx+1:])
		count, err := strconv.ParseInt(countStr, 10, 64)
		if err != nil {
			continue
		}

		name := SyscallName(nr)
		family := SyscallFamilyOf(nr)

		snap.Total += count
		snap.ByFamily[family] += count
		snap.TopCalls = append(snap.TopCalls, SyscallStats{
			ID:     nr,
			Name:   name,
			Count:  count,
			Family: family,
		})
	}

	// Sort by count desc
	sortSyscallStats(snap.TopCalls)

	// Keep top 15
	if len(snap.TopCalls) > 15 {
		snap.TopCalls = snap.TopCalls[:15]
	}

	if snap.Total == 0 && snap.Error == "" {
		snap.Error = fmt.Sprintf("no syscalls captured (pids=%d) | raw_len=%d", len(pids), len(outStr))
		t.mu.Lock()
		t.lastError = snap.Error
		t.mu.Unlock()
	}

	return snap
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func sortSyscallStats(stats []SyscallStats) {
	for i := 1; i < len(stats); i++ {
		for j := i; j > 0 && stats[j].Count > stats[j-1].Count; j-- {
			stats[j], stats[j-1] = stats[j-1], stats[j]
		}
	}
}
