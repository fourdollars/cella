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
	ID    int
	Name  string
	Count int64
	Family SyscallFamily
}

// Snapshot is a point-in-time view of syscall activity
type Snapshot struct {
	Timestamp time.Time
	Total     int64
	ByFamily  map[SyscallFamily]int64
	TopCalls  []SyscallStats
}

// Tracer tracks syscall activity for a container using bpftrace
type Tracer struct {
	mu          sync.RWMutex
	containerName string
	cgroupPath    string
	pids          []int
	current       *Snapshot
	history       []Snapshot
	maxHistory    int
	cancel        context.CancelFunc
	running       bool
}

// NewTracer creates a syscall tracer for a container
func NewTracer(containerName, cgroupPath string) *Tracer {
	return &Tracer{
		containerName: containerName,
		cgroupPath:    cgroupPath,
		maxHistory:    60, // 60 snapshots = 2 min at 2s interval
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

	// Find all PIDs in the container's cgroup
	pids, err := t.findPIDs()
	if err != nil {
		return fmt.Errorf("find container PIDs: %w", err)
	}
	t.mu.Lock()
	t.pids = pids
	t.mu.Unlock()

	go t.runBpftrace(ctx)
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

// findPIDs reads all PIDs from the container's cgroup
func (t *Tracer) findPIDs() ([]int, error) {
	// Recursively find all cgroup.procs files under the cgroup path
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

// runBpftrace runs bpftrace in a loop, collecting 2-second snapshots
func (t *Tracer) runBpftrace(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.mu.Lock()
			t.running = false
			t.mu.Unlock()
			return
		case <-ticker.C:
			// Refresh PIDs (processes come and go)
			pids, err := t.findPIDs()
			if err != nil || len(pids) == 0 {
				continue
			}
			t.mu.Lock()
			t.pids = pids
			t.mu.Unlock()

			snap := t.collectSnapshot(ctx, pids)
			if snap != nil {
				t.mu.Lock()
				t.current = snap
				t.history = append(t.history, *snap)
				if len(t.history) > t.maxHistory {
					t.history = t.history[len(t.history)-t.maxHistory:]
				}
				t.mu.Unlock()
			}
		}
	}
}

// collectSnapshot uses bpftrace to get a 2-second syscall sample
func (t *Tracer) collectSnapshot(ctx context.Context, pids []int) *Snapshot {
	// Build PID filter for bpftrace
	// For large PID sets, we sample the first 20 to keep bpftrace overhead low
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

	bctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(bctx, "sudo", "bpftrace", "-e", script)
	out, _ := cmd.CombinedOutput()

	// Parse bpftrace output: @[NR]: count
	snap := &Snapshot{
		Timestamp: time.Now(),
		ByFamily:  make(map[SyscallFamily]int64),
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
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

	if snap.Total == 0 {
		return nil
	}

	return snap
}

func sortSyscallStats(stats []SyscallStats) {
	for i := 1; i < len(stats); i++ {
		for j := i; j > 0 && stats[j].Count > stats[j-1].Count; j-- {
			stats[j], stats[j-1] = stats[j-1], stats[j]
		}
	}
}
