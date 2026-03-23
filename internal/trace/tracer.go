package trace

import (
	"context"
	"sync"
	"time"
)

// SyscallEvent represents a traced syscall
type SyscallEvent struct {
	Timestamp time.Time
	Container string
	PID       int
	Syscall   string
	Family    string // file-io, network, process, memory, signals, scheduler
	Args      string
	Result    int
	Latency   time.Duration
	Blocked   bool // was it denied by seccomp?
}

// SyscallFamily categorizes syscalls into families
var SyscallFamily = map[string]string{
	// file-io
	"open": "file-io", "openat": "file-io", "read": "file-io", "write": "file-io",
	"close": "file-io", "stat": "file-io", "fstat": "file-io", "lstat": "file-io",
	"mkdir": "file-io", "rmdir": "file-io", "unlink": "file-io", "rename": "file-io",
	"chmod": "file-io", "chown": "file-io", "readdir": "file-io", "getdents64": "file-io",
	// network
	"socket": "network", "connect": "network", "bind": "network", "listen": "network",
	"accept": "network", "accept4": "network", "sendto": "network", "recvfrom": "network",
	"sendmsg": "network", "recvmsg": "network",
	// process
	"clone": "process", "clone3": "process", "fork": "process", "vfork": "process",
	"execve": "process", "execveat": "process", "exit": "process", "exit_group": "process",
	"wait4": "process", "waitid": "process",
	// memory
	"mmap": "memory", "mprotect": "memory", "munmap": "memory", "brk": "memory",
	"mremap": "memory",
	// signals
	"kill": "signals", "tgkill": "signals", "rt_sigaction": "signals",
	"rt_sigprocmask": "signals", "rt_sigreturn": "signals",
	// scheduler
	"sched_yield": "scheduler", "nanosleep": "scheduler", "clock_nanosleep": "scheduler",
	"futex": "scheduler",
}

// Tracer collects syscall events from containers
type Tracer struct {
	mu       sync.RWMutex
	events   []SyscallEvent
	maxSize  int
	handlers []func(SyscallEvent)
}

// NewTracer creates a new syscall tracer
func NewTracer(bufferSize int) *Tracer {
	return &Tracer{
		events:  make([]SyscallEvent, 0, bufferSize),
		maxSize: bufferSize,
	}
}

// OnEvent registers an event handler
func (t *Tracer) OnEvent(handler func(SyscallEvent)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.handlers = append(t.handlers, handler)
}

// Push adds an event and notifies handlers
func (t *Tracer) Push(ev SyscallEvent) {
	// Auto-classify family if not set
	if ev.Family == "" {
		if f, ok := SyscallFamily[ev.Syscall]; ok {
			ev.Family = f
		} else {
			ev.Family = "other"
		}
	}

	t.mu.Lock()
	if len(t.events) >= t.maxSize {
		// Drop oldest 25%
		copy(t.events, t.events[t.maxSize/4:])
		t.events = t.events[:t.maxSize*3/4]
	}
	t.events = append(t.events, ev)
	handlers := make([]func(SyscallEvent), len(t.handlers))
	copy(handlers, t.handlers)
	t.mu.Unlock()

	for _, h := range handlers {
		h(ev)
	}
}

// Recent returns the last N events
func (t *Tracer) Recent(n int) []SyscallEvent {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if n > len(t.events) {
		n = len(t.events)
	}
	result := make([]SyscallEvent, n)
	copy(result, t.events[len(t.events)-n:])
	return result
}

// FamilyCounts returns syscall counts per family in the last duration
func (t *Tracer) FamilyCounts(window time.Duration) map[string]int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	cutoff := time.Now().Add(-window)
	counts := make(map[string]int)
	for i := len(t.events) - 1; i >= 0; i-- {
		if t.events[i].Timestamp.Before(cutoff) {
			break
		}
		counts[t.events[i].Family]++
	}
	return counts
}

// Start begins collecting syscall events (placeholder for seccomp notify / eBPF)
func (t *Tracer) Start(ctx context.Context) error {
	// TODO: implement seccomp notify or eBPF collection
	<-ctx.Done()
	return ctx.Err()
}
