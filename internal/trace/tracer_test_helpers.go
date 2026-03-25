package trace

import "time"

// newTestTracer creates a zero-argument Tracer for unit tests.
// Avoids collision with production NewTracer(containerName, cgroupPath string).
func newTestTracer() *Tracer {
	return &Tracer{
		containerName: "test",
		cgroupPath:    "",
		maxHistory:    60,
		history:       make([]Snapshot, 0),
	}
}

// injectSnapshot appends a snapshot directly into the history ring buffer.
// Used by tests to pre-populate tracer state without running bpftrace.
func (t *Tracer) injectSnapshot(snap Snapshot) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if snap.Timestamp.IsZero() {
		snap.Timestamp = time.Now()
	}
	t.history = append(t.history, snap)
	if len(t.history) > t.maxHistory {
		t.history = t.history[len(t.history)-t.maxHistory:]
	}
}
