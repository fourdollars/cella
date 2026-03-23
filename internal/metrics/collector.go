package metrics

import (
	"sync"
	"time"
)

// Snapshot holds a point-in-time metric reading for a container
type Snapshot struct {
	Timestamp  time.Time
	CPU        float64 // percent
	MemoryUsed int64   // bytes
	MemoryMax  int64   // bytes
	NetRx      int64   // bytes/s
	NetTx      int64   // bytes/s
	DiskRead   int64   // bytes/s
	DiskWrite  int64   // bytes/s
	PIDs       int
}

// RingBuffer stores recent metric snapshots for sparkline rendering
type RingBuffer struct {
	mu   sync.RWMutex
	data []Snapshot
	size int
	head int
}

// NewRingBuffer creates a ring buffer with given capacity
func NewRingBuffer(size int) *RingBuffer {
	return &RingBuffer{
		data: make([]Snapshot, size),
		size: size,
	}
}

// Push adds a snapshot to the buffer
func (r *RingBuffer) Push(s Snapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[r.head%r.size] = s
	r.head++
}

// Last returns the N most recent snapshots (oldest first)
func (r *RingBuffer) Last(n int) []Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if n > r.size {
		n = r.size
	}
	total := r.head
	if total > r.size {
		total = r.size
	}
	if n > total {
		n = total
	}

	result := make([]Snapshot, n)
	start := r.head - n
	for i := 0; i < n; i++ {
		idx := (start + i) % r.size
		if idx < 0 {
			idx += r.size
		}
		result[i] = r.data[idx]
	}
	return result
}
