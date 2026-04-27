package metrics

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── RingBuffer tests ──

func TestRingBuffer_PushAndLast(t *testing.T) {
	rb := NewRingBuffer(5)

	// Empty buffer
	got := rb.Last(3)
	if len(got) != 0 {
		t.Fatalf("expected 0 snapshots from empty buffer, got %d", len(got))
	}

	// Push 3 items, ask for 3
	for i := 0; i < 3; i++ {
		rb.Push(Snapshot{CPU: float64(i + 1)})
	}
	got = rb.Last(3)
	if len(got) != 3 {
		t.Fatalf("expected 3 snapshots, got %d", len(got))
	}
	if got[0].CPU != 1 || got[2].CPU != 3 {
		t.Fatalf("expected [1,2,3], got [%.0f,%.0f,%.0f]", got[0].CPU, got[1].CPU, got[2].CPU)
	}
}

func TestRingBuffer_Wrap(t *testing.T) {
	rb := NewRingBuffer(3)

	// Push 5 items into size-3 buffer → should keep last 3
	for i := 1; i <= 5; i++ {
		rb.Push(Snapshot{CPU: float64(i)})
	}
	got := rb.Last(3)
	if len(got) != 3 {
		t.Fatalf("expected 3, got %d", len(got))
	}
	if got[0].CPU != 3 || got[1].CPU != 4 || got[2].CPU != 5 {
		t.Fatalf("expected [3,4,5], got [%.0f,%.0f,%.0f]", got[0].CPU, got[1].CPU, got[2].CPU)
	}
}

func TestRingBuffer_LastMoreThanAvailable(t *testing.T) {
	rb := NewRingBuffer(10)
	rb.Push(Snapshot{CPU: 42})
	got := rb.Last(100)
	if len(got) != 1 {
		t.Fatalf("expected 1 (only 1 pushed), got %d", len(got))
	}
}

func TestRingBuffer_Timestamp(t *testing.T) {
	rb := NewRingBuffer(2)
	now := time.Now()
	rb.Push(Snapshot{Timestamp: now, MemoryUsed: 1024})
	got := rb.Last(1)
	if !got[0].Timestamp.Equal(now) {
		t.Fatalf("timestamp mismatch")
	}
	if got[0].MemoryUsed != 1024 {
		t.Fatalf("expected MemoryUsed=1024, got %d", got[0].MemoryUsed)
	}
}

// ── Cgroup tests (using temp files) ──

func TestReadCPUStat(t *testing.T) {
	dir := t.TempDir()
	content := "usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\n"
	if err := os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	usec, err := ReadCPUStat(dir)
	if err != nil {
		t.Fatalf("ReadCPUStat: %v", err)
	}
	if usec != 123456 {
		t.Fatalf("expected 123456, got %d", usec)
	}
}

func TestReadCPUStat_MissingField(t *testing.T) {
	dir := t.TempDir()
	content := "user_usec 100000\nsystem_usec 23456\n"
	if err := os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := ReadCPUStat(dir)
	if err == nil {
		t.Fatal("expected error when usage_usec missing")
	}
}

func TestReadMemoryCurrent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory.current"), []byte("67108864\n"), 0644); err != nil {
		t.Fatal(err)
	}

	val, err := ReadMemoryCurrent(dir)
	if err != nil {
		t.Fatalf("ReadMemoryCurrent: %v", err)
	}
	if val != 67108864 {
		t.Fatalf("expected 67108864, got %d", val)
	}
}

func TestReadMemoryMax_Unlimited(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte("max\n"), 0644); err != nil {
		t.Fatal(err)
	}

	val, err := ReadMemoryMax(dir)
	if err != nil {
		t.Fatalf("ReadMemoryMax: %v", err)
	}
	if val != 0 {
		t.Fatalf("expected 0 for unlimited, got %d", val)
	}
}

func TestReadMemoryMax_Limited(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte("1073741824\n"), 0644); err != nil {
		t.Fatal(err)
	}

	val, err := ReadMemoryMax(dir)
	if err != nil {
		t.Fatalf("ReadMemoryMax: %v", err)
	}
	if val != 1073741824 {
		t.Fatalf("expected 1073741824, got %d", val)
	}
}

func TestReadIOStat(t *testing.T) {
	dir := t.TempDir()
	content := "259:0 rbytes=1048576 wbytes=524288 rios=100 wios=50\n259:1 rbytes=2097152 wbytes=0 rios=200 wios=0\n"
	if err := os.WriteFile(filepath.Join(dir, "io.stat"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	stat, err := ReadIOStat(dir)
	if err != nil {
		t.Fatalf("ReadIOStat: %v", err)
	}
	if stat.ReadBytes != 1048576+2097152 {
		t.Fatalf("expected ReadBytes=%d, got %d", 1048576+2097152, stat.ReadBytes)
	}
	if stat.WriteBytes != 524288 {
		t.Fatalf("expected WriteBytes=524288, got %d", stat.WriteBytes)
	}
}

func TestReadIOStat_Empty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "io.stat"), []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	stat, err := ReadIOStat(dir)
	if err != nil {
		t.Fatalf("ReadIOStat: %v", err)
	}
	if stat.ReadBytes != 0 || stat.WriteBytes != 0 {
		t.Fatalf("expected 0/0 for empty io.stat, got %d/%d", stat.ReadBytes, stat.WriteBytes)
	}
}

// ── NetStats tests (using temp sysfs) ──

func TestReadNetStats(t *testing.T) {
	// Create a fake sysfs tree
	dir := t.TempDir()
	statsDir := filepath.Join(dir, "statistics")
	if err := os.MkdirAll(statsDir, 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(statsDir, "rx_bytes"), []byte("1000\n"), 0644)
	os.WriteFile(filepath.Join(statsDir, "tx_bytes"), []byte("2000\n"), 0644)
	os.WriteFile(filepath.Join(statsDir, "rx_packets"), []byte("10\n"), 0644)
	os.WriteFile(filepath.Join(statsDir, "tx_packets"), []byte("20\n"), 0644)

	// ReadNetStats uses /sys/class/net/<iface>/statistics, so we can't easily
	// redirect. Instead, test the helper directly.
	val, err := readSysfsInt64(filepath.Join(statsDir, "rx_bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if val != 1000 {
		t.Fatalf("expected 1000, got %d", val)
	}
}

func TestSnapshot_AllFields(t *testing.T) {
	s := Snapshot{
		Timestamp:  time.Now(),
		CPU:        45.5,
		MemoryUsed: 1024 * 1024 * 512,
		MemoryMax:  1024 * 1024 * 1024,
		NetRx:      1000,
		NetTx:      2000,
		DiskRead:   500,
		DiskWrite:  300,
		PIDs:       42,
	}
	rb := NewRingBuffer(1)
	rb.Push(s)
	got := rb.Last(1)
	if got[0].CPU != 45.5 || got[0].PIDs != 42 || got[0].NetRx != 1000 {
		t.Fatalf("snapshot fields not preserved")
	}
}
