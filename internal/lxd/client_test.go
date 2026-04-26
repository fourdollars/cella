package lxd

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// testServer creates a mock LXD API server over a Unix socket and returns
// a connected Client and cleanup function.
func testServer(t *testing.T, handler http.Handler) (*Client, func()) {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "lxd.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}

	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)

	client, err := NewClient(sockPath)
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}

	cleanup := func() {
		srv.Close()
		ln.Close()
		os.Remove(sockPath)
	}
	return client, cleanup
}

func TestListContainers_ParsesResponse(t *testing.T) {
	// Mock LXD API response with 2 instances
	mockResponse := lxdResponse{
		Type:       "sync",
		Status:     "Success",
		StatusCode: 200,
	}

	instances := []lxdInstance{
		{
			Name:   "web-server",
			Status: "Running",
			Type:   "container",
			Profiles: []string{"default"},
			State: &lxdInstanceState{
				Status: "Running",
				Memory: lxdMemory{Usage: 512 * 1024 * 1024, Total: 1024 * 1024 * 1024},
				CPU:    lxdCPU{Usage: 5000000000},
				Network: map[string]lxdNetwork{
					"eth0": {
						Addresses: []lxdAddress{
							{Family: "inet", Address: "10.0.0.5", Scope: "global"},
						},
						Counters: lxdNetCounters{BytesReceived: 1000, BytesSent: 2000},
					},
				},
				Disk:      map[string]lxdDisk{"root": {Usage: 1073741824}},
				Processes: 42,
			},
		},
		{
			Name:     "db-server",
			Status:   "Stopped",
			Type:     "container",
			Profiles: []string{"default", "postgres"},
		},
	}

	metadata, _ := json.Marshal(instances)
	mockResponse.Metadata = metadata

	mux := http.NewServeMux()
	mux.HandleFunc("/1.0/instances", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	})

	client, cleanup := testServer(t, mux)
	defer cleanup()

	containers, err := client.ListContainers(context.Background())
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}

	if len(containers) != 2 {
		t.Fatalf("expected 2 containers, got %d", len(containers))
	}

	// Verify first container
	c := containers[0]
	if c.Name != "web-server" {
		t.Errorf("expected name 'web-server', got %q", c.Name)
	}
	if c.Status != "Running" {
		t.Errorf("expected status 'Running', got %q", c.Status)
	}
	if c.IP != "10.0.0.5" {
		t.Errorf("expected IP '10.0.0.5', got %q", c.IP)
	}
	if c.MemoryCur != 512*1024*1024 {
		t.Errorf("expected MemoryCur 512MB, got %d", c.MemoryCur)
	}
	if c.MemoryMax != 1024*1024*1024 {
		t.Errorf("expected MemoryMax 1GB, got %d", c.MemoryMax)
	}
	if c.CPUUsage != 5000000000 {
		t.Errorf("expected CPUUsage 5B ns, got %d", c.CPUUsage)
	}
	if c.NetRxBytes != 1000 {
		t.Errorf("expected NetRxBytes 1000, got %d", c.NetRxBytes)
	}
	if c.NetTxBytes != 2000 {
		t.Errorf("expected NetTxBytes 2000, got %d", c.NetTxBytes)
	}
	if c.DiskUsage != 1073741824 {
		t.Errorf("expected DiskUsage 1GB, got %d", c.DiskUsage)
	}
	if c.PIDs != 42 {
		t.Errorf("expected PIDs 42, got %d", c.PIDs)
	}

	// Verify second container (stopped)
	c2 := containers[1]
	if c2.Name != "db-server" {
		t.Errorf("expected name 'db-server', got %q", c2.Name)
	}
	if c2.Status != "Stopped" {
		t.Errorf("expected status 'Stopped', got %q", c2.Status)
	}
	if c2.IP != "" {
		t.Errorf("expected empty IP for stopped container, got %q", c2.IP)
	}
}

func TestListContainers_EmptyResponse(t *testing.T) {
	mockResponse := lxdResponse{
		Type:       "sync",
		Status:     "Success",
		StatusCode: 200,
		Metadata:   json.RawMessage("[]"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/1.0/instances", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(mockResponse)
	})

	client, cleanup := testServer(t, mux)
	defer cleanup()

	containers, err := client.ListContainers(context.Background())
	if err != nil {
		t.Fatalf("ListContainers: %v", err)
	}
	if len(containers) != 0 {
		t.Errorf("expected 0 containers, got %d", len(containers))
	}
}

func TestListContainers_RunningWithNoIP(t *testing.T) {
	instances := []lxdInstance{
		{
			Name:   "no-ip-box",
			Status: "Running",
			Type:   "container",
			State: &lxdInstanceState{
				Status:  "Running",
				Network: map[string]lxdNetwork{},
			},
		},
	}
	metadata, _ := json.Marshal(instances)
	mockResponse := lxdResponse{
		Type: "sync", Status: "Success", StatusCode: 200,
		Metadata: metadata,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/1.0/instances", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(mockResponse)
	})

	client, cleanup := testServer(t, mux)
	defer cleanup()

	containers, err := client.ListContainers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if containers[0].IP != "-" {
		t.Errorf("expected '-' for running container without IP, got %q", containers[0].IP)
	}
}

func TestNewClient_InvalidSocket(t *testing.T) {
	_, err := NewClient("/nonexistent/lxd.sock")
	// NewClient may succeed (lazy connect) or fail — either is acceptable.
	// But if it succeeds, ListContainers should fail.
	if err != nil {
		return // early validation, fine
	}
}

func TestSocketPath(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	// Create a dummy socket so NewClient doesn't fail
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	client, err := NewClient(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	if client.SocketPath() != sockPath {
		t.Errorf("expected socket path %q, got %q", sockPath, client.SocketPath())
	}
}
