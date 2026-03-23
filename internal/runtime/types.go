package runtime

import "context"

// ContainerInfo holds container metadata and metrics (runtime-agnostic)
type ContainerInfo struct {
	Name       string
	Status     string // Running, Stopped, Frozen, Paused, Exited, Created
	Runtime    string // "lxd", "docker"
	Type       string // container, virtual-machine
	Image      string // Docker image name (empty for LXD)
	IP         string
	Profiles   []string
	CreatedAt  string
	MemoryCur  int64 // bytes
	MemoryMax  int64 // bytes (limit)
	CPUUsage   int64 // cumulative nanoseconds
	DiskUsage  int64 // bytes
	NetRxBytes int64 // cumulative
	NetTxBytes int64 // cumulative
	PIDs       int
}

// InstanceConfig holds the full instance configuration
type InstanceConfig struct {
	Config   map[string]string            `json:"config"`
	Devices  map[string]map[string]string `json:"devices"`
	Profiles []string                     `json:"profiles"`
	// Docker-specific
	Image    string            `json:"image,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// SnapshotInfo holds snapshot metadata
type SnapshotInfo struct {
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	Stateful  bool   `json:"stateful"`
}

// ExecResult holds the result of an exec operation
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Runtime defines the interface for container runtimes
type Runtime interface {
	// Name returns the runtime identifier ("lxd" or "docker")
	Name() string

	// ListContainers returns all containers with state
	ListContainers(ctx context.Context) ([]ContainerInfo, error)

	// StartContainer starts a stopped container
	StartContainer(ctx context.Context, name string) error

	// StopContainer stops a running container
	StopContainer(ctx context.Context, name string) error

	// PauseContainer freezes/pauses a container
	PauseContainer(ctx context.Context, name string) error

	// UnpauseContainer unfreezes/unpauses a container
	UnpauseContainer(ctx context.Context, name string) error

	// ExecCommand runs a command inside a container
	ExecCommand(ctx context.Context, name string, command []string) (*ExecResult, error)

	// GetConfig returns the container configuration
	GetConfig(ctx context.Context, name string) (*InstanceConfig, error)

	// UpdateConfig patches the container configuration
	UpdateConfig(ctx context.Context, name string, config map[string]string) error

	// ListSnapshots returns snapshots for a container
	ListSnapshots(ctx context.Context, name string) ([]SnapshotInfo, error)

	// CreateSnapshot creates a snapshot
	CreateSnapshot(ctx context.Context, containerName, snapshotName string) error

	// DeleteSnapshot removes a snapshot
	DeleteSnapshot(ctx context.Context, containerName, snapshotName string) error

	// CopyContainer clones a container
	CopyContainer(ctx context.Context, source, target string) error
}
