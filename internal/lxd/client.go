package lxd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Client wraps the LXD REST API connection via unix socket
type Client struct {
	socketPath string
	httpClient *http.Client
}

// ContainerInfo holds container metadata and metrics
type ContainerInfo struct {
	Name       string
	Status     string // Running, Stopped, Frozen
	Type       string // container, virtual-machine
	IP         string
	Profiles   []string
	CreatedAt  string
	MemoryCur  int64 // bytes
	MemoryMax  int64 // bytes
	CPUUsage   int64 // cumulative nanoseconds
	DiskUsage  int64 // bytes
	NetRxBytes int64 // cumulative
	NetTxBytes int64 // cumulative
	PIDs       int
}

// lxdResponse is the standard LXD API response envelope
type lxdResponse struct {
	Type       string          `json:"type"`
	Status     string          `json:"status"`
	StatusCode int             `json:"status_code"`
	Metadata   json.RawMessage `json:"metadata"`
}

// lxdInstance represents an instance from LXD API
type lxdInstance struct {
	Name      string            `json:"name"`
	Status    string            `json:"status"`
	Type      string            `json:"type"`
	Profiles  []string          `json:"profiles"`
	CreatedAt time.Time         `json:"created_at"`
	State     *lxdInstanceState `json:"state"`
}

type lxdInstanceState struct {
	Status    string                `json:"status"`
	Memory    lxdMemory             `json:"memory"`
	CPU       lxdCPU                `json:"cpu"`
	Disk      map[string]lxdDisk    `json:"disk"`
	Network   map[string]lxdNetwork `json:"network"`
	Processes int64                 `json:"processes"`
}

type lxdMemory struct {
	Usage     int64 `json:"usage"`
	UsagePeak int64 `json:"usage_peak"`
	Total     int64 `json:"total"`
}

type lxdCPU struct {
	Usage int64 `json:"usage"` // nanoseconds
}

type lxdDisk struct {
	Usage int64 `json:"usage"`
	Total int64 `json:"total"`
}

type lxdNetwork struct {
	Addresses []lxdAddress   `json:"addresses"`
	Counters  lxdNetCounters `json:"counters"`
	State     string         `json:"state"`
}

type lxdAddress struct {
	Family  string `json:"family"`
	Address string `json:"address"`
	Scope   string `json:"scope"`
}

type lxdNetCounters struct {
	BytesReceived   int64 `json:"bytes_received"`
	BytesSent       int64 `json:"bytes_sent"`
	PacketsReceived int64 `json:"packets_received"`
	PacketsSent     int64 `json:"packets_sent"`
}

// NewClient creates a new LXD client via unix socket
func NewClient(socketPath string) (*Client, error) {
	if socketPath == "" {
		socketPath = "/var/snap/lxd/common/lxd/unix.socket"
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 30 * time.Second,
	}

	return &Client{
		socketPath: socketPath,
		httpClient: httpClient,
	}, nil
}

// doGet performs a GET request to the LXD API
func (c *Client) doGet(ctx context.Context, path string) (*lxdResponse, error) {
	url := fmt.Sprintf("http://unix%s", path)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("LXD API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var lxdResp lxdResponse
	if err := json.Unmarshal(body, &lxdResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &lxdResp, nil
}

// doPut performs a PUT request to the LXD API
func (c *Client) doPut(ctx context.Context, path string, body io.Reader) (*lxdResponse, error) {
	url := fmt.Sprintf("http://unix%s", path)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("LXD API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var lxdResp lxdResponse
	if err := json.Unmarshal(respBody, &lxdResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &lxdResp, nil
}

// ListContainers returns all containers with state info
func (c *Client) ListContainers(ctx context.Context) ([]ContainerInfo, error) {
	resp, err := c.doGet(ctx, "/1.0/instances?recursion=2")
	if err != nil {
		return nil, err
	}

	var instances []lxdInstance
	if err := json.Unmarshal(resp.Metadata, &instances); err != nil {
		return nil, fmt.Errorf("parse instances: %w", err)
	}

	var result []ContainerInfo
	for _, inst := range instances {
		ci := ContainerInfo{
			Name:      inst.Name,
			Status:    inst.Status,
			Type:      inst.Type,
			Profiles:  inst.Profiles,
			CreatedAt: inst.CreatedAt.Format("2006-01-02 15:04"),
		}

		if inst.State != nil {
			ci.MemoryCur = inst.State.Memory.Usage
			ci.MemoryMax = inst.State.Memory.Total
			ci.CPUUsage = inst.State.CPU.Usage
			ci.PIDs = int(inst.State.Processes)

			if eth0, ok := inst.State.Network["eth0"]; ok {
				for _, addr := range eth0.Addresses {
					if addr.Family == "inet" && addr.Scope == "global" {
						ci.IP = addr.Address
						break
					}
				}
				ci.NetRxBytes = eth0.Counters.BytesReceived
				ci.NetTxBytes = eth0.Counters.BytesSent
			}

			if root, ok := inst.State.Disk["root"]; ok {
				ci.DiskUsage = root.Usage
			}
		}

		if ci.IP == "" && ci.Status == "Running" {
			ci.IP = "-"
		}

		result = append(result, ci)
	}

	return result, nil
}

// GetInstanceState gets detailed state for a single instance
func (c *Client) GetInstanceState(ctx context.Context, name string) (*ContainerInfo, error) {
	resp, err := c.doGet(ctx, fmt.Sprintf("/1.0/instances/%s/state", name))
	if err != nil {
		return nil, err
	}

	var state lxdInstanceState
	if err := json.Unmarshal(resp.Metadata, &state); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}

	ci := &ContainerInfo{
		Name:      name,
		Status:    state.Status,
		MemoryCur: state.Memory.Usage,
		MemoryMax: state.Memory.Total,
		CPUUsage:  state.CPU.Usage,
		PIDs:      int(state.Processes),
	}

	if eth0, ok := state.Network["eth0"]; ok {
		for _, addr := range eth0.Addresses {
			if addr.Family == "inet" && addr.Scope == "global" {
				ci.IP = addr.Address
				break
			}
		}
		ci.NetRxBytes = eth0.Counters.BytesReceived
		ci.NetTxBytes = eth0.Counters.BytesSent
	}

	if root, ok := state.Disk["root"]; ok {
		ci.DiskUsage = root.Usage
	}

	return ci, nil
}

// changeState sends a state change request to a container
func (c *Client) changeState(ctx context.Context, name, action string) error {
	body := strings.NewReader(fmt.Sprintf(`{"action":"%s","timeout":30,"force":false}`, action))
	resp, err := c.doPut(ctx, fmt.Sprintf("/1.0/instances/%s/state", name), body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		return fmt.Errorf("state change failed: %s", resp.Status)
	}
	return nil
}

func (c *Client) StartContainer(ctx context.Context, name string) error {
	return c.changeState(ctx, name, "start")
}

func (c *Client) StopContainer(ctx context.Context, name string) error {
	return c.changeState(ctx, name, "stop")
}

func (c *Client) FreezeContainer(ctx context.Context, name string) error {
	return c.changeState(ctx, name, "freeze")
}

func (c *Client) UnfreezeContainer(ctx context.Context, name string) error {
	return c.changeState(ctx, name, "unfreeze")
}
