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

// ExecResult holds the result of an exec operation
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// lxdResponse is the standard LXD API response envelope
type lxdResponse struct {
	Type       string          `json:"type"`
	Status     string          `json:"status"`
	StatusCode int             `json:"status_code"`
	Metadata   json.RawMessage `json:"metadata"`
	Operation  string          `json:"operation"`
}

// lxdOperation represents an async operation
type lxdOperation struct {
	ID         string                 `json:"id"`
	Class      string                 `json:"class"`
	Status     string                 `json:"status"`
	StatusCode int                    `json:"status_code"`
	Metadata   map[string]interface{} `json:"metadata"`
}

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
	Usage int64 `json:"usage"`
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

func (c *Client) doPost(ctx context.Context, path string, body io.Reader) (*lxdResponse, error) {
	url := fmt.Sprintf("http://unix%s", path)
	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
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

// ExecCommand runs a command inside a container via LXD exec API
// Returns stdout output. For non-interactive use.
func (c *Client) ExecCommand(ctx context.Context, name string, command []string) (*ExecResult, error) {
	payload := map[string]interface{}{
		"command":      command,
		"wait-for-websocket": false,
		"record-output":      true,
		"interactive":        false,
	}
	payloadBytes, _ := json.Marshal(payload)

	resp, err := c.doPost(ctx, fmt.Sprintf("/1.0/instances/%s/exec", name), strings.NewReader(string(payloadBytes)))
	if err != nil {
		return nil, fmt.Errorf("exec request failed: %w", err)
	}

	// The response contains an operation URL — we need to wait for it
	opURL := resp.Operation
	if opURL == "" {
		// Try to extract from metadata
		var opMeta struct {
			ID string `json:"id"`
		}
		json.Unmarshal(resp.Metadata, &opMeta)
		if opMeta.ID != "" {
			opURL = fmt.Sprintf("/1.0/operations/%s", opMeta.ID)
		}
	}

	if opURL == "" {
		return nil, fmt.Errorf("no operation URL in exec response")
	}

	// Wait for the operation to complete
	waitResp, err := c.doGet(ctx, opURL+"/wait?timeout=30")
	if err != nil {
		return nil, fmt.Errorf("wait for exec: %w", err)
	}

	var op lxdOperation
	if err := json.Unmarshal(waitResp.Metadata, &op); err != nil {
		return nil, fmt.Errorf("parse operation: %w", err)
	}

	result := &ExecResult{}

	// Get exit code from operation metadata
	if returnVal, ok := op.Metadata["return"]; ok {
		switch v := returnVal.(type) {
		case float64:
			result.ExitCode = int(v)
		}
	}

	// Get output from log files (raw file content, not JSON)
	if output, ok := op.Metadata["output"]; ok {
		if outputMap, ok := output.(map[string]interface{}); ok {
			if stdoutPath, ok := outputMap["1"].(string); ok {
				data, err := c.doGetRaw(ctx, stdoutPath)
				if err == nil {
					result.Stdout = data
				}
			}
			if stderrPath, ok := outputMap["2"].(string); ok {
				data, err := c.doGetRaw(ctx, stderrPath)
				if err == nil {
					result.Stderr = data
				}
			}
		}
	}

	return result, nil
}

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

// doGetRaw performs a GET and returns the raw body (for log files, not JSON)
func (c *Client) doGetRaw(ctx context.Context, path string) (string, error) {
	url := fmt.Sprintf("http://unix%s", path)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("LXD API request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	return string(body), nil
}

// SocketPath returns the socket path for event streaming
func (c *Client) SocketPath() string {
	return c.socketPath
}
