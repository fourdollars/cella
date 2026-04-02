package lxd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

// InstanceConfig holds the full instance configuration
type InstanceConfig struct {
	Config   map[string]string            `json:"config"`
	Devices  map[string]map[string]string `json:"devices"`
	Profiles []string                     `json:"profiles"`
}

// SnapshotInfo holds snapshot metadata
type SnapshotInfo struct {
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	Stateful  bool   `json:"stateful"`
	Size      int64  `json:"size"` // bytes; 0 for dir-backed storage
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
	Config    map[string]string `json:"config"`
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

func (c *Client) doPatch(ctx context.Context, path string, body io.Reader) (*lxdResponse, error) {
	url := fmt.Sprintf("http://unix%s", path)
	req, err := http.NewRequestWithContext(ctx, "PATCH", url, body)
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

func (c *Client) doDelete(ctx context.Context, path string) (*lxdResponse, error) {
	url := fmt.Sprintf("http://unix%s", path)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return nil, err
	}

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

// GetContainerConfig gets the full instance configuration
func (c *Client) GetContainerConfig(ctx context.Context, name string) (*InstanceConfig, error) {
	resp, err := c.doGet(ctx, fmt.Sprintf("/1.0/instances/%s", name))
	if err != nil {
		return nil, err
	}

	var inst struct {
		Config   map[string]string            `json:"config"`
		Devices  map[string]map[string]string `json:"devices"`
		Profiles []string                     `json:"profiles"`
	}
	if err := json.Unmarshal(resp.Metadata, &inst); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return &InstanceConfig{
		Config:   inst.Config,
		Devices:  inst.Devices,
		Profiles: inst.Profiles,
	}, nil
}

// UpdateContainerConfig patches the instance configuration (merge, not replace)
func (c *Client) UpdateContainerConfig(ctx context.Context, name string, config map[string]string) error {
	payload := map[string]interface{}{
		"config": config,
	}
	payloadBytes, _ := json.Marshal(payload)

	resp, err := c.doPatch(ctx, fmt.Sprintf("/1.0/instances/%s", name), strings.NewReader(string(payloadBytes)))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		return fmt.Errorf("update config failed: %s (code %d)", resp.Status, resp.StatusCode)
	}
	return nil
}

// lxdSnapshotRaw is used to unmarshal snapshot entries from the LXD API,
// capturing the size field which may not exist in the runtime.SnapshotInfo type.
type lxdSnapshotRaw struct {
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	Stateful  bool   `json:"stateful"`
	Size      int64  `json:"size"` // bytes; 0 for dir-backed storage
}

// ListSnapshots returns all snapshots for a container
func (c *Client) ListSnapshots(ctx context.Context, name string) ([]SnapshotInfo, error) {
	resp, err := c.doGet(ctx, fmt.Sprintf("/1.0/instances/%s/snapshots?recursion=1", name))
	if err != nil {
		return nil, err
	}

	var raw []lxdSnapshotRaw
	if err := json.Unmarshal(resp.Metadata, &raw); err != nil {
		return nil, fmt.Errorf("parse snapshots: %w", err)
	}
	snapshots := make([]SnapshotInfo, len(raw))
	for i, r := range raw {
		snapshots[i] = SnapshotInfo{
			Name:      r.Name,
			CreatedAt: r.CreatedAt,
			Stateful:  r.Stateful,
			Size:      r.Size,
		}
	}

	// For dir-backed storage, LXD doesn't track snapshot sizes.
	// Fall back to measuring the snapshot directory with du.
	needsDu := false
	for _, s := range snapshots {
		if s.Size == 0 {
			needsDu = true
			break
		}
	}
	if needsDu && len(snapshots) > 0 {
		if poolDir := c.getStoragePoolDir(ctx, name); poolDir != "" {
			snapshotBaseDir := filepath.Join(poolDir, "containers-snapshots", name)
			for i := range snapshots {
				if snapshots[i].Size > 0 {
					continue
				}
				dir := filepath.Join(snapshotBaseDir, snapshots[i].Name)
				if sz := dirSizeBytes(dir); sz > 0 {
					snapshots[i].Size = sz
				}
			}
		}
	}

	return snapshots, nil
}

// getStoragePoolDir returns the source path of the dir-backed storage pool
// used by the given instance, or "" if not applicable.
func (c *Client) getStoragePoolDir(ctx context.Context, instanceName string) string {
	// Get instance expanded_devices to find the root pool
	resp, err := c.doGet(ctx, fmt.Sprintf("/1.0/instances/%s", instanceName))
	if err != nil {
		return ""
	}
	var inst struct {
		ExpandedDevices map[string]map[string]string `json:"expanded_devices"`
	}
	if err := json.Unmarshal(resp.Metadata, &inst); err != nil {
		return ""
	}
	poolName := ""
	for _, dev := range inst.ExpandedDevices {
		if dev["type"] == "disk" && dev["path"] == "/" {
			poolName = dev["pool"]
			break
		}
	}
	if poolName == "" {
		return ""
	}

	// Get storage pool info
	resp, err = c.doGet(ctx, fmt.Sprintf("/1.0/storage-pools/%s", poolName))
	if err != nil {
		return ""
	}
	var pool struct {
		Driver string            `json:"driver"`
		Config map[string]string `json:"config"`
	}
	if err := json.Unmarshal(resp.Metadata, &pool); err != nil {
		return ""
	}
	if pool.Driver != "dir" {
		return "" // only dir backend needs du fallback
	}
	return pool.Config["source"]
}

// dirSizeBytes returns the total size of a directory in bytes using du.
// Returns 0 on any error.
func dirSizeBytes(path string) int64 {
	out, err := exec.Command("du", "-sb", path).Output()
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return 0
	}
	n, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// CreateSnapshot creates a snapshot of the container
func (c *Client) CreateSnapshot(ctx context.Context, containerName, snapshotName string, stateful bool) error {
	payload := map[string]interface{}{
		"name":     snapshotName,
		"stateful": stateful,
	}
	payloadBytes, _ := json.Marshal(payload)

	resp, err := c.doPost(ctx, fmt.Sprintf("/1.0/instances/%s/snapshots", containerName),
		strings.NewReader(string(payloadBytes)))
	if err != nil {
		return fmt.Errorf("create snapshot: %w", err)
	}

	// Wait for async operation
	if resp.Operation != "" {
		_, err = c.doGet(ctx, resp.Operation+"/wait?timeout=60")
		if err != nil {
			return fmt.Errorf("wait for snapshot: %w", err)
		}
	}
	return nil
}

// DeleteSnapshot deletes a snapshot
func (c *Client) DeleteSnapshot(ctx context.Context, containerName, snapshotName string) error {
	resp, err := c.doDelete(ctx, fmt.Sprintf("/1.0/instances/%s/snapshots/%s", containerName, snapshotName))
	if err != nil {
		return fmt.Errorf("delete snapshot: %w", err)
	}
	if resp.Operation != "" {
		_, err = c.doGet(ctx, resp.Operation+"/wait?timeout=60")
		if err != nil {
			return fmt.Errorf("wait for delete: %w", err)
		}
	}
	return nil
}

// CopyContainer copies/clones an instance to a new name
func (c *Client) CopyContainer(ctx context.Context, sourceName, targetName string) error {
	payload := map[string]interface{}{
		"name": targetName,
		"source": map[string]interface{}{
			"type":   "copy",
			"source": sourceName,
		},
	}
	payloadBytes, _ := json.Marshal(payload)

	resp, err := c.doPost(ctx, "/1.0/instances", strings.NewReader(string(payloadBytes)))
	if err != nil {
		return fmt.Errorf("copy container: %w", err)
	}

	if resp.Operation != "" {
		_, err = c.doGet(ctx, resp.Operation+"/wait?timeout=120")
		if err != nil {
			return fmt.Errorf("wait for copy: %w", err)
		}
	}
	return nil
}

// RestoreSnapshot restores a container to a snapshot
func (c *Client) RestoreSnapshot(ctx context.Context, containerName, snapshotName string) error {
	payload := map[string]interface{}{
		"restore": snapshotName,
	}
	payloadBytes, _ := json.Marshal(payload)

	resp, err := c.doPut(ctx, fmt.Sprintf("/1.0/instances/%s", containerName),
		strings.NewReader(string(payloadBytes)))
	if err != nil {
		return fmt.Errorf("restore snapshot: %w", err)
	}

	if resp.Operation != "" {
		_, err = c.doGet(ctx, resp.Operation+"/wait?timeout=120")
		if err != nil {
			return fmt.Errorf("wait for restore: %w", err)
		}
	}
	return nil
}

// ExecCommand runs a command inside a container via LXD exec API
func (c *Client) ExecCommand(ctx context.Context, name string, command []string) (*ExecResult, error) {
	payload := map[string]interface{}{
		"command":            command,
		"wait-for-websocket": false,
		"record-output":      true,
		"interactive":        false,
	}
	payloadBytes, _ := json.Marshal(payload)

	resp, err := c.doPost(ctx, fmt.Sprintf("/1.0/instances/%s/exec", name), strings.NewReader(string(payloadBytes)))
	if err != nil {
		return nil, fmt.Errorf("exec request failed: %w", err)
	}

	opURL := resp.Operation
	if opURL == "" {
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

	waitResp, err := c.doGet(ctx, opURL+"/wait?timeout=30")
	if err != nil {
		return nil, fmt.Errorf("wait for exec: %w", err)
	}

	var op lxdOperation
	if err := json.Unmarshal(waitResp.Metadata, &op); err != nil {
		return nil, fmt.Errorf("parse operation: %w", err)
	}

	result := &ExecResult{}

	if returnVal, ok := op.Metadata["return"]; ok {
		switch v := returnVal.(type) {
		case float64:
			result.ExitCode = int(v)
		}
	}

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

func (c *Client) SocketPath() string {
	return c.socketPath
}

// HostResources holds host-level resource info from LXD
type HostResources struct {
	CPUTotal    int
	MemoryTotal int64
	MemoryUsed  int64
}

// PerCPUUsage holds per-CPU usage percentages
type PerCPUUsage struct {
	ID      int
	Percent float64
}

// HostCPURaw holds raw /proc/stat values for delta calculation
type HostCPURaw struct {
	ID    int
	User  int64
	Nice  int64
	Sys   int64
	Idle  int64
	IOW   int64
	IRQ   int64
	SIRQ  int64
	Steal int64
}

func (r HostCPURaw) Total() int64 {
	return r.User + r.Nice + r.Sys + r.Idle + r.IOW + r.IRQ + r.SIRQ + r.Steal
}

func (r HostCPURaw) Active() int64 {
	return r.Total() - r.Idle - r.IOW
}

// GetHostResources fetches host CPU/memory info from /1.0/resources
func (c *Client) GetHostResources(ctx context.Context) (*HostResources, error) {
	resp, err := c.doGet(ctx, "/1.0/resources")
	if err != nil {
		return nil, err
	}

	var res struct {
		CPU struct {
			Total int `json:"total"`
		} `json:"cpu"`
		Memory struct {
			Total int64 `json:"total"`
			Used  int64 `json:"used"`
		} `json:"memory"`
	}
	if err := json.Unmarshal(resp.Metadata, &res); err != nil {
		return nil, fmt.Errorf("parse resources: %w", err)
	}

	return &HostResources{
		CPUTotal:    res.CPU.Total,
		MemoryTotal: res.Memory.Total,
		MemoryUsed:  res.Memory.Used,
	}, nil
}

// ReadPerCPURaw reads per-CPU stats from /proc/stat
func ReadPerCPURaw() ([]HostCPURaw, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil, err
	}

	var cpus []HostCPURaw
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		// Skip the aggregate "cpu" line
		name := fields[0]
		if name == "cpu" {
			continue
		}
		// "cpu0", "cpu1", etc.
		id, err := strconv.Atoi(strings.TrimPrefix(name, "cpu"))
		if err != nil {
			continue
		}
		parseInt := func(s string) int64 {
			v, _ := strconv.ParseInt(s, 10, 64)
			return v
		}
		raw := HostCPURaw{
			ID:   id,
			User: parseInt(fields[1]),
			Nice: parseInt(fields[2]),
			Sys:  parseInt(fields[3]),
			Idle: parseInt(fields[4]),
		}
		if len(fields) > 5 {
			raw.IOW = parseInt(fields[5])
		}
		if len(fields) > 6 {
			raw.IRQ = parseInt(fields[6])
		}
		if len(fields) > 7 {
			raw.SIRQ = parseInt(fields[7])
		}
		if len(fields) > 8 {
			raw.Steal = parseInt(fields[8])
		}
		cpus = append(cpus, raw)
	}
	return cpus, nil
}

// CalcPerCPUUsage calculates per-CPU usage from two raw snapshots
func CalcPerCPUUsage(prev, cur []HostCPURaw) []PerCPUUsage {
	prevMap := make(map[int]HostCPURaw)
	for _, c := range prev {
		prevMap[c.ID] = c
	}

	var result []PerCPUUsage
	for _, c := range cur {
		p, ok := prevMap[c.ID]
		if !ok {
			result = append(result, PerCPUUsage{ID: c.ID, Percent: 0})
			continue
		}
		totalDelta := c.Total() - p.Total()
		activeDelta := c.Active() - p.Active()
		pct := 0.0
		if totalDelta > 0 {
			pct = float64(activeDelta) / float64(totalDelta) * 100
		}
		result = append(result, PerCPUUsage{ID: c.ID, Percent: pct})
	}
	return result
}

// CreateContainer creates a new LXD instance from an image alias
func (c *Client) CreateContainer(ctx context.Context, name, image string, config map[string]string) error {
	payload := map[string]interface{}{
		"name": name,
		"source": map[string]interface{}{
			"type":  "image",
			"alias": image,
		},
		"config": config,
	}
	payloadBytes, _ := json.Marshal(payload)

	resp, err := c.doPost(ctx, "/1.0/instances", strings.NewReader(string(payloadBytes)))
	if err != nil {
		return fmt.Errorf("create container: %w", err)
	}

	if resp.Operation != "" {
		_, err = c.doGet(ctx, resp.Operation+"/wait?timeout=120")
		if err != nil {
			return fmt.Errorf("wait for create: %w", err)
		}
	}
	return nil
}

// DeleteContainer removes an LXD instance (must be stopped)
func (c *Client) DeleteContainer(ctx context.Context, name string) error {
	resp, err := c.doDelete(ctx, fmt.Sprintf("/1.0/instances/%s", name))
	if err != nil {
		return fmt.Errorf("delete container: %w", err)
	}

	if resp.Operation != "" {
		_, err = c.doGet(ctx, resp.Operation+"/wait?timeout=60")
		if err != nil {
			return fmt.Errorf("wait for delete: %w", err)
		}
	}
	return nil
}
