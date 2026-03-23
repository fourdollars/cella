package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// DockerClient implements Runtime for Docker Engine
type DockerClient struct {
	socketPath string
	httpClient *http.Client
}

// NewDockerClient creates a Docker client via unix socket
func NewDockerClient(socketPath string) (*DockerClient, error) {
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}

	// Quick check: does the socket file exist?
	if _, err := os.Stat(socketPath); err != nil {
		return nil, fmt.Errorf("docker socket not found: %w", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", socketPath, 2*time.Second)
			},
		},
		Timeout: 30 * time.Second,
	}

	// Quick health check
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://unix/_ping", nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker socket not available: %w", err)
	}
	resp.Body.Close()

	return &DockerClient{
		socketPath: socketPath,
		httpClient: httpClient,
	}, nil
}

func (d *DockerClient) Name() string { return "docker" }

func (d *DockerClient) doGet(ctx context.Context, path string) ([]byte, error) {
	url := fmt.Sprintf("http://unix%s", path)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker API failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("docker API %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func (d *DockerClient) doPost(ctx context.Context, path string, body io.Reader) ([]byte, error) {
	url := fmt.Sprintf("http://unix%s", path)
	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker API failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("docker API %d: %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

func (d *DockerClient) doDelete(ctx context.Context, path string) error {
	url := fmt.Sprintf("http://unix%s", path)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("docker API failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("docker API %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// Docker API types

type dockerContainer struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	State   string            `json:"State"`   // running, exited, paused, created
	Status  string            `json:"Status"`  // human-readable like "Up 2 hours"
	Created int64             `json:"Created"` // unix timestamp
	Labels  map[string]string `json:"Labels"`
	Ports   []dockerPort      `json:"Ports"`
	NetworkSettings struct {
		Networks map[string]dockerNetwork `json:"Networks"`
	} `json:"NetworkSettings"`
}

type dockerPort struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}

type dockerNetwork struct {
	IPAddress string `json:"IPAddress"`
}

type dockerInspect struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Created string `json:"Created"`
	State   struct {
		Status string `json:"Status"`
		Pid    int    `json:"Pid"`
	} `json:"State"`
	Config struct {
		Image    string            `json:"Image"`
		Hostname string            `json:"Hostname"`
		Env      []string          `json:"Env"`
		Labels   map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		Memory    int64  `json:"Memory"`
		NanoCPUs  int64  `json:"NanoCpus"`
		CPUSetCPUs string `json:"CpusetCpus"`
		CPUQuota  int64  `json:"CpuQuota"`
		CPUPeriod int64  `json:"CpuPeriod"`
	} `json:"HostConfig"`
}

type dockerStats struct {
	CPUStats struct {
		CPUUsage struct {
			TotalUsage int64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage int64 `json:"system_cpu_usage"`
	} `json:"cpu_stats"`
	MemoryStats struct {
		Usage int64 `json:"usage"`
		Limit int64 `json:"limit"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		RxBytes int64 `json:"rx_bytes"`
		TxBytes int64 `json:"tx_bytes"`
	} `json:"networks"`
	PIDs struct {
		Current int `json:"current"`
	} `json:"pids_stats"`
}

// ListContainers returns all Docker containers (running + stopped)
func (d *DockerClient) ListContainers(ctx context.Context) ([]ContainerInfo, error) {
	body, err := d.doGet(ctx, "/containers/json?all=true")
	if err != nil {
		return nil, err
	}

	var containers []dockerContainer
	if err := json.Unmarshal(body, &containers); err != nil {
		return nil, fmt.Errorf("parse containers: %w", err)
	}

	var result []ContainerInfo
	for _, c := range containers {
		name := c.ID[:12]
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		status := "Stopped"
		switch c.State {
		case "running":
			status = "Running"
		case "paused":
			status = "Frozen" // map to same status as LXD
		case "exited":
			status = "Stopped"
		case "created":
			status = "Stopped"
		case "restarting":
			status = "Running"
		}

		ci := ContainerInfo{
			Name:      name,
			Status:    status,
			Runtime:   "docker",
			Type:      "container",
			Image:     c.Image,
			CreatedAt: time.Unix(c.Created, 0).Format("2006-01-02 15:04"),
		}

		// Get IP from first network
		for _, net := range c.NetworkSettings.Networks {
			if net.IPAddress != "" {
				ci.IP = net.IPAddress
				break
			}
		}

		// Fetch stats for running containers
		if c.State == "running" {
			statsBody, err := d.doGet(ctx, fmt.Sprintf("/containers/%s/stats?stream=false", c.ID))
			if err == nil {
				var stats dockerStats
				if json.Unmarshal(statsBody, &stats) == nil {
					ci.MemoryCur = stats.MemoryStats.Usage
					ci.MemoryMax = stats.MemoryStats.Limit
					ci.CPUUsage = stats.CPUStats.CPUUsage.TotalUsage
					ci.PIDs = stats.PIDs.Current

					for _, net := range stats.Networks {
						ci.NetRxBytes += net.RxBytes
						ci.NetTxBytes += net.TxBytes
					}
				}
			}
		}

		if ci.IP == "" && ci.Status == "Running" {
			ci.IP = "-"
		}

		result = append(result, ci)
	}

	return result, nil
}

func (d *DockerClient) StartContainer(ctx context.Context, name string) error {
	_, err := d.doPost(ctx, fmt.Sprintf("/containers/%s/start", name), nil)
	return err
}

func (d *DockerClient) StopContainer(ctx context.Context, name string) error {
	_, err := d.doPost(ctx, fmt.Sprintf("/containers/%s/stop?t=10", name), nil)
	return err
}

func (d *DockerClient) PauseContainer(ctx context.Context, name string) error {
	_, err := d.doPost(ctx, fmt.Sprintf("/containers/%s/pause", name), nil)
	return err
}

func (d *DockerClient) UnpauseContainer(ctx context.Context, name string) error {
	_, err := d.doPost(ctx, fmt.Sprintf("/containers/%s/unpause", name), nil)
	return err
}

func (d *DockerClient) ExecCommand(ctx context.Context, name string, command []string) (*ExecResult, error) {
	// Step 1: Create exec instance
	payload := map[string]interface{}{
		"AttachStdout": true,
		"AttachStderr": true,
		"Cmd":          command,
	}
	payloadBytes, _ := json.Marshal(payload)

	body, err := d.doPost(ctx, fmt.Sprintf("/containers/%s/exec", name), strings.NewReader(string(payloadBytes)))
	if err != nil {
		return nil, fmt.Errorf("create exec: %w", err)
	}

	var execResp struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(body, &execResp); err != nil {
		return nil, fmt.Errorf("parse exec response: %w", err)
	}

	// Step 2: Start exec (non-interactive, capture output)
	startPayload := `{"Detach":false,"Tty":false}`
	url := fmt.Sprintf("http://unix/exec/%s/start", execResp.ID)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(startPayload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("start exec: %w", err)
	}
	defer resp.Body.Close()

	output, _ := io.ReadAll(resp.Body)

	// Step 3: Get exit code
	inspectBody, err := d.doGet(ctx, fmt.Sprintf("/exec/%s/json", execResp.ID))
	result := &ExecResult{Stdout: string(output)}
	if err == nil {
		var inspectResp struct {
			ExitCode int `json:"ExitCode"`
		}
		if json.Unmarshal(inspectBody, &inspectResp) == nil {
			result.ExitCode = inspectResp.ExitCode
		}
	}

	return result, nil
}

func (d *DockerClient) GetConfig(ctx context.Context, name string) (*InstanceConfig, error) {
	body, err := d.doGet(ctx, fmt.Sprintf("/containers/%s/json", name))
	if err != nil {
		return nil, err
	}

	var inspect dockerInspect
	if err := json.Unmarshal(body, &inspect); err != nil {
		return nil, fmt.Errorf("parse inspect: %w", err)
	}

	config := map[string]string{}
	if inspect.HostConfig.NanoCPUs > 0 {
		config["limits.cpu"] = fmt.Sprintf("%.2f", float64(inspect.HostConfig.NanoCPUs)/1e9)
	} else if inspect.HostConfig.CPUSetCPUs != "" {
		config["limits.cpu"] = inspect.HostConfig.CPUSetCPUs
	} else if inspect.HostConfig.CPUQuota > 0 && inspect.HostConfig.CPUPeriod > 0 {
		cpus := float64(inspect.HostConfig.CPUQuota) / float64(inspect.HostConfig.CPUPeriod)
		config["limits.cpu"] = fmt.Sprintf("%.1f", cpus)
	}
	if inspect.HostConfig.Memory > 0 {
		config["limits.memory"] = formatDockerBytes(inspect.HostConfig.Memory)
	}

	// Map env vars
	for _, e := range inspect.Config.Env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			config["env."+parts[0]] = parts[1]
		}
	}

	return &InstanceConfig{
		Config: config,
		Image:  inspect.Config.Image,
		Labels: inspect.Config.Labels,
	}, nil
}

func (d *DockerClient) UpdateConfig(ctx context.Context, name string, config map[string]string) error {
	// Docker doesn't support live config update like LXD
	// We can update resource limits via /containers/{id}/update
	update := map[string]interface{}{}

	if v, ok := config["limits.memory"]; ok {
		update["Memory"] = parseDockerMemory(v)
	}
	if v, ok := config["limits.cpu"]; ok {
		// Try to parse as NanoCPUs (float)
		if f, err := fmt.Sscanf(v, "%f"); err == nil && f > 0 {
			_ = f // parsed but we use Sscanf differently
		}
		update["CpusetCpus"] = v
	}

	if len(update) == 0 {
		return fmt.Errorf("no updatable fields")
	}

	payloadBytes, _ := json.Marshal(update)
	_, err := d.doPost(ctx, fmt.Sprintf("/containers/%s/update", name),
		strings.NewReader(string(payloadBytes)))
	return err
}

func (d *DockerClient) ListSnapshots(ctx context.Context, name string) ([]SnapshotInfo, error) {
	// Docker doesn't have snapshots per se, but we can list checkpoints
	// For now, return empty — Docker uses `docker commit` for image snapshots
	return []SnapshotInfo{}, nil
}

func (d *DockerClient) CreateSnapshot(ctx context.Context, containerName, snapshotName string) error {
	// Docker commit: creates an image from container state
	_, err := d.doPost(ctx,
		fmt.Sprintf("/commit?container=%s&repo=%s&tag=snapshot", containerName, snapshotName), nil)
	return err
}

func (d *DockerClient) DeleteSnapshot(ctx context.Context, containerName, snapshotName string) error {
	// Delete the committed image
	return d.doDelete(ctx, fmt.Sprintf("/images/%s:snapshot", snapshotName))
}

func (d *DockerClient) CopyContainer(ctx context.Context, source, target string) error {
	// Docker: commit source to temp image, then create new container from it
	commitBody, err := d.doPost(ctx,
		fmt.Sprintf("/commit?container=%s&repo=cella-clone-%s", source, target), nil)
	if err != nil {
		return fmt.Errorf("commit source: %w", err)
	}

	var commitResp struct {
		ID string `json:"Id"`
	}
	json.Unmarshal(commitBody, &commitResp)

	// Create container from committed image
	createPayload := map[string]interface{}{
		"Image": fmt.Sprintf("cella-clone-%s:latest", target),
		"name":  target,
	}
	payloadBytes, _ := json.Marshal(createPayload)
	_, err = d.doPost(ctx, fmt.Sprintf("/containers/create?name=%s", target),
		strings.NewReader(string(payloadBytes)))
	return err
}

// SocketPath returns the Docker socket path
func (d *DockerClient) SocketPath() string {
	return d.socketPath
}

func formatDockerBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.0fGB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0fMB", float64(b)/(1<<20))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

func parseDockerMemory(s string) int64 {
	s = strings.TrimSpace(strings.ToUpper(s))
	var multiplier int64 = 1
	if strings.HasSuffix(s, "GB") || strings.HasSuffix(s, "GIB") {
		multiplier = 1 << 30
		s = strings.TrimRight(s, "GIBgib")
	} else if strings.HasSuffix(s, "MB") || strings.HasSuffix(s, "MIB") {
		multiplier = 1 << 20
		s = strings.TrimRight(s, "MIBmib")
	} else if strings.HasSuffix(s, "KB") || strings.HasSuffix(s, "KIB") {
		multiplier = 1 << 10
		s = strings.TrimRight(s, "KIBkib")
	}
	var val float64
	fmt.Sscanf(s, "%f", &val)
	return int64(val) * multiplier
}
