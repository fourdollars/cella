package runtime

import (
	"context"

	"github.com/fourdoors/cella/internal/lxd"
)

// LXDRuntime wraps an LXD client to implement the Runtime interface
type LXDRuntime struct {
	Client *lxd.Client
}

func NewLXDRuntime(client *lxd.Client) *LXDRuntime {
	return &LXDRuntime{Client: client}
}

func (r *LXDRuntime) Name() string { return "lxd" }

func (r *LXDRuntime) ListContainers(ctx context.Context) ([]ContainerInfo, error) {
	lxdContainers, err := r.Client.ListContainers(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]ContainerInfo, len(lxdContainers))
	for i, c := range lxdContainers {
		result[i] = ContainerInfo{
			Name:       c.Name,
			Status:     c.Status,
			Runtime:    "lxd",
			Type:       c.Type,
			IP:         c.IP,
			Profiles:   c.Profiles,
			CreatedAt:  c.CreatedAt,
			MemoryCur:  c.MemoryCur,
			MemoryMax:  c.MemoryMax,
			CPUUsage:   c.CPUUsage,
			DiskUsage:  c.DiskUsage,
			NetRxBytes: c.NetRxBytes,
			NetTxBytes: c.NetTxBytes,
			PIDs:       c.PIDs,
		}
	}
	return result, nil
}

func (r *LXDRuntime) StartContainer(ctx context.Context, name string) error {
	return r.Client.StartContainer(ctx, name)
}

func (r *LXDRuntime) StopContainer(ctx context.Context, name string) error {
	return r.Client.StopContainer(ctx, name)
}

func (r *LXDRuntime) PauseContainer(ctx context.Context, name string) error {
	return r.Client.FreezeContainer(ctx, name)
}

func (r *LXDRuntime) UnpauseContainer(ctx context.Context, name string) error {
	return r.Client.UnfreezeContainer(ctx, name)
}

func (r *LXDRuntime) ExecCommand(ctx context.Context, name string, command []string) (*ExecResult, error) {
	res, err := r.Client.ExecCommand(ctx, name, command)
	if err != nil {
		return nil, err
	}
	return &ExecResult{
		Stdout:   res.Stdout,
		Stderr:   res.Stderr,
		ExitCode: res.ExitCode,
	}, nil
}

func (r *LXDRuntime) GetConfig(ctx context.Context, name string) (*InstanceConfig, error) {
	cfg, err := r.Client.GetContainerConfig(ctx, name)
	if err != nil {
		return nil, err
	}
	return &InstanceConfig{
		Config:   cfg.Config,
		Devices:  cfg.Devices,
		Profiles: cfg.Profiles,
	}, nil
}

func (r *LXDRuntime) UpdateConfig(ctx context.Context, name string, config map[string]string) error {
	return r.Client.UpdateContainerConfig(ctx, name, config)
}

func (r *LXDRuntime) ListSnapshots(ctx context.Context, name string) ([]SnapshotInfo, error) {
	snaps, err := r.Client.ListSnapshots(ctx, name)
	if err != nil {
		return nil, err
	}
	result := make([]SnapshotInfo, len(snaps))
	for i, s := range snaps {
		result[i] = SnapshotInfo{
			Name:      s.Name,
			CreatedAt: s.CreatedAt,
			Stateful:  s.Stateful,
		}
	}
	return result, nil
}

func (r *LXDRuntime) CreateSnapshot(ctx context.Context, containerName, snapshotName string) error {
	return r.Client.CreateSnapshot(ctx, containerName, snapshotName, false)
}

func (r *LXDRuntime) DeleteSnapshot(ctx context.Context, containerName, snapshotName string) error {
	return r.Client.DeleteSnapshot(ctx, containerName, snapshotName)
}

func (r *LXDRuntime) CopyContainer(ctx context.Context, source, target string) error {
	return r.Client.CopyContainer(ctx, source, target)
}

func (r *LXDRuntime) CreateContainer(ctx context.Context, name, image string, config map[string]string) error {
	return r.Client.CreateContainer(ctx, name, image, config)
}

func (r *LXDRuntime) DeleteContainer(ctx context.Context, name string) error {
	return r.Client.DeleteContainer(ctx, name)
}
