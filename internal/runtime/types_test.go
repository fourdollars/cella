package runtime

import "testing"

// Compile-time interface compliance checks.
// These tests ensure LXDRuntime and DockerClient both fully implement the Runtime interface.
// If a method is missing or has the wrong signature, this file won't compile.
var (
	_ Runtime = (*LXDRuntime)(nil)
	_ Runtime = (*DockerClient)(nil)
)

func TestLXDRuntimeName(t *testing.T) {
	// LXDRuntime.Name() should return "lxd" without needing a real client
	rt := &LXDRuntime{}
	if rt.Name() != "lxd" {
		t.Errorf("expected 'lxd', got %q", rt.Name())
	}
}

func TestDockerClientName(t *testing.T) {
	rt := &DockerClient{}
	if rt.Name() != "docker" {
		t.Errorf("expected 'docker', got %q", rt.Name())
	}
}

func TestContainerInfoDefaults(t *testing.T) {
	var c ContainerInfo
	if c.Name != "" {
		t.Error("expected empty name")
	}
	if c.Status != "" {
		t.Error("expected empty status")
	}
	if c.Runtime != "" {
		t.Error("expected empty runtime")
	}
	if c.CPUUsage != 0 {
		t.Error("expected zero CPU")
	}
}

func TestInstanceConfigJSON(t *testing.T) {
	cfg := InstanceConfig{
		Config:   map[string]string{"limits.cpu": "2"},
		Devices:  map[string]map[string]string{"root": {"type": "disk", "path": "/"}},
		Profiles: []string{"default"},
	}
	if cfg.Config["limits.cpu"] != "2" {
		t.Error("config not set correctly")
	}
	if len(cfg.Profiles) != 1 || cfg.Profiles[0] != "default" {
		t.Error("profiles not set correctly")
	}
}
