package tui

import (
	"testing"

	"github.com/fourdoors/cella/internal/lxd"
)

func TestMergeProfiles_OrderAndContainerOverlay(t *testing.T) {
	profiles := map[string]*lxd.Profile{
		"base": {
			Name: "base",
			Config: map[string]string{
				"net.ipv4.ip_forward": "0",
				"base.key": "from-base",
			},
			Devices: map[string]map[string]string{
				"eth0": {
					"parent": "br0",
					"nictype": "bridged",
				},
			},
		},
		"extra": {
			Name: "extra",
			Config: map[string]string{
				"net.ipv4.ip_forward": "1",
				"extra.key": "from-extra",
			},
			Devices: map[string]map[string]string{
				"eth0": {
					"mtu": "1500",
				},
			},
		},
	}

	containerCfg := &lxd.InstanceConfig{
		Config: map[string]string{
			"net.ipv4.ip_forward": "2", // should override profiles
		},
		Devices: map[string]map[string]string{},
	}

	order := []string{"base", "extra"}

	mergedCfg, mergedDevs, origin := MergeProfiles(order, profiles, containerCfg)

	// Check config override order
	if mergedCfg["net.ipv4.ip_forward"] != "2" {
		t.Fatalf("expected container override for net.ipv4.ip_forward, got %q", mergedCfg["net.ipv4.ip_forward"])
	}
	if origin["net.ipv4.ip_forward"] != "container" {
		t.Fatalf("expected origin container for net.ipv4.ip_forward, got %q", origin["net.ipv4.ip_forward"])
	}

	// Check other keys
	if mergedCfg["base.key"] != "from-base" {
		t.Fatalf("expected base.key from base profile, got %q", mergedCfg["base.key"])
	}
	if origin["base.key"] != "base" {
		t.Fatalf("expected origin base for base.key, got %q", origin["base.key"])
	}
	if mergedCfg["extra.key"] != "from-extra" {
		t.Fatalf("expected extra.key from extra profile, got %q", mergedCfg["extra.key"])
	}
	if origin["extra.key"] != "extra" {
		t.Fatalf("expected origin extra for extra.key, got %q", origin["extra.key"])
	}

	// Devices
	if mergedDevs["eth0"]["parent"] != "br0" {
		t.Fatalf("expected eth0.parent from base, got %q", mergedDevs["eth0"]["parent"])
	}
	if origin["eth0.parent"] != "base" {
		t.Fatalf("expected origin base for eth0.parent, got %q", origin["eth0.parent"])
	}
	if mergedDevs["eth0"]["mtu"] != "1500" {
		t.Fatalf("expected eth0.mtu from extra, got %q", mergedDevs["eth0"]["mtu"])
	}
	if origin["eth0.mtu"] != "extra" {
		t.Fatalf("expected origin extra for eth0.mtu, got %q", origin["eth0.mtu"])
	}
}
