package tui

import (
	"strings"
	"testing"
)

func TestBrokerDefaultsAndRender(t *testing.T) {
	a := App{width: 140}
	a.initBrokerDefaults()
	if len(a.brokerGroups) == 0 || len(a.brokerPools) == 0 || len(a.brokerPolicies) == 0 {
		t.Fatalf("broker defaults not initialized")
	}

	out := a.renderBrokerPanel()
	if !strings.Contains(out, "Token Broker") {
		t.Fatalf("unexpected render output: %q", out)
	}
}

func TestBrokerSnapshotRollback(t *testing.T) {
	a := App{width: 140}
	a.initBrokerDefaults()
	orig := a.captureBrokerSnapshot()

	a.brokerGroups[0].Weight = 99
	a.brokerGroups[0].Pool = "pool_ci"
	a.restoreBrokerSnapshot(orig)

	if a.brokerGroups[0].Weight == 99 || a.brokerGroups[0].Pool == "pool_ci" {
		t.Fatalf("rollback failed: %+v", a.brokerGroups[0])
	}
}

func TestBrokerPreview(t *testing.T) {
	a := App{width: 140}
	a.initBrokerDefaults()
	lines := a.brokerBuildPreview()
	if len(lines) < 2 {
		t.Fatalf("preview too short: %#v", lines)
	}
	if !strings.Contains(strings.Join(lines, " "), "simulation") {
		t.Fatalf("preview content mismatch: %#v", lines)
	}
}
