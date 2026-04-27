package tui

// ── Centralized key binding definitions ──
//
// This file is the single source of truth for all keyboard shortcuts in cella.
// The help overlay (help.go) renders from these definitions, ensuring docs
// stay in sync with the actual key handlers.
//
// Key handlers still live in update_key.go and panels_*.go — this file
// only documents *what* each key does, not *how*.

// HelpEntry pairs a key label with a human-readable description.
type HelpEntry struct {
	Key  string
	Desc string
}

// HelpSection groups related key bindings under a section title.
type HelpSection struct {
	Title   string
	Entries []HelpEntry
}

// ── Global Keys (active from sidebar / dashboard) ──

var navKeys = HelpSection{
	Title: "Navigation",
	Entries: []HelpEntry{
		{"↑/k", "Move up"},
		{"↓/j", "Move down"},
		{"1/2/3", "Sort: name/cpu/mem"},
		{"f", "Filter runtime"},
		{"/", "Search by name"},
		{"g", "Goto container #"},
		{"Ctrl+L", "Clear search"},
	},
}

var containerKeys = HelpSection{
	Title: "Container",
	Entries: []HelpEntry{
		{"s", "Start / Unfreeze"},
		{"x", "Stop"},
		{"p", "Pause / Unpause"},
		{"e", "Exec command"},
		{"l", "Logs (stream)"},
		{"+", "Create new"},
		{"d", "Delete (stopped)"},
	},
}

var monitorKeys = HelpSection{
	Title: "Monitor Panels",
	Entries: []HelpEntry{
		{"w", "Network"},
		{"r", "Resource limits"},
		{"n", "Snapshots / Clone"},
		{"V", "Recent events"},
		{"M", "Inference stats (RPM/TPM/cost)"},
		{"R", "Inference routing"},
		{"B", "Token Broker"},
	},
}

var securityKeys = HelpSection{
	Title: "Security Panels",
	Entries: []HelpEntry{
		{"P", "Policy (seccomp/egress/AppArmor/flags)"},
		{"Z", "Toggle syscall blocking (LXD BPF deny)"},
		{"D", "DNS monitor"},
		{"t", "Start syscall trace (bpftrace)"},
		{"T", "Stop syscall trace"},
		{"G", "Generate seccomp profile from trace"},
		{"S", "Save seccomp JSON"},
	},
}

var policyPanelKeys = HelpSection{
	Title: "In Policy Panel",
	Entries: []HelpEntry{
		{"[b]", "Toggle boot.autostart"},
		{"[P]", "Toggle security.privileged"},
		{"[N]", "Toggle security.nesting"},
		{"[V]", "Toggle security.devlxd"},
		{"[M]", "Toggle idmap.isolated"},
		{"1-3", "Apply seccomp profile"},
		{"4-7", "Apply AppArmor profile"},
		{"a/d", "Add/remove egress rule"},
	},
}

var httpsKeys = HelpSection{
	Title: "HTTPS Interception",
	Entries: []HelpEntry{
		{"A", "API audit log + interception setup"},
		{"y", "Approve request (once)"},
		{"Y", "Approve request (always)"},
		{"n", "Deny request (once)"},
		{"N", "Deny request (always)"},
	},
}

var auditPanelKeys = HelpSection{
	Title: "In Audit Panel",
	Entries: []HelpEntry{
		{"/", "Filter text"},
		{"f", "Filter by status"},
		{"H", "Toggle host machine interception"},
		{"L", "Show allow/deny lists"},
		{"S", "Export audit JSON"},
		{"c", "Clear log"},
		{"p", "Setup HTTPS interception (container)"},
		{"u", "Remove interception setup"},
	},
}

var generalKeys = HelpSection{
	Title: "General",
	Entries: []HelpEntry{
		{"E", "Export config JSON"},
		{"I", "Import config"},
		{"?", "This help"},
		{"q", "Quit"},
		{"esc", "Back / close"},
	},
}

// HelpColumns returns the three columns of help sections for the overlay.
func HelpColumns() [3][]HelpSection {
	return [3][]HelpSection{
		{navKeys, containerKeys},
		{monitorKeys, securityKeys, policyPanelKeys},
		{httpsKeys, auditPanelKeys, generalKeys},
	}
}
