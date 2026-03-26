package lxd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SeccompEvent represents a LXD seccomp notify event from the event stream.
// LXD emits these when a container syscall matches SCMP_ACT_NOTIFY.
type SeccompEvent struct {
	Container string    // container name
	Syscall   string    // syscall name (e.g. "ptrace", "mount")
	SyscallNr int       // syscall number
	PID       int       // PID inside the container
	Arch      string    // architecture string (e.g. "x86_64")
	Time      time.Time // event timestamp
	NotifyID  string    // LXD notify ID used to send the verdict
}

// SeccompVerdict is the operator's decision for a pending seccomp event.
type SeccompVerdict struct {
	Allow bool   // true = allow syscall, false = deny with EPERM
	Errno int    // errno to return on deny (default 1 = EPERM)
}

// SeccompEventCallback is called for each seccomp notify event received.
type SeccompEventCallback func(SeccompEvent)

// SeccompMonitor watches LXD seccomp events and delivers them to the TUI.
type SeccompMonitor struct {
	socketPath string
	cancel     context.CancelFunc
}

// NewSeccompMonitor creates a monitor for LXD seccomp notify events.
func NewSeccompMonitor(socketPath string) *SeccompMonitor {
	return &SeccompMonitor{socketPath: socketPath}
}

// Start begins listening for LXD seccomp events.
// Calls callback for each seccomp notify event. Blocks until context is cancelled.
func (m *SeccompMonitor) Start(ctx context.Context, callback SeccompEventCallback) error {
	ctx, m.cancel = context.WithCancel(ctx)

	conn, err := net.Dial("unix", m.socketPath)
	if err != nil {
		return fmt.Errorf("connect to LXD for seccomp monitor: %w", err)
	}
	defer conn.Close()

	// Subscribe to lifecycle + seccomp event types
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://unix/1.0/events?type=lifecycle,operation,seccomp", nil)
	if err != nil {
		return err
	}

	if err := req.Write(conn); err != nil {
		return fmt.Errorf("write seccomp event request: %w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return fmt.Errorf("read seccomp event response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("seccomp events endpoint returned %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		ev, ok := parseSeccompEvent(line)
		if !ok {
			continue
		}
		callback(ev)
	}

	if err := scanner.Err(); err != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return fmt.Errorf("seccomp event stream error: %w", err)
		}
	}

	return nil
}

// Stop stops the seccomp monitor.
func (m *SeccompMonitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
}

// SendVerdict sends the operator's allow/deny decision back to LXD for the given notify ID.
// LXD will unblock the container's syscall once it receives the verdict.
func (c *Client) SendSeccompVerdict(ctx context.Context, notifyID string, verdict SeccompVerdict) error {
	errno := verdict.Errno
	if !verdict.Allow && errno == 0 {
		errno = 1 // EPERM default
	}

	type verdictBody struct {
		Type  string `json:"type"`  // "allow" or "errno"
		Errno int    `json:"errno"` // only used when type == "errno"
	}

	body := verdictBody{}
	if verdict.Allow {
		body.Type = "allow"
	} else {
		body.Type = "errno"
		body.Errno = errno
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal seccomp verdict: %w", err)
	}

	path := fmt.Sprintf("/1.0/events/seccomp/%s", notifyID)
	resp, err := c.doPost(ctx, path, strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("send seccomp verdict: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("seccomp verdict rejected: status %d", resp.StatusCode)
	}
	return nil
}

// EnableSeccompNotify sets security.seccomp.notify = "true" on a container.
// This allows LXD to receive seccomp notify events from the container.
func (c *Client) EnableSeccompNotify(ctx context.Context, containerName string) error {
	return c.UpdateContainerConfig(ctx, containerName, map[string]string{
		"security.seccomp.notify": "true",
	})
}

// DisableSeccompNotify removes the seccomp notify setting from a container.
func (c *Client) DisableSeccompNotify(ctx context.Context, containerName string) error {
	return c.UpdateContainerConfig(ctx, containerName, map[string]string{
		"security.seccomp.notify": "",
	})
}

// ── LXD event JSON parsing ──────────────────────────────────────────────────

// rawLXDEvent is the top-level LXD event envelope (matches lifecycle monitor format).
type rawLXDEvent struct {
	Type      string          `json:"type"`
	Timestamp time.Time       `json:"timestamp"`
	Metadata  json.RawMessage `json:"metadata"`
}

// rawSeccompMeta is the metadata payload for type=="seccomp" events.
type rawSeccompMeta struct {
	Action   string `json:"action"`   // "seccomp-notify"
	Source   string `json:"source"`   // "/1.0/instances/<name>"
	NotifyID string `json:"notify-id"`
	Context  struct {
		Syscall   string `json:"syscall-name"`
		SyscallNr string `json:"syscall-nr"`
		Arch      string `json:"arch"`
		PID       string `json:"pid"`
	} `json:"context"`
}

// parseSeccompEvent decodes a raw LXD event line into a SeccompEvent.
// Returns (event, true) if the line is a valid seccomp notify event,
// or (zero, false) for any other event type or parse error.
func parseSeccompEvent(line []byte) (SeccompEvent, bool) {
	var raw rawLXDEvent
	if err := json.Unmarshal(line, &raw); err != nil {
		return SeccompEvent{}, false
	}
	if raw.Type != "seccomp" {
		return SeccompEvent{}, false
	}

	var meta rawSeccompMeta
	if err := json.Unmarshal(raw.Metadata, &meta); err != nil {
		return SeccompEvent{}, false
	}
	if meta.Action != "seccomp-notify" {
		return SeccompEvent{}, false
	}

	// Extract container name from source path "/1.0/instances/<name>"
	containerName := meta.Source
	prefix := "/1.0/instances/"
	if idx := strings.Index(containerName, prefix); idx >= 0 {
		containerName = containerName[idx+len(prefix):]
	}

	pid, _ := strconv.Atoi(meta.Context.PID)
	syscallNr, _ := strconv.Atoi(meta.Context.SyscallNr)

	return SeccompEvent{
		Container: containerName,
		Syscall:   meta.Context.Syscall,
		SyscallNr: syscallNr,
		PID:       pid,
		Arch:      meta.Context.Arch,
		Time:      raw.Timestamp,
		NotifyID:  meta.NotifyID,
	}, true
}
