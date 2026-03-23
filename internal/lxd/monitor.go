package lxd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Event represents a parsed LXD event
type Event struct {
	Type      string    `json:"type"`      // lifecycle, logging, operation
	Timestamp time.Time `json:"timestamp"`
	Metadata  EventMeta `json:"metadata"`
}

// EventMeta holds event-specific metadata
type EventMeta struct {
	Action  string                 `json:"action"`  // e.g. instance-started, instance-stopped
	Source  string                 `json:"source"`  // e.g. /1.0/instances/mycontainer
	Context map[string]interface{} `json:"context"`
}

// EventCallback is called for each received event
type EventCallback func(Event)

// Monitor watches LXD events via /1.0/events SSE endpoint
type Monitor struct {
	socketPath string
	cancel     context.CancelFunc
}

// NewMonitor creates a new event monitor
func NewMonitor(socketPath string) *Monitor {
	return &Monitor{socketPath: socketPath}
}

// Start begins listening for LXD lifecycle events.
// Calls the callback for each event. Blocks until context is cancelled.
func (m *Monitor) Start(ctx context.Context, callback EventCallback) error {
	ctx, m.cancel = context.WithCancel(ctx)

	conn, err := net.Dial("unix", m.socketPath)
	if err != nil {
		return fmt.Errorf("connect to LXD: %w", err)
	}
	defer conn.Close()

	// Send HTTP request for events
	req, err := http.NewRequestWithContext(ctx, "GET",
		"http://unix/1.0/events?type=lifecycle,operation", nil)
	if err != nil {
		return err
	}

	if err := req.Write(conn); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	// Read the HTTP response header
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("events endpoint returned %d", resp.StatusCode)
	}

	// Stream JSON events (one per line, newline-delimited JSON)
	scanner := bufio.NewScanner(reader)
	// Increase buffer for large events
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

		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue // skip unparseable events
		}

		callback(ev)
	}

	if err := scanner.Err(); err != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return fmt.Errorf("event stream error: %w", err)
		}
	}

	return nil
}

// Stop stops the event monitor
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
}

// FormatEvent creates a human-readable string from an event
func FormatEvent(ev Event) string {
	ts := ev.Timestamp.UTC().Add(8 * time.Hour).Format("15:04:05")
	action := ev.Metadata.Action

	// Extract container name from source path
	name := ev.Metadata.Source
	if idx := len("/1.0/instances/"); len(name) > idx {
		name = name[idx:]
	}

	switch {
	case action == "instance-started":
		return fmt.Sprintf("%s ▶ %s started", ts, name)
	case action == "instance-stopped":
		return fmt.Sprintf("%s ■ %s stopped", ts, name)
	case action == "instance-paused":
		return fmt.Sprintf("%s ⏸ %s paused", ts, name)
	case action == "instance-resumed":
		return fmt.Sprintf("%s ▶ %s resumed", ts, name)
	case action == "instance-created":
		return fmt.Sprintf("%s ✚ %s created", ts, name)
	case action == "instance-deleted":
		return fmt.Sprintf("%s ✖ %s deleted", ts, name)
	case action == "instance-restarted":
		return fmt.Sprintf("%s ↻ %s restarted", ts, name)
	case action == "instance-shutdown":
		return fmt.Sprintf("%s ⏻ %s shutdown", ts, name)
	case action == "instance-exec":
		return fmt.Sprintf("%s ⚡ %s exec", ts, name)
	default:
		if name != "" {
			return fmt.Sprintf("%s %s %s", ts, action, name)
		}
		return fmt.Sprintf("%s %s", ts, action)
	}
}
