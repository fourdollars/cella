package lxd

import (
	"context"
)

// Event represents an LXD event
type Event struct {
	Type      string // lifecycle, logging, operation
	Timestamp string
	Container string
	Action    string
	Message   string
}

// EventHandler processes incoming events
type EventHandler func(Event)

// Monitor watches LXD events via /1.0/events
type Monitor struct {
	client  *Client
	handler EventHandler
	cancel  context.CancelFunc
}

// NewMonitor creates an event monitor
func NewMonitor(client *Client, handler EventHandler) *Monitor {
	return &Monitor{
		client:  client,
		handler: handler,
	}
}

// Start begins listening for LXD events
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)

	// TODO: use real LXD events API
	// listener, err := m.client.conn.GetEvents()
	// listener.AddHandler([]string{"lifecycle"}, func(event api.Event) {
	//     m.handler(Event{...})
	// })

	<-ctx.Done()
	return ctx.Err()
}

// Stop stops the event monitor
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
}
