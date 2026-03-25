package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fourdoors/cella/internal/proxy"
)

// handleRoutingPanel handles keypresses in the inference routing panel
func (a *App) handleRoutingPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if a.routingInputMode {
		return a.handleRoutingInput(msg)
	}

	switch msg.String() {
	case "esc", "q":
		a.focus = panelSidebar
		return a, nil
	case "up", "k":
		if a.routingCursor > 0 {
			a.routingCursor--
		}
	case "down", "j":
		routes := a.getRoutes()
		if a.routingCursor < len(routes)-1 {
			a.routingCursor++
		}
	case "a":
		// Add new route — start input
		a.routingInputMode = true
		a.routingInputStep = 0
		a.routingInputBuf = ""
		a.routingNewRoute = proxy.InferenceRoute{Enabled: true}
		return a, nil
	case "enter", " ":
		// Toggle enable/disable selected route
		if globalProxyServer != nil {
			routes := a.getRoutes()
			if a.routingCursor < len(routes) {
				r := routes[a.routingCursor]
				r.Enabled = !r.Enabled
				globalProxyServer.Routes().Add(r)
				status := "disabled"
				if r.Enabled {
					status = "enabled"
				}
				a.addEvent(fmt.Sprintf("🔀 route %s → %s %s", r.SourceDomain, r.BackendHost, status))
			}
		}
		return a, nil
	case "d":
		// Delete selected route
		if globalProxyServer != nil {
			routes := a.getRoutes()
			if a.routingCursor < len(routes) {
				r := routes[a.routingCursor]
				globalProxyServer.Routes().Remove(r.SourceDomain)
				a.addEvent(fmt.Sprintf("🗑 route removed: %s", r.SourceDomain))
				if a.routingCursor > 0 {
					a.routingCursor--
				}
			}
		}
		return a, nil
	case "p":
		// Load presets
		if globalProxyServer != nil {
			for _, preset := range proxy.PresetRoutes() {
				globalProxyServer.Routes().Add(preset)
			}
			a.addEvent("🔀 loaded preset routes (all disabled by default)")
			return a, a.setFlash("✅ Preset routes loaded — use Enter to enable")
		}
	case "S":
		// Save routes to file
		if globalProxyServer != nil {
			filename := "/tmp/cella-routes.json"
			if err := globalProxyServer.Routes().SaveToFile(filename); err != nil {
				return a, a.setFlash(fmt.Sprintf("❌ save: %v", err))
			}
			return a, a.setFlash("✅ Routes saved to " + filename)
		}
	}
	return a, nil
}

// handleRoutingInput handles input for adding a new route (4-step wizard)
func (a *App) handleRoutingInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		a.routingInputMode = false
		a.routingInputBuf = ""
		return a, nil
	case "enter":
		switch a.routingInputStep {
		case 0: // source domain
			a.routingNewRoute.SourceDomain = a.routingInputBuf
			a.routingInputStep = 1
			a.routingInputBuf = ""
		case 1: // backend host
			a.routingNewRoute.BackendHost = a.routingInputBuf
			a.routingInputStep = 2
			a.routingInputBuf = ""
		case 2: // scheme (https/http)
			s := strings.ToLower(a.routingInputBuf)
			if s == "" || s == "https" {
				a.routingNewRoute.BackendScheme = "https"
			} else {
				a.routingNewRoute.BackendScheme = "http"
			}
			a.routingInputStep = 3
			a.routingInputBuf = ""
		case 3: // note
			a.routingNewRoute.Note = a.routingInputBuf
			// Save the route
			if globalProxyServer != nil && a.routingNewRoute.SourceDomain != "" && a.routingNewRoute.BackendHost != "" {
				globalProxyServer.Routes().Add(a.routingNewRoute)
				a.addEvent(fmt.Sprintf("🔀 route added: %s → %s", a.routingNewRoute.SourceDomain, a.routingNewRoute.BackendHost))
			}
			a.routingInputMode = false
			a.routingInputBuf = ""
		}
		return a, nil
	case "backspace":
		if len(a.routingInputBuf) > 0 {
			a.routingInputBuf = a.routingInputBuf[:len(a.routingInputBuf)-1]
		}
	default:
		k := msg.String()
		if len(k) == 1 {
			a.routingInputBuf += k
		}
	}
	return a, nil
}

// getRoutes returns the current route list
func (a App) getRoutes() []proxy.InferenceRoute {
	if globalProxyServer == nil {
		return nil
	}
	return globalProxyServer.Routes().List()
}

// renderRoutingPanel renders the inference routing panel
func (a App) renderRoutingPanel() string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e"))
	bright := lipgloss.NewStyle().Foreground(lipgloss.Color("#e67e22"))
	blue := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#58a6ff"))
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("#27ae60"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("#e74c3c"))
	purple := lipgloss.NewStyle().Foreground(lipgloss.Color("#8e44ad"))
	selected := lipgloss.NewStyle().Background(lipgloss.Color("#1a2332")).Foreground(lipgloss.Color("#f0f6fc"))

	var b strings.Builder

	// Title
	b.WriteString(blue.Render("🔀 Inference Routing ◆") + "\n\n")

	// Input wizard
	if a.routingInputMode {
		steps := []string{
			"Source domain (e.g., api.openai.com):",
			"Backend host:port (e.g., localhost:11434):",
			"Scheme [https/http] (Enter=https):",
			"Note (optional):",
		}
		if a.routingInputStep < len(steps) {
			b.WriteString(bright.Render("  Adding route — step "+fmt.Sprintf("%d", a.routingInputStep+1)+"/4") + "\n\n")
			b.WriteString(dim.Render("  "+steps[a.routingInputStep]) + "\n")
			b.WriteString("  > " + a.routingInputBuf + "█\n\n")
			b.WriteString(dim.Render("  Enter to confirm · Esc to cancel") + "\n")
		}
		return b.String()
	}

	// Routes table
	routes := a.getRoutes()

	if globalProxyServer == nil {
		b.WriteString(dim.Render("  Interception not active. Press Esc, then A → p to start.") + "\n\n")
		b.WriteString(dim.Render("  Routing requires MITM interception.") + "\n")
		return b.String()
	}

	if len(routes) == 0 {
		b.WriteString(dim.Render("  No routes configured.") + "\n\n")
		b.WriteString(dim.Render("  Press ") + bright.Render("p") + dim.Render(" to load preset routes (OpenAI/Anthropic/Copilot/Gemini → Ollama/NVIDIA)") + "\n")
		b.WriteString(dim.Render("  Press ") + bright.Render("a") + dim.Render(" to add a custom route") + "\n")
		return b.String()
	}

	sep := dim.Render("  " + strings.Repeat("─", 80))
	b.WriteString(sep + "\n")
	hdr := fmt.Sprintf("  %-3s %-30s → %-25s %-8s %s",
		"", "SOURCE DOMAIN", "BACKEND", "SCHEME", "NOTE")
	b.WriteString(dim.Render(hdr) + "\n")
	b.WriteString(sep + "\n")

	for i, r := range routes {
		enabledIcon := red.Render("○")
		rowStyle := dim
		if r.Enabled {
			enabledIcon = green.Render("●")
			rowStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#e6edf3"))
		}

		backend := r.BackendHost
		if len(backend) > 23 {
			backend = backend[:20] + "..."
		}

		note := r.Note
		if len(note) > 25 {
			note = note[:22] + "..."
		}

		line := fmt.Sprintf("  %s %-30s → %-25s %-8s %s",
			enabledIcon,
			purple.Render(r.SourceDomain),
			rowStyle.Render(backend),
			dim.Render(r.BackendScheme),
			dim.Render(note),
		)

		if i == a.routingCursor {
			// Highlight selected
			line = "▸" + line[1:]
			b.WriteString(selected.Render(line) + "\n")
		} else {
			b.WriteString(line + "\n")
		}

		// Show path prefix if set
		if r.PathPrefix != "" {
			b.WriteString(dim.Render(fmt.Sprintf("  %3s  path prefix: %s", "", r.PathPrefix)) + "\n")
		}
		if r.ModelOverride != "" {
			b.WriteString(dim.Render(fmt.Sprintf("  %3s  model → %s", "", r.ModelOverride)) + "\n")
		}
	}

	b.WriteString(sep + "\n\n")
	b.WriteString(dim.Render("  Enter/Space: toggle · a: add · d: delete · p: presets · S: save") + "\n")

	return b.String()
}
