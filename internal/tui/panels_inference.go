package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fourdoors/cella/internal/proxy"
)

// handleInferencePanel handles keypresses in the inference stats panel
func (a *App) handleInferencePanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		a.focus = panelSidebar
		return a, nil
	case "up", "k":
		if a.inferenceScroll > 0 {
			a.inferenceScroll--
		}
	case "down", "j":
		a.inferenceScroll++
	case "c":
		// Clear stats — would need a method on InferenceStats
		a.addEvent("📊 inference stats view refreshed")
	}
	return a, nil
}

// renderInferencePanel renders the inference stats panel
func (a App) renderInferencePanel() string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e"))
	bright := lipgloss.NewStyle().Foreground(lipgloss.Color("#e67e22"))
	blue := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#58a6ff"))
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("#27ae60"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("#e74c3c"))
	yellow := lipgloss.NewStyle().Foreground(lipgloss.Color("#f1c40f"))
	purple := lipgloss.NewStyle().Foreground(lipgloss.Color("#8e44ad"))

	if globalProxyServer == nil {
		return dim.Render("  Interception not active. Press Esc, then A → p to start.") + "\n"
	}

	stats := globalProxyServer.InferenceStats()
	if stats == nil {
		return dim.Render("  No inference stats available.") + "\n"
	}

	modelStats := stats.GetModelStats()
	recentReqs := stats.GetRecentRequests(30)

	var b strings.Builder

	// Title
	b.WriteString(blue.Render("📊 Inference Stats ◆") + "\n\n")

	if len(modelStats) == 0 && len(recentReqs) == 0 {
		b.WriteString(dim.Render("  No inference API calls recorded yet.") + "\n\n")
		b.WriteString(dim.Render("  Waiting for AI model API calls (OpenAI/Anthropic/Copilot)...") + "\n")
		b.WriteString(dim.Render("  Detected paths: /chat/completions, /v1/chat/completions,") + "\n")
		b.WriteString(dim.Render("  /v1/messages, /v1/completions, /v1/embeddings, /responses") + "\n")
		return b.String()
	}

	// Model overview table
	if len(modelStats) > 0 {
		b.WriteString(bright.Render("  Models") + "\n")
		b.WriteString(dim.Render("  " + strings.Repeat("─", 80)) + "\n")

		// Header
		b.WriteString(fmt.Sprintf("  %-30s %8s %8s %10s %10s %6s %6s %6s\n",
			blue.Render("MODEL"),
			dim.Render("REQS"),
			dim.Render("ERRORS"),
			dim.Render("TOK IN"),
			dim.Render("TOK OUT"),
			dim.Render("RPM"),
			dim.Render("RPH"),
			dim.Render("TPM"),
		))
		b.WriteString(dim.Render("  " + strings.Repeat("─", 80)) + "\n")

		for _, ms := range modelStats {
			// Color RPM by rate
			rpmStr := fmt.Sprintf("%d", ms.RPM)
			rpmStyle := green
			if ms.RPM > 30 {
				rpmStyle = yellow
			}
			if ms.RPM > 60 {
				rpmStyle = red
			}

			errStr := fmt.Sprintf("%d", ms.Errors)
			errStyle := dim
			if ms.Errors > 0 {
				errStyle = red
			}

			modelName := ms.Model
			if len(modelName) > 28 {
				modelName = modelName[:25] + "..."
			}

			b.WriteString(fmt.Sprintf("  %-30s %8d %8s %10s %10s %6s %6d %6s\n",
				purple.Render(modelName),
				ms.TotalRequests,
				errStyle.Render(errStr),
				green.Render(proxy.FormatTokens(ms.TotalTokensIn)),
				bright.Render(proxy.FormatTokens(ms.TotalTokensOut)),
				rpmStyle.Render(rpmStr),
				ms.RPH,
				green.Render(proxy.FormatTokens(ms.TPM)),
			))

			// Show last seen
			if !ms.LastSeen.IsZero() {
				ago := time.Since(ms.LastSeen).Truncate(time.Second)
				b.WriteString(dim.Render(fmt.Sprintf("  %30s last: %s ago\n", "", ago)))
			}
		}
		b.WriteString("\n")
	}

	// Recent requests
	if len(recentReqs) > 0 {
		b.WriteString(bright.Render("  Recent API Calls") + "\n")
		b.WriteString(dim.Render("  " + strings.Repeat("─", 80)) + "\n")

		// Show newest first
		visibleH := a.height - 20
		if visibleH < 5 {
			visibleH = 5
		}

		start := len(recentReqs) - visibleH
		if start < 0 {
			start = 0
		}

		for i := len(recentReqs) - 1; i >= start; i-- {
			req := recentReqs[i]

			statusIcon := green.Render("✅")
			if req.StatusCode >= 400 {
				statusIcon = red.Render("❌")
			}
			if req.Error != "" {
				statusIcon = red.Render("💥")
			}

			modelShort := req.Model
			if len(modelShort) > 20 {
				modelShort = modelShort[:17] + "..."
			}

			tokInfo := ""
			if req.TokensIn > 0 || req.TokensOut > 0 {
				tokInfo = fmt.Sprintf(" tok:%s→%s",
					proxy.FormatTokens(req.TokensIn),
					proxy.FormatTokens(req.TokensOut))
			}

			b.WriteString(fmt.Sprintf("  %s %s %s %s %s [%d]%s %s\n",
				dim.Render(req.Time.Format("15:04:05")),
				statusIcon,
				dim.Render(req.Container),
				purple.Render(modelShort),
				blue.Render(req.Path),
				req.StatusCode,
				green.Render(tokInfo),
				dim.Render(req.Latency.Truncate(time.Millisecond).String()),
			))
		}
	}

	return b.String()
}
