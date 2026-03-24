package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── Network panel handler ──

func (a App) handleNetworkPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		a.focus = a.prevFocus
		return a, nil
	case "r":
		if a.netTarget != "" {
			return a, fetchNetInfo(a.runtimeFor(a.netTarget), a.netTarget, a.containerRuntime(a.netTarget))
		}
	}
	return a, nil
}

// ── Network panel render ──

func (a App) renderNetworkPanel() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render(fmt.Sprintf("🌐 Network — %s ◆", a.netTarget)) + "\n\n")

	m := a.getMetric(a.netTarget)

	// RX / TX graphs
	rxMax := int64(1)
	txMax := int64(1)
	for _, v := range a.netRxHist {
		if v > rxMax {
			rxMax = v
		}
	}
	for _, v := range a.netTxHist {
		if v > txMax {
			txMax = v
		}
	}

	b.WriteString(SectionHeaderStyle.Render("Traffic") + "\n")
	b.WriteString(fmt.Sprintf("  ↓ RX: %-10s  ↑ TX: %s\n", formatBytes(m.NetRxRate)+"/s", formatBytes(m.NetTxRate)+"/s"))

	barWidth := a.width - 45
	if barWidth < 20 {
		barWidth = 20
	}
	if barWidth > 60 {
		barWidth = 60
	}

	rxPct := float64(m.NetRxRate) / float64(rxMax) * 100
	if m.NetRxRate == 0 {
		rxPct = 0
	}
	txPct := float64(m.NetTxRate) / float64(txMax) * 100
	if m.NetTxRate == 0 {
		txPct = 0
	}

	b.WriteString(fmt.Sprintf("  RX %s\n", renderProgressBar(rxPct, 100, barWidth)))
	b.WriteString(fmt.Sprintf("  TX %s\n\n", renderProgressBar(txPct, 100, barWidth)))

	// Listening ports
	b.WriteString(SectionHeaderStyle.Render(fmt.Sprintf("Listening Ports (%d)", len(a.netListens))) + "\n")
	if len(a.netListens) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).Render("  No listening ports found") + "\n")
	} else {
		for _, l := range a.netListens {
			b.WriteString(fmt.Sprintf("  %s\n", l))
		}
	}
	b.WriteString("\n")

	// Active Connections
	b.WriteString(SectionHeaderStyle.Render(fmt.Sprintf("Active Connections (%d)", len(a.netConns))) + "\n")
	if len(a.netConns) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).Render("  No active connections found") + "\n")
	} else {
		limit := 15
		for i, c := range a.netConns {
			if i >= limit {
				b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).Render(fmt.Sprintf("  ... and %d more", len(a.netConns)-limit)) + "\n")
				break
			}
			b.WriteString(fmt.Sprintf("  %s\n", c))
		}
	}

	return b.String()
}
