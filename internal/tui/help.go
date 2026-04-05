package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ── Help overlay ──

func (a App) renderHelpOverlay() string {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorBlue)

	secStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorYellow)

	keyStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorGreen).
		Width(6)

	descStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#c9d1d9"))

	renderSection := func(title string, keys [][]string) string {
		var b strings.Builder
		b.WriteString(secStyle.Render(title) + "\n")
		for _, h := range keys {
			b.WriteString(fmt.Sprintf(" %s %s\n", keyStyle.Render(h[0]), descStyle.Render(h[1])))
		}
		return b.String()
	}

	// Column 1: Navigation + Container Actions
	col1 := renderSection("Navigation", [][]string{
		{"↑/k", "Move up"},
		{"↓/j", "Move down"},
		{"1/2/3", "Sort: name/cpu/mem"},
		{"f", "Filter runtime"},
		{"/", "Search by name"},
		{"g", "Goto container #"},
		{"Ctrl+L", "Clear search"},
	})
	col1 += "\n"
	col1 += renderSection("Container", [][]string{
		{"s", "Start"},
		{"x", "Stop"},
		{"p", "Pause/Unpause"},
		{"e", "Exec command"},
		{"l", "Logs (stream)"},
		{"+", "Create new"},
		{"d", "Delete (stopped)"},
	})

	// Column 2: Panels
	col2 := renderSection("Monitor Panels", [][]string{
		{"w", "Network"},
		{"r", "Resource limits"},
		{"n", "Snapshots/Clone"},
		{"V", "Recent events"},
		{"M", "Inference stats (RPM/TPM/cost)"},
		{"R", "Inference routing"},
	})
	col2 += "\n"
	col2 += renderSection("Security Panels", [][]string{
		{"P", "Policy (seccomp/egress/AppArmor/flags)"},
		{"Z", "Toggle syscall blocking (LXD BPF deny)"},
		{"D", "DNS monitor"},
		{"t", "Start syscall trace (bpftrace)"},
		{"T", "Stop syscall trace"},
		{"G", "Generate seccomp profile from trace"},
		{"S", "Save seccomp JSON"},
	})
	col2 += "\n"
	col2 += renderSection("In Policy Panel", [][]string{
		{"[b]", "Toggle boot.autostart"},
		{"[P]", "Toggle security.privileged"},
		{"[N]", "Toggle security.nesting"},
		{"[V]", "Toggle security.devlxd"},
		{"[M]", "Toggle idmap.isolated"},
		{"1-3", "Apply seccomp profile"},
		{"4-7", "Apply AppArmor profile"},
		{"a/d", "Add/remove egress rule"},
	})

	// Column 3: HTTPS Interception + General
	col3 := renderSection("HTTPS Interception", [][]string{
		{"A", "API audit log + interception setup"},
		{"y", "Approve request (once)"},
		{"Y", "Approve request (always)"},
		{"n", "Deny request (once)"},
		{"N", "Deny request (always)"},
	})
	col3 += "\n"
	col3 += renderSection("In Audit Panel", [][]string{
		{"/", "Filter text"},
		{"f", "Filter by status"},
		{"L", "Show allow/deny lists"},
		{"S", "Export audit JSON"},
		{"c", "Clear log"},
		{"p", "Setup HTTPS interception (container)"},
		{"u", "Remove interception setup"},
	})
	col3 += "\n"
	col3 += renderSection("General", [][]string{
		{"E", "Export config JSON"},
		{"I", "Import config"},
		{"?", "This help"},
		{"q", "Quit"},
		{"esc", "Back / close"},
	})

	// Render columns side by side
	colWidth := (a.width - 12) / 3
	if colWidth < 24 {
		colWidth = 24
	}
	if colWidth > 32 {
		colWidth = 32
	}

	colStyle := lipgloss.NewStyle().Width(colWidth).PaddingRight(1)

	columns := lipgloss.JoinHorizontal(lipgloss.Top,
		colStyle.Render(col1),
		colStyle.Render(col2),
		colStyle.Render(col3),
	)

	title := titleStyle.Render("📖 cella — Keyboard Shortcuts")
	hint := lipgloss.NewStyle().Foreground(ColorDim).Italic(true).
		Render("Press any key to close")

	content := title + "\n\n" + columns + "\n" + hint

	overlay := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBlue).
		Padding(1, 2).
		Render(content)

	return lipgloss.Place(a.width, a.height, lipgloss.Center, lipgloss.Center, overlay)
}
