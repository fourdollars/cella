package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fourdoors/cella/internal/lxd"
)

// Panel focus
type panel int

const (
	panelSidebar panel = iota
	panelDashboard
)

const tickInterval = time.Second

type tickMsg time.Time
type containersMsg []lxd.ContainerInfo
type errMsg error

// App is the main TUI model
type App struct {
	client     *lxd.Client
	containers []lxd.ContainerInfo
	selected   int
	focus      panel
	width      int
	height     int
	ready      bool
	err        error
	events     []string
	lastUpdate time.Time
}

// NewApp creates the initial app model
func NewApp() App {
	client, err := lxd.NewClient("")
	return App{
		client: client,
		err:    err,
		events: []string{},
	}
}

func (a App) Init() tea.Cmd {
	return tea.Batch(fetchContainers(a.client), tea.ClearScreen)
}

func fetchContainers(client *lxd.Client) tea.Cmd {
	return func() tea.Msg {
		if client == nil {
			return errMsg(fmt.Errorf("no LXD client"))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		containers, err := client.ListContainers(ctx)
		if err != nil {
			return errMsg(err)
		}
		return containersMsg(containers)
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(tickInterval, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (a App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return a, tea.Quit
		case "up", "k":
			if a.focus == panelSidebar && a.selected > 0 {
				a.selected--
			}
		case "down", "j":
			if a.focus == panelSidebar && a.selected < len(a.containers)-1 {
				a.selected++
			}
		case "tab":
			if a.focus == panelSidebar {
				a.focus = panelDashboard
			} else {
				a.focus = panelSidebar
			}
		case "s":
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				if c.Status == "Stopped" {
					go func() {
						ctx := context.Background()
						_ = a.client.StartContainer(ctx, c.Name)
					}()
					a.events = append(a.events, fmt.Sprintf("%s ▶ starting %s...", time.Now().Format("15:04:05"), c.Name))
				}
			}
		case "p":
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				if c.Status == "Running" {
					go func() {
						ctx := context.Background()
						_ = a.client.FreezeContainer(ctx, c.Name)
					}()
					a.events = append(a.events, fmt.Sprintf("%s ⏸ freezing %s...", time.Now().Format("15:04:05"), c.Name))
				}
			}
		case "x":
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				if c.Status == "Running" {
					go func() {
						ctx := context.Background()
						_ = a.client.StopContainer(ctx, c.Name)
					}()
					a.events = append(a.events, fmt.Sprintf("%s ■ stopping %s...", time.Now().Format("15:04:05"), c.Name))
				}
			}
		}

	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
		a.ready = true

	case containersMsg:
		a.containers = []lxd.ContainerInfo(msg)
		a.lastUpdate = time.Now()
		a.err = nil
		if a.selected >= len(a.containers) {
			a.selected = len(a.containers) - 1
		}
		if a.selected < 0 {
			a.selected = 0
		}
		return a, tickCmd()

	case errMsg:
		a.err = msg
		return a, tickCmd()

	case tickMsg:
		return a, fetchContainers(a.client)
	}

	return a, nil
}

func (a App) View() string {
	if !a.ready {
		return "\n  Loading cella...\n"
	}

	if a.err != nil && len(a.containers) == 0 {
		return fmt.Sprintf("\n  ❌ Error: %v\n\n  Make sure LXD is running and accessible.\n  Press q to quit.\n", a.err)
	}

	// Header
	now := time.Now().UTC().Add(8 * time.Hour)
	running := 0
	for _, c := range a.containers {
		if c.Status == "Running" {
			running++
		}
	}
	header := lipgloss.NewStyle().
		Foreground(ColorBlue).Bold(true).
		Render(fmt.Sprintf(" 📡 cella  Containers (%d/%d running)", running, len(a.containers))) +
		lipgloss.NewStyle().Foreground(ColorDim).
			Render(fmt.Sprintf("  🕐 %s", now.Format("2006-01-02 15:04 UTC+8")))

	// Sidebar
	sidebar := a.renderSidebar()

	// Main dashboard
	dashboard := a.renderDashboard()

	// Status bar
	statusStr := ""
	if a.selected < len(a.containers) {
		c := a.containers[a.selected]
		if c.Status == "Running" {
			statusStr = fmt.Sprintf("Container: %s | IP: %s | PIDs: %d | Profiles: %s",
				c.Name, c.IP, c.PIDs, strings.Join(c.Profiles, ","))
		} else {
			statusStr = fmt.Sprintf("Container: %s [%s]", c.Name, strings.ToLower(c.Status))
		}
	}
	if a.err != nil {
		statusStr += fmt.Sprintf(" | ⚠ %v", a.err)
	}
	statusBar := StatusBarStyle.Width(a.width).Render(statusStr)

	// Layout
	sideW := 32
	mainW := a.width - sideW - 4
	if mainW < 40 {
		mainW = 40
	}
	contentH := a.height - 4
	if contentH < 10 {
		contentH = 10
	}

	sidebarStyled := SidebarStyle.Width(sideW).Height(contentH).Render(sidebar)
	dashboardStyled := MainPanelStyle.Width(mainW).Height(contentH).Render(dashboard)

	body := lipgloss.JoinHorizontal(lipgloss.Top, sidebarStyled, dashboardStyled)

	return lipgloss.JoinVertical(lipgloss.Left, header, body, statusBar)
}

func (a App) renderSidebar() string {
	var b strings.Builder

	focusIndicator := ""
	if a.focus == panelSidebar {
		focusIndicator = " ◆"
	}
	b.WriteString(TitleStyle.Render("Containers"+focusIndicator) + "\n\n")

	for i, c := range a.containers {
		indicator := "○"
		style := StoppedContainerStyle
		if c.Status == "Running" {
			indicator = "●"
			style = ActiveContainerStyle
		} else if c.Status == "Frozen" {
			indicator = "◉"
			style = lipgloss.NewStyle().Foreground(ColorYellow)
		}

		name := c.Name
		if len(name) > 16 {
			name = name[:14] + ".."
		}

		memStr := ""
		if c.MemoryCur > 0 {
			memStr = fmt.Sprintf("[%s]", formatBytes(c.MemoryCur))
		} else {
			memStr = fmt.Sprintf("[%s]", strings.ToLower(c.Status))
		}

		line := fmt.Sprintf(" %s %-16s %9s", indicator, name, memStr)

		if i == a.selected {
			line = SelectedContainerStyle.Render(fmt.Sprintf("▸%s", line[1:]))
		} else {
			line = style.Render(line)
		}

		b.WriteString(line + "\n")
	}

	b.WriteString("\n")
	b.WriteString(SectionHeaderStyle.Render("Keybinds") + "\n\n")
	helps := [][]string{
		{"↑/↓", "navigate"},
		{"s", "start"},
		{"p", "pause/freeze"},
		{"x", "stop"},
		{"e", "exec"},
		{"tab", "switch panel"},
		{"q", "quit"},
	}
	for _, h := range helps {
		b.WriteString(fmt.Sprintf(" %s %s\n",
			HelpKeyStyle.Render(fmt.Sprintf("[%s]", h[0])),
			HelpDescStyle.Render(h[1]),
		))
	}

	return b.String()
}

func (a App) renderDashboard() string {
	if len(a.containers) == 0 {
		return lipgloss.NewStyle().Foreground(ColorDim).Render("\n  No containers found\n")
	}

	c := a.containers[a.selected]
	var b strings.Builder

	focusIndicator := ""
	if a.focus == panelDashboard {
		focusIndicator = " ◆"
	}
	title := TitleStyle.Render(fmt.Sprintf("─ %s%s ", c.Name, focusIndicator))
	b.WriteString(title + "\n")

	if c.Status != "Running" {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).Render(
			fmt.Sprintf("\n  Container is %s\n\n  Press [s] to start", strings.ToLower(c.Status))))
		return b.String()
	}

	// Resource metrics
	b.WriteString(SectionHeaderStyle.Render("Resources") + "\n\n")

	// Memory bar
	memMax := c.MemoryMax
	if memMax <= 0 {
		memMax = 1 << 30 // default 1GB if unknown
	}
	memPct := float64(c.MemoryCur) / float64(memMax) * 100
	b.WriteString(renderMetric("MEM", memPct, 100, ColorBlue) +
		fmt.Sprintf("  %s / %s", formatBytes(c.MemoryCur), formatBytes(memMax)) + "\n")

	// Network
	b.WriteString(fmt.Sprintf(" %s ↑ %s  ↓ %s (cumulative)\n",
		MetricLabelStyle.Render("NET"),
		formatBytes(c.NetTxBytes), formatBytes(c.NetRxBytes)))

	// Disk
	if c.DiskUsage > 0 {
		b.WriteString(fmt.Sprintf(" %s %s used\n",
			MetricLabelStyle.Render("DISK"),
			formatBytes(c.DiskUsage)))
	}

	// PIDs
	b.WriteString(fmt.Sprintf(" %s %d\n",
		MetricLabelStyle.Render("PIDs"),
		c.PIDs))

	// IP / Type
	b.WriteString(fmt.Sprintf(" %s %s\n",
		MetricLabelStyle.Render("IP"),
		c.IP))
	b.WriteString(fmt.Sprintf(" %s %s\n",
		MetricLabelStyle.Render("TYPE"),
		c.Type))

	// Events
	if len(a.events) > 0 {
		b.WriteString("\n" + SectionHeaderStyle.Render("Events") + "\n\n")
		start := len(a.events) - 10
		if start < 0 {
			start = 0
		}
		for _, ev := range a.events[start:] {
			style := EventNormalStyle
			if strings.Contains(ev, "⚠") {
				style = EventWarnStyle
			}
			b.WriteString(" " + style.Render(ev) + "\n")
		}
	}

	return b.String()
}

func renderMetric(label string, value, max float64, color lipgloss.Color) string {
	pct := value / max
	if pct > 1 {
		pct = 1
	}
	barWidth := 20
	filled := int(pct * float64(barWidth))
	bar := lipgloss.NewStyle().Foreground(color).Render(strings.Repeat("█", filled)) +
		lipgloss.NewStyle().Foreground(ColorDim).Render(strings.Repeat("░", barWidth-filled))

	return fmt.Sprintf(" %s %s  %.1f%%",
		MetricLabelStyle.Render(label),
		bar,
		value)
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fGB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}
