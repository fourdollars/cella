package tui

import (
	"context"
	"fmt"
	"sort"
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

const tickInterval = 2 * time.Second
const sparklineLen = 30

type tickMsg time.Time
type containersMsg []lxd.ContainerInfo
type errMsg error

// ContainerMetrics holds computed metrics for a container
type ContainerMetrics struct {
	CPUPercent float64
	NetRxRate  int64 // bytes/s
	NetTxRate  int64 // bytes/s
	MemPercent float64
	CPUHist    []float64 // sparkline history
	MemHist    []float64
}

// prevState tracks previous poll values for delta computation
type prevState struct {
	cpuNs    int64
	netRx    int64
	netTx    int64
	polledAt time.Time
}

// App is the main TUI model
type App struct {
	client     *lxd.Client
	containers []lxd.ContainerInfo
	metrics    map[string]*ContainerMetrics
	prev       map[string]*prevState
	selected   int
	focus      panel
	width      int
	height     int
	ready      bool
	err        error
	events     []string
	lastUpdate time.Time
	sortBy     string // "name", "cpu", "mem"
}

// NewApp creates the initial app model
func NewApp() App {
	client, err := lxd.NewClient("")
	return App{
		client:  client,
		err:     err,
		metrics: make(map[string]*ContainerMetrics),
		prev:    make(map[string]*prevState),
		events:  []string{},
		sortBy:  "name",
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
		case "1":
			a.sortBy = "name"
			a.sortContainers()
		case "2":
			a.sortBy = "cpu"
			a.sortContainers()
		case "3":
			a.sortBy = "mem"
			a.sortContainers()
		case "s":
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				if c.Status == "Stopped" {
					go func() {
						ctx := context.Background()
						_ = a.client.StartContainer(ctx, c.Name)
					}()
					a.addEvent(fmt.Sprintf("▶ starting %s...", c.Name))
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
					a.addEvent(fmt.Sprintf("⏸ freezing %s...", c.Name))
				} else if c.Status == "Frozen" {
					go func() {
						ctx := context.Background()
						_ = a.client.UnfreezeContainer(ctx, c.Name)
					}()
					a.addEvent(fmt.Sprintf("▶ unfreezing %s...", c.Name))
				}
			}
		case "x":
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				if c.Status == "Running" || c.Status == "Frozen" {
					go func() {
						ctx := context.Background()
						_ = a.client.StopContainer(ctx, c.Name)
					}()
					a.addEvent(fmt.Sprintf("■ stopping %s...", c.Name))
				}
			}
		}

	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
		a.ready = true

	case containersMsg:
		now := time.Now()
		newContainers := []lxd.ContainerInfo(msg)

		// Compute deltas
		for i := range newContainers {
			c := &newContainers[i]
			name := c.Name

			if _, ok := a.metrics[name]; !ok {
				a.metrics[name] = &ContainerMetrics{
					CPUHist: make([]float64, 0, sparklineLen),
					MemHist: make([]float64, 0, sparklineLen),
				}
			}
			m := a.metrics[name]

			if c.Status == "Running" {
				if prev, ok := a.prev[name]; ok && !prev.polledAt.IsZero() {
					dt := now.Sub(prev.polledAt)
					if dt > 0 {
						dCPU := c.CPUUsage - prev.cpuNs
						if dCPU < 0 {
							dCPU = 0
						}
						m.CPUPercent = float64(dCPU) / float64(dt.Nanoseconds()) * 100.0

						dRx := c.NetRxBytes - prev.netRx
						dTx := c.NetTxBytes - prev.netTx
						if dRx < 0 {
							dRx = 0
						}
						if dTx < 0 {
							dTx = 0
						}
						dtSec := dt.Seconds()
						if dtSec > 0 {
							m.NetRxRate = int64(float64(dRx) / dtSec)
							m.NetTxRate = int64(float64(dTx) / dtSec)
						}
					}
				}

				if c.MemoryMax > 0 {
					m.MemPercent = float64(c.MemoryCur) / float64(c.MemoryMax) * 100
				}

				m.CPUHist = appendHist(m.CPUHist, m.CPUPercent, sparklineLen)
				m.MemHist = appendHist(m.MemHist, m.MemPercent, sparklineLen)

				a.prev[name] = &prevState{
					cpuNs:    c.CPUUsage,
					netRx:    c.NetRxBytes,
					netTx:    c.NetTxBytes,
					polledAt: now,
				}
			} else {
				m.CPUPercent = 0
				m.MemPercent = 0
				m.NetRxRate = 0
				m.NetTxRate = 0
			}
		}

		a.containers = newContainers
		a.sortContainers()
		a.lastUpdate = now
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

func appendHist(hist []float64, val float64, maxLen int) []float64 {
	hist = append(hist, val)
	if len(hist) > maxLen {
		hist = hist[len(hist)-maxLen:]
	}
	return hist
}

func (a *App) sortContainers() {
	switch a.sortBy {
	case "cpu":
		sort.Slice(a.containers, func(i, j int) bool {
			mi := a.getMetric(a.containers[i].Name)
			mj := a.getMetric(a.containers[j].Name)
			return mi.CPUPercent > mj.CPUPercent
		})
	case "mem":
		sort.Slice(a.containers, func(i, j int) bool {
			return a.containers[i].MemoryCur > a.containers[j].MemoryCur
		})
	default:
		sort.Slice(a.containers, func(i, j int) bool {
			si := statusOrder(a.containers[i].Status)
			sj := statusOrder(a.containers[j].Status)
			if si != sj {
				return si < sj
			}
			return a.containers[i].Name < a.containers[j].Name
		})
	}
}

func statusOrder(s string) int {
	switch s {
	case "Running":
		return 0
	case "Frozen":
		return 1
	default:
		return 2
	}
}

func (a *App) getMetric(name string) *ContainerMetrics {
	if m, ok := a.metrics[name]; ok {
		return m
	}
	return &ContainerMetrics{}
}

func (a *App) addEvent(msg string) {
	ts := time.Now().UTC().Add(8 * time.Hour).Format("15:04:05")
	a.events = append(a.events, fmt.Sprintf("%s %s", ts, msg))
	if len(a.events) > 50 {
		a.events = a.events[len(a.events)-50:]
	}
}

func (a App) View() string {
	if !a.ready {
		return "\n  Loading cella...\n"
	}

	if a.err != nil && len(a.containers) == 0 {
		return fmt.Sprintf("\n  ❌ Error: %v\n\n  Make sure LXD is running and accessible.\n  Press q to quit.\n", a.err)
	}

	now := time.Now().UTC().Add(8 * time.Hour)
	running := 0
	var totalMem int64
	var totalCPU float64
	for _, c := range a.containers {
		if c.Status == "Running" {
			running++
			totalMem += c.MemoryCur
			totalCPU += a.getMetric(c.Name).CPUPercent
		}
	}
	header := lipgloss.NewStyle().
		Foreground(ColorBlue).Bold(true).
		Render(fmt.Sprintf(" 📡 cella")) +
		lipgloss.NewStyle().Foreground(ColorSubtle).
			Render(fmt.Sprintf("  %d/%d running", running, len(a.containers))) +
		lipgloss.NewStyle().Foreground(ColorDim).
			Render(fmt.Sprintf("  CPU Σ%.1f%%  MEM Σ%s", totalCPU, formatBytes(totalMem))) +
		lipgloss.NewStyle().Foreground(ColorDim).
			Render(fmt.Sprintf("  🕐 %s", now.Format("15:04:05"))) +
		lipgloss.NewStyle().Foreground(ColorDim).
			Render(fmt.Sprintf("  sort:[%s]", a.sortBy))

	sidebar := a.renderSidebar()
	dashboard := a.renderDashboard()

	statusStr := ""
	if a.selected < len(a.containers) {
		c := a.containers[a.selected]
		m := a.getMetric(c.Name)
		if c.Status == "Running" {
			statusStr = fmt.Sprintf(" %s | %s | CPU %.1f%% | MEM %s | PIDs %d | ↑%s/s ↓%s/s",
				c.Name, c.IP, m.CPUPercent,
				formatBytes(c.MemoryCur), c.PIDs,
				formatBytes(m.NetTxRate), formatBytes(m.NetRxRate))
		} else {
			statusStr = fmt.Sprintf(" %s [%s]", c.Name, strings.ToLower(c.Status))
		}
	}
	if a.err != nil {
		statusStr += fmt.Sprintf(" | ⚠ %v", a.err)
	}
	statusBar := StatusBarStyle.Width(a.width).Render(statusStr)

	sideW := 34
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
		m := a.getMetric(c.Name)
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

		rightInfo := ""
		if c.Status == "Running" {
			rightInfo = fmt.Sprintf("%4.1f%% %s", m.CPUPercent, formatBytesShort(c.MemoryCur))
		} else {
			rightInfo = strings.ToLower(c.Status)
		}

		line := fmt.Sprintf(" %s %-16s %s", indicator, name, rightInfo)

		if i == a.selected {
			line = SelectedContainerStyle.Render(fmt.Sprintf("▸%s", line[1:]))
		} else {
			line = style.Render(line)
		}

		b.WriteString(line + "\n")
	}

	b.WriteString("\n")
	b.WriteString(SectionHeaderStyle.Render("Keys") + "\n")
	helps := [][]string{
		{"↑↓", "select"}, {"s", "start"}, {"x", "stop"}, {"p", "pause"},
		{"1", "sort:name"}, {"2", "sort:cpu"}, {"3", "sort:mem"},
		{"tab", "panel"}, {"q", "quit"},
	}
	for _, h := range helps {
		b.WriteString(fmt.Sprintf(" %s %s\n",
			HelpKeyStyle.Render(h[0]),
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
	m := a.getMetric(c.Name)
	var b strings.Builder

	focusIndicator := ""
	if a.focus == panelDashboard {
		focusIndicator = " ◆"
	}
	b.WriteString(TitleStyle.Render(fmt.Sprintf("─ %s%s ", c.Name, focusIndicator)) + "\n")

	if c.Status != "Running" {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).Render(
			fmt.Sprintf("\n  Container is %s\n\n  Press [s] to start", strings.ToLower(c.Status))))
		return b.String()
	}

	// CPU
	b.WriteString(SectionHeaderStyle.Render("CPU") + "\n")
	b.WriteString(renderBar("", m.CPUPercent, 100, ColorGreen, 30))
	b.WriteString(fmt.Sprintf("  %.2f%%\n", m.CPUPercent))
	if len(m.CPUHist) > 1 {
		b.WriteString("  " + renderSparkline(m.CPUHist, ColorGreen) + "\n")
	}

	// Memory
	b.WriteString(SectionHeaderStyle.Render("Memory") + "\n")
	memMax := c.MemoryMax
	if memMax <= 0 {
		memMax = 1 << 30
	}
	b.WriteString(renderBar("", m.MemPercent, 100, ColorBlue, 30))
	b.WriteString(fmt.Sprintf("  %s / %s (%.1f%%)\n", formatBytes(c.MemoryCur), formatBytes(memMax), m.MemPercent))
	if len(m.MemHist) > 1 {
		b.WriteString("  " + renderSparkline(m.MemHist, ColorBlue) + "\n")
	}

	// Network
	b.WriteString(SectionHeaderStyle.Render("Network") + "\n")
	b.WriteString(fmt.Sprintf("  ↑ %s/s  ↓ %s/s\n",
		formatBytes(m.NetTxRate), formatBytes(m.NetRxRate)))
	b.WriteString(fmt.Sprintf("  Total: ↑ %s  ↓ %s\n",
		formatBytes(c.NetTxBytes), formatBytes(c.NetRxBytes)))

	// Disk
	if c.DiskUsage > 0 {
		b.WriteString(SectionHeaderStyle.Render("Disk") + "\n")
		b.WriteString(fmt.Sprintf("  %s used\n", formatBytes(c.DiskUsage)))
	}

	// Info
	b.WriteString(SectionHeaderStyle.Render("Info") + "\n")
	b.WriteString(fmt.Sprintf("  IP: %s  PIDs: %d  Type: %s\n", c.IP, c.PIDs, c.Type))
	b.WriteString(fmt.Sprintf("  Profiles: %s  Created: %s\n",
		strings.Join(c.Profiles, ", "), c.CreatedAt))

	// Events
	if len(a.events) > 0 {
		b.WriteString(SectionHeaderStyle.Render("Events") + "\n")
		start := len(a.events) - 8
		if start < 0 {
			start = 0
		}
		for _, ev := range a.events[start:] {
			style := EventNormalStyle
			if strings.Contains(ev, "⚠") || strings.Contains(ev, "■") {
				style = EventWarnStyle
			}
			b.WriteString("  " + style.Render(ev) + "\n")
		}
	}

	return b.String()
}

func renderBar(label string, value, max float64, color lipgloss.Color, width int) string {
	pct := value / max
	if pct > 1 {
		pct = 1
	}
	if pct < 0 {
		pct = 0
	}
	filled := int(pct * float64(width))
	bar := lipgloss.NewStyle().Foreground(color).Render(strings.Repeat("█", filled)) +
		lipgloss.NewStyle().Foreground(ColorDim).Render(strings.Repeat("░", width-filled))
	if label != "" {
		return fmt.Sprintf("  %s %s", MetricLabelStyle.Render(label), bar)
	}
	return fmt.Sprintf("  %s", bar)
}

var sparkChars = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

func renderSparkline(data []float64, color lipgloss.Color) string {
	if len(data) == 0 {
		return ""
	}
	maxVal := 0.0
	for _, v := range data {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal == 0 {
		maxVal = 1
	}

	var sb strings.Builder
	for _, v := range data {
		idx := int(v / maxVal * float64(len(sparkChars)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkChars) {
			idx = len(sparkChars) - 1
		}
		sb.WriteRune(sparkChars[idx])
	}
	return lipgloss.NewStyle().Foreground(color).Render(sb.String())
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

func formatBytesShort(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.0fG", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0fM", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0fK", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}
