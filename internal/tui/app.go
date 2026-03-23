package tui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fourdoors/cella/internal/lxd"
	"github.com/fourdoors/cella/internal/trace"
)

// Panel focus
type panel int

const (
	panelSidebar panel = iota
	panelDashboard
	panelExecInput
	panelExecOutput
	panelSyscall
	panelSeccompGen
	panelLogs
)

const tickInterval = 2 * time.Second
const sparklineLen = 30

type tickMsg time.Time
type containersMsg []lxd.ContainerInfo
type errMsg error
type lxdEventMsg string
type execResultMsg struct {
	stdout string
	stderr string
	err    error
}
type logLinesMsg []string
type logErrMsg error

// ContainerMetrics holds computed metrics for a container
type ContainerMetrics struct {
	CPUPercent float64
	NetRxRate  int64
	NetTxRate  int64
	MemPercent float64
	CPUHist    []float64
	MemHist    []float64
}

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
	prevFocus  panel // remember focus before syscall panel
	width      int
	height     int
	ready      bool
	err        error
	events     []string
	lastUpdate time.Time
	sortBy     string
	eventCh    chan string

	// Exec mode
	execInput   string
	execOutput  string
	execRunning bool
	execScroll  int

	// Syscall tracing
	tracers map[string]*trace.Tracer // container name → tracer

	// Seccomp profile generator
	seccompJSON   string
	seccompSummary string
	seccompScroll int

	// Container logs
	logLines  []string
	logScroll int
	logTarget string

	// Flash message (temporary notification)
	flashText   string
	flashExpiry time.Time
}

type flashExpireMsg struct{}

func NewApp() App {
	client, err := lxd.NewClient("")
	return App{
		client:  client,
		err:     err,
		metrics: make(map[string]*ContainerMetrics),
		prev:    make(map[string]*prevState),
		events:  []string{},
		sortBy:  "name",
		eventCh: make(chan string, 100),
		tracers: make(map[string]*trace.Tracer),
	}
}

func (a App) Init() tea.Cmd {
	return tea.Batch(
		fetchContainers(a.client),
		tea.ClearScreen,
		a.startEventMonitor(),
		a.listenEvents(),
	)
}

func (a App) startEventMonitor() tea.Cmd {
	return func() tea.Msg {
		if a.client == nil {
			return nil
		}
		monitor := lxd.NewMonitor(a.client.SocketPath())
		go func() {
			_ = monitor.Start(context.Background(), func(ev lxd.Event) {
				formatted := lxd.FormatEvent(ev)
				if formatted != "" {
					select {
					case a.eventCh <- formatted:
					default:
					}
				}
			})
		}()
		return nil
	}
}

func (a App) listenEvents() tea.Cmd {
	return func() tea.Msg {
		ev := <-a.eventCh
		return lxdEventMsg(ev)
	}
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

func runExecInContainer(client *lxd.Client, containerName string, command string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := client.ExecCommand(ctx, containerName, []string{"/bin/sh", "-c", command})
		if err != nil {
			return execResultMsg{err: err}
		}

		return execResultMsg{
			stdout: result.Stdout,
			stderr: result.Stderr,
		}
	}
}

func enterShell(containerName string) tea.Cmd {
	c := exec.Command("sudo", "lxc", "exec", containerName, "--", "/bin/bash")
	return tea.ExecProcess(c, func(err error) tea.Msg {
		if err != nil {
			return execResultMsg{err: fmt.Errorf("shell exited: %w", err)}
		}
		return execResultMsg{stdout: "(shell session ended)\n\nPress Esc or q to return to dashboard."}
	})
}

func fetchLogs(client *lxd.Client, containerName string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result, err := client.ExecCommand(ctx, containerName,
			[]string{"/bin/sh", "-c", "journalctl --no-pager -n 200 2>/dev/null || tail -n 200 /var/log/syslog 2>/dev/null || echo 'No logs available'"})
		if err != nil {
			return logErrMsg(err)
		}
		lines := strings.Split(result.Stdout, "\n")
		return logLinesMsg(lines)
	}
}

func (a App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if a.focus == panelExecInput {
			return a.handleExecInput(msg)
		}
		if a.focus == panelExecOutput {
			return a.handleExecOutput(msg)
		}
		if a.focus == panelSyscall {
			return a.handleSyscallPanel(msg)
		}
		if a.focus == panelSeccompGen {
			return a.handleSeccompPanel(msg)
		}
		if a.focus == panelLogs {
			return a.handleLogsPanel(msg)
		}

		switch msg.String() {
		case "q", "ctrl+c":
			// Stop all tracers on exit
			for _, t := range a.tracers {
				t.Stop()
			}
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
		case "T":
			// Stop tracing for selected container (from any normal panel)
			if a.selected < len(a.containers) {
				name := a.containers[a.selected].Name
				if t, ok := a.tracers[name]; ok {
					t.Stop()
					delete(a.tracers, name)
					a.addEvent(fmt.Sprintf("🔬 syscall tracing stopped for %s", name))
				}
			}
		case "G":
			// Generate seccomp profile from trace data
			if a.selected < len(a.containers) {
				name := a.containers[a.selected].Name
				if tracer, ok := a.tracers[name]; ok {
					profile, err := trace.GenerateProfile(tracer, name)
					if err != nil {
						a.addEvent(fmt.Sprintf("⚠ seccomp gen failed: %v", err))
					} else {
						jsonStr, _ := trace.ProfileToJSON(profile)
						a.seccompJSON = jsonStr
						a.seccompSummary = trace.ProfileSummary(profile)
						a.seccompScroll = 0
						a.prevFocus = a.focus
						a.focus = panelSeccompGen
						a.addEvent(fmt.Sprintf("🛡 seccomp profile generated for %s (%d syscalls)",
							name, len(profile.Syscalls[0].Names)))
					}
				} else {
					a.addEvent(fmt.Sprintf("⚠ start tracing first (press t on %s)", name))
				}
			}
		case "l":
			// Container logs
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				if c.Status == "Running" {
					a.logTarget = c.Name
					a.logLines = nil
					a.logScroll = 0
					a.prevFocus = a.focus
					a.focus = panelLogs
					return a, fetchLogs(a.client, c.Name)
				}
			}
		case "e":
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				if c.Status == "Running" {
					a.focus = panelExecInput
					a.execInput = ""
					a.execOutput = ""
					a.execScroll = 0
				}
			}
		case "t":
			// Toggle syscall tracing panel
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				if c.Status == "Running" {
					name := c.Name
					if _, exists := a.tracers[name]; !exists {
						cgroupPath := fmt.Sprintf("/sys/fs/cgroup/lxc.payload.%s", name)
						tracer := trace.NewTracer(name, cgroupPath)
						_ = tracer.Start(context.Background())
						a.tracers[name] = tracer
						a.addEvent(fmt.Sprintf("🔬 syscall tracing started for %s", name))
					}
					a.prevFocus = a.focus
					a.focus = panelSyscall
				}
			}
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
					// Stop tracer if running
					if t, ok := a.tracers[c.Name]; ok {
						t.Stop()
						delete(a.tracers, c.Name)
					}
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

	case lxdEventMsg:
		a.addEvent(string(msg))
		return a, a.listenEvents()

	case execResultMsg:
		a.execRunning = false
		if msg.err != nil {
			a.execOutput = fmt.Sprintf("❌ Error: %v", msg.err)
		} else {
			output := msg.stdout
			if msg.stderr != "" {
				if output != "" {
					output += "\n"
				}
				output += msg.stderr
			}
			if output == "" {
				output = "(no output)"
			}
			a.execOutput = output
		}
		a.focus = panelExecOutput
		a.execScroll = 0
		return a, nil

	case logLinesMsg:
		a.logLines = []string(msg)
		a.logScroll = 0
		// Auto-scroll to bottom
		visibleH := a.height - 10
		if visibleH < 5 {
			visibleH = 5
		}
		if len(a.logLines) > visibleH {
			a.logScroll = len(a.logLines) - visibleH
		}
		return a, nil

	case logErrMsg:
		a.logLines = []string{fmt.Sprintf("❌ Error fetching logs: %v", msg)}
		return a, nil

	case flashExpireMsg:
		if time.Now().After(a.flashExpiry) {
			a.flashText = ""
		}
		return a, nil

	case containersMsg:
		now := time.Now()
		newContainers := []lxd.ContainerInfo(msg)

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

// ── Input handlers ──

func (a App) handleExecInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		a.focus = panelDashboard
		a.execInput = ""
		return a, nil
	case "enter":
		if a.execInput == "" {
			return a, nil
		}
		containerName := a.containers[a.selected].Name
		cmd := strings.TrimSpace(a.execInput)

		if cmd == "bash" || cmd == "sh" || cmd == "/bin/bash" || cmd == "/bin/sh" {
			a.focus = panelDashboard
			a.execInput = ""
			return a, enterShell(containerName)
		}

		a.execRunning = true
		a.execOutput = ""
		return a, runExecInContainer(a.client, containerName, cmd)
	case "backspace":
		if len(a.execInput) > 0 {
			a.execInput = a.execInput[:len(a.execInput)-1]
		}
	case "ctrl+u":
		a.execInput = ""
	case "ctrl+w":
		input := strings.TrimRight(a.execInput, " ")
		idx := strings.LastIndex(input, " ")
		if idx >= 0 {
			a.execInput = input[:idx+1]
		} else {
			a.execInput = ""
		}
	default:
		r := msg.String()
		if len(r) == 1 && r[0] >= 32 && r[0] < 127 {
			a.execInput += r
		} else if r == " " {
			a.execInput += " "
		}
	}
	return a, nil
}

func (a App) handleExecOutput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		a.focus = panelDashboard
		a.execOutput = ""
		a.execScroll = 0
		return a, nil
	case "e":
		a.focus = panelExecInput
		a.execInput = ""
		a.execOutput = ""
		a.execScroll = 0
		return a, nil
	case "up", "k":
		if a.execScroll > 0 {
			a.execScroll--
		}
	case "down", "j":
		lines := strings.Split(a.execOutput, "\n")
		maxScroll := len(lines) - (a.height - 10)
		if maxScroll < 0 {
			maxScroll = 0
		}
		if a.execScroll < maxScroll {
			a.execScroll++
		}
	}
	return a, nil
}

func (a App) handleSyscallPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		a.focus = a.prevFocus
		return a, nil
	case "up", "k":
		if a.selected > 0 {
			a.selected--
			a.ensureTracing()
		}
		return a, nil
	case "down", "j":
		if a.selected < len(a.containers)-1 {
			a.selected++
			a.ensureTracing()
		}
		return a, nil
	case "T":
		// Stop tracing for current container
		if a.selected < len(a.containers) {
			name := a.containers[a.selected].Name
			if t, ok := a.tracers[name]; ok {
				t.Stop()
				delete(a.tracers, name)
				a.addEvent(fmt.Sprintf("🔬 syscall tracing stopped for %s", name))
			}
			a.focus = a.prevFocus
		}
		return a, nil
	case "G":
		// Generate seccomp profile from syscall panel
		if a.selected < len(a.containers) {
			name := a.containers[a.selected].Name
			if tracer, ok := a.tracers[name]; ok {
				profile, err := trace.GenerateProfile(tracer, name)
				if err != nil {
					a.addEvent(fmt.Sprintf("⚠ seccomp gen: %v", err))
				} else {
					jsonStr, _ := trace.ProfileToJSON(profile)
					a.seccompJSON = jsonStr
					a.seccompSummary = trace.ProfileSummary(profile)
					a.seccompScroll = 0
					a.prevFocus = panelSyscall
					a.focus = panelSeccompGen
					a.addEvent(fmt.Sprintf("🛡 seccomp profile: %d syscalls for %s",
						len(profile.Syscalls[0].Names), name))
				}
			}
		}
		return a, nil
	case "tab":
		a.focus = panelSidebar
		return a, nil
	}
	return a, nil
}

// ensureTracing starts tracing for the currently selected container if not already running
func (a *App) ensureTracing() {
	if a.selected >= len(a.containers) {
		return
	}
	c := a.containers[a.selected]
	if c.Status != "Running" {
		return
	}
	name := c.Name
	if _, exists := a.tracers[name]; !exists {
		cgroupPath := fmt.Sprintf("/sys/fs/cgroup/lxc.payload.%s", name)
		tracer := trace.NewTracer(name, cgroupPath)
		_ = tracer.Start(context.Background())
		a.tracers[name] = tracer
		a.addEvent(fmt.Sprintf("🔬 syscall tracing started for %s", name))
	}
}

func (a App) handleSeccompPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		a.focus = a.prevFocus
		return a, nil
	case "up", "k":
		if a.seccompScroll > 0 {
			a.seccompScroll--
		}
	case "down", "j":
		lines := strings.Split(a.seccompJSON, "\n")
		maxScroll := len(lines) - (a.height - 14)
		if maxScroll < 0 {
			maxScroll = 0
		}
		if a.seccompScroll < maxScroll {
			a.seccompScroll++
		}
	case "S":
		// Save profile to file
		if a.seccompJSON != "" && a.selected < len(a.containers) {
			name := a.containers[a.selected].Name
			filename := fmt.Sprintf("/tmp/cella-seccomp-%s.json", name)
			if err := saveToFile(filename, a.seccompJSON); err != nil {
				a.addEvent(fmt.Sprintf("⚠ save failed: %v", err))
				return a, a.setFlash(fmt.Sprintf("❌ Save failed: %v", err))
			}
			a.addEvent(fmt.Sprintf("💾 saved to %s", filename))
			return a, a.setFlash(fmt.Sprintf("✅ Saved to %s", filename))
		}
	}
	return a, nil
}

func (a App) handleLogsPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		a.focus = a.prevFocus
		return a, nil
	case "up", "k":
		if a.logScroll > 0 {
			a.logScroll--
		}
	case "down", "j":
		maxScroll := len(a.logLines) - (a.height - 10)
		if maxScroll < 0 {
			maxScroll = 0
		}
		if a.logScroll < maxScroll {
			a.logScroll++
		}
	case "g":
		a.logScroll = 0
	case "G":
		maxScroll := len(a.logLines) - (a.height - 10)
		if maxScroll < 0 {
			maxScroll = 0
		}
		a.logScroll = maxScroll
	case "r":
		// Refresh logs
		if a.logTarget != "" {
			return a, fetchLogs(a.client, a.logTarget)
		}
	}
	return a, nil
}

// ── Helpers ──

func saveToFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

func (a *App) setFlash(text string) tea.Cmd {
	a.flashText = text
	a.flashExpiry = time.Now().Add(3 * time.Second)
	return tea.Tick(3*time.Second, func(t time.Time) tea.Msg {
		return flashExpireMsg{}
	})
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
	a.events = append(a.events, msg)
	if len(a.events) > 100 {
		a.events = a.events[len(a.events)-100:]
	}
}

// ── View ──

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
	var totalMem int64
	var totalCPU float64
	for _, c := range a.containers {
		if c.Status == "Running" {
			running++
			totalMem += c.MemoryCur
			totalCPU += a.getMetric(c.Name).CPUPercent
		}
	}

	tracingCount := 0
	for _, t := range a.tracers {
		if t.IsRunning() {
			tracingCount++
		}
	}

	header := lipgloss.NewStyle().Foreground(ColorBlue).Bold(true).Render(" 📡 cella") +
		lipgloss.NewStyle().Foreground(ColorSubtle).
			Render(fmt.Sprintf("  %d/%d running", running, len(a.containers))) +
		lipgloss.NewStyle().Foreground(ColorDim).
			Render(fmt.Sprintf("  CPU Σ%.1f%%  MEM Σ%s", totalCPU, formatBytes(totalMem))) +
		lipgloss.NewStyle().Foreground(ColorDim).
			Render(fmt.Sprintf("  🕐 %s", now.Format("15:04:05"))) +
		lipgloss.NewStyle().Foreground(ColorDim).
			Render(fmt.Sprintf("  sort:[%s]", a.sortBy))

	if tracingCount > 0 {
		header += lipgloss.NewStyle().Foreground(ColorOrange).Bold(true).
			Render(fmt.Sprintf("  🔬 tracing:%d", tracingCount))
	}

	// Sidebar
	sidebar := a.renderSidebar()

	// Main area
	var dashboard string
	switch a.focus {
	case panelExecInput:
		dashboard = a.renderExecInput()
	case panelExecOutput:
		dashboard = a.renderExecOutput()
	case panelSyscall:
		dashboard = a.renderSyscallPanel()
	case panelSeccompGen:
		dashboard = a.renderSeccompPanel()
	case panelLogs:
		dashboard = a.renderLogsPanel()
	default:
		dashboard = a.renderDashboard()
	}

	// Status bar
	statusStr := a.renderStatusBar()
	statusBar := StatusBarStyle.Width(a.width).Render(statusStr)

	// Layout
	sideW := 34
	mainW := a.width - sideW - 4
	if mainW < 40 {
		mainW = 40
	}
	contentH := a.height - 4
	if contentH < 10 {
		contentH = 10
	}

	// Dynamic border colors based on focus
	sidebarBorder := ColorBorder
	mainBorder := ColorBorder
	if a.focus == panelSidebar {
		sidebarBorder = ColorBorderFocus
	} else {
		mainBorder = ColorBorderFocus
	}

	sidebarStyled := SidebarStyle.Width(sideW).Height(contentH).
		BorderForeground(sidebarBorder).Render(sidebar)
	dashboardStyled := MainPanelStyle.Width(mainW).Height(contentH).
		BorderForeground(mainBorder).Render(dashboard)

	body := lipgloss.JoinHorizontal(lipgloss.Top, sidebarStyled, dashboardStyled)

	return lipgloss.JoinVertical(lipgloss.Left, header, body, statusBar)
}

func (a App) renderStatusBar() string {
	switch a.focus {
	case panelExecInput:
		return " EXEC MODE │ type command → Enter │ 'bash' for shell │ Esc to cancel"
	case panelExecOutput:
		return " OUTPUT │ ↑↓ scroll │ e: new command │ Esc/q: back to dashboard"
	case panelSyscall:
		return " SYSCALL TRACE │ ↑↓ switch container │ G: generate seccomp │ T: stop │ Esc/q: back"
	case panelSeccompGen:
		return " SECCOMP PROFILE │ ↑↓ scroll │ S: save to file │ Esc/q: back"
	case panelLogs:
		return " LOGS │ ↑↓ scroll │ g/G: top/bottom │ r: refresh │ Esc/q: back"
	default:
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			m := a.getMetric(c.Name)
			traceIndicator := ""
			if _, ok := a.tracers[c.Name]; ok {
				traceIndicator = " │ 🔬 tracing"
			}
			if c.Status == "Running" {
				return fmt.Sprintf(" %s │ %s │ CPU %.1f%% │ MEM %s │ [e]xec [l]ogs [t]race%s",
					c.Name, c.IP, m.CPUPercent,
					formatBytes(c.MemoryCur), traceIndicator)
			}
			return fmt.Sprintf(" %s [%s] │ [s]tart", c.Name, strings.ToLower(c.Status))
		}
		return ""
	}
}

// ── Syscall panel ──

func (a App) renderSyscallPanel() string {
	if a.selected >= len(a.containers) {
		return ""
	}
	containerName := a.containers[a.selected].Name
	tracer, ok := a.tracers[containerName]

	var b strings.Builder

	b.WriteString(TitleStyle.Render(fmt.Sprintf("🔬 Syscall Trace — %s ◆", containerName)) + "\n")

	if !ok || !tracer.IsRunning() {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).
			Render("\n  Tracer not active. Press [t] on a running container to start.\n"))
		return b.String()
	}

	snap := tracer.GetSnapshot()
	if snap == nil {
		lastErr := tracer.LastError()
		msg := "⏳ Collecting first snapshot... (wait ~5 seconds)\n"
		if lastErr != "" {
			msg += fmt.Sprintf("\n  ⚠ %s\n", lastErr)
		}
		b.WriteString(lipgloss.NewStyle().Foreground(ColorYellow).
			Render("\n  " + msg))
		return b.String()
	}

	// Show error if present
	if snap.Error != "" && snap.Total == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorRed).
			Render(fmt.Sprintf("\n  ⚠ %s\n", snap.Error)))
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).
			Render("\n  Retrying every 5 seconds...\n"))
		return b.String()
	}

	// Summary line
	b.WriteString(lipgloss.NewStyle().Foreground(ColorText).
		Render(fmt.Sprintf("  Total: %d syscalls/sample  |  %s\n\n",
			snap.Total,
			snap.Timestamp.UTC().Add(8*time.Hour).Format("15:04:05"))))

	// Family breakdown with bars
	b.WriteString(SectionHeaderStyle.Render("By Family") + "\n")
	families := []struct {
		name  string
		key   trace.SyscallFamily
		color lipgloss.Color
	}{
		{"File    ", trace.FamilyFile, ColorGreen},
		{"Network ", trace.FamilyNetwork, ColorBlue},
		{"Process ", trace.FamilyProcess, ColorPurple},
		{"Memory  ", trace.FamilyMemory, ColorOrange},
		{"IPC/Sync", trace.FamilyIPC, ColorYellow},
		{"Signal  ", trace.FamilySignal, ColorRed},
		{"Other   ", trace.FamilyOther, ColorDim},
	}

	for _, f := range families {
		count := snap.ByFamily[f.key]
		if count == 0 && snap.Total > 0 {
			continue
		}
		pct := float64(0)
		if snap.Total > 0 {
			pct = float64(count) / float64(snap.Total) * 100
		}
		barWidth := 20
		filled := int(pct / 100 * float64(barWidth))
		if filled < 0 {
			filled = 0
		}
		bar := lipgloss.NewStyle().Foreground(f.color).Render(strings.Repeat("█", filled)) +
			lipgloss.NewStyle().Foreground(ColorDim).Render(strings.Repeat("░", barWidth-filled))
		b.WriteString(fmt.Sprintf("  %s %s %5.1f%% (%d)\n",
			lipgloss.NewStyle().Foreground(f.color).Render(f.name),
			bar, pct, count))
	}

	// Top syscalls table
	b.WriteString("\n" + SectionHeaderStyle.Render("Top Syscalls") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(ColorSubtle).
		Render("  NR   NAME                COUNT   FAMILY\n"))
	b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).
		Render("  " + strings.Repeat("─", 50) + "\n"))

	for i, sc := range snap.TopCalls {
		if i >= 12 {
			break
		}
		familyColor := ColorDim
		switch sc.Family {
		case trace.FamilyFile:
			familyColor = ColorGreen
		case trace.FamilyNetwork:
			familyColor = ColorBlue
		case trace.FamilyProcess:
			familyColor = ColorPurple
		case trace.FamilyMemory:
			familyColor = ColorOrange
		case trace.FamilyIPC:
			familyColor = ColorYellow
		case trace.FamilySignal:
			familyColor = ColorRed
		}

		pct := float64(0)
		if snap.Total > 0 {
			pct = float64(sc.Count) / float64(snap.Total) * 100
		}

		b.WriteString(fmt.Sprintf("  %-4d %-18s %6d %5.1f%% %s\n",
			sc.ID,
			lipgloss.NewStyle().Foreground(ColorText).Render(sc.Name),
			sc.Count,
			pct,
			lipgloss.NewStyle().Foreground(familyColor).Render(string(sc.Family)),
		))
	}

	// Sparkline history of total syscalls
	history := tracer.GetHistory()
	if len(history) > 1 {
		b.WriteString("\n" + SectionHeaderStyle.Render("Activity") + "\n")
		totals := make([]float64, len(history))
		for i, h := range history {
			totals[i] = float64(h.Total)
		}
		b.WriteString("  " + renderSparkline(totals, ColorOrange) + "\n")
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).
			Render(fmt.Sprintf("  ← %d samples (2s each) →\n", len(history))))
	}

	return b.String()
}

// ── Exec panels ──

func (a App) renderExecInput() string {
	var b strings.Builder
	containerName := ""
	if a.selected < len(a.containers) {
		containerName = a.containers[a.selected].Name
	}

	b.WriteString(TitleStyle.Render(fmt.Sprintf("⚡ Exec in %s ◆", containerName)) + "\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(ColorSubtle).Render("  Type a command to execute inside the container.") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(ColorSubtle).Render("  Type 'bash' or 'sh' for interactive shell.") + "\n\n")

	prompt := lipgloss.NewStyle().Foreground(ColorGreen).Bold(true).Render(fmt.Sprintf("  %s $ ", containerName))
	cursor := lipgloss.NewStyle().Foreground(ColorBlue).Bold(true).Render("█")
	inputText := lipgloss.NewStyle().Foreground(ColorText).Render(a.execInput)
	b.WriteString(prompt + inputText + cursor + "\n")

	if a.execRunning {
		b.WriteString("\n" + lipgloss.NewStyle().Foreground(ColorYellow).Render("  ⏳ Running...") + "\n")
	}

	b.WriteString("\n" + SectionHeaderStyle.Render("Quick Commands") + "\n")
	suggestions := [][]string{
		{"bash", "Interactive shell"},
		{"ps aux", "Process list"},
		{"df -h", "Disk usage"},
		{"free -h", "Memory info"},
		{"ip addr", "Network config"},
	}
	for _, s := range suggestions {
		b.WriteString(fmt.Sprintf("  %s  %s\n",
			HelpKeyStyle.Render(s[0]),
			HelpDescStyle.Render(s[1]),
		))
	}

	return b.String()
}

func (a App) renderExecOutput() string {
	var b strings.Builder
	containerName := ""
	if a.selected < len(a.containers) {
		containerName = a.containers[a.selected].Name
	}

	b.WriteString(TitleStyle.Render(fmt.Sprintf("⚡ Output — %s ◆", containerName)) + "\n")

	lines := strings.Split(a.execOutput, "\n")
	totalLines := len(lines)

	visibleH := a.height - 12
	if visibleH < 5 {
		visibleH = 5
	}

	start := a.execScroll
	end := start + visibleH
	if end > totalLines {
		end = totalLines
	}
	if start > totalLines {
		start = totalLines
	}

	if totalLines > visibleH {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).
			Render(fmt.Sprintf("  [%d-%d of %d lines]\n", start+1, end, totalLines)))
	}

	outputStyle := lipgloss.NewStyle().Foreground(ColorText)
	for i := start; i < end; i++ {
		b.WriteString("  " + outputStyle.Render(lines[i]) + "\n")
	}

	return b.String()
}

// ── Seccomp panel ──

func (a App) renderSeccompPanel() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("🛡 Generated Seccomp Profile ◆") + "\n")

	// Summary
	if a.seccompSummary != "" {
		lines := strings.Split(a.seccompSummary, "\n")
		for _, line := range lines {
			b.WriteString("  " + lipgloss.NewStyle().Foreground(ColorText).Render(line) + "\n")
		}
	}

	b.WriteString("\n" + SectionHeaderStyle.Render("JSON Profile") + "\n")

	// Scrollable JSON
	lines := strings.Split(a.seccompJSON, "\n")
	totalLines := len(lines)
	visibleH := a.height - 18
	if visibleH < 5 {
		visibleH = 5
	}

	start := a.seccompScroll
	end := start + visibleH
	if end > totalLines {
		end = totalLines
	}
	if start > totalLines {
		start = totalLines
	}

	if totalLines > visibleH {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).
			Render(fmt.Sprintf("  [%d-%d of %d lines]\n", start+1, end, totalLines)))
	}

	jsonStyle := lipgloss.NewStyle().Foreground(ColorGreen)
	for i := start; i < end; i++ {
		b.WriteString("  " + jsonStyle.Render(lines[i]) + "\n")
	}

	b.WriteString("\n" + lipgloss.NewStyle().Foreground(ColorYellow).Bold(true).
		Render("  Press S to save │ Esc to go back") + "\n")

	// Flash message
	if a.flashText != "" && time.Now().Before(a.flashExpiry) {
		b.WriteString("\n" + lipgloss.NewStyle().
			Foreground(lipgloss.Color("#0d1117")).
			Background(ColorGreen).
			Bold(true).
			Padding(0, 1).
			Render(a.flashText) + "\n")
	}

	return b.String()
}

// ── Logs panel ──

func (a App) renderLogsPanel() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render(fmt.Sprintf("📋 Logs — %s ◆", a.logTarget)) + "\n")

	if len(a.logLines) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorYellow).
			Render("\n  ⏳ Loading logs...\n"))
		return b.String()
	}

	totalLines := len(a.logLines)
	visibleH := a.height - 10
	if visibleH < 5 {
		visibleH = 5
	}

	start := a.logScroll
	end := start + visibleH
	if end > totalLines {
		end = totalLines
	}
	if start > totalLines {
		start = totalLines
	}

	if totalLines > visibleH {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).
			Render(fmt.Sprintf("  [%d-%d of %d lines]\n", start+1, end, totalLines)))
	}

	logStyle := lipgloss.NewStyle().Foreground(ColorText)
	warnStyle := lipgloss.NewStyle().Foreground(ColorYellow)
	errStyle := lipgloss.NewStyle().Foreground(ColorRed)

	for i := start; i < end; i++ {
		line := a.logLines[i]
		style := logStyle
		lower := strings.ToLower(line)
		if strings.Contains(lower, "error") || strings.Contains(lower, "fatal") || strings.Contains(lower, "critical") {
			style = errStyle
		} else if strings.Contains(lower, "warn") || strings.Contains(lower, "timeout") {
			style = warnStyle
		}
		b.WriteString("  " + style.Render(line) + "\n")
	}

	return b.String()
}

// ── Sidebar & Dashboard ──

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

		// Show trace indicator
		traceIcon := " "
		if _, ok := a.tracers[c.Name]; ok {
			traceIcon = "🔬"
		}

		name := c.Name
		if len(name) > 14 {
			name = name[:12] + ".."
		}

		rightInfo := ""
		if c.Status == "Running" {
			rightInfo = fmt.Sprintf("%4.1f%% %s", m.CPUPercent, formatBytesShort(c.MemoryCur))
		} else {
			rightInfo = strings.ToLower(c.Status)
		}

		line := fmt.Sprintf(" %s%s %-14s %s", indicator, traceIcon, name, rightInfo)

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
		{"↑↓", "select"}, {"e", "exec"}, {"l", "logs"},
		{"t", "trace"}, {"G", "gen seccomp"}, {"T", "stop trace"},
		{"s", "start"}, {"x", "stop"}, {"p", "pause"},
		{"1-3", "sort"}, {"tab", "panel"}, {"q", "quit"},
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
		b.WriteString(SectionHeaderStyle.Render("Events (live)") + "\n")
		start := len(a.events) - 6
		if start < 0 {
			start = 0
		}
		for _, ev := range a.events[start:] {
			style := EventNormalStyle
			if strings.Contains(ev, "■") || strings.Contains(ev, "✖") {
				style = EventErrorStyle
			} else if strings.Contains(ev, "⚠") || strings.Contains(ev, "⏸") {
				style = EventWarnStyle
			} else if strings.Contains(ev, "▶") || strings.Contains(ev, "✚") || strings.Contains(ev, "🔬") {
				style = lipgloss.NewStyle().Foreground(ColorGreen)
			}
			b.WriteString("  " + style.Render(ev) + "\n")
		}
	}

	return b.String()
}

// ── Render helpers ──

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
