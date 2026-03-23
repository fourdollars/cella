package tui

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fourdoors/cella/internal/lxd"
	"github.com/fourdoors/cella/internal/runtime"
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
	panelResources
	panelSnapshots
	panelHelp
	panelNetwork
	panelCreate
	panelExport
)

const tickInterval = 2 * time.Second
const sparklineLen = 30

type tickMsg time.Time
type containersMsg []runtime.ContainerInfo
type errMsg error
type lxdEventMsg string
type execResultMsg struct {
	stdout string
	stderr string
	err    error
}
type logLinesMsg []string
type logErrMsg error
type logStreamMsg struct {
	line string
}
type logStreamDoneMsg struct{}
type netInfoMsg struct {
	conns   []string
	listens []string
	err     error
}
type configMsg struct {
	config  *runtime.InstanceConfig
	hostRes *lxd.HostResources
	cpuRaw  []lxd.HostCPURaw
	err     error
}
type snapshotsMsg struct {
	snapshots []runtime.SnapshotInfo
	err       error
}
type asyncResultMsg struct {
	text string
	err  error
}

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
	client        *lxd.Client           // LXD client (for events, host resources)
	runtimes      []runtime.Runtime     // all active runtimes
	allContainers []runtime.ContainerInfo // unfiltered
	containers    []runtime.ContainerInfo // filtered view (used by all panels)
	metrics       map[string]*ContainerMetrics
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
	logLines    []string
	logScroll   int
	logTarget   string
	logFollow   bool // true = streaming mode
	logCancel   context.CancelFunc // cancel log stream
	logCh       chan string // log stream channel

	// Flash message (temporary notification)
	flashText   string
	flashExpiry time.Time

	// Resource limits panel
	resConfig    *runtime.InstanceConfig
	resTarget    string
	resRuntime   string // runtime of target container
	resCursor    int // 0=cpu, 1=memory
	resInput     string
	resEditing   bool
	hostRes      *lxd.HostResources
	prevCPURaw   []lxd.HostCPURaw
	perCPUUsage  []lxd.PerCPUUsage

	// Snapshots panel
	snapshots    []runtime.SnapshotInfo
	snapTarget   string
	snapRuntime  string // runtime of target container
	snapCursor   int
	snapInput    string
	snapNaming   bool // entering snapshot name
	snapCloning  bool // entering clone target name

	// Help overlay
	showHelp bool

	// Network panel
	netTarget   string
	netConns    []string   // connection lines
	netListens  []string   // listening ports
	netRxHist   []int64    // RX rate history (bytes/s)
	netTxHist   []int64    // TX rate history (bytes/s)

	// Sidebar scroll
	sideScroll int

	// Data fetch in-flight guard
	fetching bool

	// Runtime filter: "" = all, "lxd", "docker"
	runtimeFilter string

	// Create container
	createStep    int    // 0=runtime, 1=image, 2=name, 3=confirm
	createRuntime string // "lxd" or "docker"
	createImage   string
	createName    string
	createInput   string

	// Delete confirmation
	confirmDelete bool

	// Goto container by number
	gotoMode  bool
	gotoInput string

	// Quit confirmation
	confirmQuit bool
}

type flashExpireMsg struct{}

func NewApp() App {
	var runtimes []runtime.Runtime
	var lxdClient *lxd.Client

	// Try LXD
	client, err := lxd.NewClient("")
	if err == nil {
		lxdClient = client
		runtimes = append(runtimes, runtime.NewLXDRuntime(client))
	}

	// Try Docker
	dockerClient, err := runtime.NewDockerClient("")
	if err == nil {
		runtimes = append(runtimes, dockerClient)
	}

	return App{
		client:   lxdClient,
		runtimes: runtimes,
		metrics:  make(map[string]*ContainerMetrics),
		prev:     make(map[string]*prevState),
		events:   []string{},
		sortBy:   "name",
		eventCh:  make(chan string, 100),
		tracers:  make(map[string]*trace.Tracer),
	}
}

func (a App) Init() tea.Cmd {
	cmds := []tea.Cmd{
		fetchAllContainers(a.runtimes),
		tickCmd(), // tick runs independently from data fetch
		tea.ClearScreen,
	}
	// LXD event monitor only if LXD is available
	if a.client != nil {
		cmds = append(cmds, a.startEventMonitor(), a.listenEvents())
	}
	return tea.Batch(cmds...)
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

func fetchAllContainers(runtimes []runtime.Runtime) tea.Cmd {
	return func() tea.Msg {
		if len(runtimes) == 0 {
			return errMsg(fmt.Errorf("no container runtimes available"))
		}

		type result struct {
			containers []runtime.ContainerInfo
			err        error
		}

		ch := make(chan result, len(runtimes))
		for _, rt := range runtimes {
			go func(r runtime.Runtime) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				containers, err := r.ListContainers(ctx)
				ch <- result{containers, err}
			}(rt)
		}

		var all []runtime.ContainerInfo
		for range runtimes {
			res := <-ch
			if res.err == nil {
				all = append(all, res.containers...)
			}
		}
		return containersMsg(all)
	}
}

// runtimeFor returns the Runtime for a given container based on its Runtime field
func (a App) runtimeFor(containerName string) runtime.Runtime {
	for _, c := range a.containers {
		if c.Name == containerName {
			for _, rt := range a.runtimes {
				if rt.Name() == c.Runtime {
					return rt
				}
			}
		}
	}
	// Default to first runtime
	if len(a.runtimes) > 0 {
		return a.runtimes[0]
	}
	return nil
}

// containerRuntime returns the runtime string for a container name
func (a App) containerRuntime(name string) string {
	for _, c := range a.containers {
		if c.Name == name {
			return c.Runtime
		}
	}
	return ""
}

// resolveCgroupPath returns the cgroup path for a container based on its runtime
func resolveCgroupPath(c runtime.ContainerInfo) string {
	switch c.Runtime {
	case "docker":
		return fmt.Sprintf("/sys/fs/cgroup/system.slice/docker-%s.scope", c.ID)
	default:
		return fmt.Sprintf("/sys/fs/cgroup/lxc.payload.%s", c.Name)
	}
}

// filteredContainers returns containers matching current runtime filter
func (a App) filteredContainers() []runtime.ContainerInfo {
	if a.runtimeFilter == "" {
		return a.containers
	}
	var result []runtime.ContainerInfo
	for _, c := range a.containers {
		if c.Runtime == a.runtimeFilter {
			result = append(result, c)
		}
	}
	return result
}

// selectedContainer returns the currently selected container (filter-aware)
func (a App) selectedContainer() *runtime.ContainerInfo {
	filtered := a.filteredContainers()
	if a.selected >= 0 && a.selected < len(filtered) {
		return &filtered[a.selected]
	}
	return nil
}

func tickCmd() tea.Cmd {
	return tea.Tick(tickInterval, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func runExecInContainer(rt runtime.Runtime, containerName string, command string) tea.Cmd {
	return func() tea.Msg {
		if rt == nil {
			return execResultMsg{err: fmt.Errorf("no runtime for %s", containerName)}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := rt.ExecCommand(ctx, containerName, []string{"/bin/sh", "-c", command})
		if err != nil {
			return execResultMsg{err: err}
		}

		return execResultMsg{
			stdout: result.Stdout,
			stderr: result.Stderr,
		}
	}
}

// startLogStream starts a background log tail process
func startLogStream(rt runtime.Runtime, name string, rtName string, ch chan string, ctx context.Context) tea.Cmd {
	return func() tea.Msg {
		var cmd *exec.Cmd
		if rtName == "docker" {
			cmd = exec.CommandContext(ctx, "docker", "logs", "-f", "--tail", "200", name)
		} else {
			// LXD: exec journalctl inside container
			cmd = exec.CommandContext(ctx, "sudo", "lxc", "exec", name, "--", "sh", "-c",
				"journalctl -f -n 200 2>/dev/null || tail -f /var/log/syslog 2>/dev/null || tail -f /var/log/messages 2>/dev/null")
		}

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			ch <- fmt.Sprintf("❌ pipe error: %v", err)
			return logStreamDoneMsg{}
		}
		cmd.Stderr = cmd.Stdout // merge stderr

		if err := cmd.Start(); err != nil {
			ch <- fmt.Sprintf("❌ start error: %v", err)
			return logStreamDoneMsg{}
		}

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				cmd.Process.Kill()
				return logStreamDoneMsg{}
			case ch <- scanner.Text():
			}
		}
		cmd.Wait()
		return logStreamDoneMsg{}
	}
}

// listenLogStream reads one line from log channel
func listenLogStream(ch chan string) tea.Cmd {
	return func() tea.Msg {
		line, ok := <-ch
		if !ok {
			return logStreamDoneMsg{}
		}
		return logStreamMsg{line: line}
	}
}

func fetchNetInfo(rt runtime.Runtime, name string, rtName string) tea.Cmd {
	return func() tea.Msg {
		if rt == nil {
			return netInfoMsg{err: fmt.Errorf("no runtime")}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Get connections
		var connCmd, listenCmd []string
		if rtName == "docker" {
			connCmd = []string{"sh", "-c", "ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null || echo 'no tool'"}
			listenCmd = []string{"sh", "-c", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo 'no tool'"}
		} else {
			connCmd = []string{"/bin/sh", "-c", "ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null || echo 'no tool'"}
			listenCmd = []string{"/bin/sh", "-c", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo 'no tool'"}
		}

		connResult, _ := rt.ExecCommand(ctx, name, connCmd)
		listenResult, _ := rt.ExecCommand(ctx, name, listenCmd)

		var conns, listens []string
		if connResult != nil {
			for _, line := range strings.Split(connResult.Stdout, "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "State") && !strings.HasPrefix(line, "Proto") {
					conns = append(conns, line)
				}
			}
		}
		if listenResult != nil {
			for _, line := range strings.Split(listenResult.Stdout, "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "State") && !strings.HasPrefix(line, "Proto") {
					listens = append(listens, line)
				}
			}
		}

		return netInfoMsg{conns: conns, listens: listens}
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

func fetchLogs(rt runtime.Runtime, containerName string) tea.Cmd {
	return func() tea.Msg {
		if rt == nil {
			return logErrMsg(fmt.Errorf("no runtime"))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result, err := rt.ExecCommand(ctx, containerName,
			[]string{"/bin/sh", "-c", "journalctl --no-pager -n 200 2>/dev/null || tail -n 200 /var/log/syslog 2>/dev/null || echo 'No logs available'"})
		if err != nil {
			return logErrMsg(err)
		}
		lines := strings.Split(result.Stdout, "\n")
		return logLinesMsg(lines)
	}
}

func fetchConfig(rt runtime.Runtime, name string) tea.Cmd {
	return func() tea.Msg {
		if rt == nil {
			return configMsg{err: fmt.Errorf("no runtime")}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		config, err := rt.GetConfig(ctx, name)
		if err != nil {
			return configMsg{err: err}
		}
		// Host resources and per-CPU stats (LXD-specific, best effort)
		var hostRes *lxd.HostResources
		if lxdRt, ok := rt.(*runtime.LXDRuntime); ok {
			hostRes, _ = lxdRt.Client.GetHostResources(ctx)
		}
		cpuRaw, _ := lxd.ReadPerCPURaw() // works on any linux host
		return configMsg{config: config, hostRes: hostRes, cpuRaw: cpuRaw}
	}
}

func fetchSnapshots(rt runtime.Runtime, name string) tea.Cmd {
	return func() tea.Msg {
		if rt == nil {
			return snapshotsMsg{err: fmt.Errorf("no runtime")}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		snaps, err := rt.ListSnapshots(ctx, name)
		return snapshotsMsg{snapshots: snaps, err: err}
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
		if a.focus == panelNetwork {
			return a.handleNetworkPanel(msg)
		}
		if a.focus == panelResources {
			return a.handleResourcesPanel(msg)
		}
		if a.focus == panelSnapshots {
			return a.handleSnapshotsPanel(msg)
		}
		if a.focus == panelCreate {
			return a.handleCreatePanel(msg)
		}
		if a.focus == panelExport {
			return a.handleImportPanel(msg)
		}

		// Delete confirmation — intercept all keys
		if a.confirmDelete {
			switch msg.String() {
			case "y", "Y":
				a.confirmDelete = false
				if a.selected < len(a.containers) {
					c := a.containers[a.selected]
					rt := a.runtimeFor(c.Name)
					name := c.Name
					return a, func() tea.Msg {
						ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
						defer cancel()
						if err := rt.DeleteContainer(ctx, name); err != nil {
							return asyncResultMsg{err: err}
						}
						return asyncResultMsg{text: fmt.Sprintf("🗑 Deleted %s", name)}
					}
				}
			default:
				a.confirmDelete = false
			}
			return a, nil
		}

		// Goto mode — intercept keys for number input
		if a.gotoMode {
			switch key := msg.String(); {
			case key >= "0" && key <= "9":
				a.gotoInput += key
			case key == "enter":
				if a.gotoInput != "" {
					n := 0
					fmt.Sscanf(a.gotoInput, "%d", &n)
					if n >= 0 && n < len(a.containers) {
						a.selected = n
						a.ensureSidebarVisible()
					}
				}
				a.gotoMode = false
				a.gotoInput = ""
			case key == "esc" || key == "backspace" && a.gotoInput == "":
				a.gotoMode = false
				a.gotoInput = ""
			case key == "backspace":
				if len(a.gotoInput) > 0 {
					a.gotoInput = a.gotoInput[:len(a.gotoInput)-1]
				}
			default:
				// Invalid key, cancel goto
				a.gotoMode = false
				a.gotoInput = ""
			}
			return a, nil
		}

		// Quit confirmation mode — intercept all keys
		if a.confirmQuit {
			switch msg.String() {
			case "y", "Y", "ctrl+c":
				for _, t := range a.tracers {
					t.Stop()
				}
				return a, tea.Quit
			default:
				a.confirmQuit = false
				return a, nil
			}
		}

		// Help overlay — any key dismisses
		if a.showHelp {
			a.showHelp = false
			return a, nil
		}

		switch msg.String() {
		case "q", "ctrl+c":
			a.confirmQuit = true
			return a, nil
		case "?":
			a.showHelp = true
			return a, nil
		case "g":
			// Enter goto mode
			a.gotoMode = true
			a.gotoInput = ""
			return a, nil
		case "up", "k":
			if a.focus == panelSidebar && a.selected > 0 {
				a.selected--
				a.ensureSidebarVisible()
			}
		case "down", "j":
			if a.focus == panelSidebar && a.selected < len(a.containers)-1 {
				a.selected++
				a.ensureSidebarVisible()
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
		case "f":
			// Cycle runtime filter: all → lxd → docker → all
			switch a.runtimeFilter {
			case "":
				a.runtimeFilter = "lxd"
			case "lxd":
				a.runtimeFilter = "docker"
			default:
				a.runtimeFilter = ""
			}
			a.applyFilter()
			a.selected = 0
			a.sideScroll = 0
		case "E":
			// Export config for selected container
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				rt := a.runtimeFor(c.Name)
				name := c.Name
				return a, func() tea.Msg {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					cfg, err := rt.GetConfig(ctx, name)
					if err != nil {
						return asyncResultMsg{err: fmt.Errorf("export: %w", err)}
					}
					export := map[string]interface{}{
						"name":     name,
						"config":   cfg.Config,
						"devices":  cfg.Devices,
						"profiles": cfg.Profiles,
					}
					data, _ := json.MarshalIndent(export, "", "  ")
					filename := fmt.Sprintf("%s.json", name)
					if err := os.WriteFile(filename, data, 0644); err != nil {
						return asyncResultMsg{err: fmt.Errorf("write %s: %w", filename, err)}
					}
					return asyncResultMsg{text: fmt.Sprintf("📤 Exported %s → %s (%d bytes)", name, filename, len(data))}
				}
			}
		case "I":
			// Import config — enter filename
			if a.selected < len(a.containers) {
				a.createInput = ""
				a.prevFocus = a.focus
				a.focus = panelExport // reuse for import prompt
				return a, nil
			}
		case "+":
			// Create new container
			a.createStep = 0
			a.createRuntime = ""
			a.createImage = ""
			a.createName = ""
			a.createInput = ""
			a.prevFocus = a.focus
			a.focus = panelCreate
			return a, nil
		case "d":
			// Delete selected container (must be stopped)
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				if c.Status == "Stopped" || c.Status == "Exited" || c.Status == "Created" {
					a.confirmDelete = true
					return a, nil
				}
			}
		case "w":
			// Network panel
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				if c.Status == "Running" {
					a.netTarget = c.Name
					a.netConns = nil
					a.netListens = nil
					a.prevFocus = a.focus
					a.focus = panelNetwork
					rtName := a.containerRuntime(c.Name)
					return a, fetchNetInfo(a.runtimeFor(c.Name), c.Name, rtName)
				}
			}
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
			// Container logs (streaming)
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				if c.Status == "Running" {
					// Stop any existing log stream
					if a.logCancel != nil {
						a.logCancel()
					}
					a.logTarget = c.Name
					a.logLines = nil
					a.logScroll = 0
					a.logFollow = true
					a.prevFocus = a.focus
					a.focus = panelLogs
					ctx, cancel := context.WithCancel(context.Background())
					a.logCancel = cancel
					a.logCh = make(chan string, 100)
					rtName := a.containerRuntime(c.Name)
					return a, tea.Batch(
						startLogStream(a.runtimeFor(c.Name), c.Name, rtName, a.logCh, ctx),
						listenLogStream(a.logCh),
					)
				}
			}
		case "r":
			// Resource limits
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				a.resTarget = c.Name
				a.resConfig = nil
				a.resCursor = 0
				a.resEditing = false
				a.prevFocus = a.focus
				a.focus = panelResources
				return a, fetchConfig(a.runtimeFor(c.Name), c.Name)
			}
		case "n":
			// Snapshots
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				a.snapTarget = c.Name
				a.snapshots = nil
				a.snapCursor = 0
				a.snapNaming = false
				a.snapCloning = false
				a.prevFocus = a.focus
				a.focus = panelSnapshots
				return a, fetchSnapshots(a.runtimeFor(c.Name), c.Name)
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
						cgroupPath := resolveCgroupPath(c)
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
					rt := a.runtimeFor(c.Name)
					go func() {
						ctx := context.Background()
						if rt != nil {
							_ = rt.StartContainer(ctx, c.Name)
						}
					}()
					a.addEvent(fmt.Sprintf("▶ starting %s...", c.Name))
				}
			}
		case "p":
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				if c.Status == "Running" {
					rt := a.runtimeFor(c.Name)
					go func() {
						ctx := context.Background()
						if rt != nil {
							_ = rt.PauseContainer(ctx, c.Name)
						}
					}()
					a.addEvent(fmt.Sprintf("⏸ pausing %s...", c.Name))
				} else if c.Status == "Frozen" {
					rt := a.runtimeFor(c.Name)
					go func() {
						ctx := context.Background()
						if rt != nil {
							_ = rt.UnpauseContainer(ctx, c.Name)
						}
					}()
					a.addEvent(fmt.Sprintf("▶ unpausing %s...", c.Name))
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
					rt := a.runtimeFor(c.Name)
					go func() {
						ctx := context.Background()
						if rt != nil {
							_ = rt.StopContainer(ctx, c.Name)
						}
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

	case logStreamMsg:
		a.logLines = append(a.logLines, msg.line)
		// Cap at 2000 lines
		if len(a.logLines) > 2000 {
			a.logLines = a.logLines[len(a.logLines)-2000:]
		}
		// Auto-scroll to bottom if following
		if a.logFollow {
			visibleH := a.height - 10
			if visibleH < 5 {
				visibleH = 5
			}
			if len(a.logLines) > visibleH {
				a.logScroll = len(a.logLines) - visibleH
			}
		}
		// Keep listening
		if a.logCh != nil {
			return a, listenLogStream(a.logCh)
		}
		return a, nil

	case logStreamDoneMsg:
		a.logFollow = false
		return a, nil

	case logErrMsg:
		a.logLines = []string{fmt.Sprintf("❌ Error fetching logs: %v", msg)}
		return a, nil

	case netInfoMsg:
		if msg.err != nil {
			a.addEvent(fmt.Sprintf("⚠ network: %v", msg.err))
		} else {
			a.netConns = msg.conns
			a.netListens = msg.listens
			// Track rate history
			if a.selected < len(a.containers) {
				m := a.getMetric(a.containers[a.selected].Name)
				a.netRxHist = append(a.netRxHist, m.NetRxRate)
				a.netTxHist = append(a.netTxHist, m.NetTxRate)
				if len(a.netRxHist) > sparklineLen {
					a.netRxHist = a.netRxHist[len(a.netRxHist)-sparklineLen:]
				}
				if len(a.netTxHist) > sparklineLen {
					a.netTxHist = a.netTxHist[len(a.netTxHist)-sparklineLen:]
				}
			}
		}
		return a, nil

	case flashExpireMsg:
		if time.Now().After(a.flashExpiry) {
			a.flashText = ""
		}
		return a, nil

	case configMsg:
		if msg.err != nil {
			a.addEvent(fmt.Sprintf("⚠ config: %v", msg.err))
			a.focus = a.prevFocus
		} else {
			a.resConfig = msg.config
			if msg.hostRes != nil {
				a.hostRes = msg.hostRes
			}
			if msg.cpuRaw != nil {
				if a.prevCPURaw != nil {
					a.perCPUUsage = lxd.CalcPerCPUUsage(a.prevCPURaw, msg.cpuRaw)
				}
				a.prevCPURaw = msg.cpuRaw
			}
		}
		return a, nil

	case snapshotsMsg:
		if msg.err != nil {
			a.addEvent(fmt.Sprintf("⚠ snapshots: %v", msg.err))
			a.focus = a.prevFocus
		} else {
			a.snapshots = msg.snapshots
		}
		return a, nil

	case asyncResultMsg:
		if msg.err != nil {
			a.addEvent(fmt.Sprintf("⚠ %v", msg.err))
			return a, a.setFlash(fmt.Sprintf("❌ %v", msg.err))
		}
		a.addEvent(msg.text)
		return a, a.setFlash(fmt.Sprintf("✅ %s", msg.text))

	case containersMsg:
		a.fetching = false
		now := time.Now()
		newContainers := []runtime.ContainerInfo(msg)

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
					if dt > 500*time.Millisecond { // ignore tiny deltas (timer jitter)
						dCPU := c.CPUUsage - prev.cpuNs
						if dCPU < 0 {
							dCPU = 0
						}
						cpuPct := float64(dCPU) / float64(dt.Nanoseconds()) * 100.0
						// Sanity clamp: cannot exceed numCPU * 100%
						maxCPU := float64(goruntime.NumCPU()) * 100.0
						if cpuPct > maxCPU {
							cpuPct = 0 // counter reset or overflow — discard
						}
						m.CPUPercent = cpuPct

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

		a.allContainers = newContainers
		a.sortContainers()
		a.applyFilter()
		a.lastUpdate = now
		a.err = nil
		if a.selected >= len(a.containers) {
			a.selected = len(a.containers) - 1
		}
		if a.selected < 0 {
			a.selected = 0
		}
		return a, nil

	case errMsg:
		a.fetching = false
		a.err = msg
		return a, nil

	case tickMsg:
		// Tick fires independently — always schedule next tick
		cmds := []tea.Cmd{tickCmd()}
		// Only start new fetch if previous one completed
		if !a.fetching {
			a.fetching = true
			cmds = append(cmds, fetchAllContainers(a.runtimes))
			if a.focus == panelResources && a.resTarget != "" {
				cmds = append(cmds, fetchConfig(a.runtimeFor(a.resTarget), a.resTarget))
			}
			if a.focus == panelNetwork && a.netTarget != "" {
				cmds = append(cmds, fetchNetInfo(a.runtimeFor(a.netTarget), a.netTarget, a.containerRuntime(a.netTarget)))
			}
		}
		return a, tea.Batch(cmds...)
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
		return a, runExecInContainer(a.runtimeFor(containerName), containerName, cmd)
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
		cgroupPath := resolveCgroupPath(c)
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

func (a App) handleImportPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "enter":
		filename := a.createInput
		a.focus = a.prevFocus
		a.createInput = ""
		return a, func() tea.Msg {
			data, err := os.ReadFile(filename)
			if err != nil {
				return asyncResultMsg{err: fmt.Errorf("read %s: %w", filename, err)}
			}
			var imported struct {
				Name     string                       `json:"name"`
				Config   map[string]string            `json:"config"`
				Devices  map[string]map[string]string `json:"devices"`
				Profiles []string                     `json:"profiles"`
			}
			if err := json.Unmarshal(data, &imported); err != nil {
				return asyncResultMsg{err: fmt.Errorf("parse %s: %w", filename, err)}
			}
			if imported.Name == "" {
				return asyncResultMsg{err: fmt.Errorf("missing 'name' in %s", filename)}
			}
			// Apply config to existing container (if name matches selected) or create new
			return asyncResultMsg{text: fmt.Sprintf("📥 Imported config from %s for '%s' (%d keys)", filename, imported.Name, len(imported.Config))}
		}
	case "backspace":
		if len(a.createInput) > 0 {
			a.createInput = a.createInput[:len(a.createInput)-1]
		}
	case "esc":
		a.focus = a.prevFocus
		a.createInput = ""
	default:
		if len(key) == 1 || key == "." || key == "/" || key == "-" || key == "_" {
			a.createInput += key
		}
	}
	return a, nil
}

func (a App) handleCreatePanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	switch a.createStep {
	case 0: // Select runtime
		switch key {
		case "1":
			a.createRuntime = "lxd"
			a.createStep = 1
			a.createInput = ""
		case "2":
			a.createRuntime = "docker"
			a.createStep = 1
			a.createInput = ""
		case "esc", "q":
			a.focus = a.prevFocus
		}
		return a, nil

	case 1: // Enter image
		switch key {
		case "enter":
			a.createImage = a.createInput
			a.createInput = ""
			a.createStep = 2
		case "backspace":
			if len(a.createInput) > 0 {
				a.createInput = a.createInput[:len(a.createInput)-1]
			}
		case "esc":
			a.createStep = 0
		default:
			if len(key) == 1 {
				a.createInput += key
			}
		}
		return a, nil

	case 2: // Enter name
		switch key {
		case "enter":
			a.createName = a.createInput
			a.createInput = ""
			a.createStep = 3
		case "backspace":
			if len(a.createInput) > 0 {
				a.createInput = a.createInput[:len(a.createInput)-1]
			}
		case "esc":
			a.createStep = 1
		default:
			if len(key) == 1 {
				a.createInput += key
			}
		}
		return a, nil

	case 3: // Confirm
		switch key {
		case "y", "Y", "enter":
			a.focus = a.prevFocus
			rtName := a.createRuntime
			image := a.createImage
			name := a.createName
			// Find the runtime
			var rt runtime.Runtime
			for _, r := range a.runtimes {
				if r.Name() == rtName {
					rt = r
					break
				}
			}
			if rt == nil {
				return a, a.setFlash("❌ Runtime not available")
			}
			return a, func() tea.Msg {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				if err := rt.CreateContainer(ctx, name, image, nil); err != nil {
					return asyncResultMsg{err: err}
				}
				return asyncResultMsg{text: fmt.Sprintf("✨ Created %s (%s/%s)", name, rtName, image)}
			}
		case "n", "N", "esc":
			a.createStep = 2
		}
		return a, nil
	}
	return a, nil
}

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

func (a App) handleLogsPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		// Stop log stream on exit
		if a.logCancel != nil {
			a.logCancel()
			a.logCancel = nil
		}
		a.logFollow = false
		a.focus = a.prevFocus
		return a, nil
	case "up", "k":
		a.logFollow = false // manual scroll disables follow
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
		a.logFollow = false
		a.logScroll = 0
	case "G":
		maxScroll := len(a.logLines) - (a.height - 10)
		if maxScroll < 0 {
			maxScroll = 0
		}
		a.logScroll = maxScroll
		a.logFollow = true // G = go to bottom + follow
	case "F":
		// Toggle follow mode
		a.logFollow = !a.logFollow
		if a.logFollow {
			maxScroll := len(a.logLines) - (a.height - 10)
			if maxScroll < 0 {
				maxScroll = 0
			}
			a.logScroll = maxScroll
		}
	case "r":
		// Refresh logs (non-streaming)
		if a.logTarget != "" {
			if a.logCancel != nil {
				a.logCancel()
				a.logCancel = nil
			}
			a.logFollow = false
			return a, fetchLogs(a.runtimeFor(a.logTarget), a.logTarget)
		}
	}
	return a, nil
}

func (a App) handleResourcesPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if a.resEditing {
		switch msg.String() {
		case "esc":
			a.resEditing = false
			a.resInput = ""
			return a, nil
		case "enter":
			a.resEditing = false
			val := strings.TrimSpace(a.resInput)
			a.resInput = ""
			if val == "" {
				return a, nil
			}
			var configKey string
			switch a.resCursor {
			case 0:
				configKey = "limits.cpu"
			case 1:
				configKey = "limits.memory"
			}
			if configKey != "" {
				name := a.resTarget
				rt := a.runtimeFor(name)
				return a, func() tea.Msg {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if rt == nil {
						return asyncResultMsg{err: fmt.Errorf("no runtime for %s", name)}
					}
					err := rt.UpdateConfig(ctx, name, map[string]string{configKey: val})
					if err != nil {
						return asyncResultMsg{err: fmt.Errorf("set %s=%s: %w", configKey, val, err)}
					}
					return asyncResultMsg{text: fmt.Sprintf("%s set to %s for %s", configKey, val, name)}
				}
			}
			return a, nil
		case "backspace":
			if len(a.resInput) > 0 {
				a.resInput = a.resInput[:len(a.resInput)-1]
			}
			return a, nil
		default:
			if len(msg.String()) == 1 {
				a.resInput += msg.String()
			}
			return a, nil
		}
	}

	switch msg.String() {
	case "esc", "q":
		a.focus = a.prevFocus
		return a, nil
	case "up", "k":
		if a.resCursor > 0 {
			a.resCursor--
		}
	case "down", "j":
		if a.resCursor < 1 {
			a.resCursor++
		}
	case "enter":
		a.resEditing = true
		a.resInput = ""
	case "r":
		return a, fetchConfig(a.runtimeFor(a.resTarget), a.resTarget)
	}
	return a, nil
}

func (a App) handleSnapshotsPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Text input mode for naming
	if a.snapNaming || a.snapCloning {
		switch msg.String() {
		case "esc":
			a.snapNaming = false
			a.snapCloning = false
			a.snapInput = ""
			return a, nil
		case "enter":
			val := strings.TrimSpace(a.snapInput)
			a.snapInput = ""
			if val == "" {
				a.snapNaming = false
				a.snapCloning = false
				return a, nil
			}
			name := a.snapTarget
			if a.snapNaming {
				a.snapNaming = false
				rt := a.runtimeFor(name)
				return a, func() tea.Msg {
					ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
					defer cancel()
					if rt == nil {
						return asyncResultMsg{err: fmt.Errorf("no runtime for %s", name)}
					}
					err := rt.CreateSnapshot(ctx, name, val)
					if err != nil {
						return asyncResultMsg{err: fmt.Errorf("snapshot: %w", err)}
					}
					return asyncResultMsg{text: fmt.Sprintf("📸 snapshot '%s' created for %s", val, name)}
				}
			}
			if a.snapCloning {
				a.snapCloning = false
				rt := a.runtimeFor(name)
				return a, func() tea.Msg {
					ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
					defer cancel()
					if rt == nil {
						return asyncResultMsg{err: fmt.Errorf("no runtime for %s", name)}
					}
					err := rt.CopyContainer(ctx, name, val)
					if err != nil {
						return asyncResultMsg{err: fmt.Errorf("clone: %w", err)}
					}
					return asyncResultMsg{text: fmt.Sprintf("🐑 cloned %s → %s", name, val)}
				}
			}
			return a, nil
		case "backspace":
			if len(a.snapInput) > 0 {
				a.snapInput = a.snapInput[:len(a.snapInput)-1]
			}
			return a, nil
		default:
			if len(msg.String()) == 1 {
				a.snapInput += msg.String()
			}
			return a, nil
		}
	}

	switch msg.String() {
	case "esc", "q":
		a.focus = a.prevFocus
		return a, nil
	case "up", "k":
		if a.snapCursor > 0 {
			a.snapCursor--
		}
	case "down", "j":
		if a.snapCursor < len(a.snapshots)-1 {
			a.snapCursor++
		}
	case "n":
		a.snapNaming = true
		a.snapInput = fmt.Sprintf("snap-%s", time.Now().Format("20060102-1504"))
	case "c":
		a.snapCloning = true
		a.snapInput = a.snapTarget + "-clone"
	case "R":
		// Restore snapshot (LXD only)
		if a.snapCursor < len(a.snapshots) {
			snapName := a.snapshots[a.snapCursor].Name
			name := a.snapTarget
			if a.containerRuntime(name) == "docker" {
				a.addEvent("⚠ Docker doesn't support snapshot restore")
				return a, nil
			}
			return a, func() tea.Msg {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				// RestoreSnapshot is LXD-specific, use client directly
				lxdClient, _ := lxd.NewClient("")
				if lxdClient != nil {
					err := lxdClient.RestoreSnapshot(ctx, name, snapName)
					if err != nil {
						return asyncResultMsg{err: fmt.Errorf("restore: %w", err)}
					}
				}
				return asyncResultMsg{text: fmt.Sprintf("⏪ restored %s to snapshot '%s'", name, snapName)}
			}
		}
	case "D":
		// Delete snapshot
		if a.snapCursor < len(a.snapshots) {
			snapName := a.snapshots[a.snapCursor].Name
			name := a.snapTarget
			rt := a.runtimeFor(name)
			return a, func() tea.Msg {
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()
				if rt == nil {
					return asyncResultMsg{err: fmt.Errorf("no runtime for %s", name)}
				}
				err := rt.DeleteSnapshot(ctx, name, snapName)
				if err != nil {
					return asyncResultMsg{err: fmt.Errorf("delete snapshot: %w", err)}
				}
				return asyncResultMsg{text: fmt.Sprintf("🗑 deleted snapshot '%s' from %s", snapName, name)}
			}
		}
	case "r":
		return a, fetchSnapshots(a.runtimeFor(a.snapTarget), a.snapTarget)
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
		sort.Slice(a.allContainers, func(i, j int) bool {
			mi := a.getMetric(a.allContainers[i].Name)
			mj := a.getMetric(a.allContainers[j].Name)
			return mi.CPUPercent > mj.CPUPercent
		})
	case "mem":
		sort.Slice(a.allContainers, func(i, j int) bool {
			return a.allContainers[i].MemoryCur > a.allContainers[j].MemoryCur
		})
	default:
		sort.Slice(a.allContainers, func(i, j int) bool {
			si := statusOrder(a.allContainers[i].Status)
			sj := statusOrder(a.allContainers[j].Status)
			if si != sj {
				return si < sj
			}
			return a.allContainers[i].Name < a.allContainers[j].Name
		})
	}
}

func (a *App) applyFilter() {
	if a.runtimeFilter == "" {
		a.containers = a.allContainers
		return
	}
	filtered := make([]runtime.ContainerInfo, 0, len(a.allContainers))
	for _, c := range a.allContainers {
		if c.Runtime == a.runtimeFilter {
			filtered = append(filtered, c)
		}
	}
	a.containers = filtered
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

	// Help overlay
	if a.showHelp {
		return a.renderHelpOverlay()
	}
	if a.err != nil && len(a.containers) == 0 {
		return fmt.Sprintf("\n  ❌ Error: %v\n\n  Make sure LXD is running and accessible.\n  Press q to quit.\n", a.err)
	}

	// Header
	now := time.Now().UTC().Add(8 * time.Hour)
	running := 0
	var totalMem int64
	var totalCPU float64
	for _, c := range a.allContainers {
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
			Render(fmt.Sprintf("  %d/%d running", running, len(a.allContainers))) +
		lipgloss.NewStyle().Foreground(ColorDim).
			Render(fmt.Sprintf("  CPU Σ%.1f%%  MEM Σ%s", totalCPU, formatBytes(totalMem))) +
		lipgloss.NewStyle().Foreground(ColorDim).
			Render(fmt.Sprintf("  🕐 %s", now.Format("15:04:05"))) +
		lipgloss.NewStyle().Foreground(ColorDim).
			Render(fmt.Sprintf("  sort:[%s]", a.sortBy))

	// Filter indicator
	if a.runtimeFilter != "" {
		icon := "🔷"
		if a.runtimeFilter == "docker" {
			icon = "🐳"
		}
		header += lipgloss.NewStyle().Foreground(ColorYellow).Bold(true).
			Render(fmt.Sprintf("  %s filter:[%s]", icon, a.runtimeFilter))
	}

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
	case panelNetwork:
		dashboard = a.renderNetworkPanel()
	case panelCreate:
		dashboard = a.renderCreatePanel()
	case panelExport:
		dashboard = a.renderImportPanel()
	case panelResources:
		dashboard = a.renderResourcesPanel()
	case panelSnapshots:
		dashboard = a.renderSnapshotsPanel()
	default:
		dashboard = a.renderDashboard()
	}

	// Status bar
	statusStr := a.renderStatusBar()
	statusBar := StatusBarStyle.Width(a.width).Render(statusStr)

	// Layout
	sideW := a.calcSidebarWidth()
	mainW := a.width - sideW - 4
	if mainW < 40 {
		mainW = 40
	}
	contentH := a.height - 4
	if contentH < 10 {
		contentH = 10
	}

	// Sidebar always has focus highlight (dashboard is display-only)
	sidebarBorder := ColorBorderFocus
	mainBorder := ColorBorder

	sidebarStyled := SidebarStyle.Width(sideW).Height(contentH).
		BorderForeground(sidebarBorder).Render(sidebar)
	dashboardStyled := MainPanelStyle.Width(mainW).Height(contentH).
		BorderForeground(mainBorder).Render(dashboard)

	body := lipgloss.JoinHorizontal(lipgloss.Top, sidebarStyled, dashboardStyled)

	return lipgloss.JoinVertical(lipgloss.Left, header, body, statusBar)
}

func (a App) renderStatusBar() string {
	if a.gotoMode {
		return fmt.Sprintf(" GOTO │ type number → Enter │ Esc: cancel │ > %s█", a.gotoInput)
	}
	if a.confirmQuit {
		return " ⚠ Quit cella? (y/n)"
	}
	if a.confirmDelete {
		name := ""
		if a.selected < len(a.containers) {
			name = a.containers[a.selected].Name
		}
		return fmt.Sprintf(" ⚠ Delete '%s'? This is irreversible! (y/n)", name)
	}
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
		follow := ""
		if a.logFollow {
			follow = " │ 🔴 F: toggle follow"
		}
		return " LOGS │ ↑↓ scroll │ g/G: top/bottom │ F: follow │ r: refresh │ Esc/q: back" + follow
	case panelNetwork:
		return " NETWORK │ r: refresh │ Esc/q: back"
	case panelCreate:
		return " CREATE │ follow prompts │ Esc: back"
	case panelExport:
		return " IMPORT │ type filename → Enter │ Esc: cancel"
	case panelResources:
		return " RESOURCES │ ↑↓ select │ Enter: edit │ Esc/q: back"
	case panelSnapshots:
		return " SNAPSHOTS │ ↑↓ select │ n: new │ c: clone │ R: restore │ D: delete │ Esc/q: back"
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
	header := fmt.Sprintf("  %-4s %-18s %6s %6s %-10s", "NR", "NAME", "COUNT", "%", "FAMILY")
	b.WriteString(lipgloss.NewStyle().Foreground(ColorSubtle).Render(header) + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).Render("  " + strings.Repeat("─", 48)) + "\n")

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

		// Pad name to fixed width BEFORE applying ANSI style (otherwise escape codes break alignment)
		paddedName := fmt.Sprintf("%-18s", sc.Name)
		styledName := lipgloss.NewStyle().Foreground(ColorText).Render(paddedName)
		styledFamily := lipgloss.NewStyle().Foreground(familyColor).Render(string(sc.Family))

		b.WriteString(fmt.Sprintf("  %-4d %s %6d %5.1f%% %s\n",
			sc.ID,
			styledName,
			sc.Count,
			pct,
			styledFamily,
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

// ── Import panel ──

func (a App) renderImportPanel() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("📥 Import Config ◆") + "\n\n")

	promptStyle := lipgloss.NewStyle().Foreground(ColorBlue).Bold(true)
	inputStyle := lipgloss.NewStyle().Foreground(ColorGreen).Bold(true)
	dimStyle := lipgloss.NewStyle().Foreground(ColorDim)

	b.WriteString(promptStyle.Render("  Enter JSON config file path:") + "\n")
	b.WriteString(inputStyle.Render(fmt.Sprintf("  > %s█", a.createInput)) + "\n\n")
	b.WriteString(dimStyle.Render("  Enter to import, Esc to cancel") + "\n")
	b.WriteString(dimStyle.Render("  Tip: export first with E, then modify the JSON") + "\n")

	return b.String()
}

// ── Create panel ──

func (a App) renderCreatePanel() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("✨ Create Container ◆") + "\n\n")

	promptStyle := lipgloss.NewStyle().Foreground(ColorBlue).Bold(true)
	dimStyle := lipgloss.NewStyle().Foreground(ColorDim)
	inputStyle := lipgloss.NewStyle().Foreground(ColorGreen).Bold(true)

	switch a.createStep {
	case 0:
		b.WriteString(promptStyle.Render("  Select runtime:") + "\n\n")
		b.WriteString("  [1] 🔷 LXD\n")
		b.WriteString("  [2] 🐳 Docker\n\n")
		b.WriteString(dimStyle.Render("  Press 1 or 2, Esc to cancel") + "\n")

	case 1:
		icon := "🔷"
		if a.createRuntime == "docker" {
			icon = "🐳"
		}
		b.WriteString(dimStyle.Render(fmt.Sprintf("  Runtime: %s %s", icon, a.createRuntime)) + "\n\n")
		if a.createRuntime == "docker" {
			b.WriteString(promptStyle.Render("  Image name (e.g. ubuntu, alpine, nginx):") + "\n")
		} else {
			b.WriteString(promptStyle.Render("  Image alias (e.g. ubuntu:22.04, alpine):") + "\n")
		}
		b.WriteString(inputStyle.Render(fmt.Sprintf("  > %s█", a.createInput)) + "\n\n")
		b.WriteString(dimStyle.Render("  Enter to confirm, Esc to go back") + "\n")

	case 2:
		b.WriteString(dimStyle.Render(fmt.Sprintf("  Runtime: %s  Image: %s", a.createRuntime, a.createImage)) + "\n\n")
		b.WriteString(promptStyle.Render("  Container name:") + "\n")
		b.WriteString(inputStyle.Render(fmt.Sprintf("  > %s█", a.createInput)) + "\n\n")
		b.WriteString(dimStyle.Render("  Enter to confirm, Esc to go back") + "\n")

	case 3:
		b.WriteString(SectionHeaderStyle.Render("  Confirm creation:") + "\n\n")
		b.WriteString(fmt.Sprintf("  Runtime:  %s\n", a.createRuntime))
		b.WriteString(fmt.Sprintf("  Image:    %s\n", a.createImage))
		b.WriteString(fmt.Sprintf("  Name:     %s\n\n", a.createName))
		b.WriteString(promptStyle.Render("  Create? (y/n)") + "\n")
	}

	return b.String()
}

// ── Network panel ──

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
	if m.NetRxRate == 0 { rxPct = 0 }
	txPct := float64(m.NetTxRate) / float64(txMax) * 100
	if m.NetTxRate == 0 { txPct = 0 }

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

// ── Logs panel ──

func (a App) renderLogsPanel() string {
	var b strings.Builder

	followTag := ""
	if a.logFollow {
		followTag = lipgloss.NewStyle().Foreground(ColorGreen).Bold(true).Render(" 🔴 LIVE")
	}
	b.WriteString(TitleStyle.Render(fmt.Sprintf("📋 Logs — %s ◆", a.logTarget)) + followTag + "\n")

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

// ── Resources panel ──

func (a App) renderResourcesPanel() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render(fmt.Sprintf("⚙ Resource Limits — %s ◆", a.resTarget)) + "\n")

	if a.resConfig == nil {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorYellow).
			Render("\n  ⏳ Loading configuration...\n"))
		return b.String()
	}

	// Host system info
	if a.hostRes != nil {
		hostStyle := lipgloss.NewStyle().Foreground(ColorSubtle)
		memFree := a.hostRes.MemoryTotal - a.hostRes.MemoryUsed
		memPct := float64(a.hostRes.MemoryUsed) / float64(a.hostRes.MemoryTotal) * 100
		b.WriteString(hostStyle.Render(fmt.Sprintf("  Host: %d CPUs │ RAM %s / %s (%.0f%% used, %s free)",
			a.hostRes.CPUTotal,
			formatBytes(a.hostRes.MemoryUsed), formatBytes(a.hostRes.MemoryTotal),
			memPct, formatBytes(memFree))) + "\n\n")
	}

	config := a.resConfig.Config

	type resRow struct {
		label   string
		key     string
		current string
		hint    string
	}

	cpuHint := "e.g. 2, 0-3, 200ms/100ms"
	memHint := "e.g. 256MB, 1GB, 2GiB"
	if a.hostRes != nil {
		cpuHint = fmt.Sprintf("max %d │ e.g. 2, 0-3, 200ms/100ms", a.hostRes.CPUTotal)
		memFree := a.hostRes.MemoryTotal - a.hostRes.MemoryUsed
		memHint = fmt.Sprintf("free %s │ e.g. 256MB, 1GB", formatBytes(memFree))
	}

	rows := []resRow{
		{
			label:   "CPU Limit",
			key:     "limits.cpu",
			current: config["limits.cpu"],
			hint:    cpuHint,
		},
		{
			label:   "Memory Limit",
			key:     "limits.memory",
			current: config["limits.memory"],
			hint:    memHint,
		},
	}

	b.WriteString("\n")
	for i, row := range rows {
		cursor := "  "
		style := lipgloss.NewStyle().Foreground(ColorText)
		if i == a.resCursor {
			cursor = "▸ "
			style = style.Foreground(ColorBlue).Bold(true)
		}

		val := row.current
		if val == "" {
			val = "(not set)"
		}

		b.WriteString(cursor + style.Render(fmt.Sprintf("%-14s", row.label)))

		if a.resEditing && i == a.resCursor {
			b.WriteString(lipgloss.NewStyle().Foreground(ColorGreen).Bold(true).
				Render(fmt.Sprintf("  → %s▌", a.resInput)))
			b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).
				Render(fmt.Sprintf("  (%s)", row.hint)))
		} else {
			b.WriteString(lipgloss.NewStyle().Foreground(ColorText).
				Render(fmt.Sprintf("  %s", val)))
		}
		b.WriteString("\n\n")
	}

	// Show other useful config values (read-only)
	b.WriteString(SectionHeaderStyle.Render("Current Usage") + "\n\n")

	barWidth := 30

	// Find container in our list for live metrics
	for _, c := range a.containers {
		if c.Name == a.resTarget {
			if m, ok := a.metrics[c.Name]; ok {
				// Check if CPU is pinned to specific cores
				cpuPins := parseCPUPins(config["limits.cpu"])

				if len(cpuPins) > 0 && len(a.perCPUUsage) > 0 {
					// Show per-CPU bars for pinned cores
					usageMap := make(map[int]float64)
					for _, u := range a.perCPUUsage {
						usageMap[u.ID] = u.Percent
					}
					for _, cpuID := range cpuPins {
						pct := usageMap[cpuID]
						bar := renderProgressBar(pct, 100.0, barWidth)
						b.WriteString(fmt.Sprintf("  CPU%-2d   %s  %.1f%%\n", cpuID, bar, pct))
					}
				} else {
					// Aggregate CPU bar
					cpuPct := m.CPUPercent
					cpuBar := renderProgressBar(cpuPct, 100.0, barWidth)
					b.WriteString(fmt.Sprintf("  CPU     %s  %.1f%%\n", cpuBar, cpuPct))
				}

				// Memory bar (container usage vs limit or host total)
				memLimit := c.MemoryMax
				if memLimit == 0 && a.hostRes != nil {
					memLimit = a.hostRes.MemoryTotal
				}
				memPct := 0.0
				if memLimit > 0 {
					memPct = float64(c.MemoryCur) / float64(memLimit) * 100
				}
				memBar := renderProgressBar(memPct, 100.0, barWidth)
				b.WriteString(fmt.Sprintf("  MEM     %s  %s / %s (%.0f%%)\n",
					memBar, formatBytes(c.MemoryCur), formatBytes(memLimit), memPct))

				// Disk bar (if available)
				if c.DiskUsage > 0 {
					b.WriteString(fmt.Sprintf("  DISK    %s\n", formatBytes(c.DiskUsage)))
				}

				b.WriteString(fmt.Sprintf("  PIDs    %d\n", c.PIDs))

				// Network rates
				b.WriteString(fmt.Sprintf("  NET     ↓ %s/s  ↑ %s/s\n",
					formatBytes(m.NetRxRate), formatBytes(m.NetTxRate)))
			}
			break
		}
	}

	// Host-level bar if available
	if a.hostRes != nil {
		b.WriteString("\n" + SectionHeaderStyle.Render("Host Overview") + "\n\n")
		hostMemPct := float64(a.hostRes.MemoryUsed) / float64(a.hostRes.MemoryTotal) * 100
		hostMemBar := renderProgressBar(hostMemPct, 100.0, barWidth)
		b.WriteString(fmt.Sprintf("  RAM     %s  %s / %s (%.0f%%)\n",
			hostMemBar,
			formatBytes(a.hostRes.MemoryUsed), formatBytes(a.hostRes.MemoryTotal), hostMemPct))
	}

	b.WriteString("\n" + SectionHeaderStyle.Render("Other Limits") + "\n\n")
	otherKeys := []string{"limits.cpu.allowance", "limits.cpu.priority",
		"limits.disk.priority", "limits.memory.swap", "limits.processes"}
	for _, k := range otherKeys {
		if v, ok := config[k]; ok {
			b.WriteString(fmt.Sprintf("  %-26s %s\n", k, v))
		}
	}

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

// ── Snapshots panel ──

func (a App) renderSnapshotsPanel() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render(fmt.Sprintf("📸 Snapshots — %s ◆", a.snapTarget)) + "\n")

	if a.snapshots == nil {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorYellow).
			Render("\n  ⏳ Loading snapshots...\n"))
		return b.String()
	}

	if len(a.snapshots) == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).
			Render("\n  No snapshots yet.\n"))
	} else {
		b.WriteString("\n")
		for i, snap := range a.snapshots {
			cursor := "  "
			style := lipgloss.NewStyle().Foreground(ColorText)
			if i == a.snapCursor {
				cursor = "▸ "
				style = style.Foreground(ColorBlue).Bold(true)
			}
			stateful := ""
			if snap.Stateful {
				stateful = " [stateful]"
			}
			b.WriteString(cursor + style.Render(fmt.Sprintf("%-20s  %s%s", snap.Name, snap.CreatedAt, stateful)) + "\n")
		}
	}

	// Input mode
	if a.snapNaming {
		b.WriteString("\n" + lipgloss.NewStyle().Foreground(ColorGreen).Bold(true).
			Render(fmt.Sprintf("  New snapshot name: %s▌", a.snapInput)) + "\n")
	}
	if a.snapCloning {
		b.WriteString("\n" + lipgloss.NewStyle().Foreground(ColorGreen).Bold(true).
			Render(fmt.Sprintf("  Clone target name: %s▌", a.snapInput)) + "\n")
	}

	b.WriteString(fmt.Sprintf("\n  %d snapshot(s)\n", len(a.snapshots)))

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

// ensureSidebarVisible adjusts sideScroll so selected item is visible
func (a *App) ensureSidebarVisible() {
	visibleH := a.sidebarVisibleRows()
	if visibleH <= 0 {
		return
	}
	if a.selected < a.sideScroll {
		a.sideScroll = a.selected
	}
	if a.selected >= a.sideScroll+visibleH {
		a.sideScroll = a.selected - visibleH + 1
	}
}

// sidebarVisibleRows returns how many container rows fit in the sidebar
// calcSidebarWidth dynamically sizes sidebar based on longest container name.
// Layout per line (worst case):
//   "▸"(1) + "%2d"(2-3) + indicator●(2cells) + rtIcon🔷(2cells) + name + " "(1) + "100% 99.9G"(10)
//   = 19 cells + name length
func (a App) calcSidebarWidth() int {
	// Layout: "▸"(1) + "%2d"(2-3) + indicator●(2cells) + rtIcon🔷(2cells) + name + rightInfo(10: "%4s %5s")
	const overhead = 18 // prefix(~8 cells) + right column(10 cells)
	const minW = 32
	const maxW = 55

	maxName := 0
	for _, c := range a.containers {
		if len(c.Name) > maxName {
			maxName = len(c.Name)
		}
	}

	w := overhead + maxName
	if w < minW {
		w = minW
	}
	if w > maxW {
		w = maxW
	}
	// Don't let sidebar eat more than 40% of terminal width
	limit := a.width * 40 / 100
	if limit < minW {
		limit = minW
	}
	if w > limit {
		w = limit
	}
	return w
}

// sidebarNameMax returns how many chars of container name can fit in sidebar
func (a App) sidebarNameMax() int {
	const overhead = 18
	w := a.calcSidebarWidth()
	nameMax := w - overhead
	if nameMax < 8 {
		nameMax = 8
	}
	return nameMax
}

func (a App) sidebarVisibleRows() int {
	// contentH - title(2 lines) - footer hint(2 lines) - border padding
	h := a.height - 4 - 4
	if h < 3 {
		h = 3
	}
	return h
}

// ── Sidebar & Dashboard ──

func (a App) renderSidebar() string {
	var b strings.Builder

	focusIndicator := ""
	if a.focus == panelSidebar {
		focusIndicator = " ◆"
	}
	b.WriteString(TitleStyle.Render("Containers"+focusIndicator) + "\n\n")

	visibleH := a.sidebarVisibleRows()
	total := len(a.containers)

	// Clamp scroll
	maxScroll := total - visibleH
	if maxScroll < 0 {
		maxScroll = 0
	}
	scroll := a.sideScroll
	if scroll > maxScroll {
		scroll = maxScroll
	}

	// Scroll up indicator
	if scroll > 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).Render("  ▲ more") + "\n")
		visibleH-- // one line used for indicator
	}

	end := scroll + visibleH
	if end > total {
		end = total
	}

	// Need bottom indicator?
	needBottomIndicator := end < total

	if needBottomIndicator && end > scroll+1 {
		end-- // reserve one line for ▼ indicator
	}

	for i := scroll; i < end; i++ {
		c := a.containers[i]
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

		// Runtime icon
		rtIcon := "🔷"
		if c.Runtime == "docker" {
			rtIcon = "🐳"
		}

		// Show trace indicator
		traceIcon := ""
		if _, ok := a.tracers[c.Name]; ok {
			traceIcon = "🔬"
		}

		name := c.Name
		nameMax := a.sidebarNameMax()
		// 🔬 trace icon takes 2 terminal cells — shrink name to compensate
		if traceIcon != "" {
			nameMax -= 2
			if nameMax < 6 {
				nameMax = 6
			}
		}
		if len(name) > nameMax {
			name = name[:nameMax-2] + ".."
		}

		rightInfo := ""
		if c.Status == "Running" {
			cpu := fmt.Sprintf("%.0f%%", m.CPUPercent)
			mem := formatBytesShort(c.MemoryCur)
			rightInfo = fmt.Sprintf("%4s %5s", cpu, mem)
		} else {
			rightInfo = fmt.Sprintf("%10s", strings.ToLower(c.Status))
		}

		line := fmt.Sprintf("%2d%s%s%s%-*s%s", i, indicator, rtIcon, traceIcon, nameMax, name, rightInfo)

		if i == a.selected {
			line = SelectedContainerStyle.Render("▸" + line)
		} else {
			line = style.Render(" " + line)
		}

		b.WriteString(line + "\n")
	}

	// Scroll down indicator
	if needBottomIndicator {
		b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).Render("  ▼ more") + "\n")
	}

	// Compact footer hint
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).Render(" [?] help") + "\n")

	return b.String()
}

func (a App) renderHelpOverlay() string {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorBlue).
		MarginBottom(1)

	sectionStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ColorYellow).
		MarginTop(1)

	keyStyle := HelpKeyStyle.Copy().Width(10)
	descStyle := HelpDescStyle

	var b strings.Builder
	b.WriteString(titleStyle.Render("  📖 cella — Keyboard Shortcuts") + "\n\n")

	b.WriteString(sectionStyle.Render("  Navigation") + "\n")
	navKeys := [][]string{
		{"↑/k", "Move up"},
		{"↓/j", "Move down"},
		{"1", "Sort by name"},
		{"2", "Sort by CPU"},
		{"3", "Sort by memory"},
	}
	for _, h := range navKeys {
		b.WriteString(fmt.Sprintf("  %s %s\n", keyStyle.Render(h[0]), descStyle.Render(h[1])))
	}

	b.WriteString(sectionStyle.Render("  Container Actions") + "\n")
	actionKeys := [][]string{
		{"s", "Start container"},
		{"x", "Stop container"},
		{"p", "Pause / Unpause"},
		{"e", "Execute command"},
		{"l", "View logs (streaming)"},
		{"+", "Create new container"},
		{"d", "Delete container (stopped only)"},
	}
	for _, h := range actionKeys {
		b.WriteString(fmt.Sprintf("  %s %s\n", keyStyle.Render(h[0]), descStyle.Render(h[1])))
	}

	b.WriteString(sectionStyle.Render("  Panels") + "\n")
	panelKeys := [][]string{
		{"w", "Network monitoring"},
		{"r", "Resource limits & usage"},
		{"n", "Snapshots & clone"},
		{"t", "Start syscall trace"},
		{"T", "Stop syscall trace"},
		{"G", "Generate seccomp profile"},
		{"S", "Save seccomp profile"},
	}
	for _, h := range panelKeys {
		b.WriteString(fmt.Sprintf("  %s %s\n", keyStyle.Render(h[0]), descStyle.Render(h[1])))
	}

	b.WriteString(sectionStyle.Render("  General") + "\n")
	generalKeys := [][]string{
		{"E", "Export container config (JSON)"},
		{"I", "Import config from file"},
		{"f", "Cycle runtime filter"},
		{"g", "Goto container # (type number, Enter)"},
		{"?", "Show this help"},
		{"q", "Quit (with confirmation)"},
		{"esc", "Back / close panel"},
	}
	for _, h := range generalKeys {
		b.WriteString(fmt.Sprintf("  %s %s\n", keyStyle.Render(h[0]), descStyle.Render(h[1])))
	}

	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(ColorDim).Italic(true).
		Render("  Press any key to close") + "\n")

	overlay := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBlue).
		Padding(1, 2).
		Width(50).
		Render(b.String())

	// Center the overlay
	return lipgloss.Place(a.width, a.height, lipgloss.Center, lipgloss.Center, overlay)
}

func (a App) renderDashboard() string {
	if len(a.containers) == 0 {
		return lipgloss.NewStyle().Foreground(ColorDim).Render("\n  No containers found\n")
	}

	c := a.containers[a.selected]
	m := a.getMetric(c.Name)
	var b strings.Builder

	rtIcon := "🔷"
	rtLabel := "LXD"
	if c.Runtime == "docker" {
		rtIcon = "🐳"
		rtLabel = "Docker"
	}

	focusIndicator := ""
	title := fmt.Sprintf("─ %s %s %s%s ", rtIcon, c.Name, rtLabel, focusIndicator)
	if c.Image != "" {
		title = fmt.Sprintf("─ %s %s (%s)%s ", rtIcon, c.Name, c.Image, focusIndicator)
	}
	b.WriteString(TitleStyle.Render(title) + "\n")

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

// parseCPUPins parses limits.cpu value and returns pinned CPU IDs if it's a range/list
// Returns nil if it's a plain count (e.g. "2") or empty
func parseCPUPins(cpuLimit string) []int {
	cpuLimit = strings.TrimSpace(cpuLimit)
	if cpuLimit == "" {
		return nil
	}
	// Check if it's a range like "2-3" or "0-3" or list "0,2,4"
	if strings.Contains(cpuLimit, "-") && !strings.Contains(cpuLimit, "ms") {
		// Range: "2-3"
		parts := strings.SplitN(cpuLimit, "-", 2)
		start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil {
			return nil
		}
		var pins []int
		for i := start; i <= end; i++ {
			pins = append(pins, i)
		}
		return pins
	}
	if strings.Contains(cpuLimit, ",") {
		// List: "0,2,4"
		var pins []int
		for _, s := range strings.Split(cpuLimit, ",") {
			id, err := strconv.Atoi(strings.TrimSpace(s))
			if err == nil {
				pins = append(pins, id)
			}
		}
		if len(pins) > 0 {
			return pins
		}
	}
	return nil
}

// renderProgressBar draws a colored bar like: [████████░░░░░░]
func renderProgressBar(value, max float64, width int) string {
	if max <= 0 {
		max = 100
	}
	pct := value / max
	if pct > 1 {
		pct = 1
	}
	if pct < 0 {
		pct = 0
	}

	filled := int(pct * float64(width))
	empty := width - filled

	// Color based on percentage
	var barColor lipgloss.Color
	switch {
	case pct >= 0.9:
		barColor = ColorRed
	case pct >= 0.7:
		barColor = ColorYellow
	default:
		barColor = ColorGreen
	}

	filledStr := lipgloss.NewStyle().Foreground(barColor).Render(strings.Repeat("█", filled))
	emptyStr := lipgloss.NewStyle().Foreground(ColorDim).Render(strings.Repeat("░", empty))

	return fmt.Sprintf("[%s%s]", filledStr, emptyStr)
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
