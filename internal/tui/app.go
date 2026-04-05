package tui

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"os/exec"
	goruntime "runtime"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	xansi "github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/lipgloss"
	"github.com/fourdoors/cella/internal/lxd"
	"github.com/fourdoors/cella/internal/runtime"
	"github.com/fourdoors/cella/internal/security"
	"github.com/fourdoors/cella/internal/trace"
	"github.com/fourdoors/cella/internal/proxy"
)

// Panel focus
type panel int

type timedEvent struct {
	Time time.Time
	Text string
}

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
	panelPolicy
	panelDNS
	panelEvents
	panelAudit
	panelInference
	panelRouting
)

const tickInterval = 2 * time.Second
const sparklineLen = 30

// Package-level proxy state — survives Bubbletea model copies
var (
	globalProxyServer     *proxy.Server
	globalTproxyListener  *proxy.TransparentListener
	globalApprovalCh      chan proxy.ApprovalRequest
	globalListeningApprvals bool
)

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
	text     string
	err      error
	extraKey string // optional: used to record interceptedIPs (container name)
	extra    string // optional: used to record interceptedIPs (container IP)
}

// ContainerMetrics holds computed metrics for a container
type ContainerMetrics struct {
	CPUPercent    float64
	NetRxRate     int64
	NetTxRate     int64
	DiskReadRate  int64 // bytes/s
	DiskWriteRate int64 // bytes/s
	MemPercent    float64
	CPUHist       []float64
	MemHist       []float64
	NetRxHist     []float64 // RX rate history (bytes/s)
	NetTxHist     []float64 // TX rate history (bytes/s)
	DiskRHist     []float64 // read rate history
	DiskWHist     []float64 // write rate history
}

type prevState struct {
	cpuNs     int64
	netRx     int64
	netTx     int64
	diskRead  int64
	diskWrite int64
	polledAt  time.Time
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
	events     []timedEvent
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

	// Policy panel
	policyScroll     int
	policyMode       string // "view", "egress-add"
	policyInput      string // for egress domain input
	policyEgress     string // current nftables rules text
	policySeccomp    string // current seccomp profile name
	policyAppArmor   string // current AppArmor profile
	policyPrivileged bool
	policyNesting    bool
	policyDenyList   []string          // security.syscalls.deny active list
	policyDevLXD     bool              // security.devlxd enabled
	policyIdmapIso   bool              // security.idmap.isolated enabled
	policyAutostart  bool              // boot.autostart
	// LXD profiles (loaded when policy panel fetches info)
	policyProfiles          []string
	policyProfileDetails    map[string]*lxd.Profile
	policyContainerCfg      *lxd.InstanceConfig
	// Show sensitive fields in merged view
	policyShowSensitive    bool
	// security.syscalls.intercept.*
	policyInterceptMknod     bool
	policyInterceptBpf       bool
	policyInterceptBpfDev    bool
	policyInterceptSetxattr  bool
	policyInterceptSched     bool
	policyInterceptSysinfo   bool
	policyInterceptMount     bool
	policyInterceptMountShift bool
	policyInterceptMountFuse  string // e.g. "ext4=fuse2fs"
	policyInterceptMountAllow string // e.g. "ext4,btrfs"
	syscallBlocked   map[string]bool   // container name → syscall blocking active

	// DNS monitor (H panel)
	dnsMonitor *security.DNSMonitor
	dnsScroll  int
	dnsMode    string // "view", "allow", "deny"

	// Events panel
	eventScroll int

	// Quit confirmation
	confirmQuit bool

	// interceptedIPs tracks containers with active nftables REDIRECT rules.
	// Key = container name, Value = container IP.
	// Used to clean up rules on exit.
	interceptedIPs map[string]string

	// Proxy + Operator Approval
	pendingApproval *proxy.ApprovalRequest
	auditScroll       int
	auditFilterMode   bool
	auditFilterInput  string
	auditFilterText   string
	auditStatusFilter string
	auditShowLists    bool   // L: show allowlist/denylist instead of log
	inferenceScroll   int
	routingCursor    int
	routingInputMode bool
	routingInputStep int
	routingInputBuf  string
	routingNewRoute  proxy.InferenceRoute

	// Seccomp Notify Operator Approval
	pendingSeccompApproval *SeccompApprovalRequest
	seccompAllowlist       map[string]map[string]bool // container → syscall → permanently allowed

	// Search / filter by name
	searchMode   bool
	searchInput  string
	searchFilter string
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

	app := App{
		client:         lxdClient,
		runtimes:       runtimes,
		metrics:        make(map[string]*ContainerMetrics),
		prev:           make(map[string]*prevState),
		events:         []timedEvent{},
		sortBy:         "name",
		eventCh:        make(chan string, 100),
		tracers:        make(map[string]*trace.Tracer),
		interceptedIPs: make(map[string]string),
	}

	return app
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
	// Start listening for proxy approval requests
	if globalApprovalCh != nil {
		cmds = append(cmds, listenApprovals(globalApprovalCh))
	}
	// Start listening for seccomp syscall approval requests
	if globalSeccompApprovalCh != nil {
		cmds = append(cmds, listenSeccompApprovals(globalSeccompApprovalCh))
		globalListeningSeccompApprovals = true
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
			cmd = exec.CommandContext(ctx, "lxc", "exec", name, "--", "sh", "-c",
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
	c := exec.Command("lxc", "exec", containerName, "--", "/bin/bash")
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
		// Operator approval overlays take priority over everything else
		// Seccomp approval (syscall) checked first — container thread is frozen
		if a.pendingSeccompApproval != nil {
			return a.handleSeccompApprovalKey(msg)
		}
		// Network (proxy) approval checked second
		if a.pendingApproval != nil {
			return a.handleApprovalKey(msg)
		}
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
		if a.focus == panelPolicy {
			return a.handlePolicyPanel(msg)
		}
		if a.focus == panelDNS {
			return a.handleDNSPanel(msg)
		}
		if a.focus == panelEvents {
			return a.handleEventsPanel(msg)
		}
		if a.focus == panelRouting {
			return a.handleRoutingPanel(msg)
		}
		if a.focus == panelInference {
			return a.handleInferencePanel(msg)
		}
		if a.focus == panelAudit {
			return a.handleAuditPanel(msg)
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

		// Search mode — intercept keys for search input
		if a.searchMode {
			switch key := msg.String(); key {
			case "enter":
				a.searchFilter = a.searchInput
				a.searchMode = false
				a.searchInput = ""
				a.applyFilter()
				a.selected = 0
				a.sideScroll = 0
			case "esc":
				a.searchMode = false
				a.searchInput = ""
			case "backspace":
				if len(a.searchInput) > 0 {
					a.searchInput = a.searchInput[:len(a.searchInput)-1]
				}
			case "ctrl+u":
				a.searchInput = ""
			default:
				if len(key) == 1 && key[0] >= 32 && key[0] < 127 {
					a.searchInput += key
				} else if key == " " {
					a.searchInput += " "
				}
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
				// Clean up nftables REDIRECT rules for all intercepted containers.
				for _, ip := range a.interceptedIPs {
					_ = proxy.RemoveTransparentRedirect(ip)
				}
				if globalTproxyListener != nil {
					globalTproxyListener.Stop()
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
		case "/":
			// Enter search mode
			a.searchMode = true
			a.searchInput = ""
			return a, nil
		case "ctrl+l":
			// Clear search filter
			a.searchFilter = ""
			a.applyFilter()
			a.selected = 0
			a.sideScroll = 0
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
			if a.focus == panelSidebar || a.focus == panelDashboard {
				a.sortBy = "name"
				a.sortContainers()
			}
		case "2":
			if a.focus == panelSidebar || a.focus == panelDashboard {
				a.sortBy = "cpu"
				a.sortContainers()
			}
		case "3":
			if a.focus == panelSidebar || a.focus == panelDashboard {
				a.sortBy = "mem"
				a.sortContainers()
			}
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
		case "P":
			// Policy panel
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				a.policyScroll = 0
				a.policyMode = "view"
				a.policyInput = ""
				a.prevFocus = a.focus
				a.focus = panelPolicy
				return a, a.fetchPolicyInfo(c)
			}
		case "Z":
			// Toggle syscall blocking (LXD BPF deny) for selected container — works from any panel
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				if c.Runtime != "lxd" {
					return a, a.setFlash("❌ Syscall blocking only supported for LXD containers")
				}
				return a, a.toggleSeccompNotifyForContainer(c.Name)
			}
		case "D":
			// DNS Monitor panel
			if a.dnsMonitor == nil {
				a.dnsMonitor = security.NewDNSMonitor()
			}
			if !a.dnsMonitor.IsRunning() {
				a.dnsMonitor.Start()
			}
			a.dnsScroll = 0
			a.dnsMode = "view"
			a.prevFocus = a.focus
			a.focus = panelDNS
			return a, nil
		case "A":
			// API Audit panel
			a.auditScroll = 0
			a.prevFocus = a.focus
			a.focus = panelAudit
			return a, nil
		case "R":
			// Inference routing panel
			a.routingCursor = 0
			a.prevFocus = a.focus
			a.focus = panelRouting
			return a, nil
		case "M":
			// Inference stats panel
			a.inferenceScroll = 0
			a.prevFocus = a.focus
			a.focus = panelInference
			return a, nil
		case "V":
			// Events panel
			a.eventScroll = len(a.events) - 1 // start at bottom (latest)
			if a.eventScroll < 0 {
				a.eventScroll = 0
			}
			a.prevFocus = a.focus
			a.focus = panelEvents
			return a, nil
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
				rt := a.runtimeFor(c.Name)
				if c.Status == "Stopped" {
					go func() {
						ctx := context.Background()
						if rt != nil {
							_ = rt.StartContainer(ctx, c.Name)
						}
					}()
					a.addEvent(fmt.Sprintf("▶ starting %s...", c.Name))
				} else if c.Status == "Frozen" {
					// Container may be frozen by a clone/copy operation that was
					// interrupted; unfreeze it instead of silently doing nothing.
					go func() {
						ctx := context.Background()
						if rt != nil {
							_ = rt.UnpauseContainer(ctx, c.Name)
						}
					}()
					a.addEvent(fmt.Sprintf("▶ unfreezing %s...", c.Name))
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

	case tea.MouseMsg:
		return a.handleMouse(msg)

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

	case policyInfoMsg:
		if msg.err != nil {
			a.addEvent(fmt.Sprintf("⚠ policy: %v", msg.err))
		} else {
			a.policyEgress = msg.egress
			a.policySeccomp = msg.seccomp
			a.policyAppArmor = msg.apparmor
			a.policyPrivileged = msg.privileged
			a.policyNesting = msg.nesting
			a.policyDenyList = msg.syscallDeny
			a.policyDevLXD = msg.devlxd
			a.policyIdmapIso = msg.idmapIso
			a.policyAutostart = msg.autostart
			a.policyInterceptMknod = msg.interceptMknod
			a.policyInterceptBpf = msg.interceptBpf
			a.policyInterceptBpfDev = msg.interceptBpfDev
			a.policyInterceptSetxattr = msg.interceptSetxattr
			a.policyInterceptSched = msg.interceptSched
			a.policyInterceptSysinfo = msg.interceptSysinfo
			a.policyInterceptMount = msg.interceptMount
			a.policyInterceptMountShift = msg.interceptMountShift
			a.policyInterceptMountFuse = msg.interceptMountFuse
			a.policyInterceptMountAllow = msg.interceptMountAllow
			// Update per-container blocking state map
			if a.selected < len(a.containers) {
				name := a.containers[a.selected].Name
				if a.syscallBlocked == nil {
					a.syscallBlocked = make(map[string]bool)
				}
				a.syscallBlocked[name] = len(msg.syscallDeny) > 0
			}

			// Profiles and container config (LXD)
			a.policyProfiles = msg.Profiles
			a.policyProfileDetails = msg.ProfileDetails
			a.policyContainerCfg = msg.ContainerCfg
		}
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
		cmds := []tea.Cmd{a.setFlash(fmt.Sprintf("✅ %s", msg.text))}
		// Record intercepted container IP for cleanup on exit;
		// empty extra = removal signal
		if msg.extraKey != "" {
			if msg.extra != "" {
				if a.interceptedIPs == nil {
					a.interceptedIPs = make(map[string]string)
				}
				a.interceptedIPs[msg.extraKey] = msg.extra
			} else {
				delete(a.interceptedIPs, msg.extraKey)
			}
		}
		// Start listening for approval requests after lazy proxy init
		if globalApprovalCh != nil && !globalListeningApprvals {
			globalListeningApprvals = true
			cmds = append(cmds, listenApprovals(globalApprovalCh))
		}
		return a, tea.Batch(cmds...)

	case containersMsg:
		a.fetching = false
		now := time.Now()
		newContainers := []runtime.ContainerInfo(msg)

		for i := range newContainers {
			c := &newContainers[i]
			name := c.Name

			if _, ok := a.metrics[name]; !ok {
				a.metrics[name] = &ContainerMetrics{
					CPUHist:   make([]float64, 0, sparklineLen),
					MemHist:   make([]float64, 0, sparklineLen),
					NetRxHist: make([]float64, 0, sparklineLen),
					NetTxHist: make([]float64, 0, sparklineLen),
					DiskRHist: make([]float64, 0, sparklineLen),
					DiskWHist: make([]float64, 0, sparklineLen),
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

						dDiskR := c.DiskRead - prev.diskRead
						dDiskW := c.DiskWrite - prev.diskWrite
						if dDiskR < 0 {
							dDiskR = 0
						}
						if dDiskW < 0 {
							dDiskW = 0
						}

						dtSec := dt.Seconds()
						if dtSec > 0 {
							m.NetRxRate = int64(float64(dRx) / dtSec)
							m.NetTxRate = int64(float64(dTx) / dtSec)
							m.DiskReadRate = int64(float64(dDiskR) / dtSec)
							m.DiskWriteRate = int64(float64(dDiskW) / dtSec)
						}
					}
				}

				if c.MemoryMax > 0 {
					m.MemPercent = float64(c.MemoryCur) / float64(c.MemoryMax) * 100
				}

				m.CPUHist = appendHist(m.CPUHist, m.CPUPercent, sparklineLen)
				m.MemHist = appendHist(m.MemHist, m.MemPercent, sparklineLen)
				m.NetRxHist = appendHist(m.NetRxHist, float64(m.NetRxRate), sparklineLen)
				m.NetTxHist = appendHist(m.NetTxHist, float64(m.NetTxRate), sparklineLen)
				m.DiskRHist = appendHist(m.DiskRHist, float64(m.DiskReadRate), sparklineLen)
				m.DiskWHist = appendHist(m.DiskWHist, float64(m.DiskWriteRate), sparklineLen)

				a.prev[name] = &prevState{
					cpuNs:     c.CPUUsage,
					netRx:     c.NetRxBytes,
					netTx:     c.NetTxBytes,
					diskRead:  c.DiskRead,
					diskWrite: c.DiskWrite,
					polledAt:  now,
				}
			} else {
				m.CPUPercent = 0
				m.MemPercent = 0
				m.NetRxRate = 0
				m.NetTxRate = 0
			}
		}

		a.allContainers = newContainers
		// Update proxy container IP mapping
		if globalProxyServer != nil {
			ipMap := make(map[string]string)
			for _, c := range newContainers {
				if c.IP != "" {
					ipMap[c.IP] = c.Name
				}
			}
			globalProxyServer.UpdateContainerMap(ipMap)
		}
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

	case approvalMsg:
		req := proxy.ApprovalRequest(msg)
		a.pendingApproval = &req
		a.addEvent(fmt.Sprintf("🔒 approval needed: %s → %s", req.Container, req.Domain))
		return a, nil

	case seccompApprovalMsg:
		req := SeccompApprovalRequest(msg)
		a.pendingSeccompApproval = &req
		a.addEvent(fmt.Sprintf("⚠ syscall approval: %s → %s (pid %d)", req.Container, req.Syscall, req.PID))
		return a, nil

	case seccompNotifyToggleMsg:
		if msg.enabled {
			a.addEvent(fmt.Sprintf("🔒 seccomp notify ENABLED: %s — dangerous syscalls require approval", msg.container))
			a.flashText = fmt.Sprintf("🔒 seccomp notify ON for %s", msg.container)
		} else {
			a.addEvent(fmt.Sprintf("🔓 seccomp notify DISABLED: %s", msg.container))
			a.flashText = fmt.Sprintf("🔓 seccomp notify OFF for %s", msg.container)
		}
		a.flashExpiry = time.Now().Add(3 * time.Second)
		// Keep sidebar icon in sync
		if a.syscallBlocked == nil {
			a.syscallBlocked = make(map[string]bool)
		}
		a.syscallBlocked[msg.container] = msg.enabled
		// Re-arm seccomp approval listener if it was just started
		if msg.enabled && globalSeccompApprovalCh != nil && !globalListeningSeccompApprovals {
			return a, listenSeccompApprovals(globalSeccompApprovalCh)
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

// ── Helpers ──

// cellaConfigDir returns ~/.config/cella/<subdir> and ensures it exists.
func cellaConfigDir(subdir string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home dir: %w", err)
	}
	dir := filepath.Join(home, ".config", "cella", subdir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("cannot create dir %s: %w", dir, err)
	}
	return dir, nil
}

func saveToFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
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
	if a.runtimeFilter == "" && a.searchFilter == "" {
		a.containers = a.allContainers
		return
	}
	searchLower := strings.ToLower(a.searchFilter)
	filtered := make([]runtime.ContainerInfo, 0, len(a.allContainers))
	for _, c := range a.allContainers {
		if a.runtimeFilter != "" && c.Runtime != a.runtimeFilter {
			continue
		}
		if a.searchFilter != "" && !strings.Contains(strings.ToLower(c.Name), searchLower) {
			continue
		}
		filtered = append(filtered, c)
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
	a.events = append(a.events, timedEvent{Time: time.Now(), Text: msg})
	if len(a.events) > 200 {
		a.events = a.events[len(a.events)-200:]
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

	// Search filter indicator
	if a.searchFilter != "" {
		header += lipgloss.NewStyle().Foreground(ColorYellow).Bold(true).
			Render(fmt.Sprintf("  🔍 search:[%s]", a.searchFilter))
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
	case panelPolicy:
		dashboard = a.renderPolicyPanel()
	case panelDNS:
		dashboard = a.renderDNSPanel()
	case panelEvents:
		dashboard = a.renderEventsPanel()
	case panelInference:
		dashboard = a.renderInferencePanel()
	case panelRouting:
		dashboard = a.renderRoutingPanel()
	case panelAudit:
		dashboard = a.renderAuditPanel()
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

	// Truncate every dashboard line to prevent overflow into the sidebar.
	// border(1)+padding(1) on each side = 4 chars overhead; subtract 2 extra
	// for safety to account for double-width rune edge cases.
	dashMaxW := mainW - 6
	if dashMaxW < 20 {
		dashMaxW = 20
	}
	{
		lines := strings.Split(dashboard, "\n")
		for i, l := range lines {
			lines[i] = xansi.Truncate(l, dashMaxW, "")
		}
		dashboard = strings.Join(lines, "\n")
	}

	dashboardStyled := MainPanelStyle.Width(mainW).Height(contentH).
		BorderForeground(mainBorder).Render(dashboard)

	body := lipgloss.JoinHorizontal(lipgloss.Top, sidebarStyled, dashboardStyled)

	// Seccomp (syscall) overlay takes top priority — container thread is frozen
	seccompOverlay := a.renderSeccompApprovalOverlay()
	if seccompOverlay != "" {
		return lipgloss.JoinVertical(lipgloss.Left, header, body, seccompOverlay)
	}
	// Network (proxy) approval overlay
	approvalOverlay := a.renderApprovalOverlay()
	if approvalOverlay != "" {
		return lipgloss.JoinVertical(lipgloss.Left, header, body, approvalOverlay)
	}
	return lipgloss.JoinVertical(lipgloss.Left, header, body, statusBar)
}

func (a App) renderStatusBar() string {
	// Flash message takes priority over normal status bar
	if a.flashText != "" && time.Now().Before(a.flashExpiry) {
		return " " + a.flashText
	}
	if a.searchMode {
		return fmt.Sprintf(" 🔍 SEARCH │ type name → Enter │ Esc: cancel │ > %s█", a.searchInput)
	}
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
		return " OUTPUT │ ↑↓ scroll │ e: new command │ Esc/q: back"
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
	case panelPolicy:
		if a.policyMode == "egress-add" {
			return " POLICY │ type domain → Enter │ Esc: cancel"
		}
		if a.policyMode == "egress-del-confirm" {
			return " POLICY │ y: confirm delete all egress rules │ any key: cancel"
		}
		if a.policyMode == "import" {
			return " POLICY │ type filename (.yaml/.json) → Enter │ Esc: cancel"
		}
		return " POLICY │ b: boot.autostart │ P: privileged │ N: nesting │ V: devlxd │ M: idmapIso │ 1-3: seccomp │ 4-7: apparmor │ a/d: egress │ e: export │ i: import │ r: refresh │ Esc: back"
	case panelDNS:
		return " DNS │ ↑↓ select │ a: allow │ x: deny │ u: unset │ Esc/q: back"
	case panelEvents:
		return " EVENTS │ ↑↓ scroll │ c: clear │ Esc/q: back"
	case panelInference:
		return " INFERENCE STATS │ ↑↓ scroll │ S: export │ Esc: back"
	case panelRouting:
		if a.routingInputMode {
			return " ROUTING │ type value → Enter │ Esc: cancel"
		}
		return " ROUTING │ ↑↓ select │ Enter: toggle │ a: add │ d: delete │ p: presets │ S: save │ Esc: back"
	case panelAudit:
		if a.auditFilterMode {
			return fmt.Sprintf(" AUDIT FILTER │ type to filter → Enter │ Esc: cancel │ > %s█", a.auditFilterInput)
		}
		return " API AUDIT │ p: setup proxy │ u: undo │ /: filter │ f: status │ S: export │ c: clear │ Esc: back"
	case panelCreate:
		return " CREATE │ follow prompts │ Esc: back"
	case panelExport:
		return " IMPORT │ type filename → Enter │ Esc: cancel"
	case panelResources:
		return " RESOURCES │ ↑↓ select │ Enter: edit │ Esc/q: back"
	case panelSnapshots:
		return " SNAPSHOTS │ ↑↓ select │ n: new │ c: clone │ R: restore │ D: delete │ Esc/q: back"
	default:
		searchIndicator := ""
		if a.searchFilter != "" {
			searchIndicator = fmt.Sprintf(" │ 🔍 \"%s\"", a.searchFilter)
		}
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			m := a.getMetric(c.Name)
			traceIndicator := ""
			if _, ok := a.tracers[c.Name]; ok {
				traceIndicator = " │ 🔬 tracing"
			}
			if c.Status == "Running" {
				return fmt.Sprintf(" %s │ %s │ CPU %.1f%% │ MEM %s │ [e]xec [l]ogs [t]race%s%s",
					c.Name, c.IP, m.CPUPercent,
					formatBytes(c.MemoryCur), traceIndicator, searchIndicator)
			}
			return fmt.Sprintf(" %s [%s] │ [s]tart%s", c.Name, strings.ToLower(c.Status), searchIndicator)
		}
		return "" + searchIndicator
	}
}

