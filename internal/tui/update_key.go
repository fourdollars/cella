package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/fourdoors/cella/internal/proxy"
	"github.com/fourdoors/cella/internal/security"
	"github.com/fourdoors/cella/internal/trace"
)

// updateKey handles all tea.KeyMsg events, dispatched from Update().
func (a App) updateKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
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
	if a.focus == panelBroker {
		return a.handleBrokerPanel(msg)
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
	case "B":
		// Token Broker panel
		a.prevFocus = a.focus
		a.focus = panelBroker
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

	return a, nil
}
