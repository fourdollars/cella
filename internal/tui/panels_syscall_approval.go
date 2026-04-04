package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fourdoors/cella/internal/lxd"
)

// ── Seccomp Approval types ─────────────────────────────────────────────────

// SeccompApprovalRequest is the TUI-level message for a pending seccomp event.
// It wraps the LXD SeccompEvent and adds a response channel for the verdict.
type SeccompApprovalRequest struct {
	lxd.SeccompEvent
	ResponseCh chan lxd.SeccompVerdict
}

// seccompApprovalMsg is the Bubbletea Msg type used to deliver a new request to the model.
type seccompApprovalMsg SeccompApprovalRequest

// Package-level state for seccomp notify (mirrors proxy approval pattern)
var (
	globalSeccompApprovalCh         chan SeccompApprovalRequest
	globalListeningSeccompApprovals bool
)

// ── Listener command ───────────────────────────────────────────────────────

// listenSeccompApprovals blocks on the channel and returns a Msg when a request arrives.
func listenSeccompApprovals(ch chan SeccompApprovalRequest) tea.Cmd {
	return func() tea.Msg {
		req, ok := <-ch
		if !ok {
			return nil
		}
		return seccompApprovalMsg(req)
	}
}

// listenSeccompApprovalsContinue re-arms the listener after handling one request.
func (a App) listenSeccompApprovalsContinue() tea.Cmd {
	if globalSeccompApprovalCh == nil {
		return nil
	}
	return listenSeccompApprovals(globalSeccompApprovalCh)
}

// ── Handler ────────────────────────────────────────────────────────────────

// handleSeccompApprovalKey processes key presses while the seccomp overlay is visible.
// The container's kernel thread is frozen until a verdict is sent.
func (a *App) handleSeccompApprovalKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if a.pendingSeccompApproval == nil {
		return a, nil
	}

	req := a.pendingSeccompApproval

	switch msg.String() {
	case "y":
		// Allow this one occurrence
		req.ResponseCh <- lxd.SeccompVerdict{Allow: true}
		a.addEvent(fmt.Sprintf("👤 seccomp allowed (once): %s → %s (pid %d)",
			req.Container, req.Syscall, req.PID))
		a.pendingSeccompApproval = nil
		return a, a.listenSeccompApprovalsContinue()

	case "Y":
		// Allow permanently: add to the per-container allowlist and send verdict
		req.ResponseCh <- lxd.SeccompVerdict{Allow: true}
		a.addSeccompSyscallAllow(req.Container, req.Syscall)
		a.addEvent(fmt.Sprintf("👤+ seccomp allowed (permanent): %s → %s",
			req.Container, req.Syscall))
		a.pendingSeccompApproval = nil
		return a, a.listenSeccompApprovalsContinue()

	case "n", "N":
		// Deny with EPERM
		req.ResponseCh <- lxd.SeccompVerdict{Allow: false, Errno: 1}
		a.addEvent(fmt.Sprintf("⛔ seccomp denied: %s → %s (pid %d)",
			req.Container, req.Syscall, req.PID))
		a.pendingSeccompApproval = nil
		return a, a.listenSeccompApprovalsContinue()
	}

	return a, nil
}

// addSeccompSyscallAllow records a permanent per-container syscall allowance.
func (a *App) addSeccompSyscallAllow(container, syscall string) {
	if a.seccompAllowlist == nil {
		a.seccompAllowlist = make(map[string]map[string]bool)
	}
	if a.seccompAllowlist[container] == nil {
		a.seccompAllowlist[container] = make(map[string]bool)
	}
	a.seccompAllowlist[container][syscall] = true
}

// ── Render ─────────────────────────────────────────────────────────────────

// renderSeccompApprovalOverlay draws the seccomp approval prompt.
// Returns "" when there is no pending seccomp approval (overlay is hidden).
func (a App) renderSeccompApprovalOverlay() string {
	if a.pendingSeccompApproval == nil {
		return ""
	}

	req := a.pendingSeccompApproval

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#f39c12")).
		Background(lipgloss.Color("#1a1a2e")).
		Padding(0, 1)

	syscallStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#e74c3c"))

	containerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#e67e22"))

	pidStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#8b949e"))

	optStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#8b949e"))

	keyStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#27ae60"))

	warnStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#e74c3c")).
		Italic(true)

	title := titleStyle.Render("⚠ SYSCALL APPROVAL REQUIRED")

	info := fmt.Sprintf("  %s called %s  %s",
		containerStyle.Render(req.Container),
		syscallStyle.Render(req.Syscall),
		pidStyle.Render(fmt.Sprintf("(pid %d)", req.PID)))

	elapsed := time.Since(req.Time).Round(time.Millisecond)
	timeNote := warnStyle.Render(fmt.Sprintf("  ⏳ container thread frozen — waiting %s for your decision", elapsed))

	keys := fmt.Sprintf("  %s %s  %s %s  %s %s",
		keyStyle.Render("[y]"), optStyle.Render("allow once"),
		keyStyle.Render("[Y]"), optStyle.Render("allow always"),
		keyStyle.Render("[n]"), optStyle.Render("deny (EPERM)"))

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#f39c12")).
		Padding(0, 1).
		Width(a.width - 4).
		Render(title + "\n" + info + "\n" + timeNote + "\n" + keys)

	return box
}

// ── Background goroutine: seccomp event fan-in ─────────────────────────────

// startSeccompApprovalListener starts a goroutine that watches the LXD seccomp
// event stream and forwards events requiring operator approval to the TUI channel.
//
// Events for syscalls already in the permanent allowlist (set via [Y]) are
// auto-approved without surfacing to the TUI.
//
// A 30-second safety timeout auto-denies if the TUI is unresponsive, ensuring
// the container is never frozen indefinitely.
func startSeccompApprovalListener(
	socketPath string,
	approvalCh chan SeccompApprovalRequest,
	getAllowlist func(container, syscall string) bool,
) {
	go func() {
		client, err := lxd.NewClient(socketPath)
		if err != nil {
			return
		}

		mon := lxd.NewSeccompMonitor(socketPath)
		ctx := context.Background()

		_ = mon.Start(ctx, func(ev lxd.SeccompEvent) {
			// Check permanent allowlist first
			if getAllowlist(ev.Container, ev.Syscall) {
				_ = client.SendSeccompVerdict(ctx, ev.NotifyID, lxd.SeccompVerdict{Allow: true})
				return
			}

			responseCh := make(chan lxd.SeccompVerdict, 1)
			req := SeccompApprovalRequest{
				SeccompEvent: ev,
				ResponseCh:   responseCh,
			}

			// Non-blocking send — drop and auto-deny if TUI channel is full
			select {
			case approvalCh <- req:
				// Wait for the operator's decision (30s safety timeout)
				select {
				case verdict := <-responseCh:
					_ = client.SendSeccompVerdict(ctx, ev.NotifyID, verdict)
				case <-time.After(30 * time.Second):
					_ = client.SendSeccompVerdict(ctx, ev.NotifyID, lxd.SeccompVerdict{Allow: false, Errno: 1})
				}
			default:
				// TUI busy — deny immediately to unfreeze container
				_ = client.SendSeccompVerdict(ctx, ev.NotifyID, lxd.SeccompVerdict{Allow: false, Errno: 1})
			}
		})
	}()
}

// ── Z key: toggle dangerous syscall blocking per container ──────────────────

// toggleSeccompNotifyForContainer toggles dangerous syscall blocking for a
// container. Called from handlePolicyPanel when the operator presses "Z".
//
// Implementation uses LXD's security.syscalls.deny BPF filter syntax to
// block the DangerousSyscalls list at the container level. This is the
// correct LXD v5.x API for syscall restrictions — the old seccomp notify
// REST endpoint does not exist in LXD v5.x.
//
//	Enable:  applies security.syscalls.deny with the DangerousSyscalls list,
//	         so dangerous syscalls return EPERM. bpftrace monitoring continues
//	         to show syscall activity. The TUI approval overlay fires when
//	         bpftrace detects a dangerous syscall attempt.
//
//	Disable: clears security.syscalls.deny, restoring unrestricted access.
//
// Note: LXD requires a container restart to apply seccomp filter changes.
// cella applies the filter and warns the operator if the container is running.
func (a *App) toggleSeccompNotifyForContainer(containerName string) tea.Cmd {
	return func() tea.Msg {
		if a.client == nil {
			return errMsg(fmt.Errorf("syscall blocking requires LXD client"))
		}
		ctx := context.Background()

		// Check current deny list to determine toggle direction
		current, err := a.client.GetSyscallDenyList(ctx, containerName)
		if err != nil {
			return errMsg(fmt.Errorf("get syscall deny list: %w", err))
		}

		currentlyEnabled := len(current) > 0

		if currentlyEnabled {
			// Disable: clear the deny list
			if err := a.client.SetSyscallDenyList(ctx, containerName, nil); err != nil {
				return errMsg(fmt.Errorf("clear syscall deny list: %w", err))
			}
			return seccompNotifyToggleMsg{container: containerName, enabled: false}
		}

		// Enable: apply DangerousSyscalls deny list
		if err := a.client.SetSyscallDenyList(ctx, containerName, lxd.DangerousSyscalls); err != nil {
			return errMsg(fmt.Errorf("set syscall deny list: %w", err))
		}

		// Initialise bpftrace-based approval channel (idempotent — only once per process)
		// The approval overlay fires when bpftrace detects a dangerous syscall attempt.
		if globalSeccompApprovalCh == nil {
			globalSeccompApprovalCh = make(chan SeccompApprovalRequest, 16)
		}
		if !globalListeningSeccompApprovals {
			allowlistFn := func(container, syscall string) bool {
				if a.seccompAllowlist == nil {
					return false
				}
				if m, ok := a.seccompAllowlist[container]; ok {
					return m[syscall]
				}
				return false
			}
			startSeccompApprovalListener(a.client.SocketPath(), globalSeccompApprovalCh, allowlistFn)
			globalListeningSeccompApprovals = true
		}

		return seccompNotifyToggleMsg{container: containerName, enabled: true}
	}
}

// seccompNotifyToggleMsg is the Msg returned after toggling seccomp notify.
type seccompNotifyToggleMsg struct {
	container string
	enabled   bool
}
