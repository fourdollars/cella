package tui

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fourdoors/cella/internal/runtime"
	"github.com/fourdoors/cella/internal/security"
)

// ── Policy info message type ──

type policyInfoMsg struct {
	egress      string
	seccomp     string
	apparmor    string
	privileged  bool
	nesting     bool
	syscallDeny []string // security.syscalls.deny list (empty = not set)
	err         error
}

// ── Fetch policy info ──

func (a App) fetchPolicyInfo(c runtime.ContainerInfo) tea.Cmd {
	name := c.Name
	rtName := c.Runtime
	return func() tea.Msg {
		var egress, seccompName, apparmorName string

		// Read egress rules (nftables)
		if rules, err := security.ListEgressRules(name); err == nil {
			egress = rules
		} else {
			egress = "(no egress rules)"
		}

		// Read seccomp profile from container config
		if rtName == "lxd" {
			out, err := exec.Command("lxc", "config", "get", name, "raw.lxc").CombinedOutput()
			if err == nil {
				raw := strings.TrimSpace(string(out))
				if strings.Contains(raw, "seccomp") {
					// Try to extract the profile path and read its name
					parts := strings.SplitN(raw, "=", 2)
					if len(parts) == 2 {
						profPath := strings.TrimSpace(parts[1])
						if p, err := security.LoadProfile(profPath); err == nil && p.Name != "" {
							seccompName = p.Name
						} else {
							seccompName = profPath
						}
					} else {
						seccompName = raw
					}
				} else {
					seccompName = "(default)"
				}
			} else {
				seccompName = "(unknown)"
			}
		} else {
			seccompName = "(docker default)"
		}

		// Read AppArmor profile
		if rtName == "lxd" {
			profileName, err := security.ReadAppArmorProfile(name)
			if err == nil {
				apparmorName = profileName
			} else {
				apparmorName = "(unknown)"
			}

			// Check security flags
			var privileged, nesting bool
			out2, err2 := exec.Command("lxc", "config", "get", name, "security.nesting").CombinedOutput()
			if err2 == nil && strings.TrimSpace(string(out2)) == "true" {
				nesting = true
			}
			out3, err3 := exec.Command("lxc", "config", "get", name, "security.privileged").CombinedOutput()
			if err3 == nil && strings.TrimSpace(string(out3)) == "true" {
				privileged = true
			}

			// Read syscall deny list (security.syscalls.deny)
			var syscallDenyList []string
			out4, err4 := exec.Command("lxc", "config", "get", name, "security.syscalls.deny").CombinedOutput()
			if err4 == nil {
				raw4 := strings.TrimSpace(string(out4))
				if raw4 != "" {
					for _, part := range strings.Fields(raw4) {
						// strip :errno=N suffix
						if idx := strings.Index(part, ":"); idx >= 0 {
							part = part[:idx]
						}
						syscallDenyList = append(syscallDenyList, part)
					}
				}
			}

			return policyInfoMsg{
				egress:      egress,
				seccomp:     seccompName,
				apparmor:    apparmorName,
				privileged:  privileged,
				nesting:     nesting,
				syscallDeny: syscallDenyList,
			}
		} else {
			apparmorName = "(docker default)"
		}

		return policyInfoMsg{
			egress:     egress,
			seccomp:    seccompName,
			apparmor:   apparmorName,
			privileged: false,
			nesting:    false,
		}
	}
}

// ── Policy panel handler ──

func (a App) handlePolicyPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if a.policyMode == "egress-del-confirm" {
		switch msg.String() {
		case "y", "Y":
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				if err := security.RemoveEgressRules(c.Name, c.IP); err != nil {
					a.addEvent(fmt.Sprintf("⚠ egress remove failed: %v", err))
				} else {
					a.addEvent(fmt.Sprintf("🛡 egress rules removed for %s", c.Name))
				}
				a.policyMode = "view"
				return a, a.fetchPolicyInfo(c)
			}
		default:
			a.policyMode = "view"
		}
		return a, nil
	}

	if a.policyMode == "import" {
		key := msg.String()
		switch {
		case key == "enter":
			path := strings.TrimSpace(a.policyInput)
			if path != "" && a.selected < len(a.containers) {
				c := a.containers[a.selected]
				if err := security.ImportPolicy(c.Name, path); err != nil {
					a.addEvent(fmt.Sprintf("⚠ import: %v", err))
				} else {
					a.addEvent(fmt.Sprintf("📄 policy imported from %s for %s", path, c.Name))
				}
				a.policyMode = "view"
				a.policyInput = ""
				return a, a.fetchPolicyInfo(c)
			}
			a.policyMode = "view"
			a.policyInput = ""
			return a, nil
		case key == "esc":
			a.policyMode = "view"
			a.policyInput = ""
			return a, nil
		case key == "backspace":
			if len(a.policyInput) > 0 {
				a.policyInput = a.policyInput[:len(a.policyInput)-1]
			}
			return a, nil
		default:
			if len(key) == 1 {
				a.policyInput += key
			}
			return a, nil
		}
	}

	if a.policyMode == "egress-add" {
		key := msg.String()
		switch {
		case key == "enter":
			domain := strings.TrimSpace(a.policyInput)
			if domain != "" && a.selected < len(a.containers) {
				c := a.containers[a.selected]
				// Resolve domain to IPv4 addresses only (nftables ip family)
				allIPs, err := net.LookupHost(domain)
				if err != nil {
					a.addEvent(fmt.Sprintf("⚠ resolve %s failed: %v", domain, err))
					a.policyMode = "view"
					a.policyInput = ""
					return a, nil
				}
				var ips []string
				for _, ip := range allIPs {
					if net.ParseIP(ip) != nil && !strings.Contains(ip, ":") {
						ips = append(ips, ip)
					}
				}
				if len(ips) == 0 {
					a.addEvent(fmt.Sprintf("⚠ %s has no IPv4 addresses", domain))
					a.policyMode = "view"
					a.policyInput = ""
					return a, nil
				}
				// Apply egress rule with resolved IPs
				rule := security.EgressRule{
					Container: c.Name,
					SrcIP:     c.IP,
					Allow:     ips,
				}
				if err := security.ApplyEgressRules(rule); err != nil {
					a.addEvent(fmt.Sprintf("⚠ egress add failed: %v", err))
				} else {
					a.addEvent(fmt.Sprintf("🛡 egress allow %s (%s) for %s", domain, strings.Join(ips, ","), c.Name))
				}
				// Refresh
				a.policyMode = "view"
				a.policyInput = ""
				return a, a.fetchPolicyInfo(c)
			}
			a.policyMode = "view"
			a.policyInput = ""
			return a, nil
		case key == "esc":
			a.policyMode = "view"
			a.policyInput = ""
			return a, nil
		case key == "backspace":
			if len(a.policyInput) > 0 {
				a.policyInput = a.policyInput[:len(a.policyInput)-1]
			}
			return a, nil
		default:
			if len(key) == 1 {
				a.policyInput += key
			}
			return a, nil
		}
	}

	switch msg.String() {
	case "esc", "q":
		a.focus = a.prevFocus
		return a, nil
	case "up", "k":
		if a.policyScroll > 0 {
			a.policyScroll--
		}
		return a, nil
	case "down", "j":
		a.policyScroll++
		return a, nil
	case "1":
		// Apply strict seccomp
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			a.applySeccompProfile(c.Name, c.Runtime, "strict")
			return a, a.fetchPolicyInfo(c)
		}
	case "2":
		// Apply moderate seccomp
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			a.applySeccompProfile(c.Name, c.Runtime, "moderate")
			return a, a.fetchPolicyInfo(c)
		}
	case "3":
		// Apply permissive seccomp
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			a.applySeccompProfile(c.Name, c.Runtime, "permissive")
			return a, a.fetchPolicyInfo(c)
		}
	case "a":
		// Add egress rule
		a.policyMode = "egress-add"
		a.policyInput = ""
		return a, nil
	case "d":
		// Remove all egress rules for container (with confirmation)
		if a.selected < len(a.containers) {
			name := a.containers[a.selected].Name
			a.policyMode = "egress-del-confirm"
			a.addEvent(fmt.Sprintf("🛡 Press 'y' to remove all egress rules for %s", name))
			return a, nil
		}
	case "r":
		// Refresh
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			return a, a.fetchPolicyInfo(c)
		}
	case "4":
		// AppArmor: default
		if a.selected < len(a.containers) && a.containers[a.selected].Runtime == "lxd" {
			c := a.containers[a.selected]
			if err := security.ApplyAppArmorProfile(c.Name, security.AppArmorDefault); err != nil {
				a.addEvent(fmt.Sprintf("⚠ apparmor: %v", err))
			} else {
				a.addEvent(fmt.Sprintf("🛡 apparmor → default for %s", c.Name))
			}
			return a, a.fetchPolicyInfo(c)
		}
	case "5":
		// AppArmor: hardened
		if a.selected < len(a.containers) && a.containers[a.selected].Runtime == "lxd" {
			c := a.containers[a.selected]
			if err := security.ApplyAppArmorProfile(c.Name, security.AppArmorHardened); err != nil {
				a.addEvent(fmt.Sprintf("⚠ apparmor: %v", err))
			} else {
				a.addEvent(fmt.Sprintf("🛡 apparmor → hardened for %s", c.Name))
			}
			return a, a.fetchPolicyInfo(c)
		}
	case "6":
		// AppArmor: net-restricted
		if a.selected < len(a.containers) && a.containers[a.selected].Runtime == "lxd" {
			c := a.containers[a.selected]
			if err := security.ApplyAppArmorProfile(c.Name, security.AppArmorNetRestricted); err != nil {
				a.addEvent(fmt.Sprintf("⚠ apparmor: %v", err))
			} else {
				a.addEvent(fmt.Sprintf("🛡 apparmor → net-restricted for %s", c.Name))
			}
			return a, a.fetchPolicyInfo(c)
		}
	case "7":
		// AppArmor: read-only
		if a.selected < len(a.containers) && a.containers[a.selected].Runtime == "lxd" {
			c := a.containers[a.selected]
			if err := security.ApplyAppArmorProfile(c.Name, security.AppArmorReadOnly); err != nil {
				a.addEvent(fmt.Sprintf("⚠ apparmor: %v", err))
			} else {
				a.addEvent(fmt.Sprintf("🛡 apparmor → read-only for %s", c.Name))
			}
			return a, a.fetchPolicyInfo(c)
		}
	case "e":
		// Export policy YAML
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			path := fmt.Sprintf("%s-policy.yaml", c.Name)
			if err := security.SavePolicyFile(c.Name, path); err != nil {
				a.addEvent(fmt.Sprintf("⚠ export failed: %v", err))
			} else {
				info, _ := os.Stat(path)
				size := int64(0)
				if info != nil {
					size = info.Size()
				}
				a.addEvent(fmt.Sprintf("📄 exported %s (%d bytes)", path, size))
				a.flashText = fmt.Sprintf("Policy exported: %s", path)
				a.flashExpiry = time.Now().Add(3 * time.Second)
			}
			return a, nil
		}
	case "i":
		// Import policy YAML — enter filename input mode
		a.policyMode = "import"
		a.policyInput = ""
		return a, nil
	case "Z":
		// Toggle seccomp notify (live operator approval) for LXD containers
		if a.selected < len(a.containers) && a.containers[a.selected].Runtime == "lxd" {
			c := a.containers[a.selected]
			return a, a.toggleSeccompNotifyForContainer(c.Name)
		}
	}
	return a, nil
}

// ── Apply seccomp profile ──

func (a *App) applySeccompProfile(name, rtName, profileName string) {
	if rtName == "lxd" {
		var profile security.SeccompProfile
		switch profileName {
		case "strict":
			profile = security.StrictProfile
		case "moderate":
			profile = security.ModerateProfile
		case "permissive":
			profile = security.PermissiveProfile
		}
		// Save profile to temp file and apply via lxc config
		tmpPath := fmt.Sprintf("/tmp/cella-seccomp-%s.json", name)
		if err := security.SaveProfile(tmpPath, &profile); err != nil {
			a.addEvent(fmt.Sprintf("⚠ seccomp save: %v", err))
			return
		}
		// Set raw.lxc seccomp path
		cmd := exec.Command("lxc", "config", "set", name,
			"raw.lxc", fmt.Sprintf("lxc.seccomp.profile = %s", tmpPath))
		if out, err := cmd.CombinedOutput(); err != nil {
			a.addEvent(fmt.Sprintf("⚠ seccomp apply: %s", strings.TrimSpace(string(out))))
		} else {
			a.addEvent(fmt.Sprintf("🛡 seccomp → %s for %s", profileName, name))
			a.policySeccomp = profileName
		}
	} else {
		a.addEvent(fmt.Sprintf("⚠ seccomp profiles for Docker require container restart (not yet supported)"))
	}
}

// ── Policy panel render ──

func (a App) renderPolicyPanel() string {
	var b strings.Builder

	if a.selected >= len(a.containers) {
		return "No container selected"
	}
	c := a.containers[a.selected]

	rtIcon := "🔷"
	if c.Runtime == "docker" {
		rtIcon = "🐳"
	}

	b.WriteString(TitleStyle.Render(fmt.Sprintf("🛡 Policy — %s %s %s ◆", rtIcon, c.Name, strings.ToUpper(c.Runtime))) + "\n\n")

	// Seccomp section
	b.WriteString(SectionHeaderStyle.Render("Seccomp Profile") + "\n")
	if a.policySeccomp != "" {
		b.WriteString(fmt.Sprintf("  Current: %s\n", a.policySeccomp))
	} else {
		b.WriteString("  Current: (loading...)\n")
	}
	// Show options with indicator for current
	profiles := []struct{ key, name string }{{"1", "strict"}, {"2", "moderate"}, {"3", "permissive"}}
	for _, p := range profiles {
		indicator := "  "
		if strings.Contains(strings.ToLower(a.policySeccomp), p.name) {
			indicator = "▸ "
		}
		b.WriteString(fmt.Sprintf("  %s[%s] %s\n", indicator, p.key, p.name))
	}
	b.WriteString("\n")

	// Syscall Blocking section (security.syscalls.deny)
	b.WriteString(SectionHeaderStyle.Render("Syscall Blocking (LXD BPF Deny)") + "\n")
	if len(a.policyDenyList) > 0 {
		activeStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#e74c3c"))
		b.WriteString(fmt.Sprintf("  Status: %s\n", activeStyle.Render("⛔ ACTIVE")))
		// Show first 8 blocked syscalls to avoid overflow
		shown := a.policyDenyList
		if len(shown) > 8 {
			shown = shown[:8]
		}
		b.WriteString(fmt.Sprintf("  Blocked: %s", strings.Join(shown, ", ")))
		if len(a.policyDenyList) > 8 {
			b.WriteString(fmt.Sprintf(" (+%d more)", len(a.policyDenyList)-8))
		}
		b.WriteString("\n")
		b.WriteString("  [Z] Disable blocking\n")
	} else {
		b.WriteString("  Status: 🟢 off\n")
		b.WriteString("  [Z] Enable (blocks ptrace/mount/bpf/kexec…)\n")
	}
	b.WriteString("\n")

	// AppArmor section
	b.WriteString(SectionHeaderStyle.Render("AppArmor") + "\n")
	b.WriteString(fmt.Sprintf("  Current: %s\n", a.policyAppArmor))

	// Show AppArmor profile options with indicator
	aaProfiles := []struct{ key, name string }{
		{"4", "default"},
		{"5", "hardened"},
		{"6", "net-restricted"},
		{"7", "read-only"},
	}
	for _, p := range aaProfiles {
		indicator := "  "
		if strings.Contains(strings.ToLower(a.policyAppArmor), p.name) {
			indicator = "▸ "
		}
		b.WriteString(fmt.Sprintf("  %s[%s] %s\n", indicator, p.key, p.name))
	}
	b.WriteString("\n")

	// Import mode prompt
	if a.policyMode == "import" {
		b.WriteString(SectionHeaderStyle.Render("Import Policy") + "\n")
		b.WriteString(fmt.Sprintf("  File: %s█\n\n", a.policyInput))
	}

	// Egress section
	b.WriteString(SectionHeaderStyle.Render("Egress Rules (nftables)") + "\n")
	if a.policyMode == "egress-add" {
		b.WriteString(fmt.Sprintf("  Add domain: %s█\n\n", a.policyInput))
	}
	if a.policyEgress != "" {
		lines := strings.Split(a.policyEgress, "\n")
		start := a.policyScroll
		if start >= len(lines) {
			start = len(lines) - 1
		}
		if start < 0 {
			start = 0
		}
		maxLines := a.height - 20
		if maxLines < 5 {
			maxLines = 5
		}
		end := start + maxLines
		if end > len(lines) {
			end = len(lines)
		}
		for _, line := range lines[start:end] {
			b.WriteString("  " + line + "\n")
		}
	} else {
		b.WriteString("  (loading...)\n")
	}

	// Security flags
	b.WriteString("\n")
	b.WriteString(SectionHeaderStyle.Render("Container Security Flags") + "\n")
	privIcon := "🟢 off"
	if a.policyPrivileged {
		privIcon = "🔴 ON (dangerous!)"
	}
	nestIcon := "🟢 off"
	if a.policyNesting {
		nestIcon = "🟡 on"
	}
	b.WriteString(fmt.Sprintf("  Privileged:  %s\n", privIcon))
	b.WriteString(fmt.Sprintf("  Nesting:     %s\n", nestIcon))

	return b.String()
}
