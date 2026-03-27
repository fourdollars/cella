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
	devlxd      bool
	idmapIso    bool
	syscallDeny []string // security.syscalls.deny list (empty = not set)
	// security.syscalls.intercept.*
	interceptMknod      bool
	interceptBpf        bool
	interceptBpfDev     bool
	interceptSetxattr   bool
	interceptSched      bool
	interceptSysinfo    bool
	interceptMount      bool
	interceptMountShift bool
	interceptMountFuse  string
	interceptMountAllow string
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
			var privileged, nesting, devlxd, idmapIso bool
			out2, err2 := exec.Command("lxc", "config", "get", name, "security.nesting").CombinedOutput()
			if err2 == nil && strings.TrimSpace(string(out2)) == "true" {
				nesting = true
			}
			out3, err3 := exec.Command("lxc", "config", "get", name, "security.privileged").CombinedOutput()
			if err3 == nil && strings.TrimSpace(string(out3)) == "true" {
				privileged = true
			}
			out5, err5 := exec.Command("lxc", "config", "get", name, "security.devlxd").CombinedOutput()
			if err5 == nil && strings.TrimSpace(string(out5)) == "false" {
				devlxd = false
			} else {
				devlxd = true // default is enabled
			}
			out6, err6 := exec.Command("lxc", "config", "get", name, "security.idmap.isolated").CombinedOutput()
			if err6 == nil && strings.TrimSpace(string(out6)) == "true" {
				idmapIso = true
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

			// Read security.syscalls.intercept.*
			lxcBool := func(key string) bool {
				o, e := exec.Command("lxc", "config", "get", name, key).CombinedOutput()
				return e == nil && strings.TrimSpace(string(o)) == "true"
			}
			lxcStr := func(key string) string {
				o, e := exec.Command("lxc", "config", "get", name, key).CombinedOutput()
				if e == nil {
					return strings.TrimSpace(string(o))
				}
				return ""
			}

			return policyInfoMsg{
				egress:              egress,
				seccomp:             seccompName,
				apparmor:            apparmorName,
				privileged:          privileged,
				nesting:             nesting,
				devlxd:              devlxd,
				idmapIso:            idmapIso,
				syscallDeny:         syscallDenyList,
				interceptMknod:      lxcBool("security.syscalls.intercept.mknod"),
				interceptBpf:        lxcBool("security.syscalls.intercept.bpf"),
				interceptBpfDev:     lxcBool("security.syscalls.intercept.bpf.devices"),
				interceptSetxattr:   lxcBool("security.syscalls.intercept.setxattr"),
				interceptSched:      lxcBool("security.syscalls.intercept.sched_setscheduler"),
				interceptSysinfo:    lxcBool("security.syscalls.intercept.sysinfo"),
				interceptMount:      lxcBool("security.syscalls.intercept.mount"),
				interceptMountShift: lxcBool("security.syscalls.intercept.mount.shift"),
				interceptMountFuse:  lxcStr("security.syscalls.intercept.mount.fuse"),
				interceptMountAllow: lxcStr("security.syscalls.intercept.mount.allowed"),
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
	// intercept-mount-fuse input mode
	if a.policyMode == "intercept-mount-fuse" {
		key := msg.String()
		switch {
		case key == "enter":
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				val := strings.TrimSpace(a.policyInput)
				var cmd *exec.Cmd
				if val == "" {
					cmd = exec.Command("lxc", "config", "unset", c.Name, "security.syscalls.intercept.mount.fuse")
				} else {
					cmd = exec.Command("lxc", "config", "set", c.Name, "security.syscalls.intercept.mount.fuse", val)
				}
				if out, err := cmd.CombinedOutput(); err != nil {
					a.addEvent(fmt.Sprintf("⚠ mount.fuse: %s", strings.TrimSpace(string(out))))
				} else {
					a.addEvent(fmt.Sprintf("🛡 %s intercept.mount.fuse → %q", c.Name, val))
				}
				a.policyMode = "view"
				a.policyInput = ""
				return a, a.fetchPolicyInfo(c)
			}
			a.policyMode = "view"; a.policyInput = ""; return a, nil
		case key == "esc":
			a.policyMode = "view"; a.policyInput = ""; return a, nil
		case key == "backspace":
			if len(a.policyInput) > 0 { a.policyInput = a.policyInput[:len(a.policyInput)-1] }
			return a, nil
		default:
			if len(key) == 1 { a.policyInput += key }
			return a, nil
		}
	}

	// intercept-mount-allowed input mode
	if a.policyMode == "intercept-mount-allowed" {
		key := msg.String()
		switch {
		case key == "enter":
			if a.selected < len(a.containers) {
				c := a.containers[a.selected]
				val := strings.TrimSpace(a.policyInput)
				var cmd *exec.Cmd
				if val == "" {
					cmd = exec.Command("lxc", "config", "unset", c.Name, "security.syscalls.intercept.mount.allowed")
				} else {
					cmd = exec.Command("lxc", "config", "set", c.Name, "security.syscalls.intercept.mount.allowed", val)
				}
				if out, err := cmd.CombinedOutput(); err != nil {
					a.addEvent(fmt.Sprintf("⚠ mount.allowed: %s", strings.TrimSpace(string(out))))
				} else {
					a.addEvent(fmt.Sprintf("🛡 %s intercept.mount.allowed → %q", c.Name, val))
				}
				a.policyMode = "view"
				a.policyInput = ""
				return a, a.fetchPolicyInfo(c)
			}
			a.policyMode = "view"; a.policyInput = ""; return a, nil
		case key == "esc":
			a.policyMode = "view"; a.policyInput = ""; return a, nil
		case key == "backspace":
			if len(a.policyInput) > 0 { a.policyInput = a.policyInput[:len(a.policyInput)-1] }
			return a, nil
		default:
			if len(key) == 1 { a.policyInput += key }
			return a, nil
		}
	}

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
		// Navigate to previous container
		if a.selected > 0 {
			a.selected--
			a.policyScroll = 0
			if a.selected < len(a.containers) {
				return a, a.fetchPolicyInfo(a.containers[a.selected])
			}
		}
		return a, nil
	case "down", "j":
		// Navigate to next container
		if a.selected < len(a.containers)-1 {
			a.selected++
			a.policyScroll = 0
			if a.selected < len(a.containers) {
				return a, a.fetchPolicyInfo(a.containers[a.selected])
			}
		}
		return a, nil
	case "[":
		if a.policyScroll > 0 {
			a.policyScroll--
		}
		return a, nil
	case "]":
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
	case "P":
		// Toggle security.privileged
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			if c.Runtime != "lxd" {
				a.addEvent("⚠ security.privileged: LXD only")
				return a, nil
			}
			newVal := "true"
			if a.policyPrivileged {
				newVal = "false"
			}
			if out, err := exec.Command("lxc", "config", "set", c.Name, "security.privileged", newVal).CombinedOutput(); err != nil {
				a.addEvent(fmt.Sprintf("⚠ privileged: %s", strings.TrimSpace(string(out))))
			} else {
				a.addEvent(fmt.Sprintf("🛡 %s security.privileged → %s", c.Name, newVal))
			}
			return a, a.fetchPolicyInfo(c)
		}
	case "N":
		// Toggle security.nesting
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			if c.Runtime != "lxd" {
				a.addEvent("⚠ security.nesting: LXD only")
				return a, nil
			}
			newVal := "true"
			if a.policyNesting {
				newVal = "false"
			}
			if out, err := exec.Command("lxc", "config", "set", c.Name, "security.nesting", newVal).CombinedOutput(); err != nil {
				a.addEvent(fmt.Sprintf("⚠ nesting: %s", strings.TrimSpace(string(out))))
			} else {
				a.addEvent(fmt.Sprintf("🛡 %s security.nesting → %s", c.Name, newVal))
			}
			return a, a.fetchPolicyInfo(c)
		}
	case "V":
		// Toggle security.devlxd
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			if c.Runtime != "lxd" {
				a.addEvent("⚠ security.devlxd: LXD only")
				return a, nil
			}
			newVal := "false"
			if !a.policyDevLXD {
				newVal = "true"
			}
			if out, err := exec.Command("lxc", "config", "set", c.Name, "security.devlxd", newVal).CombinedOutput(); err != nil {
				a.addEvent(fmt.Sprintf("⚠ devlxd: %s", strings.TrimSpace(string(out))))
			} else {
				a.addEvent(fmt.Sprintf("🛡 %s security.devlxd → %s", c.Name, newVal))
			}
			return a, a.fetchPolicyInfo(c)
		}
	case "M":
		// Toggle security.idmap.isolated
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			if c.Runtime != "lxd" {
				a.addEvent("⚠ security.idmap.isolated: LXD only")
				return a, nil
			}
			newVal := "true"
			if a.policyIdmapIso {
				newVal = "false"
			}
			if out, err := exec.Command("lxc", "config", "set", c.Name, "security.idmap.isolated", newVal).CombinedOutput(); err != nil {
				a.addEvent(fmt.Sprintf("⚠ idmap.isolated: %s", strings.TrimSpace(string(out))))
			} else {
				a.addEvent(fmt.Sprintf("🛡 %s security.idmap.isolated → %s", c.Name, newVal))
			}
			return a, a.fetchPolicyInfo(c)
		}

	// ── syscalls.intercept toggles ──
	case "I":
		// Toggle security.syscalls.intercept.mknod
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			if c.Runtime != "lxd" { a.addEvent("⚠ intercept.mknod: LXD only"); return a, nil }
			return a.toggleInterceptBool(c, "security.syscalls.intercept.mknod", a.policyInterceptMknod)
		}
	case "B":
		// Toggle security.syscalls.intercept.bpf
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			if c.Runtime != "lxd" { a.addEvent("⚠ intercept.bpf: LXD only"); return a, nil }
			return a.toggleInterceptBool(c, "security.syscalls.intercept.bpf", a.policyInterceptBpf)
		}
	case "O":
		// Toggle security.syscalls.intercept.bpf.devices
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			if c.Runtime != "lxd" { a.addEvent("⚠ intercept.bpf.devices: LXD only"); return a, nil }
			return a.toggleInterceptBool(c, "security.syscalls.intercept.bpf.devices", a.policyInterceptBpfDev)
		}
	case "X":
		// Toggle security.syscalls.intercept.setxattr
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			if c.Runtime != "lxd" { a.addEvent("⚠ intercept.setxattr: LXD only"); return a, nil }
			return a.toggleInterceptBool(c, "security.syscalls.intercept.setxattr", a.policyInterceptSetxattr)
		}
	case "C":
		// Toggle security.syscalls.intercept.sched_setscheduler
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			if c.Runtime != "lxd" { a.addEvent("⚠ intercept.sched: LXD only"); return a, nil }
			return a.toggleInterceptBool(c, "security.syscalls.intercept.sched_setscheduler", a.policyInterceptSched)
		}
	case "Y":
		// Toggle security.syscalls.intercept.sysinfo
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			if c.Runtime != "lxd" { a.addEvent("⚠ intercept.sysinfo: LXD only"); return a, nil }
			return a.toggleInterceptBool(c, "security.syscalls.intercept.sysinfo", a.policyInterceptSysinfo)
		}
	case "U":
		// Toggle security.syscalls.intercept.mount
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			if c.Runtime != "lxd" { a.addEvent("⚠ intercept.mount: LXD only"); return a, nil }
			return a.toggleInterceptBool(c, "security.syscalls.intercept.mount", a.policyInterceptMount)
		}
	case "H":
		// Toggle security.syscalls.intercept.mount.shift
		if a.selected < len(a.containers) {
			c := a.containers[a.selected]
			if c.Runtime != "lxd" { a.addEvent("⚠ intercept.mount.shift: LXD only"); return a, nil }
			return a.toggleInterceptBool(c, "security.syscalls.intercept.mount.shift", a.policyInterceptMountShift)
		}
	case "F":
		// Edit security.syscalls.intercept.mount.fuse (string input)
		if a.selected < len(a.containers) && a.containers[a.selected].Runtime == "lxd" {
			a.policyMode = "intercept-mount-fuse"
			a.policyInput = a.policyInterceptMountFuse
			return a, nil
		}
	case "L":
		// Edit security.syscalls.intercept.mount.allowed (string input)
		if a.selected < len(a.containers) && a.containers[a.selected].Runtime == "lxd" {
			a.policyMode = "intercept-mount-allowed"
			a.policyInput = a.policyInterceptMountAllow
			return a, nil
		}
	}
	return a, nil
}

// ── toggleInterceptBool helper ──
func (a App) toggleInterceptBool(c runtime.ContainerInfo, key string, current bool) (tea.Model, tea.Cmd) {
	newVal := "true"
	if current {
		newVal = "false"
	}
	if out, err := exec.Command("lxc", "config", "set", c.Name, key, newVal).CombinedOutput(); err != nil {
		a.addEvent(fmt.Sprintf("⚠ %s: %s", key, strings.TrimSpace(string(out))))
	} else {
		shortKey := key[len("security.syscalls.intercept."):]
		a.addEvent(fmt.Sprintf("🛡 %s intercept.%s → %s", c.Name, shortKey, newVal))
	}
	return a, a.fetchPolicyInfo(c)
}

// Intercept string input modes are handled at the top of handlePolicyPanel.

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
	if a.selected >= len(a.containers) {
		return "No container selected"
	}
	c := a.containers[a.selected]

	rtIcon := "🔷"
	if c.Runtime == "docker" {
		rtIcon = "🐳"
	}

	title := TitleStyle.Render(fmt.Sprintf("🛡 Policy — %s %s %s ◆", rtIcon, c.Name, strings.ToUpper(c.Runtime)))

	keyHint := lipgloss.NewStyle().Foreground(lipgloss.Color("#f0a500")).Bold(true)
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#666"))
	on := lipgloss.NewStyle().Foreground(lipgloss.Color("#27ae60")).Render("🟢")
	off := lipgloss.NewStyle().Foreground(lipgloss.Color("#555")).Render("⚫")
	boolIcon := func(v bool) string {
		if v { return on }
		return off
	}
	strVal := func(v string) string {
		if v == "" { return dim.Render("(unset)") }
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#7ec8e3")).Render(v)
	}

	// ── Left column: Seccomp + Syscall Blocking + AppArmor ──
	var left strings.Builder

	// Seccomp
	left.WriteString(SectionHeaderStyle.Render("Seccomp") + "\n")
	seccomp := a.policySeccomp
	if seccomp == "" { seccomp = "(loading...)" }
	left.WriteString(fmt.Sprintf("  %s\n", seccomp))
	for _, p := range []struct{ key, name string }{{"1", "strict"}, {"2", "moderate"}, {"3", "permissive"}} {
		ind := "  "
		if strings.Contains(strings.ToLower(a.policySeccomp), p.name) { ind = "▸ " }
		left.WriteString(fmt.Sprintf("  %s[%s] %s\n", ind, p.key, p.name))
	}

	left.WriteString("\n")

	// Syscall Blocking (BPF deny)
	left.WriteString(SectionHeaderStyle.Render("Syscall Block [Z]") + "\n")
	if len(a.policyDenyList) > 0 {
		activeStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#e74c3c"))
		left.WriteString(fmt.Sprintf("  %s\n", activeStyle.Render("⛔ ACTIVE")))
		shown := a.policyDenyList
		if len(shown) > 5 { shown = shown[:5] }
		left.WriteString(fmt.Sprintf("  %s", strings.Join(shown, ", ")))
		if len(a.policyDenyList) > 5 { left.WriteString(fmt.Sprintf(" +%d", len(a.policyDenyList)-5)) }
		left.WriteString("\n")
	} else {
		left.WriteString(fmt.Sprintf("  %s\n", dim.Render("off — [Z] enable")))
	}

	left.WriteString("\n")

	// AppArmor
	left.WriteString(SectionHeaderStyle.Render("AppArmor") + "\n")
	aa := a.policyAppArmor
	if aa == "" { aa = "(loading...)" }
	left.WriteString(fmt.Sprintf("  %s\n", aa))
	for _, p := range []struct{ key, name string }{{"4", "default"}, {"5", "hardened"}, {"6", "net-restricted"}, {"7", "read-only"}} {
		ind := "  "
		if strings.Contains(strings.ToLower(a.policyAppArmor), p.name) { ind = "▸ " }
		left.WriteString(fmt.Sprintf("  %s[%s] %s\n", ind, p.key, p.name))
	}

	// ── Right column: Security Flags + Syscall Intercept ──
	var right strings.Builder

	// Security Flags
	right.WriteString(SectionHeaderStyle.Render("Security Flags") + "\n")
	label := func(v bool) string {
		if v { return "on" }
		return dim.Render("off")
	}
	privLabel := label(a.policyPrivileged)
	if a.policyPrivileged { privLabel = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#e74c3c")).Render("ON!") }
	right.WriteString(fmt.Sprintf("  (%s)rivileged  %s %s\n", keyHint.Render("P"), boolIcon(a.policyPrivileged), privLabel))
	right.WriteString(fmt.Sprintf("  (%s)esting     %s %s\n", keyHint.Render("N"), boolIcon(a.policyNesting), label(a.policyNesting)))
	right.WriteString(fmt.Sprintf("  (%s)evLXD      %s %s\n", keyHint.Render("V"), boolIcon(a.policyDevLXD), label(a.policyDevLXD)))
	right.WriteString(fmt.Sprintf("  (%s)dmapIso    %s %s\n", keyHint.Render("M"), boolIcon(a.policyIdmapIso), label(a.policyIdmapIso)))

	right.WriteString("\n")

	// Syscall Intercept
	right.WriteString(SectionHeaderStyle.Render("Syscall Intercept") + "\n")
	right.WriteString(fmt.Sprintf("  (%s) mknod         %s %s\n", keyHint.Render("I"), boolIcon(a.policyInterceptMknod), label(a.policyInterceptMknod)))
	right.WriteString(fmt.Sprintf("  (%s) bpf           %s %s\n", keyHint.Render("B"), boolIcon(a.policyInterceptBpf), label(a.policyInterceptBpf)))
	right.WriteString(fmt.Sprintf("  (%s) bpf.devices   %s %s\n", keyHint.Render("O"), boolIcon(a.policyInterceptBpfDev), label(a.policyInterceptBpfDev)))
	right.WriteString(fmt.Sprintf("  (%s) setxattr      %s %s\n", keyHint.Render("X"), boolIcon(a.policyInterceptSetxattr), label(a.policyInterceptSetxattr)))
	right.WriteString(fmt.Sprintf("  (%s) sched_set     %s %s\n", keyHint.Render("C"), boolIcon(a.policyInterceptSched), label(a.policyInterceptSched)))
	right.WriteString(fmt.Sprintf("  (%s) sysinfo       %s %s\n", keyHint.Render("Y"), boolIcon(a.policyInterceptSysinfo), label(a.policyInterceptSysinfo)))
	right.WriteString(fmt.Sprintf("  (%s) mount         %s %s\n", keyHint.Render("U"), boolIcon(a.policyInterceptMount), label(a.policyInterceptMount)))
	right.WriteString(fmt.Sprintf("  (%s) mount.shift   %s %s\n", keyHint.Render("H"), boolIcon(a.policyInterceptMountShift), label(a.policyInterceptMountShift)))
	if a.policyMode == "intercept-mount-fuse" {
		right.WriteString(fmt.Sprintf("  (%s) mount.fuse    %s█\n", keyHint.Render("F"), a.policyInput))
	} else {
		right.WriteString(fmt.Sprintf("  (%s) mount.fuse    %s\n", keyHint.Render("F"), strVal(a.policyInterceptMountFuse)))
	}
	if a.policyMode == "intercept-mount-allowed" {
		right.WriteString(fmt.Sprintf("  (%s) mount.allowed %s█\n", keyHint.Render("L"), a.policyInput))
	} else {
		right.WriteString(fmt.Sprintf("  (%s) mount.allowed %s\n", keyHint.Render("L"), strVal(a.policyInterceptMountAllow)))
	}

	// ── Two-column join ──
	colW := (a.width - 6) / 2
	if colW < 28 { colW = 28 }
	colStyle := lipgloss.NewStyle().Width(colW)
	columns := lipgloss.JoinHorizontal(lipgloss.Top,
		colStyle.Render(left.String()),
		colStyle.Render(right.String()),
	)

	// ── Bottom: Egress (full width, limited height) ──
	var egress strings.Builder
	egress.WriteString(SectionHeaderStyle.Render("Egress Rules (nftables)") + "\n")
	if a.policyMode == "egress-add" {
		egress.WriteString(fmt.Sprintf("  Add domain: %s█\n", a.policyInput))
	} else if a.policyMode == "import" {
		egress.WriteString(fmt.Sprintf("  Import file: %s█\n", a.policyInput))
	}
	if a.policyEgress != "" {
		lines := strings.Split(a.policyEgress, "\n")
		start := a.policyScroll
		if start < 0 { start = 0 }
		if start >= len(lines) { start = len(lines) - 1 }
		maxLines := 4
		end := start + maxLines
		if end > len(lines) { end = len(lines) }
		for _, line := range lines[start:end] {
			egress.WriteString("  " + line + "\n")
		}
		if len(lines) > maxLines {
			egress.WriteString(dim.Render(fmt.Sprintf("  [/] scroll (%d/%d lines)", start+maxLines, len(lines))) + "\n")
		}
	} else {
		egress.WriteString(dim.Render("  (no egress rules)") + "\n")
	}

	// ── Status bar ──
	hint := dim.Render("(r)efresh  ↑↓ switch container  (a) add egress  (d) remove  (e) export  (i) import  (esc) back")

	return title + "\n\n" + columns + "\n" + egress.String() + "\n" + hint
}
