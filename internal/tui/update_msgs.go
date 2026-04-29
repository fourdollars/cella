package tui

import (
	"fmt"
	"net"
	goruntime "runtime"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/fourdoors/cella/internal/runtime"
)

// updateContainers handles containersMsg, dispatched from Update().
func (a App) updateContainers(msg containersMsg) (tea.Model, tea.Cmd) {
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
	// Auto-setup proxy for containers loaded from persisted allow/deny lists
	var autoSetupCmds []tea.Cmd
	if len(a.pendingAutoSetup) > 0 {
		var stillPending []string
		for _, name := range a.pendingAutoSetup {
			// Find the container in the current list
			var found *runtime.ContainerInfo
			for i := range newContainers {
				if newContainers[i].Name == name {
					found = &newContainers[i]
					break
				}
			}
			if found != nil && (found.Runtime == "lxd" || found.Runtime == "docker") && found.Status == "Running" && found.IP != "" && found.IP != "-" && net.ParseIP(found.IP) != nil {
				a.addEvent(fmt.Sprintf("🔧 auto-setup proxy: %s (%s)", name, found.IP))
				autoSetupCmds = append(autoSetupCmds, a.autoSetupProxy(name, found.Runtime, globalProxyServer))
			} else {
				stillPending = append(stillPending, name)
			}
		}
		a.pendingAutoSetup = stillPending
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
	if len(autoSetupCmds) > 0 {
		return a, tea.Batch(autoSetupCmds...)
	}
	return a, nil

}

// updateTick handles tickMsg, dispatched from Update().
func (a App) updateTick() (tea.Model, tea.Cmd) {
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
