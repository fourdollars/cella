package security

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DNSEntry represents a captured DNS query/response.
type DNSEntry struct {
	Domain    string
	IPs       []string  // resolved IP addresses
	SrcIP     string    // container IP that made the query
	QueryCount int64
	BytesSent int64     // estimated from packet sizes
	LastSeen  time.Time
	Status    string    // "allow", "deny", "" (unset)
}

// DNSMonitor captures DNS traffic on the bridge interface and maintains a lookup table.
type DNSMonitor struct {
	mu      sync.RWMutex
	entries map[string]*DNSEntry // key: domain name
	ipMap   map[string]string    // IP -> domain reverse lookup
	cancel  context.CancelFunc
	running bool
}

// NewDNSMonitor creates a new DNS monitor.
func NewDNSMonitor() *DNSMonitor {
	return &DNSMonitor{
		entries: make(map[string]*DNSEntry),
		ipMap:   make(map[string]string),
	}
}

// Start begins capturing DNS traffic using tcpdump on lxdbr0.
func (m *DNSMonitor) Start() error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.running = true
	m.mu.Unlock()

	go m.capture(ctx)
	return nil
}

// Stop stops the DNS capture.
func (m *DNSMonitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
	}
	m.running = false
}

// IsRunning returns whether the monitor is active.
func (m *DNSMonitor) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// Entries returns a snapshot of all DNS entries sorted by query count (desc).
func (m *DNSMonitor) Entries() []*DNSEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*DNSEntry, 0, len(m.entries))
	for _, e := range m.entries {
		cp := *e
		cp.IPs = append([]string{}, e.IPs...)
		result = append(result, &cp)
	}
	return result
}

// EntriesForContainer returns DNS entries that were queried by a specific container IP.
func (m *DNSMonitor) EntriesForContainer(containerIP string) []*DNSEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*DNSEntry, 0)
	for _, e := range m.entries {
		if e.SrcIP == containerIP {
			cp := *e
			cp.IPs = append([]string{}, e.IPs...)
			result = append(result, &cp)
		}
	}
	return result
}

// LookupDomain returns the domain name for a given IP (reverse lookup from captured DNS).
func (m *DNSMonitor) LookupDomain(ip string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ipMap[ip]
}

// SetStatus sets the allow/deny status for a domain.
func (m *DNSMonitor) SetStatus(domain, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.entries[domain]; ok {
		e.Status = status
	}
}

// ResolveAndAdd resolves a domain name and adds it to the entries map.
// Used when the user types a domain in the TUI.
func (m *DNSMonitor) ResolveAndAdd(domain, srcIP string) ([]string, error) {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", domain, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.entries[domain]
	if !exists {
		entry = &DNSEntry{
			Domain: domain,
			SrcIP:  srcIP,
		}
		m.entries[domain] = entry
	}

	// Merge IPs
	ipSet := make(map[string]bool)
	for _, ip := range entry.IPs {
		ipSet[ip] = true
	}
	for _, ip := range ips {
		if !ipSet[ip] {
			entry.IPs = append(entry.IPs, ip)
		}
		m.ipMap[ip] = domain
	}
	entry.LastSeen = time.Now()

	return ips, nil
}

// regex patterns for parsing tcpdump DNS output
var (
	// Match: "10.25.54.145.12345 > 10.25.54.1.53: 12345+ A? github.com. (28)"
	dnsQueryRe = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\.\d+ > \d+\.\d+\.\d+\.\d+\.53: \d+\+? (?:\[1au\] )?(?:A|AAAA)\? ([^\s]+)\.`)

	// Match: "10.25.54.1.53 > 10.25.54.145.12345: 12345 1/0/1 A 142.250.204.46 (55)"
	dnsResponseRe = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+\.53 > (\d+\.\d+\.\d+\.\d+)\.\d+: .+ A (\d+\.\d+\.\d+\.\d+)`)

	// Match multiple A records in response
	dnsMultiRe = regexp.MustCompile(`A (\d+\.\d+\.\d+\.\d+)`)
)

func (m *DNSMonitor) capture(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}

		cmd := exec.CommandContext(ctx, "sudo", "-n", "tcpdump",
			"-l", "-i", bridgeIf, "-n", "port", "53")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		cmd.Stderr = nil // suppress stderr

		if err := cmd.Start(); err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		scanner := bufio.NewScanner(stdout)
		var lastDomain string
		var lastSrcIP string

		for scanner.Scan() {
			line := scanner.Text()

			// Parse DNS query
			if matches := dnsQueryRe.FindStringSubmatch(line); len(matches) >= 3 {
				srcIP := matches[1]
				domain := strings.TrimSuffix(matches[2], ".")
				lastDomain = domain
				lastSrcIP = srcIP

				m.mu.Lock()
				entry, exists := m.entries[domain]
				if !exists {
					entry = &DNSEntry{
						Domain: domain,
						SrcIP:  srcIP,
					}
					m.entries[domain] = entry
				}
				entry.QueryCount++
				entry.LastSeen = time.Now()
				if entry.SrcIP == "" {
					entry.SrcIP = srcIP
				}
				m.mu.Unlock()
			}

			// Parse DNS response (A record)
			if aMatches := dnsMultiRe.FindAllStringSubmatch(line, -1); len(aMatches) > 0 {
				// Figure out which domain this response is for
				domain := lastDomain
				srcIP := lastSrcIP

				// Try to extract destination IP (the container that asked)
				if rMatches := dnsResponseRe.FindStringSubmatch(line); len(rMatches) >= 2 {
					srcIP = rMatches[1]
				}

				m.mu.Lock()
				entry, exists := m.entries[domain]
				if !exists && domain != "" {
					entry = &DNSEntry{
						Domain: domain,
						SrcIP:  srcIP,
					}
					m.entries[domain] = entry
				}
				if entry != nil {
					ipSet := make(map[string]bool)
					for _, ip := range entry.IPs {
						ipSet[ip] = true
					}
					for _, am := range aMatches {
						ip := am[1]
						if !ipSet[ip] {
							entry.IPs = append(entry.IPs, ip)
							ipSet[ip] = true
						}
						m.ipMap[ip] = domain
					}
					entry.LastSeen = time.Now()
				}
				m.mu.Unlock()
			}
		}

		cmd.Wait()
		// If context not cancelled, restart after brief delay
		if ctx.Err() == nil {
			time.Sleep(1 * time.Second)
		}
	}
}
