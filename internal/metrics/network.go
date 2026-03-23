package metrics

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// NetStats holds network counters for a veth interface
type NetStats struct {
	RxBytes   int64
	TxBytes   int64
	RxPackets int64
	TxPackets int64
}

// ReadNetStats reads /sys/class/net/<iface>/statistics counters
func ReadNetStats(iface string) (*NetStats, error) {
	base := fmt.Sprintf("/sys/class/net/%s/statistics", iface)

	rxBytes, err := readSysfsInt64(base + "/rx_bytes")
	if err != nil {
		return nil, fmt.Errorf("read rx_bytes for %s: %w", iface, err)
	}

	txBytes, err := readSysfsInt64(base + "/tx_bytes")
	if err != nil {
		return nil, fmt.Errorf("read tx_bytes for %s: %w", iface, err)
	}

	rxPkts, _ := readSysfsInt64(base + "/rx_packets")
	txPkts, _ := readSysfsInt64(base + "/tx_packets")

	return &NetStats{
		RxBytes:   rxBytes,
		TxBytes:   txBytes,
		RxPackets: rxPkts,
		TxPackets: txPkts,
	}, nil
}

// FindVethForContainer finds the host veth interface paired with a container
func FindVethForContainer(containerPID int) (string, error) {
	// Read /proc/<pid>/net/dev to get the ifindex inside container
	// Then find matching veth on host
	// This is a simplified version — real implementation would use netlink
	path := fmt.Sprintf("/proc/%d/net/dev", containerPID)
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "eth0:") {
			// Found container's eth0; need to map to host veth
			// This requires additional netlink work
			return "", fmt.Errorf("veth mapping not yet implemented")
		}
	}
	return "", fmt.Errorf("no eth0 found for PID %d", containerPID)
}

func readSysfsInt64(path string) (int64, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64)
}
