package metrics

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// CgroupV2Path is the base cgroup v2 mount point
const CgroupV2Path = "/sys/fs/cgroup"

// ReadCPUStat reads cpu.stat for a container's cgroup
func ReadCPUStat(cgroupPath string) (usageUsec int64, err error) {
	path := fmt.Sprintf("%s/cpu.stat", cgroupPath)
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[0] == "usage_usec" {
			usageUsec, err = strconv.ParseInt(fields[1], 10, 64)
			return
		}
	}
	return 0, fmt.Errorf("usage_usec not found in %s", path)
}

// ReadMemoryCurrent reads memory.current (bytes) for a cgroup
func ReadMemoryCurrent(cgroupPath string) (int64, error) {
	return readSingleInt64(fmt.Sprintf("%s/memory.current", cgroupPath))
}

// ReadMemoryMax reads memory.max (bytes) for a cgroup
func ReadMemoryMax(cgroupPath string) (int64, error) {
	content, err := os.ReadFile(fmt.Sprintf("%s/memory.max", cgroupPath))
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(content))
	if s == "max" {
		return 0, nil // unlimited
	}
	return strconv.ParseInt(s, 10, 64)
}

// ReadIOStat reads io.stat for a cgroup
type IOStat struct {
	ReadBytes  int64
	WriteBytes int64
}

func ReadIOStat(cgroupPath string) (*IOStat, error) {
	path := fmt.Sprintf("%s/io.stat", cgroupPath)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stat := &IOStat{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		for _, field := range fields {
			parts := strings.SplitN(field, "=", 2)
			if len(parts) != 2 {
				continue
			}
			val, _ := strconv.ParseInt(parts[1], 10, 64)
			switch parts[0] {
			case "rbytes":
				stat.ReadBytes += val
			case "wbytes":
				stat.WriteBytes += val
			}
		}
	}
	return stat, nil
}

// readSingleInt64 reads a file containing a single int64 value
func readSingleInt64(path string) (int64, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64)
}
