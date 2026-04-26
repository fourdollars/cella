package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fourdoors/cella/internal/lxd"
)

// MergeProfiles overlays profile configs/devices in order and then overlays container config.
// Returns merged config/devices and origin maps for config keys and device.attr keys.
func MergeProfiles(order []string, profiles map[string]*lxd.Profile, containerCfg *lxd.InstanceConfig) (map[string]string, map[string]map[string]string, map[string]string) {
	mergedConfig := make(map[string]string)
	mergedDevices := make(map[string]map[string]string)
	origin := make(map[string]string) // origin for config keys and device.attr keys (key or device.attr)

	// Apply profiles in order
	for _, pname := range order {
		p, ok := profiles[pname]
		if !ok || p == nil {
			continue
		}
		for k, v := range p.Config {
			mergedConfig[k] = v
			origin[k] = pname
		}
		for devName, attrs := range p.Devices {
			if mergedDevices[devName] == nil {
				mergedDevices[devName] = make(map[string]string)
			}
			for ak, av := range attrs {
				mergedDevices[devName][ak] = av
				origin[fmt.Sprintf("%s.%s", devName, ak)] = pname
			}
		}
	}

	// Overlay container config
	if containerCfg != nil {
		for k, v := range containerCfg.Config {
			mergedConfig[k] = v
			origin[k] = "container"
		}
		for devName, attrs := range containerCfg.Devices {
			if mergedDevices[devName] == nil {
				mergedDevices[devName] = make(map[string]string)
			}
			for ak, av := range attrs {
				mergedDevices[devName][ak] = av
				origin[fmt.Sprintf("%s.%s", devName, ak)] = "container"
			}
		}
	}

	return mergedConfig, mergedDevices, origin
}

// FormatMerged returns a human-readable string of merged config/devices with origins.
func FormatMerged(order []string, profiles map[string]*lxd.Profile, containerCfg *lxd.InstanceConfig) string {
	mergedCfg, mergedDevs, origin := MergeProfiles(order, profiles, containerCfg)
	var b strings.Builder
	b.WriteString("Merged view (profiles overlay → container):\n")

	// Config
	b.WriteString("\nConfig:\n")
	if len(mergedCfg) == 0 {
		b.WriteString("  (none)\n")
	} else {
		keys := make([]string, 0, len(mergedCfg))
		for k := range mergedCfg {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			src := origin[k]
			if src == "" {
				src = "(unknown)"
			}
			b.WriteString(fmt.Sprintf("  %s = %q  <-- %s\n", k, mergedCfg[k], src))
		}
	}

	// Devices
	b.WriteString("\nDevices:\n")
	if len(mergedDevs) == 0 {
		b.WriteString("  (none)\n")
	} else {
		devNames := make([]string, 0, len(mergedDevs))
		for d := range mergedDevs {
			devNames = append(devNames, d)
		}
		sort.Strings(devNames)
		for _, d := range devNames {
			b.WriteString(fmt.Sprintf("  %s:\n", d))
			attrs := mergedDevs[d]
			keys := make([]string, 0, len(attrs))
			for k := range attrs {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				src := origin[fmt.Sprintf("%s.%s", d, k)]
				if src == "" {
					src = "(unknown)"
				}
				b.WriteString(fmt.Sprintf("    %s = %q  <-- %s\n", k, attrs[k], src))
			}
		}
	}

	return b.String()
}
