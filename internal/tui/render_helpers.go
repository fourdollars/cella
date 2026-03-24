package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ── Render utility functions ──

func renderBar(label string, value, max float64, color lipgloss.Color, width int) string {
	pct := value / max
	if pct > 1 {
		pct = 1
	}
	if pct < 0 {
		pct = 0
	}
	filled := int(pct * float64(width))
	bar := lipgloss.NewStyle().Foreground(color).Render(strings.Repeat("█", filled)) +
		lipgloss.NewStyle().Foreground(ColorDim).Render(strings.Repeat("░", width-filled))
	if label != "" {
		return fmt.Sprintf("  %s %s", MetricLabelStyle.Render(label), bar)
	}
	return fmt.Sprintf("  %s", bar)
}

var sparkChars = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

func renderSparkline(data []float64, color lipgloss.Color) string {
	if len(data) == 0 {
		return ""
	}
	maxVal := 0.0
	for _, v := range data {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal == 0 {
		maxVal = 1
	}

	var sb strings.Builder
	for _, v := range data {
		idx := int(v / maxVal * float64(len(sparkChars)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkChars) {
			idx = len(sparkChars) - 1
		}
		sb.WriteRune(sparkChars[idx])
	}
	return lipgloss.NewStyle().Foreground(color).Render(sb.String())
}

// parseCPUPins parses limits.cpu value and returns pinned CPU IDs if it's a range/list
// Returns nil if it's a plain count (e.g. "2") or empty
func parseCPUPins(cpuLimit string) []int {
	cpuLimit = strings.TrimSpace(cpuLimit)
	if cpuLimit == "" {
		return nil
	}
	// Check if it's a range like "2-3" or "0-3" or list "0,2,4"
	if strings.Contains(cpuLimit, "-") && !strings.Contains(cpuLimit, "ms") {
		// Range: "2-3"
		parts := strings.SplitN(cpuLimit, "-", 2)
		start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil {
			return nil
		}
		var pins []int
		for i := start; i <= end; i++ {
			pins = append(pins, i)
		}
		return pins
	}
	if strings.Contains(cpuLimit, ",") {
		// List: "0,2,4"
		var pins []int
		for _, s := range strings.Split(cpuLimit, ",") {
			id, err := strconv.Atoi(strings.TrimSpace(s))
			if err == nil {
				pins = append(pins, id)
			}
		}
		if len(pins) > 0 {
			return pins
		}
	}
	return nil
}

// renderProgressBar draws a colored bar like: [████████░░░░░░]
func renderProgressBar(value, max float64, width int) string {
	if max <= 0 {
		max = 100
	}
	pct := value / max
	if pct > 1 {
		pct = 1
	}
	if pct < 0 {
		pct = 0
	}

	filled := int(pct * float64(width))
	empty := width - filled

	// Color based on percentage
	var barColor lipgloss.Color
	switch {
	case pct >= 0.9:
		barColor = ColorRed
	case pct >= 0.7:
		barColor = ColorYellow
	default:
		barColor = ColorGreen
	}

	filledStr := lipgloss.NewStyle().Foreground(barColor).Render(strings.Repeat("█", filled))
	emptyStr := lipgloss.NewStyle().Foreground(ColorDim).Render(strings.Repeat("░", empty))

	return fmt.Sprintf("[%s%s]", filledStr, emptyStr)
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fGB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

func formatBytesShort(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.0fG", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0fM", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0fK", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}
