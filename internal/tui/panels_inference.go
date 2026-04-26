package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fourdoors/cella/internal/proxy"
)

// handleInferencePanel handles keypresses in the inference stats panel
func (a *App) handleInferencePanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if a.rphEditMode {
		return a.handleRPHEdit(msg)
	}

	switch msg.String() {
	case "esc", "q":
		a.focus = panelSidebar
		return a, nil
	case "up", "k":
		if a.inferenceScroll > 0 {
			a.inferenceScroll--
		}
	case "down", "j":
		a.inferenceScroll++
	case "pgup":
		step := (a.height - 10) / 2
		if step < 1 {
			step = 1
		}
		if a.inferenceScroll > step {
			a.inferenceScroll -= step
		} else {
			a.inferenceScroll = 0
		}
	case "pgdown":
		step := (a.height - 10) / 2
		if step < 1 {
			step = 1
		}
		a.inferenceScroll += step
	case "g":
		a.inferenceScroll = 0
	case "G":
		a.inferenceScroll = 9999
	case "c":
		a.addEvent("📊 inference stats cleared")
		return a, nil
	case "S":
		if globalProxyServer != nil {
			return a, a.exportInferenceJSON()
		}
	case "L", "l":
		// Enter RPH limit management mode
		a.rphEditMode = true
		a.rphEditStep = 0 // List mode
		a.rphEditBuf = ""
		a.rphEditCursor = 0
		a.rphEditModels = a.buildRPHModelList()
		return a, nil
	}
	return a, nil
}

// exportInferenceJSON exports inference stats to a JSON file
func (a *App) exportInferenceJSON() tea.Cmd {
	return func() tea.Msg {
		if globalProxyServer == nil {
			return asyncResultMsg{err: fmt.Errorf("no inference data")}
		}
		stats := globalProxyServer.InferenceStats()
		reqs := stats.GetRecentRequests(1000)
		models := stats.GetModelStats()

		export := map[string]interface{}{
			"generated_at": time.Now().Format(time.RFC3339),
			"total_cost":   globalProxyServer.InferenceStats().TotalCostToday(),
			"models":       models,
			"requests":     reqs,
		}
		data, _ := json.MarshalIndent(export, "", "  ")
		dir, dirErr := cellaConfigDir("exports")
		if dirErr != nil {
			return asyncResultMsg{err: fmt.Errorf("dir: %w", dirErr)}
		}
		filename := filepath.Join(dir, fmt.Sprintf("inference-%s.json", time.Now().Format("20060102-150405")))
		if err := os.WriteFile(filename, data, 0644); err != nil {
			return asyncResultMsg{err: fmt.Errorf("write: %w", err)}
		}
		return asyncResultMsg{text: fmt.Sprintf("📊 Exported → %s (%d bytes)", filename, len(data))}
	}
}

// padRight pads a string to width with spaces (ANSI-safe: pad BEFORE styling).
func padRight(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(s))
}

// padLeft pads a string to width with leading spaces (ANSI-safe: pad BEFORE styling).
func padLeft(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return strings.Repeat(" ", w-len(s)) + s
}

// renderInferencePanel renders the inference stats panel
func (a App) renderInferencePanel() string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e"))
	bright := lipgloss.NewStyle().Foreground(lipgloss.Color("#e67e22"))
	blue := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#58a6ff"))
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("#27ae60"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("#e74c3c"))
	yellow := lipgloss.NewStyle().Foreground(lipgloss.Color("#f1c40f"))
	purple := lipgloss.NewStyle().Foreground(lipgloss.Color("#8e44ad"))
	gold := lipgloss.NewStyle().Foreground(lipgloss.Color("#f39c12"))

	if globalProxyServer == nil {
		return dim.Render("  Interception not active. Press Esc, then A \u2192 p to start.") + "\n"
	}

	stats := globalProxyServer.InferenceStats()
	if stats == nil {
		return dim.Render("  No inference stats available.") + "\n"
	}

	modelStats := stats.GetModelStats()
	recentReqs := stats.GetRecentRequests(50)
	totalCostToday := stats.TotalCostToday()

	var b strings.Builder

	// Title + global cost
	title := blue.Render("\U0001f4ca Inference Stats \u25c6")
	if totalCostToday > 0 {
		title += gold.Render(fmt.Sprintf("  Today: %s", proxy.FormatCost(totalCostToday)))
	}
	if stats.DailyCostBudget > 0 && totalCostToday >= stats.DailyCostBudget*0.8 {
		pct := totalCostToday / stats.DailyCostBudget * 100
		title += red.Render(fmt.Sprintf("  \u26a0 Budget %.0f%%", pct))
	}
	b.WriteString(title + "\n\n")

	if len(modelStats) == 0 {
		b.WriteString(dim.Render("  No inference API calls recorded yet.") + "\n\n")
		b.WriteString(dim.Render("  Waiting for AI model API calls...") + "\n")
		b.WriteString(dim.Render("  Detected paths: /chat/completions /v1/messages /responses") + "\n")
		return b.String()
	}

	// \u2500\u2500 Column widths \u2500\u2500
	const (
		colModel  = 26
		colReqs   = 6
		colTokIn  = 8
		colTokOut = 8
		colToks   = 8
		colRPM    = 5
		colRPH    = 10
		colTPM    = 8
		colCost   = 10
	)
	totalW := colModel + colReqs + colTokIn + colTokOut + colToks + colRPM + colRPH + colTPM + colCost + 10

	// \u2500\u2500 Model table \u2500\u2500
	b.WriteString(bright.Render("  Models") + "\n")
	sep := dim.Render("  " + strings.Repeat("\u2500", totalW))
	b.WriteString(sep + "\n")

	hdr := "  " +
		dim.Render(padRight("MODEL", colModel)) + "  " +
		dim.Render(padLeft("REQS", colReqs)) + " " +
		dim.Render(padLeft("TOK IN", colTokIn)) + " " +
		dim.Render(padLeft("TOK OUT", colTokOut)) + " " +
		dim.Render(padLeft("TOKENS", colToks)) + " " +
		dim.Render(padLeft("RPM", colRPM)) + " " +
		dim.Render(padLeft("RPH", colRPH)) + " " +
		dim.Render(padLeft("TPM", colTPM)) + " " +
		dim.Render(padLeft("COST", colCost))
	b.WriteString(hdr + "\n")
	b.WriteString(sep + "\n")

	for _, ms := range modelStats {
		rpmStyle := green
		if ms.RPM > 30 {
			rpmStyle = yellow
		}
		if ms.RPM > 60 {
			rpmStyle = red
		}

		modelName := ms.Model
		if len(modelName) > colModel {
			modelName = modelName[:colModel-3] + "..."
		}

		costStr := "-"
		if ms.HasPricing {
			costStr = proxy.FormatCost(ms.Cost)
		}

		line := "  " +
			purple.Render(padRight(modelName, colModel)) + "  " +
			padLeft(fmt.Sprintf("%d", ms.TotalRequests), colReqs) + " " +
			green.Render(padLeft(proxy.FormatTokens(ms.TotalTokensIn), colTokIn)) + " " +
			bright.Render(padLeft(proxy.FormatTokens(ms.TotalTokensOut), colTokOut)) + " " +
			dim.Render(padLeft(proxy.FormatTokens(ms.TotalTokens), colToks)) + " " +
			rpmStyle.Render(padLeft(fmt.Sprintf("%d", ms.RPM), colRPM)) + " " +
			formatRPH(ms.RPH, ms.RPHLimit, colRPH) + " " +
			green.Render(padLeft(proxy.FormatTokens(ms.TPM), colTPM)) + " " +
			gold.Render(padLeft(costStr, colCost))
		b.WriteString(line + "\n")

		// Sparkline: show TPM if token data available, otherwise show RPM
		if ms.TotalRequests > 0 {
			sparkLabel := "TPM"
			sparkData := ms.TPMHistory
			if ms.TotalTokens == 0 {
				sparkLabel = "RPM"
				sparkData = ms.RPMHistory
			}
			spark := renderInferenceSparkline(sparkData, 30)
			lastSeen := ""
			if !ms.LastSeen.IsZero() {
				lastSeen = fmt.Sprintf("  last: %s", time.Since(ms.LastSeen).Truncate(time.Second))
			}
			sparkPad := strings.Repeat(" ", colModel+4)
			b.WriteString(fmt.Sprintf("  %s%s: %s%s\n",
				sparkPad,
				sparkLabel,
				dim.Render(spark),
				dim.Render(lastSeen),
			))
		}
	}
	b.WriteString("\n")

	// \u2500\u2500 Session breakdown (by container) \u2500\u2500
	// Compute max container name width across all recent requests (min 12)
	contW := 12
	for _, r := range recentReqs {
		if len(r.Container) > contW {
			contW = len(r.Container)
		}
	}

	if len(recentReqs) > 0 {
		b.WriteString(bright.Render("  Session Breakdown") + "\n")
		b.WriteString(sep + "\n")

		type contStats struct {
			container string
			requests  int
			tokIn     int64
			tokOut    int64
			cost      float64
			models    map[string]int
		}
		contMap := make(map[string]*contStats)
		for _, r := range recentReqs {
			cs, ok := contMap[r.Container]
			if !ok {
				cs = &contStats{container: r.Container, models: make(map[string]int)}
				contMap[r.Container] = cs
			}
			cs.requests++
			cs.tokIn += r.TokensIn
			cs.tokOut += r.TokensOut
			cs.cost += proxy.CalcCost(r.Model, r.TokensIn, r.TokensOut)
			cs.models[r.Model]++
		}

		var contList []*contStats
		for _, cs := range contMap {
			contList = append(contList, cs)
		}
		sort.Slice(contList, func(i, j int) bool {
			return contList[i].requests > contList[j].requests
		})

		for _, cs := range contList {
			topModel, topCount := "", 0
			for m, c := range cs.models {
				if c > topCount {
					topModel, topCount = m, c
				}
			}
			if len(topModel) > 20 {
				topModel = topModel[:17] + "..."
			}

			b.WriteString(fmt.Sprintf("  %s %s  %s  in:%-6s out:%-6s  %s  \u2192 %s\n",
				green.Render("\u25cf"),
				bright.Render(padRight(cs.container, contW)),
				dim.Render(padLeft(fmt.Sprintf("%d", cs.requests), 4)+" reqs"),
				proxy.FormatTokens(cs.tokIn),
				proxy.FormatTokens(cs.tokOut),
				gold.Render(padLeft(proxy.FormatCost(cs.cost), 8)),
				purple.Render(topModel),
			))
		}
		b.WriteString("\n")
	}

	// \u2500\u2500 Recent requests \u2500\u2500
	if len(recentReqs) > 0 {
		b.WriteString(bright.Render("  Recent Calls") + "\n")
		b.WriteString(sep + "\n")

		visibleH := a.height - (9 + len(modelStats)*2 + 5 + len(recentReqs))
		if visibleH < 5 {
			visibleH = 10
		}
		if visibleH > 20 {
			visibleH = 20
		}

		maxScroll := len(recentReqs) - visibleH
		if maxScroll < 0 {
			maxScroll = 0
		}
		scroll := a.inferenceScroll
		if scroll > maxScroll {
			scroll = maxScroll
		}

		if scroll > 0 {
			b.WriteString(dim.Render(fmt.Sprintf("  \u25b2 %d more", scroll)) + "\n")
		}

		for i := scroll; i < scroll+visibleH && i < len(recentReqs); i++ {
			req := recentReqs[i]

			statusIcon := green.Render("\u2705")
			if req.StatusCode >= 400 || req.StatusCode == 0 {
				statusIcon = red.Render("\u274c")
			}
			if req.Error != "" {
				statusIcon = red.Render("\U0001f4a5")
			}

			modelShort := req.Model
			if len(modelShort) > 22 {
				modelShort = modelShort[:19] + "..."
			}

			contShort := req.Container

			tokInfo := ""
			costInfo := ""
			if req.TokensIn > 0 || req.TokensOut > 0 {
				tokInfo = fmt.Sprintf("%s\u2192%s",
					proxy.FormatTokens(req.TokensIn),
					proxy.FormatTokens(req.TokensOut))
				c := proxy.CalcCost(req.Model, req.TokensIn, req.TokensOut)
				if c > 0 {
					costInfo = proxy.FormatCost(c)
				}
			}

			b.WriteString("  " +
				dim.Render(req.Time.Format("15:04:05")) + " " +
				statusIcon + " " +
				dim.Render(padRight(contShort, contW)) + " " +
				purple.Render(padRight(modelShort, 22)) + " " +
				blue.Render(padRight(req.Path, 24)) + " " +
				dim.Render(fmt.Sprintf("[%3d]", req.StatusCode)) + " " +
				green.Render(padRight(tokInfo, 14)) + " " +
				gold.Render(padRight(costInfo, 8)) + " " +
				dim.Render(req.Latency.Truncate(time.Millisecond).String()) +
				"\n")
		}

		remaining := len(recentReqs) - (scroll + visibleH)
		if remaining > 0 {
			b.WriteString(dim.Render(fmt.Sprintf("  \u25bc %d more", remaining)) + "\n")
		}
	}

	return b.String()
}

// renderSparkline renders a mini bar chart from int64 slice
func renderInferenceSparkline(data []int64, width int) string {
	bars := []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	if len(data) == 0 {
		return strings.Repeat("░", width)
	}
	// Use last `width` items
	if len(data) > width {
		data = data[len(data)-width:]
	}
	// Find max
	var maxVal int64
	for _, v := range data {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal == 0 {
		return strings.Repeat("░", len(data)) + strings.Repeat(" ", width-len(data))
	}
	result := make([]rune, width)
	for i := range result {
		result[i] = ' '
	}
	offset := width - len(data)
	for i, v := range data {
		idx := int(float64(v) / float64(maxVal) * float64(len(bars)-1))
		result[offset+i] = bars[idx]
	}
	return string(result)
}

func formatRPH(rph, limit int64, width int) string {
	if limit <= 0 {
		return padLeft(fmt.Sprintf("%d", rph), width)
	}

	var visibleStr string
	var style lipgloss.Style
	var hasStyle bool

	if rph >= limit {
		visibleStr = fmt.Sprintf("%d/%d🔴", rph, limit)
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("#e74c3c"))
		hasStyle = true
	} else if float64(rph)/float64(limit) >= 0.8 {
		visibleStr = fmt.Sprintf("%d/%d⚠", rph, limit)
		style = lipgloss.NewStyle().Foreground(lipgloss.Color("#f1c40f"))
		hasStyle = true
	} else {
		visibleStr = fmt.Sprintf("%d/%d", rph, limit)
	}

	w := lipgloss.Width(visibleStr)
	pad := ""
	if w < width {
		pad = strings.Repeat(" ", width-w)
	}

	if hasStyle {
		return pad + style.Render(visibleStr)
	}
	return pad + visibleStr
}

// ── RPH Limit Editor Rendering ──

func (a App) renderRPHEditor() string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#8b949e"))
	bright := lipgloss.NewStyle().Foreground(lipgloss.Color("#e67e22"))
	blue := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#58a6ff"))
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("#27ae60"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("#e74c3c"))
	purple := lipgloss.NewStyle().Foreground(lipgloss.Color("#8e44ad"))
	bgGray := lipgloss.NewStyle().Background(lipgloss.Color("#30363d")).Foreground(lipgloss.Color("#ffffff"))

	var b strings.Builder

	if a.rphEditStep == 0 { // rphStepList
		b.WriteString(blue.Render("⚙️ RPH Limits Configuration ◆") + "\n\n")

		const colPattern = 28
		b.WriteString("  " + dim.Render(padRight("PATTERN", colPattern)) + "  " + dim.Render("LIMIT (reqs/hr)") + "\n")
		sep := dim.Render("  " + strings.Repeat("─", colPattern+20))
		b.WriteString(sep + "\n")

		if len(a.rphEditModels) == 0 {
			b.WriteString(dim.Render("  (No custom limits configured)") + "\n")
		} else {
			for i, e := range a.rphEditModels {
				patStr := e.Pattern
				if patStr == "*" {
					patStr = "* (default fallback)"
				}

				if i == a.rphEditCursor {
					b.WriteString(bgGray.Render(fmt.Sprintf("  %-28s  %s", patStr, fmt.Sprintf("%d", e.Limit))) + "\n")
				} else {
					b.WriteString("  " + purple.Render(padRight(patStr, colPattern)) + "  " + green.Render(fmt.Sprintf("%d", e.Limit)) + "\n")
				}
			}
		}

		b.WriteString("\n")
		b.WriteString(dim.Render("  ─────────────────────────────────────────────────────────────") + "\n")
		b.WriteString(dim.Render("  ↑↓ select │ a: add │ e: edit │ d: delete │ 0: disable │ Esc: close") + "\n")

		return b.String()
	}

	if a.rphEditStep == 3 { // rphStepConfirm
		b.WriteString(blue.Render("⚙️ RPH Limits Configuration ◆") + "\n\n")

		const colPattern = 28
		b.WriteString("  " + dim.Render(padRight("PATTERN", colPattern)) + "  " + dim.Render("LIMIT (reqs/hr)") + "\n")
		sep := dim.Render("  " + strings.Repeat("─", colPattern+20))
		b.WriteString(sep + "\n")

		for i, e := range a.rphEditModels {
			patStr := e.Pattern
			if patStr == "*" {
				patStr = "* (default fallback)"
			}

			if i == a.rphEditCursor {
				b.WriteString("  " + red.Render(padRight(patStr, colPattern)) + "  " + red.Render(fmt.Sprintf("%-6d  ← Delete this limit? (y/N)", e.Limit)) + "\n")
			} else {
				b.WriteString("  " + purple.Render(padRight(patStr, colPattern)) + "  " + green.Render(fmt.Sprintf("%d", e.Limit)) + "\n")
			}
		}

		b.WriteString("\n")
		b.WriteString(dim.Render("  ─────────────────────────────────────────────────────────────") + "\n")
		b.WriteString(dim.Render("  y: confirm delete │ Esc/other: cancel") + "\n")
		return b.String()
	}

	// Input modes (Model or Value)
	b.WriteString(blue.Render("⚙️ Add RPH Limit ◆") + "\n\n")

	if a.rphEditStep == 1 { // rphStepModel
		b.WriteString(bright.Render("  Model Pattern (fuzzy match, * for default):") + "\n")
		b.WriteString("  " + green.Render(a.rphEditBuf+"█") + "\n\n")
		b.WriteString(dim.Render("  ─────────────────────────────────────────────────────────────") + "\n")
		b.WriteString(dim.Render("  Enter: next │ Esc: cancel") + "\n")
	} else if a.rphEditStep == 2 { // rphStepValue
		b.WriteString(dim.Render("  Model Pattern: ") + purple.Render(a.rphNewPattern) + "\n\n")
		b.WriteString(bright.Render("  Limit (requests per hour, 0 to disable):") + "\n")
		b.WriteString("  " + green.Render(a.rphEditBuf+"█") + "\n\n")
		b.WriteString(dim.Render("  ─────────────────────────────────────────────────────────────") + "\n")
		b.WriteString(dim.Render("  Enter: save │ Esc: cancel") + "\n")
	}

	return b.String()
}

// ── RPH Limit Editor Events ──

type rphModelEntry struct {
	Pattern string
	Limit   int64
	IsNew   bool
}

func (a *App) buildRPHModelList() []rphModelEntry {
	limits := proxy.GetAllRPHLimits()
	var entries []rphModelEntry
	for pattern, lim := range limits {
		entries = append(entries, rphModelEntry{Pattern: pattern, Limit: lim})
	}
	// Sort: * last, rest alphabetical
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			swap := false
			if entries[i].Pattern == "*" && entries[j].Pattern != "*" {
				swap = true
			} else if entries[i].Pattern != "*" && entries[j].Pattern != "*" && entries[i].Pattern > entries[j].Pattern {
				swap = true
			}
			if swap {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	return entries
}

func (a *App) handleRPHEdit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch a.rphEditStep {
	case 0: // List
		return a.handleRPHList(msg)
	case 1: // Model input
		return a.handleRPHInput(msg)
	case 2: // Value input
		return a.handleRPHInput(msg)
	case 3: // Confirm
		return a.handleRPHConfirm(msg)
	}
	return a, nil
}

func (a *App) handleRPHList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		a.rphEditMode = false
		return a, nil
	case "up", "k":
		if a.rphEditCursor > 0 {
			a.rphEditCursor--
		}
	case "down", "j":
		if a.rphEditCursor < len(a.rphEditModels)-1 {
			a.rphEditCursor++
		}
	case "a":
		// Add new limit
		a.rphEditStep = 1
		a.rphEditBuf = ""
		return a, nil
	case "e", "enter":
		// Edit selected limit's value
		if a.rphEditCursor < len(a.rphEditModels) {
			entry := a.rphEditModels[a.rphEditCursor]
			a.rphEditStep = 2
			a.rphEditBuf = fmt.Sprintf("%d", entry.Limit)
			a.rphNewPattern = entry.Pattern
		}
		return a, nil
	case "d":
		// Delete selected limit
		if a.rphEditCursor < len(a.rphEditModels) {
			a.rphEditStep = 3
		}
		return a, nil
	case "0":
		// Quick disable: set limit to 0 (disabled)
		if a.rphEditCursor < len(a.rphEditModels) {
			entry := a.rphEditModels[a.rphEditCursor]
			_ = proxy.SetRPHLimit(entry.Pattern, 0)
			a.rphEditModels = a.buildRPHModelList()
			a.addEvent(fmt.Sprintf("⏱ RPH limit disabled: %s", entry.Pattern))
		}
		return a, nil
	}
	return a, nil
}

func (a *App) handleRPHInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		a.rphEditStep = 0
		a.rphEditBuf = ""
		return a, nil
	case "enter":
		if a.rphEditStep == 1 {
			// Save pattern, move to value
			pattern := strings.TrimSpace(a.rphEditBuf)
			if pattern == "" {
				return a, nil
			}
			a.rphNewPattern = pattern
			a.rphEditStep = 2
			a.rphEditBuf = ""
			return a, nil
		}
		if a.rphEditStep == 2 {
			// Parse value and save
			val := strings.TrimSpace(a.rphEditBuf)
			if val == "" {
				return a, nil
			}
			var limit int64
			fmt.Sscanf(val, "%d", &limit)
			if limit < 0 {
				limit = 0
			}
			_ = proxy.SetRPHLimit(a.rphNewPattern, limit)
			a.rphEditModels = a.buildRPHModelList()
			a.rphEditStep = 0
			a.rphEditBuf = ""
			if limit == 0 {
				a.addEvent(fmt.Sprintf("⏱ RPH limit disabled: %s", a.rphNewPattern))
			} else {
				a.addEvent(fmt.Sprintf("⏱ RPH limit set: %s → %d/hr", a.rphNewPattern, limit))
			}
			// Move cursor to the new/edited entry
			for i, e := range a.rphEditModels {
				if e.Pattern == a.rphNewPattern {
					a.rphEditCursor = i
					break
				}
			}
			return a, nil
		}
	case "backspace":
		if len(a.rphEditBuf) > 0 {
			a.rphEditBuf = a.rphEditBuf[:len(a.rphEditBuf)-1]
		}
	default:
		k := msg.String()
		if len(k) == 1 {
			// For value step, only accept digits
			if a.rphEditStep == 2 {
				if k >= "0" && k <= "9" {
					a.rphEditBuf += k
				}
			} else {
				a.rphEditBuf += k
			}
		}
	}
	return a, nil
}

func (a *App) handleRPHConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		if a.rphEditCursor < len(a.rphEditModels) {
			entry := a.rphEditModels[a.rphEditCursor]
			_ = proxy.DeleteRPHLimit(entry.Pattern)
			a.rphEditModels = a.buildRPHModelList()
			if a.rphEditCursor >= len(a.rphEditModels) && a.rphEditCursor > 0 {
				a.rphEditCursor--
			}
			a.addEvent(fmt.Sprintf("🗑 RPH limit removed: %s", entry.Pattern))
		}
		a.rphEditStep = 0
		return a, nil
	default:
		// Any other key cancels
		a.rphEditStep = 0
		return a, nil
	}
}
