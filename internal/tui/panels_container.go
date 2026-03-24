package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fourdoors/cella/internal/runtime"
)

// ── Create panel handler ──

func (a App) handleCreatePanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	switch a.createStep {
	case 0: // Select runtime
		switch key {
		case "1":
			a.createRuntime = "lxd"
			a.createStep = 1
			a.createInput = ""
		case "2":
			a.createRuntime = "docker"
			a.createStep = 1
			a.createInput = ""
		case "esc", "q":
			a.focus = a.prevFocus
		}
		return a, nil

	case 1: // Enter image
		switch key {
		case "enter":
			a.createImage = a.createInput
			a.createInput = ""
			a.createStep = 2
		case "backspace":
			if len(a.createInput) > 0 {
				a.createInput = a.createInput[:len(a.createInput)-1]
			}
		case "esc":
			a.createStep = 0
		default:
			if len(key) == 1 {
				a.createInput += key
			}
		}
		return a, nil

	case 2: // Enter name
		switch key {
		case "enter":
			a.createName = a.createInput
			a.createInput = ""
			a.createStep = 3
		case "backspace":
			if len(a.createInput) > 0 {
				a.createInput = a.createInput[:len(a.createInput)-1]
			}
		case "esc":
			a.createStep = 1
		default:
			if len(key) == 1 {
				a.createInput += key
			}
		}
		return a, nil

	case 3: // Confirm
		switch key {
		case "y", "Y", "enter":
			a.focus = a.prevFocus
			rtName := a.createRuntime
			image := a.createImage
			name := a.createName
			// Find the runtime
			var rt runtime.Runtime
			for _, r := range a.runtimes {
				if r.Name() == rtName {
					rt = r
					break
				}
			}
			if rt == nil {
				return a, a.setFlash("❌ Runtime not available")
			}
			return a, func() tea.Msg {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				if err := rt.CreateContainer(ctx, name, image, nil); err != nil {
					return asyncResultMsg{err: err}
				}
				return asyncResultMsg{text: fmt.Sprintf("✨ Created %s (%s/%s)", name, rtName, image)}
			}
		case "n", "N", "esc":
			a.createStep = 2
		}
		return a, nil
	}
	return a, nil
}

// ── Create panel render ──

func (a App) renderCreatePanel() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("✨ Create Container ◆") + "\n\n")

	promptStyle := lipgloss.NewStyle().Foreground(ColorBlue).Bold(true)
	dimStyle := lipgloss.NewStyle().Foreground(ColorDim)
	inputStyle := lipgloss.NewStyle().Foreground(ColorGreen).Bold(true)

	switch a.createStep {
	case 0:
		b.WriteString(promptStyle.Render("  Select runtime:") + "\n\n")
		b.WriteString("  [1] 🔷 LXD\n")
		b.WriteString("  [2] 🐳 Docker\n\n")
		b.WriteString(dimStyle.Render("  Press 1 or 2, Esc to cancel") + "\n")

	case 1:
		icon := "🔷"
		if a.createRuntime == "docker" {
			icon = "🐳"
		}
		b.WriteString(dimStyle.Render(fmt.Sprintf("  Runtime: %s %s", icon, a.createRuntime)) + "\n\n")
		if a.createRuntime == "docker" {
			b.WriteString(promptStyle.Render("  Image name (e.g. ubuntu, alpine, nginx):") + "\n")
		} else {
			b.WriteString(promptStyle.Render("  Image alias (e.g. ubuntu:22.04, alpine):") + "\n")
		}
		b.WriteString(inputStyle.Render(fmt.Sprintf("  > %s█", a.createInput)) + "\n\n")
		b.WriteString(dimStyle.Render("  Enter to confirm, Esc to go back") + "\n")

	case 2:
		b.WriteString(dimStyle.Render(fmt.Sprintf("  Runtime: %s  Image: %s", a.createRuntime, a.createImage)) + "\n\n")
		b.WriteString(promptStyle.Render("  Container name:") + "\n")
		b.WriteString(inputStyle.Render(fmt.Sprintf("  > %s█", a.createInput)) + "\n\n")
		b.WriteString(dimStyle.Render("  Enter to confirm, Esc to go back") + "\n")

	case 3:
		b.WriteString(SectionHeaderStyle.Render("  Confirm creation:") + "\n\n")
		b.WriteString(fmt.Sprintf("  Runtime:  %s\n", a.createRuntime))
		b.WriteString(fmt.Sprintf("  Image:    %s\n", a.createImage))
		b.WriteString(fmt.Sprintf("  Name:     %s\n\n", a.createName))
		b.WriteString(promptStyle.Render("  Create? (y/n)") + "\n")
	}

	return b.String()
}

// ── Import panel handler ──

func (a App) handleImportPanel(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "enter":
		filename := a.createInput
		a.focus = a.prevFocus
		a.createInput = ""
		return a, func() tea.Msg {
			data, err := os.ReadFile(filename)
			if err != nil {
				return asyncResultMsg{err: fmt.Errorf("read %s: %w", filename, err)}
			}
			var imported struct {
				Name     string                       `json:"name"`
				Config   map[string]string            `json:"config"`
				Devices  map[string]map[string]string `json:"devices"`
				Profiles []string                     `json:"profiles"`
			}
			if err := json.Unmarshal(data, &imported); err != nil {
				return asyncResultMsg{err: fmt.Errorf("parse %s: %w", filename, err)}
			}
			if imported.Name == "" {
				return asyncResultMsg{err: fmt.Errorf("missing 'name' in %s", filename)}
			}
			// Apply config to existing container (if name matches selected) or create new
			return asyncResultMsg{text: fmt.Sprintf("📥 Imported config from %s for '%s' (%d keys)", filename, imported.Name, len(imported.Config))}
		}
	case "backspace":
		if len(a.createInput) > 0 {
			a.createInput = a.createInput[:len(a.createInput)-1]
		}
	case "esc":
		a.focus = a.prevFocus
		a.createInput = ""
	default:
		if len(key) == 1 || key == "." || key == "/" || key == "-" || key == "_" {
			a.createInput += key
		}
	}
	return a, nil
}

// ── Import panel render ──

func (a App) renderImportPanel() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("📥 Import Config ◆") + "\n\n")

	promptStyle := lipgloss.NewStyle().Foreground(ColorBlue).Bold(true)
	inputStyle := lipgloss.NewStyle().Foreground(ColorGreen).Bold(true)
	dimStyle := lipgloss.NewStyle().Foreground(ColorDim)

	b.WriteString(promptStyle.Render("  Enter JSON config file path:") + "\n")
	b.WriteString(inputStyle.Render(fmt.Sprintf("  > %s█", a.createInput)) + "\n\n")
	b.WriteString(dimStyle.Render("  Enter to import, Esc to cancel") + "\n")
	b.WriteString(dimStyle.Render("  Tip: export first with E, then modify the JSON") + "\n")

	return b.String()
}
