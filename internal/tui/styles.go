package tui

import "github.com/charmbracelet/lipgloss"

// Color palette
var (
	ColorBlue   = lipgloss.Color("#58a6ff")
	ColorGreen  = lipgloss.Color("#3fb950")
	ColorOrange = lipgloss.Color("#e67e22")
	ColorRed    = lipgloss.Color("#f85149")
	ColorPurple = lipgloss.Color("#d2a8ff")
	ColorYellow = lipgloss.Color("#e3b341")
	ColorDim    = lipgloss.Color("#484f58")
	ColorText   = lipgloss.Color("#e6edf3")
	ColorSubtle = lipgloss.Color("#8b949e")
	ColorBg     = lipgloss.Color("#0d1117")
	ColorPanel  = lipgloss.Color("#161b22")
	ColorBorder       = lipgloss.Color("#30363d") // unfocused border
	ColorBorderFocus  = lipgloss.Color("#f0f0f0") // focused border (bright white)
)

// Styles
var (
	// Sidebar
	SidebarStyle = lipgloss.NewStyle().
			Width(28).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder).
			Padding(1, 1)

	// Main panel
	MainPanelStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder).
			Padding(1, 1)

	// Status bar
	StatusBarStyle = lipgloss.NewStyle().
			Foreground(ColorSubtle).
			Background(lipgloss.Color("#161b22")).
			Padding(0, 1)

	// Container list items
	ActiveContainerStyle = lipgloss.NewStyle().
				Foreground(ColorGreen).
				Bold(true)

	StoppedContainerStyle = lipgloss.NewStyle().
				Foreground(ColorDim)

	SelectedContainerStyle = lipgloss.NewStyle().
				Foreground(ColorBlue).
				Bold(true).
				Background(lipgloss.Color("#1f2937"))

	// Title
	TitleStyle = lipgloss.NewStyle().
			Foreground(ColorBlue).
			Bold(true).
			MarginBottom(1)

	// Section headers
	SectionHeaderStyle = lipgloss.NewStyle().
				Foreground(ColorPurple).
				Bold(true).
				MarginTop(1)

	// Metrics
	MetricLabelStyle = lipgloss.NewStyle().
				Foreground(ColorSubtle).
				Width(5)

	MetricValueStyle = lipgloss.NewStyle().
				Foreground(ColorText)

	// Event styles
	EventNormalStyle = lipgloss.NewStyle().
				Foreground(ColorText)

	EventWarnStyle = lipgloss.NewStyle().
			Foreground(ColorYellow)

	EventErrorStyle = lipgloss.NewStyle().
			Foreground(ColorRed)

	// Policy
	PolicyActiveStyle = lipgloss.NewStyle().
				Foreground(ColorGreen)

	PolicyInactiveStyle = lipgloss.NewStyle().
				Foreground(ColorDim)

	// Help
	HelpKeyStyle = lipgloss.NewStyle().
			Foreground(ColorBlue).
			Bold(true)

	HelpDescStyle = lipgloss.NewStyle().
			Foreground(ColorSubtle)
)
