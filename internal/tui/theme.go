package tui

import "github.com/charmbracelet/lipgloss"

// Theme defines the color palette and styling for the TUI.
// Inspired by Claude Code's dark, clean aesthetic.
type Theme struct {
	// Primary colors
	Primary    lipgloss.Color
	Secondary  lipgloss.Color
	Accent     lipgloss.Color
	Background lipgloss.Color
	Surface    lipgloss.Color

	// Text colors
	TextPrimary   lipgloss.Color
	TextSecondary lipgloss.Color
	TextMuted     lipgloss.Color

	// Semantic colors
	Success lipgloss.Color
	Warning lipgloss.Color
	Error   lipgloss.Color
	Info    lipgloss.Color

	// Border colors
	Border      lipgloss.Color
	BorderFocus lipgloss.Color
}

// DefaultTheme returns a Claude Code–inspired dark theme.
func DefaultTheme() Theme {
	return Theme{
		Primary:    lipgloss.Color("#E8DCFF"), // Soft lavender
		Secondary:  lipgloss.Color("#B8A4D9"), // Muted purple
		Accent:     lipgloss.Color("#FF9F43"), // Warm orange accent
		Background: lipgloss.Color("#0D1117"), // Deep dark
		Surface:    lipgloss.Color("#161B22"), // Slightly lighter surface

		TextPrimary:   lipgloss.Color("#E6EDF3"),
		TextSecondary: lipgloss.Color("#8B949E"),
		TextMuted:     lipgloss.Color("#484F58"),

		Success: lipgloss.Color("#3FB950"),
		Warning: lipgloss.Color("#D29922"),
		Error:   lipgloss.Color("#F85149"),
		Info:    lipgloss.Color("#58A6FF"),

		Border:      lipgloss.Color("#30363D"),
		BorderFocus: lipgloss.Color("#58A6FF"),
	}
}

// Styles holds pre-computed lipgloss styles for the TUI.
type Styles struct {
	// Layout containers
	App       lipgloss.Style
	Sidebar   lipgloss.Style
	ChatPane  lipgloss.Style
	InputPane lipgloss.Style
	StatusBar lipgloss.Style

	// Text styles
	Title         lipgloss.Style
	Subtitle      lipgloss.Style
	Label         lipgloss.Style
	Value         lipgloss.Style
	Muted         lipgloss.Style
	UserMessage   lipgloss.Style
	AIMessage     lipgloss.Style
	SystemMessage lipgloss.Style
	ToolCall      lipgloss.Style
	Error         lipgloss.Style
	Success       lipgloss.Style
	Warning       lipgloss.Style

	// Interactive elements
	Command         lipgloss.Style
	CommandSelected lipgloss.Style
	KeyHint         lipgloss.Style
	Badge           lipgloss.Style
	BadgeConfirm    lipgloss.Style
	BadgeAutopilot  lipgloss.Style

	// Borders
	BorderedBox lipgloss.Style

	// Thinking/Reasoning display (Claude Code style)
	ThinkingBox       lipgloss.Style
	ThinkingCollapsed lipgloss.Style

	// Progress indicators
	ProgressBar     lipgloss.Style
	ProgressFilled  lipgloss.Style
	ProgressEmpty   lipgloss.Style

	// Subagent display
	SubAgentBox     lipgloss.Style
	SubAgentRunning lipgloss.Style
	SubAgentDone    lipgloss.Style

	// Diff view
	DiffAdd    lipgloss.Style
	DiffRemove lipgloss.Style
	DiffHeader lipgloss.Style
}

// NewStyles creates the style set from a theme.
func NewStyles(t Theme) Styles {
	return Styles{
		App: lipgloss.NewStyle().
			Background(t.Background),

		Sidebar: lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(t.Border).
			Padding(1, 2).
			Background(t.Surface),

		ChatPane: lipgloss.NewStyle().
			Padding(0, 1),

		InputPane: lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(t.BorderFocus).
			Padding(0, 1),

		StatusBar: lipgloss.NewStyle().
			Foreground(t.TextMuted).
			Padding(0, 1),

		Title: lipgloss.NewStyle().
			Foreground(t.Primary).
			Bold(true),

		Subtitle: lipgloss.NewStyle().
			Foreground(t.Secondary),

		Label: lipgloss.NewStyle().
			Foreground(t.TextSecondary),

		Value: lipgloss.NewStyle().
			Foreground(t.TextPrimary),

		Muted: lipgloss.NewStyle().
			Foreground(t.TextMuted),

		UserMessage: lipgloss.NewStyle().
			Foreground(t.Info).
			Bold(true),

		AIMessage: lipgloss.NewStyle().
			Foreground(t.TextPrimary),

		SystemMessage: lipgloss.NewStyle().
			Foreground(t.TextSecondary).
			Italic(true),

		ToolCall: lipgloss.NewStyle().
			Foreground(t.Accent).
			Bold(true),

		Error: lipgloss.NewStyle().
			Foreground(t.Error),

		Success: lipgloss.NewStyle().
			Foreground(t.Success),

		Warning: lipgloss.NewStyle().
			Foreground(t.Warning),

		Command: lipgloss.NewStyle().
			Foreground(t.TextSecondary).
			Padding(0, 1),

		CommandSelected: lipgloss.NewStyle().
			Foreground(t.TextPrimary).
			Background(t.Surface).
			Padding(0, 1),

		KeyHint: lipgloss.NewStyle().
			Foreground(t.TextMuted),

		Badge: lipgloss.NewStyle().
			Foreground(t.Background).
			Background(t.Secondary).
			Padding(0, 1),

		BadgeConfirm: lipgloss.NewStyle().
			Foreground(t.Background).
			Background(t.Success).
			Padding(0, 1).
			Bold(true),

		BadgeAutopilot: lipgloss.NewStyle().
			Foreground(t.Background).
			Background(t.Warning).
			Padding(0, 1).
			Bold(true),

		BorderedBox: lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(t.Border).
			Padding(1, 2),

		// Thinking/Reasoning (Claude Code style - subtle, collapsible)
		ThinkingBox: lipgloss.NewStyle().
			Foreground(t.TextMuted).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#3D4450")).
			Padding(0, 1).
			MarginBottom(1),

		ThinkingCollapsed: lipgloss.NewStyle().
			Foreground(t.TextMuted).
			Italic(true),

		// Progress indicators
		ProgressBar: lipgloss.NewStyle().
			Foreground(t.TextMuted),

		ProgressFilled: lipgloss.NewStyle().
			Foreground(t.Success),

		ProgressEmpty: lipgloss.NewStyle().
			Foreground(t.TextMuted),

		// Subagent display
		SubAgentBox: lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(t.Secondary).
			Padding(0, 1),

		SubAgentRunning: lipgloss.NewStyle().
			Foreground(t.Warning),

		SubAgentDone: lipgloss.NewStyle().
			Foreground(t.Success),

		// Diff view
		DiffAdd: lipgloss.NewStyle().
			Foreground(t.Success).
			Background(lipgloss.Color("#1a3d1a")),

		DiffRemove: lipgloss.NewStyle().
			Foreground(t.Error).
			Background(lipgloss.Color("#3d1a1a")),

		DiffHeader: lipgloss.NewStyle().
			Foreground(t.Info).
			Bold(true),
	}
}

