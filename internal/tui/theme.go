package tui

import "github.com/charmbracelet/lipgloss"

// Theme defines the color palette and styling for the TUI.
// IronGuard: High-tech security operations aesthetic
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

	// Special accent colors
	Cyan    lipgloss.Color
	Magenta lipgloss.Color
}

// DefaultTheme returns the IronGuard high-tech dark theme.
// Inspired by cybersecurity operations centers and tactical interfaces.
func DefaultTheme() Theme {
	return Theme{
		// Core palette: Deep space black with electric cyan accents
		Primary:    lipgloss.Color("#00D4FF"), // Electric cyan - primary brand
		Secondary:  lipgloss.Color("#7B68EE"), // Medium slate blue
		Accent:     lipgloss.Color("#FF6B35"), // Tactical orange for alerts
		Background: lipgloss.Color("#0A0E14"), // Near-black with blue tint
		Surface:    lipgloss.Color("#0D1219"), // Slightly elevated surface

		// Text hierarchy
		TextPrimary:   lipgloss.Color("#E4E8F0"), // Crisp white-blue
		TextSecondary: lipgloss.Color("#8892A2"), // Soft gray-blue
		TextMuted:     lipgloss.Color("#4A5568"), // Dim gray

		// Semantic - security-focused
		Success: lipgloss.Color("#00E676"), // Bright green - secure
		Warning: lipgloss.Color("#FFAB00"), // Amber - caution
		Error:   lipgloss.Color("#FF5252"), // Red - threat/error
		Info:    lipgloss.Color("#40C4FF"), // Light cyan - info

		// Borders
		Border:      lipgloss.Color("#1E2A3A"), // Subtle blue-gray
		BorderFocus: lipgloss.Color("#00D4FF"), // Electric cyan on focus

		// Special accents
		Cyan:    lipgloss.Color("#00D4FF"),
		Magenta: lipgloss.Color("#E040FB"),
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
	UserBubble    lipgloss.Style // Chat bubble for user messages
	AIMessage     lipgloss.Style
	AIBubble      lipgloss.Style // Chat bubble for AI messages
	SystemMessage lipgloss.Style
	ToolCall      lipgloss.Style
	ToolBox       lipgloss.Style // Box around tool output
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
			BorderStyle(lipgloss.ThickBorder()).
			BorderForeground(t.Border).
			BorderLeft(true).
			BorderRight(false).
			BorderTop(false).
			BorderBottom(false).
			Padding(1, 2).
			MarginLeft(1),

		ChatPane: lipgloss.NewStyle().
			Padding(0, 1),

		InputPane: lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(t.Primary).
			Padding(0, 1),

		StatusBar: lipgloss.NewStyle().
			Foreground(t.TextMuted).
			Padding(0, 1).
			MarginTop(0),

		Title: lipgloss.NewStyle().
			Foreground(t.Primary).
			Bold(true),

		Subtitle: lipgloss.NewStyle().
			Foreground(t.Secondary),

		Label: lipgloss.NewStyle().
			Foreground(t.Primary).
			Bold(true),

		Value: lipgloss.NewStyle().
			Foreground(t.TextPrimary),

		Muted: lipgloss.NewStyle().
			Foreground(t.TextMuted),

		UserMessage: lipgloss.NewStyle().
			Foreground(t.Cyan).
			Bold(true),

		UserBubble: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#0066CC")).
			Padding(0, 1).
			MarginLeft(2),

		AIMessage: lipgloss.NewStyle().
			Foreground(t.TextPrimary),

		AIBubble: lipgloss.NewStyle().
			Foreground(t.TextPrimary).
			Background(lipgloss.Color("#1A1F2E")).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(t.Primary).
			BorderLeft(true).
			BorderRight(false).
			BorderTop(false).
			BorderBottom(false).
			Padding(0, 1).
			MarginRight(4),

		SystemMessage: lipgloss.NewStyle().
			Foreground(t.TextMuted).
			Italic(true).
			PaddingLeft(1),

		ToolCall: lipgloss.NewStyle().
			Foreground(t.Accent).
			Bold(true),

		ToolBox: lipgloss.NewStyle().
			Foreground(t.TextSecondary).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#2A3A4A")).
			Padding(0, 1).
			MarginLeft(2).
			MarginRight(4),

		Error: lipgloss.NewStyle().
			Foreground(t.Error).
			Bold(true),

		Success: lipgloss.NewStyle().
			Foreground(t.Success).
			Bold(true),

		Warning: lipgloss.NewStyle().
			Foreground(t.Warning).
			Bold(true),

		Command: lipgloss.NewStyle().
			Foreground(t.TextSecondary).
			Padding(0, 1),

		CommandSelected: lipgloss.NewStyle().
			Foreground(t.Background).
			Background(t.Primary).
			Padding(0, 1).
			Bold(true),

		KeyHint: lipgloss.NewStyle().
			Foreground(t.TextMuted),

		Badge: lipgloss.NewStyle().
			Foreground(t.Background).
			Background(t.Secondary).
			Padding(0, 1).
			Bold(true),

		BadgeConfirm: lipgloss.NewStyle().
			Foreground(t.Background).
			Background(t.Success).
			Padding(0, 1).
			Bold(true),

		BadgeAutopilot: lipgloss.NewStyle().
			Foreground(t.Background).
			Background(t.Primary).
			Padding(0, 1).
			Bold(true),

		BorderedBox: lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(t.Primary).
			Padding(0, 1),

		// Thinking/Reasoning - subtle glow effect
		ThinkingBox: lipgloss.NewStyle().
			Foreground(t.TextMuted).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(t.Secondary).
			Padding(0, 1).
			MarginBottom(1),

		ThinkingCollapsed: lipgloss.NewStyle().
			Foreground(t.Secondary).
			Italic(true),

		// Progress indicators
		ProgressBar: lipgloss.NewStyle().
			Foreground(t.TextMuted),

		ProgressFilled: lipgloss.NewStyle().
			Foreground(t.Primary).
			Background(t.Primary),

		ProgressEmpty: lipgloss.NewStyle().
			Foreground(t.Border),

		// Subagent display
		SubAgentBox: lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(t.Secondary).
			Padding(0, 1),

		SubAgentRunning: lipgloss.NewStyle().
			Foreground(t.Warning).
			Bold(true),

		SubAgentDone: lipgloss.NewStyle().
			Foreground(t.Success),

		// Diff view
		DiffAdd: lipgloss.NewStyle().
			Foreground(t.Success).
			Background(lipgloss.Color("#0D2818")),

		DiffRemove: lipgloss.NewStyle().
			Foreground(t.Error).
			Background(lipgloss.Color("#2D0F0F")),

		DiffHeader: lipgloss.NewStyle().
			Foreground(t.Primary).
			Bold(true),
	}
}

