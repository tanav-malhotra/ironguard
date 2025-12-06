package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/tanav-malhotra/ironguard/internal/agent"
)

// CheckpointViewer renders a modal overlay showing the checkpoint tree.
type CheckpointViewer struct {
	nodes       []*agent.CheckpointNode
	selectedIdx int
	currentID   int
	branch      string
	width       int
	height      int
	styles      Styles
}

// NewCheckpointViewer creates a new checkpoint viewer.
func NewCheckpointViewer(cm *agent.CheckpointManager, width, height int, styles Styles) *CheckpointViewer {
	nodes := cm.ListCheckpoints()
	current := cm.GetCurrentCheckpoint()
	currentID := 0
	if current != nil {
		currentID = current.ID
	}

	return &CheckpointViewer{
		nodes:       nodes,
		selectedIdx: 0,
		currentID:   currentID,
		branch:      cm.GetCurrentBranch(),
		width:       width,
		height:      height,
		styles:      styles,
	}
}

// Up moves selection up.
func (cv *CheckpointViewer) Up() {
	if cv.selectedIdx > 0 {
		cv.selectedIdx--
	}
}

// Down moves selection down.
func (cv *CheckpointViewer) Down() {
	if cv.selectedIdx < len(cv.nodes)-1 {
		cv.selectedIdx++
	}
}

// Selected returns the currently selected checkpoint node.
func (cv *CheckpointViewer) Selected() *agent.CheckpointNode {
	if cv.selectedIdx >= 0 && cv.selectedIdx < len(cv.nodes) {
		return cv.nodes[cv.selectedIdx]
	}
	return nil
}

// Render renders the checkpoint viewer.
func (cv *CheckpointViewer) Render() string {
	if len(cv.nodes) == 0 {
		return cv.renderEmpty()
	}

	// Calculate dimensions
	viewerWidth := cv.width - 10
	if viewerWidth > 80 {
		viewerWidth = 80
	}
	if viewerWidth < 40 {
		viewerWidth = 40
	}

	viewerHeight := cv.height - 10
	if viewerHeight > 30 {
		viewerHeight = 30
	}
	if viewerHeight < 10 {
		viewerHeight = 10
	}

	// Header - use theme-matching colors
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00D4FF")). // Theme primary cyan
		Align(lipgloss.Center).
		Width(viewerWidth - 4)

	header := headerStyle.Render("📍 CHECKPOINTS")
	branchLine := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#8892A2")). // Theme text secondary
		Align(lipgloss.Center).
		Width(viewerWidth - 4).
		Render(fmt.Sprintf("Branch: %s", cv.branch))

	// Calculate visible items
	contentHeight := viewerHeight - 8 // Account for header, footer, borders
	startIdx := 0
	if cv.selectedIdx >= contentHeight {
		startIdx = cv.selectedIdx - contentHeight + 1
	}
	endIdx := startIdx + contentHeight
	if endIdx > len(cv.nodes) {
		endIdx = len(cv.nodes)
	}

	// Render checkpoint list
	var lines []string
	for i := startIdx; i < endIdx; i++ {
		node := cv.nodes[i]
		line := cv.renderNode(node, i == cv.selectedIdx, viewerWidth-6)
		lines = append(lines, line)
	}

	// Scroll indicators
	scrollInfo := ""
	if startIdx > 0 {
		scrollInfo += fmt.Sprintf("↑ %d more  ", startIdx)
	}
	if endIdx < len(cv.nodes) {
		scrollInfo += fmt.Sprintf("↓ %d more", len(cv.nodes)-endIdx)
	}
	if scrollInfo != "" {
		scrollInfo = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#4A5568")). // Theme muted
			Render(scrollInfo)
	}

	content := strings.Join(lines, "\n")

	// Footer with controls
	footerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#4A5568")). // Theme muted
		Align(lipgloss.Center).
		Width(viewerWidth - 4)

	footer := footerStyle.Render("↑↓ - Navigate  Enter - Restore  D - Delete  E - Edit  Esc - Close")

	// Combine everything
	body := lipgloss.JoinVertical(lipgloss.Left,
		"",
		header,
		branchLine,
		"",
		content,
		scrollInfo,
		"",
		footer,
	)

	// Box style - use theme-matching border
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#1E2A3A")). // Theme subtle border
		Padding(1, 2).
		Width(viewerWidth).
		Height(viewerHeight)

	return boxStyle.Render(body)
}

func (cv *CheckpointViewer) renderNode(node *agent.CheckpointNode, selected bool, width int) string {
	// Type icon
	icon := cv.getTypeIcon(node.Type)

	// Current marker
	currentMarker := "  "
	if node.ID == cv.currentID {
		currentMarker = "► "
	}

	// Branch indicator
	branchInfo := ""
	if node.BranchName != "main" {
		branchInfo = fmt.Sprintf(" [%s]", node.BranchName)
	}

	// Format line
	line := fmt.Sprintf("%s%s #%d %s%s", currentMarker, icon, node.ID, node.TimeLabel, branchInfo)

	// Truncate if needed
	if len(line) > width-2 {
		line = line[:width-5] + "..."
	}

	// Style based on selection - use theme colors
	style := lipgloss.NewStyle().Width(width)
	if selected {
		style = style.
			Background(lipgloss.Color("#00D4FF")). // Theme primary
			Foreground(lipgloss.Color("#0A0E14")). // Theme background
			Bold(true)
	} else if node.ID == cv.currentID {
		style = style.Foreground(lipgloss.Color("#00E676")) // Theme success green
	}

	return style.Render(line)
}

func (cv *CheckpointViewer) getTypeIcon(cpType agent.CheckpointType) string {
	switch cpType {
	case agent.CheckpointFileEdit:
		return "✏️"
	case agent.CheckpointFileCreate:
		return "📄"
	case agent.CheckpointFileDelete:
		return "🗑️"
	case agent.CheckpointCommand:
		return "⚡"
	case agent.CheckpointUserCreate, agent.CheckpointUserDelete, agent.CheckpointUserModify:
		return "👤"
	case agent.CheckpointService:
		return "⚙️"
	case agent.CheckpointFirewall:
		return "🔥"
	case agent.CheckpointManual:
		return "📌"
	case agent.CheckpointSession:
		return "🚀"
	default:
		return "📝"
	}
}

func (cv *CheckpointViewer) renderEmpty() string {
	width := 50
	height := 10

	content := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#8892A2")). // Theme text secondary
		Align(lipgloss.Center).
		Width(width - 4).
		Render("No checkpoints yet.\n\nCheckpoints are created automatically\nwhen the AI modifies files.\n\nUse /checkpoints create to create one manually.")

	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#1E2A3A")). // Theme subtle border
		Padding(1, 2).
		Width(width).
		Height(height)

	return boxStyle.Render(content)
}

// CenterOverlay centers the viewer in the terminal using lipgloss.Place.
func CenterOverlay(overlay, background string, termWidth, termHeight int) string {
	// Use lipgloss.Place to center the overlay
	// We use a dark gray instead of pure black for the whitespace background
	_ = background // Background parameter kept for API compatibility
	return lipgloss.Place(
		termWidth,
		termHeight,
		lipgloss.Center,
		lipgloss.Center,
		overlay,
		lipgloss.WithWhitespaceBackground(lipgloss.Color("#0A0E14")),
	)
}


