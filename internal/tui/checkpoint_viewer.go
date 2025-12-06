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

	// Header
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00FFFF")).
		Align(lipgloss.Center).
		Width(viewerWidth - 4)

	header := headerStyle.Render("📍 CHECKPOINTS")
	branchLine := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#888888")).
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
			Foreground(lipgloss.Color("#666666")).
			Render(scrollInfo)
	}

	content := strings.Join(lines, "\n")

	// Footer with controls
	footerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#888888")).
		Align(lipgloss.Center).
		Width(viewerWidth - 4)

	footer := footerStyle.Render("↑↓ Navigate  Enter Restore  D Delete  E Edit  Esc Close")

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

	// Box style
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#00FFFF")).
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

	// Style based on selection
	style := lipgloss.NewStyle().Width(width)
	if selected {
		style = style.
			Background(lipgloss.Color("#00FFFF")).
			Foreground(lipgloss.Color("#000000")).
			Bold(true)
	} else if node.ID == cv.currentID {
		style = style.Foreground(lipgloss.Color("#00FF00"))
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
		Foreground(lipgloss.Color("#888888")).
		Align(lipgloss.Center).
		Width(width - 4).
		Render("No checkpoints yet.\n\nCheckpoints are created automatically\nwhen the AI modifies files.\n\nUse /checkpoints create to create one manually.")

	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#00FFFF")).
		Padding(1, 2).
		Width(width).
		Height(height)

	return boxStyle.Render(content)
}

// CenterOverlay centers the viewer in the terminal.
func CenterOverlay(overlay, background string, termWidth, termHeight int) string {
	overlayLines := strings.Split(overlay, "\n")
	overlayHeight := len(overlayLines)
	overlayWidth := 0
	for _, line := range overlayLines {
		if len(line) > overlayWidth {
			overlayWidth = len(line)
		}
	}

	// Calculate centering offsets
	topPad := (termHeight - overlayHeight) / 2
	if topPad < 0 {
		topPad = 0
	}
	leftPad := (termWidth - overlayWidth) / 2
	if leftPad < 0 {
		leftPad = 0
	}

	// Build centered overlay
	var result strings.Builder
	bgLines := strings.Split(background, "\n")

	for i := 0; i < termHeight; i++ {
		if i >= topPad && i < topPad+overlayHeight {
			// Overlay line
			olIdx := i - topPad
			if olIdx < len(overlayLines) {
				line := strings.Repeat(" ", leftPad) + overlayLines[olIdx]
				// Pad to full width
				if len(line) < termWidth {
					line += strings.Repeat(" ", termWidth-len(line))
				}
				result.WriteString(line)
			}
		} else {
			// Background line (dimmed)
			if i < len(bgLines) {
				result.WriteString(bgLines[i])
			}
		}
		if i < termHeight-1 {
			result.WriteString("\n")
		}
	}

	return result.String()
}

