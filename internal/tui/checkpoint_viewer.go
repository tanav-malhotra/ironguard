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

// CenterOverlay places the popup over the background content, keeping the background visible and dimmed.
// Only the chat area (left side) is dimmed; sidebar and input remain undimmed.
func CenterOverlay(overlay, background string, termWidth, termHeight int, sidebarWidth int) string {
	bgLines := strings.Split(background, "\n")
	overlayLines := strings.Split(overlay, "\n")

	overlayHeight := len(overlayLines)
	overlayWidth := 0
	for _, line := range overlayLines {
		if w := lipgloss.Width(line); w > overlayWidth {
			overlayWidth = w
		}
	}

	// Center position
	startY := (termHeight - overlayHeight) / 2
	startX := (termWidth - overlayWidth) / 2
	if startY < 0 {
		startY = 0
	}
	if startX < 0 {
		startX = 0
	}

	// Dim style for background
	dimStyle := lipgloss.NewStyle().Faint(true)

	// Determine chat area width (approximate left pane)
	chatWidth := termWidth - sidebarWidth - 3
	if chatWidth < 0 {
		chatWidth = 0
	}
	// Avoid dimming the column of the sidebar separator
	chatDimWidth := chatWidth - 1
	if chatDimWidth < 0 {
		chatDimWidth = 0
	}

	// Define non-dim rows: bottom input/status area (last 5 rows)
	noDimStartRow := termHeight - 5
	if noDimStartRow < 0 {
		noDimStartRow = 0
	}

	// Ensure background height
	for len(bgLines) < termHeight {
		bgLines = append(bgLines, "")
	}

	// Compose overlay onto dimmed background
	for oy, oLine := range overlayLines {
		y := startY + oy
		if y < 0 || y >= termHeight {
			continue
		}

		bgLine := truncateToWidth(bgLines[y], termWidth)

		// Pad overlay line to overlayWidth
		oWidth := lipgloss.Width(oLine)
		if oWidth < overlayWidth {
			oLine += strings.Repeat(" ", overlayWidth-oWidth)
		}

		left := truncateToWidth(bgLine, startX)
		right := substringFromWidth(bgLine, startX+overlayWidth, termWidth-(startX+overlayWidth))

		if y >= noDimStartRow {
			// Do not dim bottom/input area
			bgLines[y] = left + oLine + right
			continue
		}

		// Dim only chat portion on left
		leftDim := dimPrefix(left, chatDimWidth, dimStyle)

		// Remaining chat width after overlay
		remainingChat := chatDimWidth - (startX + overlayWidth)
		if remainingChat < 0 {
			remainingChat = 0
		}
		rightDim := dimPrefix(right, remainingChat, dimStyle)

		bgLines[y] = leftDim + oLine + rightDim
	}

	// Dim the rest of the lines
	for y := 0; y < termHeight; y++ {
		if y < startY || y >= startY+overlayHeight {
			if y < noDimStartRow {
				bgLines[y] = dimPrefix(bgLines[y], chatDimWidth, dimStyle)
			}
		}
	}

	return strings.Join(bgLines, "\n")
}

// truncateToWidth truncates a string (ANSI-safe) to a visual width and pads if needed.
func truncateToWidth(s string, width int) string {
	if width <= 0 {
		return ""
	}
	current := 0
	var b strings.Builder
	inEscape := false
	for _, r := range s {
		if r == '\x1b' {
			inEscape = true
			b.WriteRune(r)
			continue
		}
		if inEscape {
			b.WriteRune(r)
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
			continue
		}
		if current+1 > width {
			break
		}
		b.WriteRune(r)
		current++
	}
	for current < width {
		b.WriteRune(' ')
		current++
	}
	return b.String()
}

// substringFromWidth extracts a substring starting from a visual offset/length (ANSI-safe) and pads.
func substringFromWidth(s string, offset, length int) string {
	if length <= 0 {
		return ""
	}

	current := 0
	started := false
	var b strings.Builder
	resultWidth := 0
	inEscape := false

	for _, r := range s {
		if r == '\x1b' {
			inEscape = true
			if started {
				b.WriteRune(r)
			}
			continue
		}
		if inEscape {
			if started {
				b.WriteRune(r)
			}
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
			continue
		}

		if !started {
			if current >= offset {
				started = true
				b.WriteRune(r)
				resultWidth++
			}
			current++
		} else {
			if resultWidth >= length {
				break
			}
			b.WriteRune(r)
			resultWidth++
		}
	}

	for resultWidth < length {
		b.WriteRune(' ')
		resultWidth++
	}

	return b.String()
}

// dimPrefix dims only the first prefixWidth columns of the line (ANSI-safe), leaves the rest untouched.
func dimPrefix(s string, prefixWidth int, dimStyle lipgloss.Style) string {
	if prefixWidth <= 0 {
		return s
	}
	totalWidth := lipgloss.Width(s)
	if prefixWidth >= totalWidth {
		return dimStyle.Render(s)
	}
	left := truncateToWidth(s, prefixWidth)
	right := substringFromWidth(s, prefixWidth, totalWidth-prefixWidth)
	return dimStyle.Render(left) + right
}


