package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/tanav-malhotra/ironguard/internal/agent"
	"github.com/tanav-malhotra/ironguard/internal/tools"
)

// PopupTab represents the tabs in the popup viewer.
type PopupTab int

const (
	PopupTabTodos PopupTab = iota
	PopupTabCheckpoints
)

// PopupViewer renders a tabbed modal overlay.
type PopupViewer struct {
	activeTab       PopupTab
	todoSelectedIdx int
	cpSelectedIdx   int

	// Data
	todos       []tools.AITodoEntry
	checkpoints []*agent.CheckpointNode
	currentCpID int
	cpBranch    string

	// Dimensions
	width  int
	height int
	styles Styles
}

// NewPopupViewer creates a new tabbed popup viewer.
func NewPopupViewer(cm *agent.CheckpointManager, width, height int, styles Styles) *PopupViewer {
	nodes := cm.ListCheckpoints()
	current := cm.GetCurrentCheckpoint()
	currentID := 0
	if current != nil {
		currentID = current.ID
	}

	return &PopupViewer{
		activeTab:       PopupTabTodos, // Default to AI Todos tab
		todoSelectedIdx: 0,
		cpSelectedIdx:   0,
		todos:           tools.GetAITodos(),
		checkpoints:     nodes,
		currentCpID:     currentID,
		cpBranch:        cm.GetCurrentBranch(),
		width:           width,
		height:          height,
		styles:          styles,
	}
}

// RefreshData refreshes the data in the popup.
func (pv *PopupViewer) RefreshData(cm *agent.CheckpointManager) {
	pv.todos = tools.GetAITodos()
	pv.checkpoints = cm.ListCheckpoints()
	current := cm.GetCurrentCheckpoint()
	if current != nil {
		pv.currentCpID = current.ID
	}
	pv.cpBranch = cm.GetCurrentBranch()
}

// SetTab sets the active tab.
func (pv *PopupViewer) SetTab(tab PopupTab) {
	pv.activeTab = tab
}

// NextTab switches to the next tab.
func (pv *PopupViewer) NextTab() {
	if pv.activeTab == PopupTabTodos {
		pv.activeTab = PopupTabCheckpoints
	} else {
		pv.activeTab = PopupTabTodos
	}
}

// PrevTab switches to the previous tab.
func (pv *PopupViewer) PrevTab() {
	pv.NextTab() // With 2 tabs, next and prev are the same
}

// Up moves selection up in the current tab.
func (pv *PopupViewer) Up() {
	switch pv.activeTab {
	case PopupTabTodos:
		if pv.todoSelectedIdx > 0 {
			pv.todoSelectedIdx--
		}
	case PopupTabCheckpoints:
		if pv.cpSelectedIdx > 0 {
			pv.cpSelectedIdx--
		}
	}
}

// Down moves selection down in the current tab.
func (pv *PopupViewer) Down() {
	switch pv.activeTab {
	case PopupTabTodos:
		if pv.todoSelectedIdx < len(pv.todos)-1 {
			pv.todoSelectedIdx++
		}
	case PopupTabCheckpoints:
		if pv.cpSelectedIdx < len(pv.checkpoints)-1 {
			pv.cpSelectedIdx++
		}
	}
}

// SelectedCheckpoint returns the currently selected checkpoint.
func (pv *PopupViewer) SelectedCheckpoint() *agent.CheckpointNode {
	if pv.cpSelectedIdx >= 0 && pv.cpSelectedIdx < len(pv.checkpoints) {
		return pv.checkpoints[pv.cpSelectedIdx]
	}
	return nil
}

// SelectedTodo returns the currently selected todo.
func (pv *PopupViewer) SelectedTodo() *tools.AITodoEntry {
	if pv.todoSelectedIdx >= 0 && pv.todoSelectedIdx < len(pv.todos) {
		return &pv.todos[pv.todoSelectedIdx]
	}
	return nil
}

// Render renders the popup viewer with terminal-style aesthetic.
func (pv *PopupViewer) Render() string {
	// Calculate dimensions
	viewerWidth := pv.width - 10
	if viewerWidth > 76 {
		viewerWidth = 76
	}
	if viewerWidth < 40 {
		viewerWidth = 40
	}

	viewerHeight := pv.height - 8
	if viewerHeight > 28 {
		viewerHeight = 28
	}
	if viewerHeight < 10 {
		viewerHeight = 10
	}

	innerWidth := viewerWidth - 4

	// Colors
	borderColor := lipgloss.Color("#00D4FF")
	mutedColor := lipgloss.Color("#4A5568")
	accentColor := lipgloss.Color("#00D4FF")

	// Build the popup manually with ROUNDED box-drawing characters
	var lines []string

	// Top border with title (rounded corners)
	title := " IRONGUARD VIEWER "
	topLeft := "╭"
	topRight := "╮"
	topLine := strings.Repeat("─", (innerWidth-len(title))/2) + title + strings.Repeat("─", (innerWidth-len(title)+1)/2)
	lines = append(lines, lipgloss.NewStyle().Foreground(borderColor).Render(topLeft+topLine+topRight))

	// Empty line
	lines = append(lines, pv.renderBoxLine("", innerWidth, borderColor))

	// Tabs
	tabs := pv.renderTerminalTabs(innerWidth)
	lines = append(lines, pv.renderBoxLine(tabs, innerWidth, borderColor))

	// Separator under tabs
	sepLine := strings.Repeat("─", innerWidth)
	lines = append(lines, lipgloss.NewStyle().Foreground(borderColor).Render("├"+sepLine+"┤"))

	// Content area
	contentHeight := viewerHeight - 8 // Account for header, tabs, separator, footer
	var content string
	var footer string
	switch pv.activeTab {
	case PopupTabTodos:
		content = pv.renderTodosTerminal(innerWidth, contentHeight)
		footer = "↑↓ select  ←→ tab  ESC close"
	case PopupTabCheckpoints:
		content = pv.renderCheckpointsTerminal(innerWidth, contentHeight)
		footer = "↑↓ select  ←→ tab  ENTER restore  D delete  ESC close"
	}

	// Add content lines
	contentLines := strings.Split(content, "\n")
	for i := 0; i < contentHeight; i++ {
		line := ""
		if i < len(contentLines) {
			line = contentLines[i]
		}
		lines = append(lines, pv.renderBoxLine(line, innerWidth, borderColor))
	}

	// Separator above footer
	lines = append(lines, lipgloss.NewStyle().Foreground(borderColor).Render("├"+sepLine+"┤"))

	// Footer
	footerStyle := lipgloss.NewStyle().Foreground(mutedColor)
	footerPadded := pv.centerText(footerStyle.Render(footer), innerWidth)
	lines = append(lines, pv.renderBoxLine(footerPadded, innerWidth, borderColor))

	// Bottom border (rounded corners)
	bottomLeft := "╰"
	bottomRight := "╯"
	bottomLine := strings.Repeat("─", innerWidth)
	lines = append(lines, lipgloss.NewStyle().Foreground(borderColor).Render(bottomLeft+bottomLine+bottomRight))

	// Add accent glow effect (subtle)
	glowStyle := lipgloss.NewStyle().
		Foreground(accentColor)

	return glowStyle.Render(strings.Join(lines, "\n"))
}

// renderBoxLine renders a line with box borders.
func (pv *PopupViewer) renderBoxLine(content string, innerWidth int, borderColor lipgloss.Color) string {
	borderStyle := lipgloss.NewStyle().Foreground(borderColor)
	contentWidth := lipgloss.Width(content)
	padding := innerWidth - contentWidth
	if padding < 0 {
		padding = 0
	}
	return borderStyle.Render("│") + content + strings.Repeat(" ", padding) + borderStyle.Render("│")
}

// centerText centers text within a given width.
func (pv *PopupViewer) centerText(text string, width int) string {
	textWidth := lipgloss.Width(text)
	if textWidth >= width {
		return text
	}
	leftPad := (width - textWidth) / 2
	rightPad := width - textWidth - leftPad
	return strings.Repeat(" ", leftPad) + text + strings.Repeat(" ", rightPad)
}

// renderTerminalTabs renders tabs in terminal style.
func (pv *PopupViewer) renderTerminalTabs(width int) string {
	todoCount := len(pv.todos)
	cpCount := len(pv.checkpoints)

	// Tab labels
	todosLabel := fmt.Sprintf("[ AI TASKS (%d) ]", todoCount)
	cpLabel := fmt.Sprintf("[ CHECKPOINTS (%d) ]", cpCount)

	// Styles
	activeStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#0A0E14")).
		Background(lipgloss.Color("#00D4FF"))

	inactiveStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6B7280"))

	var todosTab, cpTab string
	if pv.activeTab == PopupTabTodos {
		todosTab = activeStyle.Render(todosLabel)
		cpTab = inactiveStyle.Render(cpLabel)
	} else {
		todosTab = inactiveStyle.Render(todosLabel)
		cpTab = activeStyle.Render(cpLabel)
	}

	// Center the tabs
	tabs := todosTab + "  " + cpTab
	return pv.centerText(tabs, width)
}

// renderTodosTerminal renders the AI todos in terminal style.
func (pv *PopupViewer) renderTodosTerminal(width, height int) string {
	if len(pv.todos) == 0 {
		emptyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280"))
		return pv.centerText(emptyStyle.Render("No AI tasks yet."), width) + "\n\n" +
			pv.centerText(emptyStyle.Render("The AI will create tasks here when it"), width) + "\n" +
			pv.centerText(emptyStyle.Render("plans work using create_todo or plan_tasks."), width)
	}

	// Status icons (terminal-friendly)
	statusIcons := map[string]string{
		"pending":     "○",
		"in_progress": "◐",
		"completed":   "●",
		"cancelled":   "×",
	}

	priorityMarkers := map[string]string{
		"high":   "!!!",
		"medium": "!! ",
		"low":    "!  ",
	}

	// Calculate visible items
	listHeight := height - 3 // Leave room for summary
	startIdx := 0
	if pv.todoSelectedIdx >= listHeight {
		startIdx = pv.todoSelectedIdx - listHeight + 1
	}
	endIdx := startIdx + listHeight
	if endIdx > len(pv.todos) {
		endIdx = len(pv.todos)
	}

	var lines []string

	// Scroll indicator at top
	if startIdx > 0 {
		scrollStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#4A5568"))
		lines = append(lines, scrollStyle.Render(fmt.Sprintf("  ↑ %d more", startIdx)))
	}

	for i := startIdx; i < endIdx; i++ {
		todo := pv.todos[i]
		icon := statusIcons[todo.Status]
		if icon == "" {
			icon = "○"
		}
		priority := priorityMarkers[todo.Priority]
		if priority == "" {
			priority = "   "
		}

		// Format: [○] !!! #1 Task description...
		line := fmt.Sprintf(" %s %s #%-2d %s", icon, priority, todo.ID, todo.Description)

		// Truncate if needed
		if len(line) > width-2 {
			line = line[:width-5] + "..."
		}

		// Pad to width
		for len(line) < width {
			line += " "
		}

		// Style based on selection and status
		if i == pv.todoSelectedIdx {
			style := lipgloss.NewStyle().
				Background(lipgloss.Color("#00D4FF")).
				Foreground(lipgloss.Color("#0A0E14")).
				Bold(true)
			lines = append(lines, style.Render(line))
		} else {
			var style lipgloss.Style
			switch todo.Status {
			case "completed":
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("#00E676"))
			case "in_progress":
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFB000"))
			case "cancelled":
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5370")).Strikethrough(true)
			default:
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("#E8EDF4"))
			}
			lines = append(lines, style.Render(line))
		}
	}

	// Scroll indicator at bottom
	if endIdx < len(pv.todos) {
		scrollStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#4A5568"))
		lines = append(lines, scrollStyle.Render(fmt.Sprintf("  ↓ %d more", len(pv.todos)-endIdx)))
	}

	// Summary line
	pending, inProgress, completed := 0, 0, 0
	for _, t := range pv.todos {
		switch t.Status {
		case "pending":
			pending++
		case "in_progress":
			inProgress++
		case "completed":
			completed++
		}
	}

	summaryStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280"))
	summary := fmt.Sprintf("○ %d pending  ◐ %d active  ● %d done", pending, inProgress, completed)
	lines = append(lines, "", pv.centerText(summaryStyle.Render(summary), width))

	return strings.Join(lines, "\n")
}

// renderCheckpointsTerminal renders checkpoints in terminal style.
func (pv *PopupViewer) renderCheckpointsTerminal(width, height int) string {
	if len(pv.checkpoints) == 0 {
		emptyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280"))
		return pv.centerText(emptyStyle.Render("No checkpoints yet."), width) + "\n\n" +
			pv.centerText(emptyStyle.Render("Checkpoints are created automatically"), width) + "\n" +
			pv.centerText(emptyStyle.Render("when the AI modifies files."), width) + "\n\n" +
			pv.centerText(emptyStyle.Render("Use /checkpoints create for manual saves."), width)
	}

	// Branch info
	branchStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00D4FF"))
	mutedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280"))
	branchLine := mutedStyle.Render("branch: ") + branchStyle.Render(pv.cpBranch)

	// Calculate visible items
	listHeight := height - 3 // Leave room for branch line
	startIdx := 0
	if pv.cpSelectedIdx >= listHeight {
		startIdx = pv.cpSelectedIdx - listHeight + 1
	}
	endIdx := startIdx + listHeight
	if endIdx > len(pv.checkpoints) {
		endIdx = len(pv.checkpoints)
	}

	var lines []string
	lines = append(lines, pv.centerText(branchLine, width), "")

	// Scroll indicator at top
	if startIdx > 0 {
		scrollStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#4A5568"))
		lines = append(lines, scrollStyle.Render(fmt.Sprintf("  ↑ %d more", startIdx)))
	}

	for i := startIdx; i < endIdx; i++ {
		node := pv.checkpoints[i]
		line := pv.renderCheckpointTerminal(node, i == pv.cpSelectedIdx, width)
		lines = append(lines, line)
	}

	// Scroll indicator at bottom
	if endIdx < len(pv.checkpoints) {
		scrollStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#4A5568"))
		lines = append(lines, scrollStyle.Render(fmt.Sprintf("  ↓ %d more", len(pv.checkpoints)-endIdx)))
	}

	return strings.Join(lines, "\n")
}

// renderCheckpointTerminal renders a single checkpoint in terminal style.
func (pv *PopupViewer) renderCheckpointTerminal(node *agent.CheckpointNode, selected bool, width int) string {
	// Type icon (ASCII-friendly)
	icon := pv.getTerminalIcon(node.Type)

	// Current marker
	marker := "  "
	if node.ID == pv.currentCpID {
		marker = "► "
	}

	// Branch indicator
	branchInfo := ""
	if node.BranchName != "main" {
		branchInfo = fmt.Sprintf(" @%s", node.BranchName)
	}

	// Description (truncated)
	desc := node.Description
	maxDescLen := width - 20 - len(branchInfo)
	if len(desc) > maxDescLen {
		desc = desc[:maxDescLen-3] + "..."
	}

	// Format line: ► [✎] #1 2m ago  description @branch
	line := fmt.Sprintf("%s%s #%-2d %-6s %s%s", marker, icon, node.ID, node.TimeLabel, desc, branchInfo)

	// Pad to width
	for len(line) < width {
		line += " "
	}

	// Style based on selection
	if selected {
		style := lipgloss.NewStyle().
			Background(lipgloss.Color("#00D4FF")).
			Foreground(lipgloss.Color("#0A0E14")).
			Bold(true)
		return style.Render(line)
	} else if node.ID == pv.currentCpID {
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("#00E676"))
		return style.Render(line)
	}

	return lipgloss.NewStyle().Foreground(lipgloss.Color("#E8EDF4")).Render(line)
}

// getTerminalIcon returns ASCII-friendly icons for checkpoint types.
func (pv *PopupViewer) getTerminalIcon(cpType agent.CheckpointType) string {
	switch cpType {
	case agent.CheckpointFileEdit:
		return "[✎]"
	case agent.CheckpointFileCreate:
		return "[+]"
	case agent.CheckpointFileDelete:
		return "[-]"
	case agent.CheckpointCommand:
		return "[>]"
	case agent.CheckpointUserCreate, agent.CheckpointUserDelete, agent.CheckpointUserModify:
		return "[U]"
	case agent.CheckpointService:
		return "[S]"
	case agent.CheckpointFirewall:
		return "[F]"
	case agent.CheckpointManual:
		return "[M]"
	case agent.CheckpointSession:
		return "[*]"
	default:
		return "[?]"
	}
}

