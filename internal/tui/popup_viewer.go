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

// Render renders the popup viewer.
func (pv *PopupViewer) Render() string {
	// Calculate dimensions
	viewerWidth := pv.width - 10
	if viewerWidth > 80 {
		viewerWidth = 80
	}
	if viewerWidth < 40 {
		viewerWidth = 40
	}

	viewerHeight := pv.height - 10
	if viewerHeight > 30 {
		viewerHeight = 30
	}
	if viewerHeight < 10 {
		viewerHeight = 10
	}

	// Render tabs
	tabs := pv.renderTabs(viewerWidth - 4)

	// Render content based on active tab
	var content string
	var footer string
	switch pv.activeTab {
	case PopupTabTodos:
		content = pv.renderTodosContent(viewerWidth-6, viewerHeight-10)
		footer = "↑↓ Navigate  ←→ Switch Tab  Esc - Close"
	case PopupTabCheckpoints:
		content = pv.renderCheckpointsContent(viewerWidth-6, viewerHeight-10)
		footer = "↑↓ Navigate  ←→ Switch Tab  Enter - Restore  D - Delete  Esc - Close"
	}

	// Footer with controls
	footerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#4A5568")).
		Align(lipgloss.Center).
		Width(viewerWidth - 4)
	footerRendered := footerStyle.Render(footer)

	// Combine everything
	body := lipgloss.JoinVertical(lipgloss.Left,
		"",
		tabs,
		"",
		content,
		"",
		footerRendered,
	)

	// Box style
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#1E2A3A")).
		Padding(1, 2).
		Width(viewerWidth).
		Height(viewerHeight)

	return boxStyle.Render(body)
}

func (pv *PopupViewer) renderTabs(width int) string {
	tabWidth := (width - 4) / 2

	// Tab styles
	activeStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#0A0E14")).
		Background(lipgloss.Color("#00D4FF")).
		Align(lipgloss.Center).
		Width(tabWidth).
		Padding(0, 1)

	inactiveStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#8892A2")).
		Background(lipgloss.Color("#1E2A3A")).
		Align(lipgloss.Center).
		Width(tabWidth).
		Padding(0, 1)

	var todosTab, checkpointsTab string

	todoCount := len(pv.todos)
	cpCount := len(pv.checkpoints)

	if pv.activeTab == PopupTabTodos {
		todosTab = activeStyle.Render(fmt.Sprintf("📋 AI TODOS (%d)", todoCount))
		checkpointsTab = inactiveStyle.Render(fmt.Sprintf("📍 CHECKPOINTS (%d)", cpCount))
	} else {
		todosTab = inactiveStyle.Render(fmt.Sprintf("📋 AI TODOS (%d)", todoCount))
		checkpointsTab = activeStyle.Render(fmt.Sprintf("📍 CHECKPOINTS (%d)", cpCount))
	}

	return lipgloss.JoinHorizontal(lipgloss.Top, todosTab, " ", checkpointsTab)
}

func (pv *PopupViewer) renderTodosContent(width, height int) string {
	if len(pv.todos) == 0 {
		emptyStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8892A2")).
			Align(lipgloss.Center).
			Width(width)
		return emptyStyle.Render("\n\nNo AI tasks yet.\n\nThe AI will create tasks here when it\nplans work using create_todo or plan_tasks.\n")
	}

	// Status icons
	statusIcons := map[string]string{
		"pending":     "○",
		"in_progress": "◐",
		"completed":   "●",
		"cancelled":   "✗",
	}

	priorityIcons := map[string]string{
		"high":   "🔴",
		"medium": "🟡",
		"low":    "🟢",
	}

	// Calculate visible items
	startIdx := 0
	if pv.todoSelectedIdx >= height {
		startIdx = pv.todoSelectedIdx - height + 1
	}
	endIdx := startIdx + height
	if endIdx > len(pv.todos) {
		endIdx = len(pv.todos)
	}

	var lines []string

	// Scroll indicator at top
	if startIdx > 0 {
		scrollUp := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#4A5568")).
			Render(fmt.Sprintf("↑ %d more above", startIdx))
		lines = append(lines, scrollUp)
	}

	for i := startIdx; i < endIdx; i++ {
		todo := pv.todos[i]
		icon := statusIcons[todo.Status]
		pIcon := priorityIcons[todo.Priority]
		if pIcon == "" {
			pIcon = "🟡"
		}

		line := fmt.Sprintf("%s %s #%d: %s", icon, pIcon, todo.ID, todo.Description)

		// Truncate if needed
		if len(line) > width-2 {
			line = line[:width-5] + "..."
		}

		// Style based on selection and status
		style := lipgloss.NewStyle().Width(width)
		if i == pv.todoSelectedIdx {
			style = style.
				Background(lipgloss.Color("#00D4FF")).
				Foreground(lipgloss.Color("#0A0E14")).
				Bold(true)
		} else {
			switch todo.Status {
			case "completed":
				style = style.Foreground(lipgloss.Color("#00E676"))
			case "in_progress":
				style = style.Foreground(lipgloss.Color("#FFB000"))
			case "cancelled":
				style = style.Foreground(lipgloss.Color("#FF5370"))
			default:
				style = style.Foreground(lipgloss.Color("#E8EDF4"))
			}
		}

		lines = append(lines, style.Render(line))
	}

	// Scroll indicator at bottom
	if endIdx < len(pv.todos) {
		scrollDown := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#4A5568")).
			Render(fmt.Sprintf("↓ %d more below", len(pv.todos)-endIdx))
		lines = append(lines, scrollDown)
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

	summaryStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#8892A2")).
		Align(lipgloss.Center).
		Width(width)
	summary := summaryStyle.Render(fmt.Sprintf("─── %d pending │ %d in progress │ %d done ───", pending, inProgress, completed))
	lines = append(lines, "", summary)

	return strings.Join(lines, "\n")
}

func (pv *PopupViewer) renderCheckpointsContent(width, height int) string {
	if len(pv.checkpoints) == 0 {
		emptyStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8892A2")).
			Align(lipgloss.Center).
			Width(width)
		return emptyStyle.Render("\n\nNo checkpoints yet.\n\nCheckpoints are created automatically\nwhen the AI modifies files.\n\nUse /checkpoints create to create one manually.")
	}

	// Branch info
	branchLine := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#8892A2")).
		Align(lipgloss.Center).
		Width(width).
		Render(fmt.Sprintf("Branch: %s", pv.cpBranch))

	// Calculate visible items
	contentHeight := height - 3 // Account for branch line and scroll indicators
	startIdx := 0
	if pv.cpSelectedIdx >= contentHeight {
		startIdx = pv.cpSelectedIdx - contentHeight + 1
	}
	endIdx := startIdx + contentHeight
	if endIdx > len(pv.checkpoints) {
		endIdx = len(pv.checkpoints)
	}

	var lines []string
	lines = append(lines, branchLine, "")

	// Scroll indicator at top
	if startIdx > 0 {
		scrollUp := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#4A5568")).
			Render(fmt.Sprintf("↑ %d more above", startIdx))
		lines = append(lines, scrollUp)
	}

	for i := startIdx; i < endIdx; i++ {
		node := pv.checkpoints[i]
		line := pv.renderCheckpointNode(node, i == pv.cpSelectedIdx, width)
		lines = append(lines, line)
	}

	// Scroll indicator at bottom
	if endIdx < len(pv.checkpoints) {
		scrollDown := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#4A5568")).
			Render(fmt.Sprintf("↓ %d more below", len(pv.checkpoints)-endIdx))
		lines = append(lines, scrollDown)
	}

	return strings.Join(lines, "\n")
}

func (pv *PopupViewer) renderCheckpointNode(node *agent.CheckpointNode, selected bool, width int) string {
	// Type icon
	icon := pv.getTypeIcon(node.Type)

	// Current marker
	currentMarker := "  "
	if node.ID == pv.currentCpID {
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
			Background(lipgloss.Color("#00D4FF")).
			Foreground(lipgloss.Color("#0A0E14")).
			Bold(true)
	} else if node.ID == pv.currentCpID {
		style = style.Foreground(lipgloss.Color("#00E676"))
	}

	return style.Render(line)
}

func (pv *PopupViewer) getTypeIcon(cpType agent.CheckpointType) string {
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

