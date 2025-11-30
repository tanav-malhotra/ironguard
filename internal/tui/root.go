package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/tanav-malhotra/ironguard/internal/agent"
	"github.com/tanav-malhotra/ironguard/internal/config"
	"github.com/tanav-malhotra/ironguard/internal/mcp"
	"github.com/tanav-malhotra/ironguard/internal/tools"
)

// Run starts the top-level TUI program.
func Run(cfg config.Config) error {
	m := newModel(cfg)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// AgentEventMsg wraps agent events for the TUI.
type AgentEventMsg struct {
	Event agent.Event
}

// QueuedMessage represents a message waiting to be sent to the AI.
type QueuedMessage struct {
	Content   string
	Interrupt bool // If true, interrupts current AI task
}

// AutocompleteItem represents an item in the autocomplete dropdown.
type AutocompleteItem struct {
	Text        string // The text to insert (command name or argument)
	Description string // Description to show
	IsArg       bool   // True if this is an argument option, false if command
}

type model struct {
	cfg config.Config

	// Chat state
	messages      []Message
	input         textinput.Model
	scrollOffset  int
	messageQueue  []QueuedMessage // queued user messages (Enter=queue, Ctrl+Enter=interrupt)
	pendingAction *PendingAction

	// Autocomplete state
	showAutocomplete    bool
	autocompleteItems   []AutocompleteItem
	autocompleteIdx     int
	autocompleteForArgs bool   // true when showing arg options, false for commands
	autocompleteCmdName string // command name when showing arg options

	// Confirmation dialog
	showConfirm    bool
	confirmAction  *PendingAction
	confirmMessage string
	confirmToolID  string

	// API keys (in-memory only)
	apiKeys map[string]string

	// Layout state
	quitting     bool
	ready        bool
	width        int
	height       int
	sidebarWidth int

	// Styling
	theme  Theme
	styles Styles

	// Command registry
	cmdRegistry *CommandRegistry

	// Agent
	agent       *agent.Agent
	agentBusy   bool
	agentStatus string

	// Manual tasks
	manualTasks *ManualTaskManager

	// AI Todo list (for AI to track its own tasks)
	aiTodos []AITodo

	// Score tracking
	currentScore  int
	previousScore int
	scoreDelta    int

	// MCP server manager
	mcpManager *mcp.Manager

	// Program reference for sending commands
	program *tea.Program
}

// AITodo represents a task the AI created for itself.
type AITodo struct {
	ID          int
	Description string
	Status      string // "pending", "in_progress", "completed", "cancelled"
	CreatedAt   string
}

func newModel(cfg config.Config) model {
	ti := textinput.New()
	ti.Placeholder = "Type a message or /command…"
	ti.Focus()
	ti.CharLimit = 2000
	ti.Width = 60

	theme := DefaultTheme()
	styles := NewStyles(theme)

	// Create agent
	ag := agent.New(&cfg)

	welcomeMsg := `═══════════════════════════════════════════════════════════
              ⚔️  IRONGUARD - COMPETITION MODE  ⚔️
═══════════════════════════════════════════════════════════

Ready to dominate CyberPatriot. Target: 100/100 in <30 min.

QUICK START:
  1. Set API key:  /key <your-api-key>
  2. Start AI:     /harden  (AI does EVERYTHING automatically)

The AI will automatically:
  • Read the README & forensics questions
  • Answer forensics, delete bad users, fix vulns
  • Check score after each action
  • Keep working until 100/100

CONTROLS:
  /stop or Ctrl+C  - Pause AI (doesn't quit!)
  /help            - All commands
  Ctrl+Q or /quit  - Exit app

Mode: AUTOPILOT | Screen: OBSERVE (AI can't control mouse)
Model: claude-opus-4-5 (maximum capability)
═══════════════════════════════════════════════════════════`

	// Create MCP manager
	mcpMgr := mcp.NewManager()

	// Connect MCP tools to agent's tool registry
	mcpAdapter := mcp.NewToolsAdapter(mcpMgr)
	ag.SetMCPManager(mcpAdapter)

	// Sync screen mode with tools package on startup
	tools.SetScreenMode(cfg.ScreenMode)

	return model{
		cfg:          cfg,
		messages:     []Message{NewSystemMessage(welcomeMsg)},
		input:        ti,
		apiKeys:      make(map[string]string),
		sidebarWidth: 32, // Wider for manual tasks
		theme:        theme,
		styles:       styles,
		cmdRegistry:  NewCommandRegistry(),
		agent:        ag,
		manualTasks:  NewManualTaskManager(),
		mcpManager:   mcpMgr,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, m.listenToAgent())
}

// listenToAgent creates a command that listens for agent events.
func (m model) listenToAgent() tea.Cmd {
	return func() tea.Msg {
		event := <-m.agent.Events()
		return AgentEventMsg{Event: event}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKeyMsg(msg)
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.input.Width = msg.Width - m.sidebarWidth - 8
		m.ready = true
		return m, nil
	case AgentEventMsg:
		return m.handleAgentEvent(msg.Event)
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)

	// Update autocomplete based on input
	m.updateAutocomplete()

	return m, cmd
}

func (m *model) handleAgentEvent(event agent.Event) (tea.Model, tea.Cmd) {
	switch event.Type {
	case agent.EventStreamStart:
		m.agentBusy = true
		m.agentStatus = "Thinking..."
		// Add streaming message placeholder
		m.messages = append(m.messages, StreamingAIMessage())

	case agent.EventStreamDelta:
		// Append to the last message if it's streaming
		if len(m.messages) > 0 {
			last := &m.messages[len(m.messages)-1]
			if last.Role == RoleAI && last.IsStreaming {
				last.Content += event.Content
			}
		}

	case agent.EventStreamEnd:
		m.agentBusy = false
		m.agentStatus = ""
		// Mark streaming complete
		if len(m.messages) > 0 {
			last := &m.messages[len(m.messages)-1]
			if last.Role == RoleAI && last.IsStreaming {
				last.IsStreaming = false
			}
		}
		// Process queued messages
		if len(m.messageQueue) > 0 {
			nextMsg := m.messageQueue[0]
			m.messageQueue = m.messageQueue[1:]
			m.messages = append(m.messages, NewSystemMessage("📤 Sending queued message..."))
			return m, m.startChat(nextMsg.Content)
		}

	case agent.EventToolCall:
		m.agentStatus = fmt.Sprintf("Calling %s...", event.Tool.Name)
		m.messages = append(m.messages, NewToolMessage(
			event.Tool.Name,
			event.Tool.Arguments,
			"",
			"",
		))

	case agent.EventToolResult:
		// Update the last tool message with output
		for i := len(m.messages) - 1; i >= 0; i-- {
			if m.messages[i].Role == RoleTool && m.messages[i].ToolName == event.Tool.Name {
				m.messages[i].ToolOutput = event.Tool.Output
				m.messages[i].ToolError = event.Tool.Error
				break
			}
		}

	case agent.EventConfirmRequired:
		m.showConfirm = true
		m.confirmMessage = fmt.Sprintf("Execute: %s\nArgs: %s", event.Tool.Name, truncate(event.Tool.Arguments, 100))
		m.confirmToolID = event.Tool.ID

	case agent.EventError:
		m.agentBusy = false
		m.agentStatus = ""
		m.messages = append(m.messages, NewSystemMessage("Error: "+event.Error.Error()))

	case agent.EventStatusUpdate:
		m.agentStatus = event.Content

	case agent.EventThinking:
		// Update thinking display
		if len(m.messages) > 0 {
			last := &m.messages[len(m.messages)-1]
			if last.Role == RoleAI && last.IsStreaming {
				last.Thinking += event.Thinking
			}
		}

	case agent.EventSubAgentSpawned:
		if event.SubAgent != nil {
			m.messages = append(m.messages, NewSystemMessage(
				fmt.Sprintf("🤖 Subagent spawned: %s\n   Task: %s", event.SubAgent.ID, truncate(event.SubAgent.Task, 60)),
			))
		}

	case agent.EventSubAgentUpdate:
		if event.SubAgent != nil {
			statusIcon := map[string]string{
				"running":   "⏳",
				"completed": "✅",
				"failed":    "❌",
				"cancelled": "⏹️",
			}[event.SubAgent.Status]
			if statusIcon == "" {
				statusIcon = "❓"
			}
			msg := fmt.Sprintf("%s Subagent %s: %s", statusIcon, event.SubAgent.ID, event.SubAgent.Status)
			if event.SubAgent.Result != "" {
				msg += fmt.Sprintf("\n   Result: %s", truncate(event.SubAgent.Result, 80))
			}
			m.messages = append(m.messages, NewSystemMessage(msg))
		}

	case agent.EventScoreUpdate:
		m.previousScore = m.currentScore
		m.currentScore = event.Score
		m.scoreDelta = m.currentScore - m.previousScore
	}

	// Continue listening for events
	return m, m.listenToAgent()
}

func (m *model) handleKeyMsg(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Handle confirmation dialog
	if m.showConfirm {
		switch msg.String() {
		case "y", "Y", "enter":
			m.showConfirm = false
			m.agent.Confirm(agent.ConfirmResponse{Approved: true, ToolID: m.confirmToolID})
			m.confirmToolID = ""
			return m, nil
		case "n", "N", "esc":
			m.showConfirm = false
			m.agent.Confirm(agent.ConfirmResponse{Approved: false, ToolID: m.confirmToolID})
			m.messages = append(m.messages, NewSystemMessage("Action cancelled."))
			m.confirmToolID = ""
			return m, nil
		}
		return m, nil
	}

	switch msg.Type {
	case tea.KeyCtrlC:
		// Ctrl+C is commonly used to copy text in terminals - let it pass through
		// Use /stop to cancel AI, /quit to exit
		return m, nil

	case tea.KeyCtrlQ:
		// Ctrl+Q does nothing - use /quit instead
		return m, nil

	case tea.KeyEsc:
		// Esc only closes autocomplete dropdown
		if m.showAutocomplete {
			m.showAutocomplete = false
			return m, nil
		}
		return m, nil

	case tea.KeyCtrlL:
		m.messages = []Message{}
		m.agent.ClearHistory()
		return m, nil

	case tea.KeyTab:
		if m.showAutocomplete && len(m.autocompleteItems) > 0 {
			m.autocompleteIdx = (m.autocompleteIdx + 1) % len(m.autocompleteItems)
			selected := m.autocompleteItems[m.autocompleteIdx]
			if m.autocompleteForArgs {
				// Completing an argument
				m.input.SetValue("/" + m.autocompleteCmdName + " " + selected.Text)
			} else {
				// Completing a command name - add space to trigger arg completion
				m.input.SetValue("/" + selected.Text + " ")
			}
			m.input.SetCursor(len(m.input.Value()))
			m.updateAutocomplete()
			return m, nil
		}
		return m, nil

	case tea.KeyShiftTab:
		if m.showAutocomplete && len(m.autocompleteItems) > 0 {
			m.autocompleteIdx--
			if m.autocompleteIdx < 0 {
				m.autocompleteIdx = len(m.autocompleteItems) - 1
			}
			selected := m.autocompleteItems[m.autocompleteIdx]
			if m.autocompleteForArgs {
				m.input.SetValue("/" + m.autocompleteCmdName + " " + selected.Text)
			} else {
				m.input.SetValue("/" + selected.Text + " ")
			}
			m.input.SetCursor(len(m.input.Value()))
			m.updateAutocomplete()
			return m, nil
		}
		return m, nil

	case tea.KeyUp:
		if m.showAutocomplete && len(m.autocompleteItems) > 0 {
			m.autocompleteIdx--
			if m.autocompleteIdx < 0 {
				m.autocompleteIdx = len(m.autocompleteItems) - 1
			}
			return m, nil
		}
		if m.scrollOffset < len(m.messages)-1 {
			m.scrollOffset++
		}
		return m, nil

	case tea.KeyDown:
		if m.showAutocomplete && len(m.autocompleteItems) > 0 {
			m.autocompleteIdx = (m.autocompleteIdx + 1) % len(m.autocompleteItems)
			return m, nil
		}
		if m.scrollOffset > 0 {
			m.scrollOffset--
		}
		return m, nil

	case tea.KeyEnter:
		val := strings.TrimSpace(m.input.Value())
		if val == "" {
			return m, nil
		}

		if m.showAutocomplete && len(m.autocompleteItems) > 0 {
			selected := m.autocompleteItems[m.autocompleteIdx]
			if m.autocompleteForArgs {
				// Complete the argument and close autocomplete
				m.input.SetValue("/" + m.autocompleteCmdName + " " + selected.Text)
				m.input.SetCursor(len(m.input.Value()))
				m.showAutocomplete = false
				m.autocompleteForArgs = false
				return m, nil
			} else {
				// Complete the command and show arg options
				m.input.SetValue("/" + selected.Text + " ")
				m.input.SetCursor(len(m.input.Value()))
				m.updateAutocomplete()
				return m, nil
			}
		}

		m.input.SetValue("")
		m.showAutocomplete = false
		m.scrollOffset = 0

		// Handle slash commands (always execute immediately)
		if strings.HasPrefix(val, "/") {
			return m.handleSlashCommand(val)
		}

		// Regular chat message
		m.messages = append(m.messages, NewUserMessage(val))

		// Queue for AI if agent is busy (Enter = queue)
		if m.agentBusy {
			m.messageQueue = append(m.messageQueue, QueuedMessage{Content: val, Interrupt: false})
			m.messages = append(m.messages, NewSystemMessage("📥 Queued (AI is busy) - Ctrl+Enter to interrupt"))
			return m, nil
		}

		return m, m.startChat(val)

	case tea.KeyCtrlJ: // Ctrl+Enter (some terminals send Ctrl+J for Ctrl+Enter)
		val := strings.TrimSpace(m.input.Value())
		if val == "" {
			return m, nil
		}

		m.input.SetValue("")
		m.showAutocomplete = false
		m.scrollOffset = 0

		// Handle slash commands
		if strings.HasPrefix(val, "/") {
			return m.handleSlashCommand(val)
		}

		m.messages = append(m.messages, NewUserMessage(val))

		// Ctrl+Enter = interrupt and send immediately
		if m.agentBusy {
			m.agent.Cancel() // Interrupt current task
			m.messages = append(m.messages, NewSystemMessage("⚡ Interrupted AI - sending your message now"))
			// Small delay to let cancellation propagate
			return m, tea.Batch(
				func() tea.Msg { return nil },
				m.startChat(val),
			)
		}

		return m, m.startChat(val)
	}

	// Update text input
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m.updateAutocomplete()
	return m, cmd
}

func (m *model) startChat(message string) tea.Cmd {
	return func() tea.Msg {
		// Expand @ mentions in the message
		expandedMessage, mentions := ExpandMentionsInMessage(message)
		
		// Log mentions for user visibility
		for _, mention := range mentions {
			if mention.Type == MentionFile && mention.Content != "" {
				// File was loaded successfully - the content is in expandedMessage
			}
		}
		
		go m.agent.Chat(context.Background(), expandedMessage)
		return nil
	}
}

func (m *model) handleSlashCommand(input string) (tea.Model, tea.Cmd) {
	parts := strings.SplitN(input[1:], " ", 2)
	cmdName := parts[0]
	args := ""
	if len(parts) > 1 {
		args = parts[1]
	}

	cmd := m.cmdRegistry.Get(cmdName)
	if cmd == nil {
		m.messages = append(m.messages, NewSystemMessage("Unknown command: /"+cmdName+"\nType /help for available commands."))
		return m, nil
	}

	result := cmd.Handler(m, args)
	if result != "" {
		m.messages = append(m.messages, NewSystemMessage(result))
	}

	if m.quitting {
		return m, tea.Quit
	}

	// Handle pending actions
	if m.pendingAction != nil {
		if m.cfg.Mode == config.ModeConfirm && m.pendingAction.Type != ActionChat {
			m.showConfirm = true
			m.confirmAction = m.pendingAction
			m.confirmMessage = "Execute: " + m.pendingAction.Description + "?"
			m.pendingAction = nil
		} else {
			action := m.pendingAction
			m.pendingAction = nil
			return m, m.executeAction(action)
		}
	}

	return m, nil
}

func (m *model) updateAutocomplete() {
	val := m.input.Value()

	if !strings.HasPrefix(val, "/") {
		m.showAutocomplete = false
		m.autocompleteItems = nil
		m.autocompleteIdx = 0
		m.autocompleteForArgs = false
		m.autocompleteCmdName = ""
		return
	}

	// Check if we have a space (command is complete, show arg options)
	if strings.Contains(val, " ") {
		parts := strings.SplitN(val[1:], " ", 2)
		cmdName := parts[0]
		argPrefix := ""
		if len(parts) > 1 {
			argPrefix = parts[1]
		}

		// Get arg options for this command
		argOptions := m.cmdRegistry.GetArgOptions(cmdName, argPrefix)
		if len(argOptions) > 0 {
			m.autocompleteItems = make([]AutocompleteItem, len(argOptions))
			for i, opt := range argOptions {
				m.autocompleteItems[i] = AutocompleteItem{
					Text:        opt,
					Description: "",
					IsArg:       true,
				}
			}
			m.showAutocomplete = true
			m.autocompleteForArgs = true
			m.autocompleteCmdName = cmdName
			if m.autocompleteIdx >= len(m.autocompleteItems) {
				m.autocompleteIdx = 0
			}
		} else {
			m.showAutocomplete = false
			m.autocompleteItems = nil
			m.autocompleteForArgs = false
		}
	} else {
		// No space yet, show command options
		prefix := val[1:]
		commands := m.cmdRegistry.Find(prefix)
		m.autocompleteItems = make([]AutocompleteItem, len(commands))
		for i, cmd := range commands {
			desc := cmd.Description
			if cmd.Args != "" {
				desc = cmd.Args + " - " + desc
			}
			m.autocompleteItems[i] = AutocompleteItem{
				Text:        cmd.Name,
				Description: desc,
				IsArg:       false,
			}
		}
		m.showAutocomplete = len(m.autocompleteItems) > 0
		m.autocompleteForArgs = false
		m.autocompleteCmdName = ""
		if m.autocompleteIdx >= len(m.autocompleteItems) {
			m.autocompleteIdx = 0
		}
	}
}

func (m *model) executeAction(action *PendingAction) tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()
		var result string
		var err error

		switch action.Type {
		case ActionReadReadme:
			result, err = m.agent.ExecuteTool(ctx, "read_readme", nil)
		case ActionReadForensics:
			result, err = m.agent.ExecuteTool(ctx, "read_forensics", nil)
		case ActionWriteAnswer:
			// Parse args: "<question-num> <answer>"
			parts := strings.SplitN(action.Args, " ", 2)
			if len(parts) == 2 {
				result, err = m.agent.ExecuteTool(ctx, "write_answer", map[string]interface{}{
					"question_file": "Forensics Question " + parts[0] + ".txt",
					"answer":        parts[1],
				})
			} else {
				err = fmt.Errorf("invalid answer format")
			}
		case ActionRunCommand:
			result, err = m.agent.ExecuteTool(ctx, "run_command", map[string]interface{}{
				"command": action.Args,
			})
		case ActionHarden:
			go m.agent.Chat(ctx, "Please read the README and start hardening this system. Begin by identifying what needs to be done.")
		case ActionChat:
			go m.agent.Chat(ctx, action.Args)
		case ActionAuto:
			var targetScore int
			fmt.Sscanf(action.Args, "%d", &targetScore)
			go m.agent.StartAutonomous(ctx, targetScore)
		case ActionCheckScore:
			result, err = m.agent.ExecuteTool(ctx, "read_score_report", nil)
		case ActionSearch:
			result, err = m.agent.ExecuteTool(ctx, "web_search", map[string]interface{}{
				"query": action.Args,
			})
		case ActionScreenshot:
			result, err = m.agent.ExecuteTool(ctx, "take_screenshot", map[string]interface{}{
				"region": "full",
			})
		case ActionClick:
			// Parse "x y" from args
			var x, y int
			fmt.Sscanf(action.Args, "%d %d", &x, &y)
			result, err = m.agent.ExecuteTool(ctx, "mouse_click", map[string]interface{}{
				"x": x,
				"y": y,
			})
		case ActionType_:
			result, err = m.agent.ExecuteTool(ctx, "keyboard_type", map[string]interface{}{
				"text": action.Args,
			})
		case ActionHotkey:
			result, err = m.agent.ExecuteTool(ctx, "keyboard_hotkey", map[string]interface{}{
				"keys": action.Args,
			})
		case ActionListWindows:
			result, err = m.agent.ExecuteTool(ctx, "list_windows", nil)
		case ActionFocusWindow:
			result, err = m.agent.ExecuteTool(ctx, "focus_window", map[string]interface{}{
				"title": action.Args,
			})
		case ActionMCPAdd:
			// Parse: name|command|arg1,arg2,arg3
			parts := strings.Split(action.Args, "|")
			if len(parts) < 2 {
				err = fmt.Errorf("invalid MCP add args")
			} else {
				name := parts[0]
				command := parts[1]
				var args []string
				if len(parts) > 2 && parts[2] != "" {
					args = strings.Split(parts[2], ",")
				}
				err = m.mcpManager.AddServer(mcp.ServerConfig{
					Name:    name,
					Command: command,
					Args:    args,
				})
				if err == nil {
					// Get info about connected server
					info, _ := m.mcpManager.GetServerInfo(name)
					if info != nil {
						result = fmt.Sprintf("✅ Connected to MCP server '%s'\n   Tools available: %d\n   Use /mcp-tools %s to see them.", name, info.ToolCount, name)
					} else {
						result = fmt.Sprintf("✅ Connected to MCP server '%s'", name)
					}
				}
			}
		case ActionMCPRemove:
			err = m.mcpManager.RemoveServer(action.Args)
			if err == nil {
				result = fmt.Sprintf("✅ Disconnected MCP server '%s'", action.Args)
			}
		case ActionSubAgentLimitChanged:
			// Send a system message to the AI about the change (queued, non-interrupting)
			newMax := action.Args
			systemMsg := fmt.Sprintf("[SYSTEM] The maximum concurrent subagents limit has been changed to %s. You can now spawn up to %s subagents in parallel.", newMax, newMax)
			// Queue this message - it will be processed after AI finishes current step
			m.agent.QueueSystemMessage(systemMsg)
			result = fmt.Sprintf("✅ Subagent limit set to %s (AI will be notified after current step)", newMax)
		case ActionSettingChanged:
			// Send a system message to the AI about setting changes (queued, non-interrupting)
			var systemMsg string
			switch action.Args {
			case "confirm":
				systemMsg = "[SYSTEM] Execution mode changed to CONFIRM. You must now wait for user approval before each action is executed. The user will see a confirmation prompt for every tool call."
			case "autopilot":
				systemMsg = "[SYSTEM] Execution mode changed to AUTOPILOT. You can now execute actions automatically without waiting for user approval. Work fast and autonomously!"
			case "screen_observe":
				systemMsg = "[SYSTEM] Screen mode changed to OBSERVE. You can take screenshots to see the screen, but you CANNOT use mouse_click, keyboard_type, or keyboard_hotkey. These tools will fail if you try to use them."
			case "screen_control":
				systemMsg = "[SYSTEM] Screen mode changed to CONTROL. You now have FULL access to mouse and keyboard! You can use mouse_click, keyboard_type, keyboard_hotkey, focus_window, and all screen interaction tools. Use this power for Packet Tracer, GUI settings, or any task requiring screen interaction."
			default:
				systemMsg = fmt.Sprintf("[SYSTEM] Setting changed: %s", action.Description)
			}
			// Queue this message - it will be processed after AI finishes current step
			m.agent.QueueSystemMessage(systemMsg)
			result = fmt.Sprintf("✅ Setting changed (AI will be notified after current step)")
		}

		if err != nil {
			return AgentEventMsg{Event: agent.Event{Type: agent.EventError, Error: err}}
		}
		if result != "" {
			return AgentEventMsg{Event: agent.Event{
				Type: agent.EventToolResult,
				Tool: &agent.ToolCallInfo{
					Name:   action.Description,
					Output: result,
				},
			}}
		}
		return nil
	}
}

func (m model) View() string {
	if !m.ready {
		return "Loading ironguard TUI…"
	}

	chatWidth := m.width - m.sidebarWidth - 3
	chatHeight := m.height - 6

	sidebar := m.renderSidebar()
	chat := m.renderChat(chatWidth, chatHeight)
	inputArea := m.renderInput(chatWidth)
	statusBar := m.renderStatusBar()

	mainContent := lipgloss.JoinVertical(lipgloss.Left, chat, inputArea)
	content := lipgloss.JoinHorizontal(lipgloss.Top, mainContent, sidebar)

	return lipgloss.JoinVertical(lipgloss.Left, content, statusBar)
}

func (m model) renderSidebar() string {
	var sb strings.Builder

	title := m.styles.Title.Render("⚔ IRONGUARD")
	sb.WriteString(title + "\n\n")

	// Score display (prominent)
	sb.WriteString(m.styles.Label.Render("📊 SCORE") + "\n")
	if m.currentScore > 0 {
		scoreStr := fmt.Sprintf("  %d/100", m.currentScore)
		if m.scoreDelta > 0 {
			scoreStr += m.styles.Success.Render(fmt.Sprintf(" (+%d)", m.scoreDelta))
		} else if m.scoreDelta < 0 {
			scoreStr += m.styles.Error.Render(fmt.Sprintf(" (%d)", m.scoreDelta))
		}
		sb.WriteString(m.styles.Value.Render(scoreStr) + "\n\n")
	} else {
		sb.WriteString(m.styles.Muted.Render("  Not checked") + "\n\n")
	}

	// Status
	sb.WriteString(m.styles.Label.Render("Status") + "\n")
	if m.agentBusy {
		sb.WriteString(m.styles.Warning.Render("  ● Working") + "\n")
		if m.agentStatus != "" {
			status := m.agentStatus
			if len(status) > 24 {
				status = status[:21] + "..."
			}
			sb.WriteString(m.styles.Muted.Render("  "+status) + "\n")
		}
	} else {
		sb.WriteString(m.styles.Success.Render("  ● Ready") + "\n")
	}
	sb.WriteString("\n")

	// Mode badge
	var modeBadge string
	if m.cfg.Mode == config.ModeConfirm {
		modeBadge = m.styles.BadgeConfirm.Render("CONFIRM")
	} else {
		modeBadge = m.styles.BadgeAutopilot.Render("AUTO")
	}
	sb.WriteString(m.styles.Muted.Render(string(m.cfg.Provider)) + " " + modeBadge + "\n\n")

	// Separator
	sb.WriteString(m.styles.Muted.Render(strings.Repeat("─", m.sidebarWidth-4)) + "\n\n")

	// Subagents section (if any are active)
	subAgents := m.agent.GetSubAgents()
	if len(subAgents) > 0 {
		sb.WriteString(m.styles.Label.Render("🤖 SUBAGENTS") + "\n")
		runningCount := 0
		for _, sa := range subAgents {
			if sa.Status == "running" {
				runningCount++
				sb.WriteString(m.styles.SubAgentRunning.Render(fmt.Sprintf("  ⏳ %s", sa.ID)) + "\n")
				if sa.CurrentStep != "" {
					step := sa.CurrentStep
					if len(step) > 20 {
						step = step[:17] + "..."
					}
					sb.WriteString(m.styles.Muted.Render(fmt.Sprintf("     %s", step)) + "\n")
				}
			}
		}
		completedCount := len(subAgents) - runningCount
		if completedCount > 0 {
			sb.WriteString(m.styles.SubAgentDone.Render(fmt.Sprintf("  ✅ %d done", completedCount)) + "\n")
		}
		sb.WriteString("\n")
	}

	// Manual tasks section
	sb.WriteString(m.styles.Label.Render("📋 MANUAL TASKS") + "\n")
	total, pending, _ := m.manualTasks.Count()
	if total == 0 {
		sb.WriteString(m.styles.Muted.Render("  No tasks") + "\n")
	} else {
		sb.WriteString(m.styles.Muted.Render(fmt.Sprintf("  %d pending", pending)) + "\n\n")
		sb.WriteString(m.manualTasks.FormatForSidebar(m.sidebarWidth - 4))
	}

	// MCP servers section (if any connected)
	if m.mcpManager != nil {
		servers := m.mcpManager.ListServers()
		if len(servers) > 0 {
			sb.WriteString("\n" + m.styles.Label.Render("🔌 MCP SERVERS") + "\n")
			for _, s := range servers {
				sb.WriteString(m.styles.Muted.Render(fmt.Sprintf("  • %s", s)) + "\n")
			}
		}
	}

	// Queue indicator
	if len(m.messageQueue) > 0 {
		sb.WriteString("\n" + m.styles.Warning.Render(fmt.Sprintf("⏳ %d queued", len(m.messageQueue))) + "\n")
	}

	return m.styles.Sidebar.
		Width(m.sidebarWidth).
		Height(m.height - 2).
		Render(sb.String())
}

func (m model) renderChat(width, height int) string {
	var lines []string

	for _, msg := range m.messages {
		line := m.formatMessage(msg, width-4)
		lines = append(lines, line)
	}

	visibleLines := lines
	totalLines := len(lines)
	if totalLines > height && height > 0 {
		start := totalLines - height - m.scrollOffset
		if start < 0 {
			start = 0
		}
		end := start + height
		if end > totalLines {
			end = totalLines
		}
		visibleLines = lines[start:end]
	}

	content := strings.Join(visibleLines, "\n")

	if m.scrollOffset > 0 {
		content += "\n" + m.styles.Muted.Render(fmt.Sprintf("↓ %d more", m.scrollOffset))
	}

	return m.styles.ChatPane.
		Width(width).
		Height(height).
		Render(content)
}

func (m model) formatMessage(msg Message, width int) string {
	switch msg.Role {
	case RoleUser:
		prefix := m.styles.UserMessage.Render("You: ")
		return prefix + msg.Content

	case RoleAI:
		var sb strings.Builder
		
		// Show thinking/reasoning if present (Claude Code style)
		if msg.Thinking != "" {
			thinkingLines := strings.Split(msg.Thinking, "\n")
			thinkingPreview := ""
			if len(thinkingLines) > 3 {
				thinkingPreview = strings.Join(thinkingLines[:3], "\n") + "..."
			} else {
				thinkingPreview = msg.Thinking
			}
			
			if msg.ThinkingVisible {
				// Expanded view
				sb.WriteString(m.styles.ThinkingBox.Render("💭 THINKING (click to collapse):\n" + msg.Thinking))
			} else {
				// Collapsed view
				sb.WriteString(m.styles.ThinkingCollapsed.Render("💭 " + truncate(thinkingPreview, 60) + " [expand]"))
			}
			sb.WriteString("\n")
		}
		
		prefix := m.styles.AIMessage.Bold(true).Render("AI: ")
		content := msg.Content
		if msg.IsStreaming {
			content += m.styles.Muted.Render("▌")
		}
		sb.WriteString(prefix + content)
		return sb.String()

	case RoleSystem:
		return m.styles.SystemMessage.Render(msg.Content)

	case RoleTool:
		var sb strings.Builder
		
		// Tool header with collapse indicator
		if msg.Collapsed {
			sb.WriteString(m.styles.ToolCall.Render("⚡ " + msg.ToolName + " [+]"))
			if msg.ToolOutput != "" {
				sb.WriteString(m.styles.Muted.Render(" → " + truncate(msg.ToolOutput, 30)))
			}
		} else {
			sb.WriteString(m.styles.ToolCall.Render("⚡ " + msg.ToolName + " [-]"))
			if msg.ToolInput != "" {
				inputLines := strings.Split(msg.ToolInput, "\n")
				if len(inputLines) > 3 {
					sb.WriteString("\n" + m.styles.Muted.Render("  Input: "+truncate(inputLines[0], 50)+" ("+fmt.Sprintf("%d", len(inputLines))+" lines)"))
				} else {
					sb.WriteString("\n" + m.styles.Muted.Render("  Input: "+truncate(msg.ToolInput, 60)))
				}
			}
			if msg.ToolOutput != "" {
				outputLines := strings.Split(msg.ToolOutput, "\n")
				if len(outputLines) > 5 {
					// Show first 3 lines with line count
					preview := strings.Join(outputLines[:3], "\n  ")
					sb.WriteString("\n" + m.styles.Value.Render("  Output:\n  "+preview+"\n  ... ("+fmt.Sprintf("%d", len(outputLines))+" total lines)"))
				} else {
					sb.WriteString("\n" + m.styles.Value.Render("  Output: "+truncate(msg.ToolOutput, 100)))
				}
			}
			if msg.ToolError != "" {
				sb.WriteString("\n" + m.styles.Error.Render("  Error: "+msg.ToolError))
			}
		}
		return sb.String()

	default:
		return msg.Content
	}
}

func (m model) renderInput(width int) string {
	var sb strings.Builder

	// Show queued messages above input (Claude Code style)
	if len(m.messageQueue) > 0 {
		queueBox := m.styles.Muted.Render("📥 QUEUED MESSAGES (will send when AI is ready):\n")
		for i, qm := range m.messageQueue {
			prefix := fmt.Sprintf("  %d. ", i+1)
			content := qm.Content
			if len(content) > 50 {
				content = content[:47] + "..."
			}
			if qm.Interrupt {
				queueBox += m.styles.Warning.Render(prefix+"⚡ "+content) + "\n"
			} else {
				queueBox += m.styles.Muted.Render(prefix+content) + "\n"
			}
		}
		queueBox += m.styles.Muted.Render("  (Ctrl+Enter to interrupt AI and send immediately)\n")
		sb.WriteString(m.styles.BorderedBox.Width(width).Render(queueBox) + "\n")
	}

	if m.showAutocomplete && len(m.autocompleteItems) > 0 {
		sb.WriteString(m.renderAutocomplete(width) + "\n")
	}

	if m.showConfirm {
		confirmBox := m.styles.BorderedBox.
			BorderForeground(m.theme.Warning).
			Render(m.confirmMessage + "\n\n" +
				m.styles.Success.Render("[Y]es") + "  " +
				m.styles.Error.Render("[N]o"))
		sb.WriteString(confirmBox + "\n")
	}

	// Input hint
	hint := "Enter: queue message | Ctrl+Enter: interrupt & send | /: commands"
	if !m.agentBusy {
		hint = "Enter: send message | /: commands"
	}

	inputStyle := m.styles.InputPane.Width(width)
	sb.WriteString(inputStyle.Render(m.input.View()))
	sb.WriteString("\n" + m.styles.Muted.Render(hint))

	return sb.String()
}

func (m model) renderAutocomplete(width int) string {
	var lines []string
	maxShow := 8
	if len(m.autocompleteItems) < maxShow {
		maxShow = len(m.autocompleteItems)
	}

	// Show header based on what we're completing
	if m.autocompleteForArgs {
		lines = append(lines, m.styles.Muted.Render(fmt.Sprintf("  Options for /%s:", m.autocompleteCmdName)))
	}

	for i := 0; i < maxShow; i++ {
		item := m.autocompleteItems[i]
		var line string
		if item.IsArg {
			// Argument option
			line = "  " + item.Text
			if item.Description != "" {
				line += " - " + item.Description
			}
		} else {
			// Command
			line = "/" + item.Text
			if item.Description != "" {
				line += " - " + item.Description
			}
		}

		if i == m.autocompleteIdx {
			lines = append(lines, m.styles.CommandSelected.Render(line))
		} else {
			lines = append(lines, m.styles.Command.Render(line))
		}
	}

	if len(m.autocompleteItems) > maxShow {
		lines = append(lines, m.styles.Muted.Render(fmt.Sprintf("  ... and %d more", len(m.autocompleteItems)-maxShow)))
	}

	return m.styles.BorderedBox.
		Width(width).
		Render(strings.Join(lines, "\n"))
}

func (m model) renderStatusBar() string {
	left := m.styles.KeyHint.Render("/stop: Stop AI | /quit: Exit | /undo | Tab: Autocomplete")

	// Token usage
	stats := m.agent.GetTokenStats()
	tokenInfo := fmt.Sprintf("📊 %dk/%dk", stats.CurrentContext/1000, stats.ContextLimit/1000)
	if stats.ContextPercentage > 80 {
		tokenInfo = m.styles.Error.Render(tokenInfo)
	} else if stats.ContextPercentage > 50 {
		tokenInfo = m.styles.Warning.Render(tokenInfo)
	} else {
		tokenInfo = m.styles.Muted.Render(tokenInfo)
	}

	// API key status
	keyStatus := "🔑 "
	if m.apiKeys[string(m.cfg.Provider)] != "" {
		keyStatus += m.styles.Success.Render("●")
	} else {
		keyStatus += m.styles.Error.Render("○")
	}

	// Undo count
	undoCount := m.agent.GetCheckpointManager().UndoableCount()
	undoInfo := ""
	if undoCount > 0 {
		undoInfo = m.styles.Muted.Render(fmt.Sprintf(" | ↩️ %d", undoCount))
	}

	right := tokenInfo + " " + keyStatus + undoInfo

	padding := m.width - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if padding < 0 {
		padding = 0
	}

	return m.styles.StatusBar.Render(left + strings.Repeat(" ", padding) + right)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
