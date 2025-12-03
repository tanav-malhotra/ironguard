package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/tanav-malhotra/ironguard/internal/agent"
	"github.com/tanav-malhotra/ironguard/internal/audio"
	"github.com/tanav-malhotra/ironguard/internal/config"
	"github.com/tanav-malhotra/ironguard/internal/mcp"
	"github.com/tanav-malhotra/ironguard/internal/tools"
)

// Run starts the top-level TUI program.
func Run(cfg config.Config) error {
	// Configure and initialize audio system (non-fatal if it fails)
	audio.SetOptions(cfg.NoSound, cfg.NoRepeatSound)
	if err := audio.Init(); err != nil {
		// Audio init failed - continue without sound
		// This is fine, sound is optional
	}
	
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
	
	// Vulnerability tracking
	vulnsFound int
	vulnsTotal int
	prevVulnsFound int // For calculating dings

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

	// Welcome message is set after initialization for API key check
	welcomeMsg := ""

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
	// Generate welcome message with banner
	welcomeMsg := m.generateWelcomeScreen()
	m.messages = append(m.messages, NewSystemMessage(welcomeMsg))
	return tea.Batch(textinput.Blink, m.listenToAgent())
}

// generateWelcomeScreen creates the startup banner and instructions
func (m model) generateWelcomeScreen() string {
	// Box width = 75 chars (including borders)
	// Inner width = 73 chars
	banner := `
    ██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
    ██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
    ██║██████╔╝██║   ██║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
    ██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
    ██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
    ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
                  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                       AUTONOMOUS SECURITY HARDENING SYSTEM
                  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`

	// Check if API key is configured
	hasAPIKey := m.agent.HasAPIKey()

	var statusLine string
	if hasAPIKey {
		statusLine = `
 ┌─────────────────────────────────────────────────────────────────────────┐
 │  [*] SYSTEM ONLINE                                STATUS: OPERATIONAL   │
 └─────────────────────────────────────────────────────────────────────────┘`
	} else {
		statusLine = `
 ┌─────────────────────────────────────────────────────────────────────────┐
 │  [ ] AWAITING CONFIGURATION                          STATUS: STANDBY    │
 └─────────────────────────────────────────────────────────────────────────┘`
	}

	quickStart := `
 ╭─────────────────────────────────────────────────────────────────────────╮
 │                             QUICK START                                 │
 ├─────────────────────────────────────────────────────────────────────────┤
 │                                                                         │
 │   STEP 1   /key <api-key>           Configure AI provider               │
 │   STEP 2   /harden                  Begin autonomous hardening          │
 │                                                                         │
 ╰─────────────────────────────────────────────────────────────────────────╯

 ╭─────────────────────────────────────────────────────────────────────────╮
 │                             CAPABILITIES                                │
 ├─────────────────────────────────────────────────────────────────────────┤
 │                                                                         │
 │   > Forensics Analysis           Automatically answers all questions    │
 │   > Vulnerability Remediation    Fixes security misconfigurations       │
 │   > User Management              Removes unauthorized accounts          │
 │   > Score Optimization           Iterates until maximum achieved        │
 │   > Screen Control               GUI automation when enabled            │
 │                                                                         │
 ╰─────────────────────────────────────────────────────────────────────────╯

 ╭─────────────────────────────────────────────────────────────────────────╮
 │  CONTROLS                                                               │
 ├─────────────────────────────────────────────────────────────────────────┤
 │  /help              All commands         Tab            Autocomplete    │
 │  /stop              Halt operation       Enter          Send message    │
 │  /quit              Exit program         Ctrl+Enter     Interrupt       │
 ╰─────────────────────────────────────────────────────────────────────────╯`

	return banner + statusLine + quickStart
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
		
		// Update vulnerability tracking if provided
		if event.VulnsFound > 0 || event.VulnsTotal > 0 {
			m.prevVulnsFound = m.vulnsFound
			m.vulnsFound = event.VulnsFound
			m.vulnsTotal = event.VulnsTotal
			
			// Play ding sounds for each new vuln found
			newVulns := m.vulnsFound - m.prevVulnsFound
			if newVulns > 0 {
				audio.PlayPointsGainedMultiple(newVulns)
			}
		}
		
		// Play victory sound at 100/100
		if m.currentScore == 100 && m.previousScore < 100 {
			audio.PlayMaxPointsAchieved()
		}
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
			// Select current item first, then move to next for next Tab press
			selected := m.autocompleteItems[m.autocompleteIdx]
			if m.autocompleteForArgs {
				// Completing an argument
				m.input.SetValue("/" + m.autocompleteCmdName + " " + selected.Text)
			} else {
				// Completing a command name - add space to trigger arg completion
				m.input.SetValue("/" + selected.Text + " ")
			}
			m.input.SetCursor(len(m.input.Value()))
			// Move to next item for next Tab press
			m.autocompleteIdx = (m.autocompleteIdx + 1) % len(m.autocompleteItems)
			m.updateAutocomplete()
			return m, nil
		}
		return m, nil

	case tea.KeyShiftTab:
		if m.showAutocomplete && len(m.autocompleteItems) > 0 {
			// Move back first, then select
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
			// Don't update input - just highlight, Enter/Tab will select
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
				// Complete the argument and execute the command
				fullCmd := "/" + m.autocompleteCmdName + " " + selected.Text
				m.input.SetValue("")
				m.showAutocomplete = false
				m.autocompleteForArgs = false
				return m.handleSlashCommand(fullCmd)
			} else {
				// Check if command has required arguments
				cmd := m.cmdRegistry.Get(selected.Text)
				if cmd != nil && cmd.Args == "" {
					// No arguments required - execute immediately
					m.input.SetValue("")
					m.showAutocomplete = false
					return m.handleSlashCommand("/" + selected.Text)
				}
				// Has arguments - complete and show arg options
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
		return "Loading IronGuard..."
	}

	chatWidth := m.width - m.sidebarWidth - 3
	chatHeight := m.height - 6

	sidebar := m.renderSidebar()
	chat := m.renderChat(chatWidth, chatHeight)
	inputArea := m.renderInputOnly(chatWidth) // Just the input box
	statusBar := m.renderStatusBar()

	// If autocomplete is showing, overlay it on the chat
	if m.showAutocomplete && len(m.autocompleteItems) > 0 {
		autocomplete := m.renderAutocomplete(chatWidth)
		// Replace bottom lines of chat with autocomplete overlay
		chat = m.overlayAutocomplete(chat, autocomplete, chatWidth, chatHeight)
	}

	mainContent := lipgloss.JoinVertical(lipgloss.Left, chat, inputArea)
	content := lipgloss.JoinHorizontal(lipgloss.Top, mainContent, sidebar)

	return lipgloss.JoinVertical(lipgloss.Left, content, statusBar)
}

func (m model) renderSidebar() string {
	var sb strings.Builder
	lineWidth := m.sidebarWidth - 6

	// Header with title
	sb.WriteString(m.styles.Title.Render("◈ IRONGUARD") + "\n")
	sb.WriteString(m.styles.Muted.Render(strings.Repeat("─", lineWidth)) + "\n\n")

	// Score display (prominent)
	sb.WriteString(m.styles.Label.Render("SCORE") + "\n")
	if m.currentScore > 0 {
		scoreBar := m.renderScoreBar(m.currentScore, lineWidth)
		sb.WriteString(scoreBar + "\n")
		scoreStr := fmt.Sprintf("%d/100", m.currentScore)
		if m.scoreDelta > 0 {
			scoreStr += m.styles.Success.Render(fmt.Sprintf(" +%d", m.scoreDelta))
		} else if m.scoreDelta < 0 {
			scoreStr += m.styles.Error.Render(fmt.Sprintf(" %d", m.scoreDelta))
		}
		sb.WriteString(m.styles.Value.Render("  "+scoreStr) + "\n")
		
		// Vulnerabilities found/total
		if m.vulnsTotal > 0 {
			vulnStr := fmt.Sprintf("  %d/%d vulns", m.vulnsFound, m.vulnsTotal)
			if m.vulnsFound == m.vulnsTotal {
				sb.WriteString(m.styles.Success.Render(vulnStr) + "\n")
			} else {
				sb.WriteString(m.styles.Muted.Render(vulnStr) + "\n")
			}
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString(m.styles.Muted.Render("  ── awaiting ──") + "\n\n")
	}

	// Status - check API key first
	sb.WriteString(m.styles.Label.Render("STATUS") + "\n")
	if !m.agent.HasAPIKey() {
		sb.WriteString(m.styles.Error.Render("  ◌ NO API KEY") + "\n")
		sb.WriteString(m.styles.Muted.Render("    /key <key>") + "\n")
	} else if m.agentBusy {
		sb.WriteString(m.styles.Warning.Render("  ◉ PROCESSING") + "\n")
		if m.agentStatus != "" {
			status := m.agentStatus
			if len(status) > lineWidth-4 {
				status = status[:lineWidth-7] + "..."
			}
			sb.WriteString(m.styles.Muted.Render("  "+status) + "\n")
		}
	} else {
		sb.WriteString(m.styles.Success.Render("  ● READY") + "\n")
	}
	sb.WriteString("\n")

	// Mode and Provider info
	sb.WriteString(m.styles.Label.Render("CONFIG") + "\n")
	providerStr := strings.ToUpper(string(m.cfg.Provider))
	sb.WriteString(m.styles.Muted.Render("  Provider: ") + m.styles.Value.Render(providerStr) + "\n")

	var modeStr string
	if m.cfg.Mode == config.ModeConfirm {
		modeStr = m.styles.Success.Render("CONFIRM")
	} else {
		modeStr = m.styles.Warning.Render("AUTO")
	}
	sb.WriteString(m.styles.Muted.Render("  Mode:     ") + modeStr + "\n")

	var screenStr string
	if m.cfg.ScreenMode == config.ScreenModeControl {
		screenStr = m.styles.Warning.Render("CONTROL")
	} else {
		screenStr = m.styles.Muted.Render("OBSERVE")
	}
	sb.WriteString(m.styles.Muted.Render("  Screen:   ") + screenStr + "\n\n")

	sb.WriteString(m.styles.Muted.Render(strings.Repeat("─", lineWidth)) + "\n\n")

	// Subagents section (if any are active)
	subAgents := m.agent.GetSubAgents()
	if len(subAgents) > 0 {
		sb.WriteString(m.styles.Label.Render("SUBAGENTS") + "\n")
		runningCount := 0
		for _, sa := range subAgents {
			if sa.Status == "running" {
				runningCount++
				sb.WriteString(m.styles.SubAgentRunning.Render(fmt.Sprintf("  ◉ %s", sa.ID)) + "\n")
				if sa.CurrentStep != "" {
					step := sa.CurrentStep
					if len(step) > lineWidth-6 {
						step = step[:lineWidth-9] + "..."
					}
					sb.WriteString(m.styles.Muted.Render("    "+step) + "\n")
				}
			}
		}
		completedCount := len(subAgents) - runningCount
		if completedCount > 0 {
			sb.WriteString(m.styles.SubAgentDone.Render(fmt.Sprintf("  ✓ %d completed", completedCount)) + "\n")
		}
		sb.WriteString("\n")
	}

	// Manual tasks section
	total, pending, _ := m.manualTasks.Count()
	if total > 0 {
		sb.WriteString(m.styles.Label.Render("MANUAL TASKS") + "\n")
		sb.WriteString(m.styles.Muted.Render(fmt.Sprintf("  %d pending", pending)) + "\n")
		sb.WriteString(m.manualTasks.FormatForSidebar(lineWidth))
		sb.WriteString("\n")
	}

	// MCP servers section (if any connected)
	if m.mcpManager != nil {
		servers := m.mcpManager.ListServers()
		if len(servers) > 0 {
			sb.WriteString(m.styles.Label.Render("MCP SERVERS") + "\n")
			for _, s := range servers {
				sb.WriteString(m.styles.Muted.Render(fmt.Sprintf("  • %s", s)) + "\n")
			}
			sb.WriteString("\n")
		}
	}

	// Queue indicator
	if len(m.messageQueue) > 0 {
		sb.WriteString(m.styles.Warning.Render(fmt.Sprintf("◉ %d QUEUED", len(m.messageQueue))) + "\n")
	}

	// Pad to fill height to prevent glitching
	content := sb.String()
	contentLines := strings.Count(content, "\n")
	targetHeight := m.height - 4
	for i := contentLines; i < targetHeight; i++ {
		content += "\n"
	}

	return m.styles.Sidebar.
		Width(m.sidebarWidth).
		Height(m.height - 2).
		Render(content)
}

// renderScoreBar creates a visual progress bar for the score
func (m model) renderScoreBar(score, width int) string {
	barWidth := width - 4
	if barWidth < 10 {
		barWidth = 10
	}
	filled := (score * barWidth) / 100
	empty := barWidth - filled

	bar := "  "
	for i := 0; i < filled; i++ {
		bar += "█"
	}
	for i := 0; i < empty; i++ {
		bar += "░"
	}

	if score >= 90 {
		return m.styles.Success.Render(bar)
	} else if score >= 70 {
		return m.styles.Warning.Render(bar)
	}
	return m.styles.Error.Render(bar)
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

		// Tool calls displayed as actions/thoughts, not messages
		// Collapsed view: compact single line
		if msg.Collapsed {
			// Show as a subtle action indicator
			actionIcon := "├─"
			if msg.ToolError != "" {
				actionIcon = "├✗"
				sb.WriteString(m.styles.Muted.Render(actionIcon + " "))
				sb.WriteString(m.styles.Error.Render(msg.ToolName))
			} else {
				sb.WriteString(m.styles.Muted.Render(actionIcon + " "))
				sb.WriteString(m.styles.ToolCall.Render(msg.ToolName))
			}
			if msg.ToolOutput != "" {
				sb.WriteString(m.styles.Muted.Render(" → " + truncate(msg.ToolOutput, 40)))
			}
			sb.WriteString(m.styles.Muted.Render(" [+]"))
		} else {
			// Expanded view: show as thought/action block
			sb.WriteString(m.styles.Muted.Render("┌─ "))
			sb.WriteString(m.styles.ToolCall.Render(msg.ToolName))
			sb.WriteString(m.styles.Muted.Render(" ─────────────────────────"))
			
			if msg.ToolInput != "" {
				inputLines := strings.Split(msg.ToolInput, "\n")
				if len(inputLines) > 3 {
					sb.WriteString("\n" + m.styles.Muted.Render("│ ") + m.styles.Muted.Render(truncate(inputLines[0], 55)+" (+"+fmt.Sprintf("%d", len(inputLines)-1)+" lines)"))
				} else {
					sb.WriteString("\n" + m.styles.Muted.Render("│ ") + m.styles.Muted.Render(truncate(msg.ToolInput, 60)))
				}
			}
			if msg.ToolOutput != "" {
				outputLines := strings.Split(msg.ToolOutput, "\n")
				if len(outputLines) > 4 {
					// Show first 2 lines with line count
					sb.WriteString("\n" + m.styles.Muted.Render("│ ") + m.styles.Value.Render(truncate(outputLines[0], 55)))
					sb.WriteString("\n" + m.styles.Muted.Render("│ ") + m.styles.Value.Render(truncate(outputLines[1], 55)))
					sb.WriteString("\n" + m.styles.Muted.Render("│ ... "+fmt.Sprintf("%d", len(outputLines)-2)+" more lines"))
				} else {
					for _, line := range outputLines {
						if line != "" {
							sb.WriteString("\n" + m.styles.Muted.Render("│ ") + m.styles.Value.Render(truncate(line, 60)))
						}
					}
				}
			}
			if msg.ToolError != "" {
				sb.WriteString("\n" + m.styles.Muted.Render("│ ") + m.styles.Error.Render("Error: "+msg.ToolError))
			}
			sb.WriteString("\n" + m.styles.Muted.Render("└────────────────────────────────────────"))
		}
		return sb.String()

	default:
		return msg.Content
	}
}

// overlayAutocomplete places the autocomplete popup over the bottom of the chat area
func (m model) overlayAutocomplete(chat, autocomplete string, width, height int) string {
	chatLines := strings.Split(chat, "\n")
	autocompleteLines := strings.Split(autocomplete, "\n")

	// Pad autocomplete lines to full width to ensure clean overlay
	for i, line := range autocompleteLines {
		lineWidth := lipgloss.Width(line)
		if lineWidth < width {
			autocompleteLines[i] = line + strings.Repeat(" ", width-lineWidth)
		}
	}

	// Calculate how many chat lines to keep
	acHeight := len(autocompleteLines)
	keepLines := len(chatLines) - acHeight
	if keepLines < 0 {
		keepLines = 0
	}

	// Build result: keep top of chat, replace bottom with autocomplete
	var result []string
	if keepLines > 0 {
		result = append(result, chatLines[:keepLines]...)
	}
	result = append(result, autocompleteLines...)

	return strings.Join(result, "\n")
}

// renderInputOnly renders just the input box without autocomplete (which is now overlaid)
func (m model) renderInputOnly(width int) string {
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

	if m.showConfirm {
		confirmBox := m.styles.BorderedBox.
			BorderForeground(m.theme.Warning).
			Render(m.confirmMessage + "\n\n" +
				m.styles.Success.Render("[Y]es") + "  " +
				m.styles.Error.Render("[N]o"))
		sb.WriteString(confirmBox + "\n")
	}

	// Input box with styled prompt
	inputStyle := m.styles.InputPane.Width(width)
	sb.WriteString(inputStyle.Render(m.input.View()))

	return sb.String()
}

func (m model) renderAutocomplete(width int) string {
	var lines []string
	maxShow := 8
	totalItems := len(m.autocompleteItems)

	if totalItems == 0 {
		return ""
	}

	// Calculate scroll window to keep selected item visible
	startIdx := 0
	if totalItems > maxShow {
		// Keep selected item in the middle of the visible window when possible
		startIdx = m.autocompleteIdx - maxShow/2
		if startIdx < 0 {
			startIdx = 0
		}
		if startIdx > totalItems-maxShow {
			startIdx = totalItems - maxShow
		}
	}

	endIdx := startIdx + maxShow
	if endIdx > totalItems {
		endIdx = totalItems
	}

	// Show header based on what we're completing
	if m.autocompleteForArgs {
		lines = append(lines, m.styles.Muted.Render(fmt.Sprintf("  Options for /%s:", m.autocompleteCmdName)))
	}

	// Show scroll indicator at top if not at beginning
	if startIdx > 0 {
		lines = append(lines, m.styles.Muted.Render(fmt.Sprintf("  ↑ %d more above", startIdx)))
	}

	for i := startIdx; i < endIdx; i++ {
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
			lines = append(lines, m.styles.CommandSelected.Render("▶ "+line))
		} else {
			lines = append(lines, m.styles.Command.Render("  "+line))
		}
	}

	// Show scroll indicator at bottom if more items below
	if endIdx < totalItems {
		lines = append(lines, m.styles.Muted.Render(fmt.Sprintf("  ↓ %d more below", totalItems-endIdx)))
	}

	return m.styles.BorderedBox.
		Width(width).
		Render(strings.Join(lines, "\n"))
}

func (m model) renderStatusBar() string {
	// Left side: key hints
	var hints []string
	if m.agentBusy {
		hints = append(hints, "/stop")
	}
	hints = append(hints, "/help", "Tab", "Enter")
	left := m.styles.Muted.Render(strings.Join(hints, " │ "))

	// Right side: status indicators
	var rightParts []string

	// Token usage with visual indicator
	stats := m.agent.GetTokenStats()
	contextPct := int(stats.ContextPercentage)
	var contextIndicator string
	if contextPct > 80 {
		contextIndicator = m.styles.Error.Render(fmt.Sprintf("CTX %d%%", contextPct))
	} else if contextPct > 50 {
		contextIndicator = m.styles.Warning.Render(fmt.Sprintf("CTX %d%%", contextPct))
	} else {
		contextIndicator = m.styles.Muted.Render(fmt.Sprintf("CTX %d%%", contextPct))
	}
	rightParts = append(rightParts, contextIndicator)

	// Session tokens
	if stats.TotalTokens > 0 {
		sessionStr := fmt.Sprintf("%dk tok", stats.TotalTokens/1000)
		rightParts = append(rightParts, m.styles.Muted.Render(sessionStr))
	}

	// Undo count
	undoCount := m.agent.GetCheckpointManager().UndoableCount()
	if undoCount > 0 {
		rightParts = append(rightParts, m.styles.Muted.Render(fmt.Sprintf("↩ %d", undoCount)))
	}

	// API key indicator
	if m.agent.HasAPIKey() {
		rightParts = append(rightParts, m.styles.Success.Render("●"))
	} else {
		rightParts = append(rightParts, m.styles.Error.Render("○"))
	}

	right := strings.Join(rightParts, " │ ")

	padding := m.width - lipgloss.Width(left) - lipgloss.Width(right) - 4
	if padding < 0 {
		padding = 1
	}

	return m.styles.StatusBar.Render(left + strings.Repeat(" ", padding) + right)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
