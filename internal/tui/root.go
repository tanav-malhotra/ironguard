package tui

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"

	"github.com/tanav-malhotra/ironguard/internal/agent"
	"github.com/tanav-malhotra/ironguard/internal/audio"
	"github.com/tanav-malhotra/ironguard/internal/config"
	"github.com/tanav-malhotra/ironguard/internal/llm"
	"github.com/tanav-malhotra/ironguard/internal/mcp"
	"github.com/tanav-malhotra/ironguard/internal/tools"
)

// Rotating placeholder messages for the input field
var inputPlaceholders = []string{
	"Reporting for duty...",
	"Awaiting orders...",
	"Ready when you are...",
	"Systems online...",
	"*cracks knuckles*",
}

// randomPlaceholder returns a random placeholder message
func randomPlaceholder() string {
	return inputPlaceholders[rand.Intn(len(inputPlaceholders))]
}

// pushUndo saves the current input state to the undo stack
func (m *model) pushUndo(state string) {
	// Don't push empty states or duplicates
	if state == "" {
		return
	}
	if len(m.undoStack) > 0 && m.undoStack[len(m.undoStack)-1] == state {
		return
	}
	m.undoStack = append(m.undoStack, state)
	// Limit stack size to 50 entries
	if len(m.undoStack) > 50 {
		m.undoStack = m.undoStack[1:]
	}
}

// Run starts the top-level TUI program.
func Run(cfg config.Config) error {
	// Configure and initialize audio system (non-fatal if it fails)
	audio.SetOptions(cfg.NoSound, cfg.NoRepeatSound, cfg.OfficialSound)
	if err := audio.Init(); err != nil {
		// Audio init failed - continue without sound
		// This is fine, sound is optional
	}

	m := newModel(cfg)
	p := tea.NewProgram(m,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(), // Mouse click capture (not all motion - that causes escape sequence issues)
	)
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

// ConnectivityCheckMsg is sent when connectivity check completes.
type ConnectivityCheckMsg struct {
	InternetOK  bool
	InternetErr error
	APIKeyOK    bool
	APIKeyErr   error
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
	inputHistory  []string // History of sent messages (for ↑/↓ navigation)
	historyIndex  int      // Current position in sent history (-1 = not browsing)
	historyDraft  string   // Saved draft when browsing history
	undoStack     []string // Stack of previous input states (for Ctrl+Z)
	lastInputLen  int      // Track input length for undo snapshots

	// Autocomplete state
	showAutocomplete       bool
	autocompleteSuppressed bool
	autocompleteItems      []AutocompleteItem
	autocompleteIdx        int
	autocompleteForArgs    bool   // true when showing arg options, false for commands
	autocompleteCmdName    string // command name when showing arg options

	// Confirmation dialog
	showConfirm    bool
	confirmAction  *PendingAction
	confirmMessage string
	confirmToolID  string

	// Popup viewer (tabbed: AI Todos + Checkpoints)
	showPopup   bool
	popupViewer *PopupViewer

	// API keys (in-memory only)
	apiKeys map[string]string

	// Layout state
	quitting     bool
	ready        bool
	width        int
	height       int
	sidebarWidth int

	// Connectivity status (checked at startup)
	internetOK      bool
	internetErr     error
	apiKeyValidated bool
	apiKeyErr       error
	checkingConn    bool // true while connectivity check is in progress

	// Styling
	theme  Theme
	styles Styles

	// Command registry
	cmdRegistry *CommandRegistry

	// Working directory (for status bar display)
	cwd string

	// Mouse handling
	lastRightClick          time.Time
	popupWasOpenBeforePress bool

	// Scroll tracking
	lastScrollMax int

	// Agent
	agent       *agent.Agent
	agentBusy   bool
	agentStatus string

	// Manual tasks
	manualTasks *ManualTaskManager

	// Score tracking
	currentScore  int
	previousScore int
	scoreDelta    int

	// Vulnerability tracking
	vulnsFound     int
	vulnsTotal     int
	prevVulnsFound int // For calculating dings

	// MCP server manager
	mcpManager *mcp.Manager

	// Program reference for sending commands
	program *tea.Program
}

func newModel(cfg config.Config) model {
	// Seed randomness once for rotating placeholders
	rand.Seed(time.Now().UnixNano())

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	ti := textinput.New()
	ti.Placeholder = "Reporting for duty..."
	ti.Focus()
	ti.CharLimit = 2000
	ti.Width = 60

	theme := DefaultTheme()
	styles := NewStyles(theme)

	// Create agent
	ag := agent.New(&cfg)

	// Create MCP manager
	mcpMgr := mcp.NewManager()

	// Connect MCP tools to agent's tool registry
	mcpAdapter := mcp.NewToolsAdapter(mcpMgr)
	ag.SetMCPManager(mcpAdapter)

	// Sync screen mode with tools package on startup
	tools.SetScreenMode(cfg.ScreenMode)

	m := model{
		cfg:           cfg,
		messages:      []Message{},
		input:         ti,
		apiKeys:       make(map[string]string),
		sidebarWidth:  32, // Wider for manual tasks
		theme:         theme,
		styles:        styles,
		cmdRegistry:   NewCommandRegistry(),
		agent:         ag,
		manualTasks:   NewManualTaskManager(),
		mcpManager:    mcpMgr,
		checkingConn:  true, // Will be set to false when connectivity check completes
		cwd:           cwd,
		lastScrollMax: 0,
	}

	// Generate welcome message here (Init uses value receiver so changes wouldn't persist)
	welcomeMsg := m.generateWelcomeScreen()
	m.messages = append(m.messages, NewSystemMessage(welcomeMsg))

	// Initialize input history
	m.inputHistory = []string{}
	m.historyIndex = -1 // -1 means not browsing history
	m.historyDraft = ""

	// Start scrolled to TOP so welcome banner is visible
	// This will be recalculated once we know the window size
	m.scrollOffset = 99999 // Will be clamped to max in renderChat

	return m
}

func (m model) Init() tea.Cmd {
	// Note: Welcome message is generated in newModel, not here
	// because Init uses a value receiver and changes wouldn't persist
	return tea.Batch(textinput.Blink, m.listenToAgent(), m.checkConnectivity())
}

// checkConnectivity performs internet and API key validation in the background.
func (m model) checkConnectivity() tea.Cmd {
	return func() tea.Msg {
		result := ConnectivityCheckMsg{}

		// Check internet first
		if err := llm.CheckInternet(); err != nil {
			result.InternetErr = err
			return result
		}
		result.InternetOK = true

		// Check API key if we have one
		if m.agent.HasAPIKey() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := m.agent.ValidateAPIKey(ctx); err != nil {
				result.APIKeyErr = err
			} else {
				result.APIKeyOK = true
			}
		}

		return result
	}
}

// generateWelcomeScreen creates the startup banner and instructions
func (m model) generateWelcomeScreen() string {
	banner := `
  ██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
  ██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██║██████╔╝██║   ██║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 

                    AUTONOMOUS SECURITY HARDENING SYSTEM                  
  ────────────────────────────────────────────────────────────────────────`

	// Check if API key is configured
	hasAPIKey := m.agent.HasAPIKey()

	var statusLine string
	if hasAPIKey {
		statusLine = `

  ┌──────────────────────────────────────────────────────────────────────┐
  │  [✓] SYSTEM ONLINE                              STATUS: OPERATIONAL  │
  └──────────────────────────────────────────────────────────────────────┘`
	} else {
		statusLine = `

  ┌──────────────────────────────────────────────────────────────────────┐
  │  [ ] AWAITING CONFIGURATION                        STATUS: STANDBY   │
  └──────────────────────────────────────────────────────────────────────┘`
	}

	quickStart := `

  QUICK START
  ────────────────────────────────────────────────────────────────────────
  STEP 1   /key <provider> <api-key>            Configure AI provider
  STEP 2   /start                               Begin autonomous hardening

  OPTIONAL (before /start)
  ────────────────────────────────────────────────────────────────────────
           /provider <claude|openai|gemini>     Switch AI provider
           /model <model-name>                  Change model (Tab for options)

  CAPABILITIES
  ────────────────────────────────────────────────────────────────────────
  › Forensics Analysis                     Automatically answers questions
  › Vulnerability Remediation              Fixes security misconfigs
  › User Management                        Removes unauthorized accounts
  › Score Optimization                     Iterates until maximum achieved
  › Screen Control                         GUI automation when enabled
  › Checkpoint System                      Undo/restore AI actions

  CONTROLS
  ────────────────────────────────────────────────────────────────────────
  /help        All commands            Tab           Autocomplete
  /stop        Halt operation          Enter         Send message
  /quit        Exit program            Ctrl+Enter    Interrupt AI
  ↑/↓          Input history           PgUp/PgDn     Scroll chat
  @file        Attach file             Right-click   Open ironguard viewer
  Ctrl+L       Clear input             Ctrl+Z        Undo
  Ctrl+R       Refresh screen          /undo         Undo AI action

  CHECKPOINT COMMANDS
  ────────────────────────────────────────────────────────────────────────
  /checkpoints <subcommand>                           Manage checkpoints
  /undo                                               Undo the last action

  TIP: Use @filename to attach files, e.g. "analyze @report.pdf"`

	return banner + statusLine + quickStart
}

// refreshTerminalSize queries the current terminal size and returns a WindowSizeMsg.
func (m model) refreshTerminalSize() tea.Cmd {
	return func() tea.Msg {
		// Try to get terminal size from stdout
		fd := int(os.Stdout.Fd())
		width, height, err := term.GetSize(fd)
		if err != nil {
			// Fallback to current size
			return nil
		}
		return tea.WindowSizeMsg{Width: width, Height: height}
	}
}

// listenToAgent creates a command that listens for agent events.
func (m model) listenToAgent() tea.Cmd {
	return func() tea.Msg {
		event := <-m.agent.Events()
		return AgentEventMsg{Event: event}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Save input state at the VERY START - before anything can modify it
	// This captures the state before terminal right-click paste
	inputBeforeUpdate := m.input.Value()
	cursorBeforeUpdate := m.input.Position()

	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKeyMsg(msg)

	case tea.MouseMsg:
		// Handle mouse events
		switch msg.Button {
		case tea.MouseButtonWheelUp:
			m.scrollOffset += 3
			maxScroll := m.getMaxScrollOffset()
			if m.scrollOffset > maxScroll {
				m.scrollOffset = maxScroll
			}
			return &m, nil
		case tea.MouseButtonWheelDown:
			m.scrollOffset -= 3
			if m.scrollOffset < 0 {
				m.scrollOffset = 0
			}
			return &m, nil
		case tea.MouseButtonRight:
			// ALWAYS restore input to undo any paste from terminal right-click
			m.input.SetValue(inputBeforeUpdate)
			m.input.SetCursor(cursorBeforeUpdate)

			now := time.Now()
			switch msg.Action {
			case tea.MouseActionPress:
				// Debounce rapid clicks
				if now.Sub(m.lastRightClick) < 150*time.Millisecond {
					return &m, nil
				}
				m.lastRightClick = now

				if m.showPopup {
					// Popup is open - close it immediately (toggle behavior)
					m.showPopup = false
					m.popupViewer = nil
					m.popupWasOpenBeforePress = true // Mark that popup was already open
				} else {
					// Popup is closed - open it now
					m.popupWasOpenBeforePress = false // Mark that this press opened the popup
					m.showPopup = true
					cm := m.agent.GetCheckpointManager()
					m.popupViewer = NewPopupViewer(cm, m.width, m.height, m.styles)
				}
				return &m, nil

			case tea.MouseActionRelease:
				// If this press opened the popup AND user held > 250ms, close on release (peek behavior)
				if !m.popupWasOpenBeforePress && m.showPopup && now.Sub(m.lastRightClick) > 250*time.Millisecond {
					m.showPopup = false
					m.popupViewer = nil
				}
				m.popupWasOpenBeforePress = false // Reset for next interaction
				return &m, nil
			}
			return &m, nil
		}
		return &m, nil

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.input.Width = msg.Width - m.sidebarWidth - 8
		if m.input.Width < 20 {
			m.input.Width = 20
		}
		m.ready = true
		// Clamp scroll offset to valid range
		maxScroll := m.getMaxScrollOffset()
		if m.scrollOffset > maxScroll {
			m.scrollOffset = maxScroll
		}
		// Clear screen on resize to prevent artifacts
		return m, tea.ClearScreen
	case AgentEventMsg:
		return m.handleAgentEvent(msg.Event)
	case ConnectivityCheckMsg:
		m.checkingConn = false
		m.internetOK = msg.InternetOK
		m.internetErr = msg.InternetErr
		m.apiKeyValidated = msg.APIKeyOK
		m.apiKeyErr = msg.APIKeyErr
		return m, nil
	}

	// Track state before update for undo
	prevValue := m.input.Value()
	prevLen := len(prevValue)

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)

	newValue := m.input.Value()
	newLen := len(newValue)

	// If input changed, clear autocomplete suppression
	if newValue != prevValue {
		m.autocompleteSuppressed = false
	}

	// If input became empty (user deleted all text), rotate placeholder
	if prevLen > 0 && newLen == 0 {
		m.pushUndo(prevValue) // Save before clearing
		m.input.Placeholder = randomPlaceholder()
	} else if newLen > 0 {
		// Save undo snapshot on significant changes:
		// - After typing a space (word boundary)
		// - When deleting multiple characters
		// - Every 10 characters typed
		if newLen > prevLen {
			// Typing
			if strings.HasSuffix(newValue, " ") || newLen-m.lastInputLen >= 10 {
				m.pushUndo(prevValue)
				m.lastInputLen = newLen
			}
		} else if prevLen-newLen >= 3 {
			// Deleted 3+ characters at once (like Ctrl+Backspace)
			m.pushUndo(prevValue)
			m.lastInputLen = newLen
		}
	}

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
	// Handle popup viewer (tabs: AI Todos, Checkpoints)
	if m.showPopup {
		return m.handlePopupViewerKey(msg)
	}

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

	// First check by key string for better cross-terminal compatibility
	keyStr := msg.String()

	switch keyStr {
	case "up":
		return m.handleArrowUp()
	case "down":
		return m.handleArrowDown()
	case "pgup":
		m.scrollOffset += 10
		maxScroll := m.getMaxScrollOffset()
		if m.scrollOffset > maxScroll {
			m.scrollOffset = maxScroll
		}
		return m, nil
	case "pgdown":
		m.scrollOffset -= 10
		if m.scrollOffset < 0 {
			m.scrollOffset = 0
		}
		return m, nil
	case "home":
		m.scrollOffset = m.getMaxScrollOffset()
		return m, nil
	case "end":
		m.scrollOffset = 0
		return m, nil
	}

	switch msg.Type {
	case tea.KeyCtrlC:
		// Ctrl+C is commonly used to copy text in terminals - let it pass through
		// Use /stop to cancel AI, /quit to exit
		return m, nil

	case tea.KeyCtrlV:
		// Ctrl+V - paste is handled by terminal emulator
		// Just let it pass through
		return m, nil

	case tea.KeyCtrlQ:
		// Ctrl+Q does nothing - use /quit instead
		return m, nil

	case tea.KeyEsc:
		// Esc only closes autocomplete dropdown
		if m.showAutocomplete {
			m.showAutocomplete = false
			m.autocompleteSuppressed = true
			return m, nil
		}
		return m, nil

	case tea.KeyCtrlL:
		// Clear input line (Ctrl+L so terminal doesn't intercept)
		if m.input.Value() != "" {
			m.pushUndo(m.input.Value()) // Save for Ctrl+Z undo
			m.input.SetValue("")
			m.input.Placeholder = randomPlaceholder()
			m.showAutocomplete = false
		}
		return m, nil

	case tea.KeyCtrlZ:
		// Undo - restore previous input state
		if len(m.undoStack) > 0 {
			// Pop from undo stack
			lastState := m.undoStack[len(m.undoStack)-1]
			m.undoStack = m.undoStack[:len(m.undoStack)-1]
			m.input.SetValue(lastState)
			m.input.CursorEnd()
			m.lastInputLen = len(lastState)
			m.updateAutocomplete()
		}
		return m, nil

	case tea.KeyCtrlR:
		// Quick refresh - re-query terminal size and redraw
		return m, tea.Batch(m.refreshTerminalSize(), tea.ClearScreen)

	case tea.KeyTab:
		if m.showAutocomplete && len(m.autocompleteItems) > 0 {
			// Select current item first, then move to next for next Tab press
			selected := m.autocompleteItems[m.autocompleteIdx]
			if m.autocompleteCmdName == "@" {
				// File completion - replace from last @ to cursor
				val := m.input.Value()
				atIdx := strings.LastIndex(val, "@")
				if atIdx >= 0 {
					m.input.SetValue(val[:atIdx+1] + selected.Text + " ")
				}
			} else if m.autocompleteForArgs {
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
		return m.handleArrowUp()

	case tea.KeyDown:
		return m.handleArrowDown()

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
				// Save to history
				if len(m.inputHistory) == 0 || m.inputHistory[len(m.inputHistory)-1] != fullCmd {
					m.inputHistory = append(m.inputHistory, fullCmd)
				}
				m.historyIndex = -1
				m.historyDraft = ""
				m.input.SetValue("")
				m.input.Placeholder = randomPlaceholder()
				m.showAutocomplete = false
				m.autocompleteForArgs = false
				return m.handleSlashCommand(fullCmd)
			} else {
				// Check if command has required arguments
				cmd := m.cmdRegistry.Get(selected.Text)
				if cmd != nil && cmd.Args == "" {
					// No arguments required - execute immediately
					cmdStr := "/" + selected.Text
					// Save to history
					if len(m.inputHistory) == 0 || m.inputHistory[len(m.inputHistory)-1] != cmdStr {
						m.inputHistory = append(m.inputHistory, cmdStr)
					}
					m.historyIndex = -1
					m.historyDraft = ""
					m.input.SetValue("")
					m.input.Placeholder = randomPlaceholder()
					m.showAutocomplete = false
					return m.handleSlashCommand(cmdStr)
				}
				// Has arguments - complete and show arg options
				m.input.SetValue("/" + selected.Text + " ")
				m.input.SetCursor(len(m.input.Value()))
				m.updateAutocomplete()
				return m, nil
			}
		}

		// Add to input history (avoid duplicates of last entry)
		if len(m.inputHistory) == 0 || m.inputHistory[len(m.inputHistory)-1] != val {
			m.inputHistory = append(m.inputHistory, val)
		}
		m.historyIndex = -1 // Reset history navigation
		m.historyDraft = ""

		m.input.SetValue("")
		m.input.Placeholder = randomPlaceholder()
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

		// Add to input history (avoid duplicates of last entry)
		if len(m.inputHistory) == 0 || m.inputHistory[len(m.inputHistory)-1] != val {
			m.inputHistory = append(m.inputHistory, val)
		}
		m.historyIndex = -1 // Reset history navigation
		m.historyDraft = ""

		m.input.SetValue("")
		m.input.Placeholder = randomPlaceholder()
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

	// Track state before update for undo
	prevValue := m.input.Value()
	prevLen := len(prevValue)

	// Update text input
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)

	newValue := m.input.Value()
	newLen := len(newValue)

	// If input changed, clear autocomplete suppression (user typed something new)
	if newValue != prevValue {
		m.autocompleteSuppressed = false
	}

	// If input became empty (user deleted all text), rotate placeholder
	if prevLen > 0 && newLen == 0 {
		m.pushUndo(prevValue)
		m.input.Placeholder = randomPlaceholder()
	} else if newLen > 0 && prevLen-newLen >= 3 {
		// Deleted 3+ characters at once
		m.pushUndo(prevValue)
	}

	m.updateAutocomplete()
	return m, cmd
}

// handleArrowUp handles up arrow key for autocomplete and input history
func (m *model) handleArrowUp() (tea.Model, tea.Cmd) {
	if m.showAutocomplete && len(m.autocompleteItems) > 0 {
		m.autocompleteIdx--
		if m.autocompleteIdx < 0 {
			m.autocompleteIdx = len(m.autocompleteItems) - 1
		}
		return m, nil
	}
	// Navigate input history (go to older entries)
	if len(m.inputHistory) > 0 {
		if m.historyIndex == -1 {
			// Starting to browse history - save current input as draft
			m.historyDraft = m.input.Value()
			m.historyIndex = len(m.inputHistory) - 1
		} else if m.historyIndex > 0 {
			m.historyIndex--
		}
		m.input.SetValue(m.inputHistory[m.historyIndex])
		m.input.CursorEnd()
		// Suppress autocomplete until user makes a change
		m.autocompleteSuppressed = true
		m.showAutocomplete = false
	}
	return m, nil
}

// handleArrowDown handles down arrow key for autocomplete and input history
func (m *model) handleArrowDown() (tea.Model, tea.Cmd) {
	if m.showAutocomplete && len(m.autocompleteItems) > 0 {
		m.autocompleteIdx = (m.autocompleteIdx + 1) % len(m.autocompleteItems)
		return m, nil
	}
	// Navigate input history (go to newer entries)
	if m.historyIndex != -1 {
		if m.historyIndex < len(m.inputHistory)-1 {
			m.historyIndex++
			m.input.SetValue(m.inputHistory[m.historyIndex])
			m.input.CursorEnd()
			// Suppress autocomplete until user makes a change
			m.autocompleteSuppressed = true
			m.showAutocomplete = false
		} else {
			// Back to the draft (current unsent input)
			m.historyIndex = -1
			m.input.SetValue(m.historyDraft)
			m.input.CursorEnd()
			// Suppress autocomplete until user makes a change
			m.autocompleteSuppressed = true
			m.showAutocomplete = false
		}
	}
	return m, nil
}

// handlePopupViewerKey handles key events when the popup viewer is open.
func (m *model) handlePopupViewerKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.popupViewer == nil {
		m.showPopup = false
		return m, nil
	}

	switch msg.String() {
	case "esc", "q":
		m.showPopup = false
		m.popupViewer = nil
		return m, nil

	case "left", "h":
		// Switch to previous tab
		m.popupViewer.PrevTab()
		return m, nil

	case "right", "l":
		// Switch to next tab
		m.popupViewer.NextTab()
		return m, nil

	case "up", "k":
		m.popupViewer.Up()
		return m, nil

	case "down", "j":
		m.popupViewer.Down()
		return m, nil

	case "enter":
		// Only works in Checkpoints tab - restore to selected checkpoint
		if m.popupViewer.activeTab == PopupTabCheckpoints {
			node := m.popupViewer.SelectedCheckpoint()
			if node != nil {
				cm := m.agent.GetCheckpointManager()
				restoredNode, newBranch, err := cm.RestoreToCheckpoint(node.ID)
				if err != nil {
					m.messages = append(m.messages, NewSystemMessage(fmt.Sprintf("❌ Failed to restore: %s", err)))
				} else {
					msg := fmt.Sprintf("✅ Restored to checkpoint #%d: %s", restoredNode.ID, restoredNode.Description)
					if newBranch != "" {
						msg += fmt.Sprintf(" (new branch: %s)", newBranch)
					}
					m.messages = append(m.messages, NewSystemMessage(msg))
					m.agent.QueueSystemMessage(fmt.Sprintf("[SYSTEM] User restored to checkpoint #%d: %s", restoredNode.ID, restoredNode.Description))
				}
			}
			m.showPopup = false
			m.popupViewer = nil
		}
		return m, nil

	case "d", "D":
		// Delete selected item (checkpoints only - AI todos are read-only)
		if m.popupViewer.activeTab == PopupTabCheckpoints {
			node := m.popupViewer.SelectedCheckpoint()
			if node != nil {
				cm := m.agent.GetCheckpointManager()
				if err := cm.DeleteCheckpoint(node.ID); err != nil {
					m.messages = append(m.messages, NewSystemMessage(fmt.Sprintf("❌ Cannot delete: %s", err)))
				} else {
					m.messages = append(m.messages, NewSystemMessage(fmt.Sprintf("✅ Deleted checkpoint #%d", node.ID)))
					// Refresh popup data
					m.popupViewer.RefreshData(cm)
				}
			}
		}
		return m, nil

	case "e", "E":
		// Edit mode - for checkpoints only for now
		if m.popupViewer.activeTab == PopupTabCheckpoints {
			m.showPopup = false
			m.popupViewer = nil
			m.messages = append(m.messages, NewSystemMessage("Use /checkpoints edit <id> <description> to edit a checkpoint."))
		}
		return m, nil
	}

	return m, nil
}

func (m *model) startChat(message string) tea.Cmd {
	return func() tea.Msg {
		// Expand @ mentions in the message
		expandedMessage, mentions := ExpandMentionsInMessage(message)

		// Collect images from mentions
		var images []llm.ImageContent
		for _, mention := range mentions {
			if mention.IsImage && len(mention.ImageData) > 0 {
				images = append(images, llm.ImageContent{
					Data:      mention.ImageData,
					MediaType: mention.MediaType,
					Path:      mention.Path,
				})
			}
		}

		// Use ChatWithImages if we have images, otherwise regular Chat
		if len(images) > 0 {
			go m.agent.ChatWithImages(context.Background(), expandedMessage, images)
		} else {
			go m.agent.Chat(context.Background(), expandedMessage)
		}
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
		// Special case: refresh action returns immediately with ClearScreen
		if m.pendingAction.Type == ActionRefresh {
			m.pendingAction = nil
			m.messages = append(m.messages, NewSystemMessage("🔄 Display refreshed"))
			// Re-query terminal size and clear screen
			return m, tea.Batch(m.refreshTerminalSize(), tea.ClearScreen)
		}

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
	// If user just dismissed autocomplete with Esc, keep it hidden until input changes
	if m.autocompleteSuppressed {
		m.showAutocomplete = false
		return
	}

	val := m.input.Value()

	// Check for @ file mentions anywhere in input
	if atIdx := strings.LastIndex(val, "@"); atIdx >= 0 {
		// Get the partial path after the last @
		partial := val[atIdx+1:]
		// Only autocomplete if we're still typing the path (no space after @)
		if !strings.Contains(partial, " ") {
			files := GetFileCompletions(partial, 10)
			if len(files) > 0 {
				m.autocompleteItems = make([]AutocompleteItem, len(files))
				for i, f := range files {
					// Keep full path for insertion; show basename in description
					displayName := f
					if idx := strings.LastIndex(f, string(os.PathSeparator)); idx >= 0 {
						displayName = f[idx+1:]
					}
					m.autocompleteItems[i] = AutocompleteItem{
						Text:        f,
						Description: displayName,
						IsArg:       true, // Treat as arg for insertion behavior
					}
				}
				m.showAutocomplete = true
				m.autocompleteForArgs = true
				m.autocompleteCmdName = "@" // Special marker for file completion
				if m.autocompleteIdx >= len(m.autocompleteItems) {
					m.autocompleteIdx = 0
				}
				return
			}
		}
	}

	// Handle / commands
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
		var argOptions []string
		if cmdName == "model" {
			// Dynamic model options based on current provider
			argOptions = m.getModelOptionsForProvider(argPrefix)
		} else {
			argOptions = m.cmdRegistry.GetArgOptions(cmdName, argPrefix)
		}
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

	// Calculate dimensions - ensure minimum sizes
	chatWidth := m.width - m.sidebarWidth - 3
	if chatWidth < 20 {
		chatWidth = 20
	}

	// Reserve space for input (3 lines) and status bar (1 line)
	chatHeight := m.height - 5
	if chatHeight < 5 {
		chatHeight = 5
	}

	// The main content area height (chat + input) should match sidebar height
	mainAreaHeight := m.height - 2

	sidebar := m.renderSidebar()
	chat := m.renderChat(chatWidth, chatHeight)
	inputArea := m.renderInputOnly(chatWidth)
	statusBar := m.renderStatusBar()

	// If autocomplete is showing, overlay it on the chat
	if m.showAutocomplete && len(m.autocompleteItems) > 0 {
		autocomplete := m.renderAutocomplete(chatWidth)
		chat = m.overlayAutocomplete(chat, autocomplete, chatWidth, chatHeight)
	}

	// Create main content with fixed height to match sidebar
	mainContent := lipgloss.JoinVertical(lipgloss.Left, chat, inputArea)

	// Force main content to have same height as sidebar
	mainContentStyle := lipgloss.NewStyle().
		Width(chatWidth + 2).
		Height(mainAreaHeight).
		MaxHeight(mainAreaHeight)
	mainContent = mainContentStyle.Render(mainContent)

	// Join horizontally - both should now have same height
	content := lipgloss.JoinHorizontal(lipgloss.Top, mainContent, sidebar)

	// Clear screen artifacts by padding to full width
	fullWidth := lipgloss.NewStyle().Width(m.width)
	content = fullWidth.Render(content)
	statusBar = fullWidth.Render(statusBar)

	finalView := lipgloss.JoinVertical(lipgloss.Left, content, statusBar)

	// Overlay popup viewer if active
	if m.showPopup && m.popupViewer != nil {
		viewer := m.popupViewer.Render()
		finalView = CenterOverlay(viewer, finalView, m.width, m.height, m.sidebarWidth)
	}

	// Apply consistent background color to entire view for cross-terminal consistency
	// This ensures the TUI looks the same on Linux Mint, Ubuntu, etc.
	bgStyle := lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Background(m.theme.Background)
	
	return bgStyle.Render(finalView)
}

func (m model) renderSidebar() string {
	var sb strings.Builder
	lineWidth := m.sidebarWidth - 6

	// Header with title
	sb.WriteString(m.styles.Title.Render("◈ IRONGUARD") + "\n")
	sb.WriteString(m.styles.Muted.Render(strings.Repeat("─", lineWidth)) + "\n")

	// Admin warning if not running with privileges
	if !m.cfg.RunningAsAdmin {
		warnStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFB000")).
			Bold(true)
		sb.WriteString(warnStyle.Render("⚠ NOT ADMIN") + "\n")
		sb.WriteString(m.styles.Muted.Render("  Limited access") + "\n")
	}
	sb.WriteString("\n")

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

	// Status - check connectivity, API key, and agent state
	sb.WriteString(m.styles.Label.Render("STATUS") + "\n")
	if m.checkingConn {
		sb.WriteString(m.styles.Warning.Render("  ◌ CHECKING...") + "\n")
	} else if m.internetErr != nil {
		sb.WriteString(m.styles.Error.Render("  ✗ NO INTERNET") + "\n")
		sb.WriteString(m.styles.Muted.Render("    Check connection") + "\n")
	} else if !m.agent.HasAPIKey() {
		sb.WriteString(m.styles.Error.Render("  ◌ NO API KEY") + "\n")
		sb.WriteString(m.styles.Muted.Render("    /key <prov> <key>") + "\n")
	} else if m.apiKeyErr != nil {
		sb.WriteString(m.styles.Error.Render("  ✗ INVALID KEY") + "\n")
		errMsg := m.apiKeyErr.Error()
		if len(errMsg) > lineWidth-4 {
			errMsg = errMsg[:lineWidth-7] + "..."
		}
		sb.WriteString(m.styles.Muted.Render("    "+errMsg) + "\n")
	} else if m.agentBusy {
		sb.WriteString(m.styles.Warning.Render("  ◉ PROCESSING") + "\n")
		if m.agentStatus != "" {
			status := m.agentStatus
			if len(status) > lineWidth-4 {
				status = status[:lineWidth-7] + "..."
			}
			sb.WriteString(m.styles.Muted.Render("  "+status) + "\n")
		}
	} else if m.internetOK && m.apiKeyValidated {
		sb.WriteString(m.styles.Success.Render("  ● READY") + "\n")
	} else if m.internetOK && m.agent.HasAPIKey() && !m.apiKeyValidated {
		// Has API key but hasn't been validated yet (still checking or check not started)
		sb.WriteString(m.styles.Warning.Render("  ◌ VALIDATING...") + "\n")
	} else {
		// Fallback - has API key, internet not checked yet
		sb.WriteString(m.styles.Warning.Render("  ◌ INITIALIZING") + "\n")
	}
	sb.WriteString("\n")

	// Mode and Provider info
	sb.WriteString(m.styles.Label.Render("CONFIG") + "\n")
	providerStr := strings.ToUpper(string(m.cfg.Provider))
	sb.WriteString(m.styles.Muted.Render("  Provider: ") + m.styles.Value.Render(providerStr) + "\n")
	if m.cfg.Model != "" {
		sb.WriteString(m.styles.Muted.Render("  Model:    ") + m.styles.Value.Render(m.cfg.Model) + "\n")
	}

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
	sidebarHeight := m.height - 2
	if sidebarHeight < 10 {
		sidebarHeight = 10
	}

	// Ensure content fills the sidebar height
	targetHeight := sidebarHeight - 2 // Account for borders
	for i := contentLines; i < targetHeight; i++ {
		content += "\n"
	}

	// Use MaxHeight to prevent overflow
	return m.styles.Sidebar.
		Width(m.sidebarWidth).
		Height(sidebarHeight).
		MaxHeight(sidebarHeight).
		MaxWidth(m.sidebarWidth).
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
	// Track and clamp scroll offset; if user was at top (max), stay at top when content grows
	newMax := m.getMaxScrollOffset()
	if m.lastScrollMax > 0 && m.scrollOffset == m.lastScrollMax {
		m.scrollOffset = newMax
	}
	if m.scrollOffset > newMax {
		m.scrollOffset = newMax
	}
	if m.scrollOffset < 0 {
		m.scrollOffset = 0
	}
	m.lastScrollMax = newMax

	// Build all content lines (each message may be multiple lines)
	var allLines []string
	var prevRole MessageRole

	// Separator style
	separatorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#333333"))
	separator := separatorStyle.Render(strings.Repeat("─", width-6))

	for i, msg := range m.messages {
		// Add visual separation between different message types
		if i > 0 {
			// Add separator line when message type changes
			if prevRole != msg.Role {
				allLines = append(allLines, "")
				// Add a subtle separator line for major transitions
				if (prevRole == RoleUser && msg.Role == RoleAI) ||
					(prevRole == RoleAI && msg.Role == RoleUser) ||
					prevRole == RoleSystem {
					// Always add separator after system messages
					allLines = append(allLines, separator)
				}
				allLines = append(allLines, "")
			}
		}

		formatted := m.formatMessage(msg, width-4)
		msgLines := strings.Split(formatted, "\n")
		allLines = append(allLines, msgLines...)

		// Always add separator after system messages (even if next is also system)
		if msg.Role == RoleSystem {
			allLines = append(allLines, separator)
		}

		prevRole = msg.Role
	}

	totalLines := len(allLines)

	// Reserve space for up to two indicator lines (above/below)
	displayHeight := height - 2
	if displayHeight < 3 {
		displayHeight = 3
	}

	// Calculate visible window
	var visibleLines []string
	var linesAbove, linesBelow int

	if totalLines <= displayHeight {
		// All content fits - no scrolling needed
		visibleLines = allLines
	} else {
		// Calculate start position based on scroll offset
		// scrollOffset=0 means we're at the bottom (newest)
		// scrollOffset>0 means we've scrolled up
		maxScroll := totalLines - displayHeight
		if maxScroll < 0 {
			maxScroll = 0
		}

		// Clamp scrollOffset to valid range
		scrollPos := m.scrollOffset
		if scrollPos > maxScroll {
			scrollPos = maxScroll
		}

		end := totalLines - scrollPos
		start := end - displayHeight

		if start < 0 {
			start = 0
			end = displayHeight
			if end > totalLines {
				end = totalLines
			}
		}

		visibleLines = allLines[start:end]
		linesAbove = start
		linesBelow = totalLines - end

		// Keep model scrollOffset in sync with the clamped value
		m.scrollOffset = scrollPos
	}

	// Build content with scroll indicators
	var content strings.Builder

	if linesAbove > 0 {
		label := "lines"
		if linesAbove == 1 {
			label = "line"
		}
		content.WriteString(m.styles.Muted.Render(fmt.Sprintf("↑ %d %s above", linesAbove, label)))
		content.WriteString("\n")
	}

	content.WriteString(strings.Join(visibleLines, "\n"))

	if linesBelow > 0 {
		label := "lines"
		if linesBelow == 1 {
			label = "line"
		}
		content.WriteString("\n")
		content.WriteString(m.styles.Muted.Render(fmt.Sprintf("↓ %d %s below", linesBelow, label)))
	}

	// Ensure chat pane doesn't overflow its bounds
	return m.styles.ChatPane.
		Width(width).
		Height(height).
		MaxHeight(height).
		MaxWidth(width).
		Render(content.String())
}

// getMaxScrollOffset calculates the maximum scroll offset based on content
func (m model) getMaxScrollOffset() int {
	// Count total lines EXACTLY as renderChat does
	totalLines := 0
	chatWidth := m.width - m.sidebarWidth - 7
	if chatWidth < 20 {
		chatWidth = 20
	}

	var prevRole MessageRole
	for i, msg := range m.messages {
		// Account for spacing between message types (must match renderChat exactly)
		if i > 0 {
			if prevRole != msg.Role {
				totalLines++ // Empty line before role change
				// Separator line for major transitions
				if (prevRole == RoleUser && msg.Role == RoleAI) ||
					(prevRole == RoleAI && msg.Role == RoleUser) ||
					prevRole == RoleSystem {
					totalLines++ // Separator line
				}
				totalLines++ // Empty line after separator
			}
		}

		formatted := m.formatMessage(msg, chatWidth)
		totalLines += strings.Count(formatted, "\n") + 1

		// Separator after system messages
		if msg.Role == RoleSystem {
			totalLines++ // Separator line
		}

		prevRole = msg.Role
	}

	// Calculate visible height (same as in renderChat)
	chatHeight := m.height - 5
	if chatHeight < 5 {
		chatHeight = 5
	}
	displayHeight := chatHeight - 2
	if displayHeight < 3 {
		displayHeight = 3
	}

	// Max scroll is when we can see the very first line at the top
	maxOffset := totalLines - displayHeight
	if maxOffset < 0 {
		maxOffset = 0
	}
	return maxOffset
}

func (m model) formatMessage(msg Message, width int) string {
	// Calculate max content width for bubbles
	maxBubbleWidth := width - 8
	if maxBubbleWidth < 20 {
		maxBubbleWidth = 20
	}

	switch msg.Role {
	case RoleUser:
		// Right-aligned user message with clean styling
		content := msg.Content

		// Wrap long content
		if len(content) > maxBubbleWidth-6 {
			content = wrapText(content, maxBubbleWidth-6)
		}

		// Build styled message
		var lines []string

		// Show "You" label right-aligned
		label := m.styles.UserMessage.Render("You ▾")
		labelWidth := lipgloss.Width(label)
		labelPadding := width - labelWidth - 1
		if labelPadding < 0 {
			labelPadding = 0
		}
		lines = append(lines, strings.Repeat(" ", labelPadding)+label)

		// Content in a subtle box, right-aligned
		contentLines := strings.Split(content, "\n")
		for _, line := range contentLines {
			styledLine := m.styles.Value.Render(line)
			lineWidth := lipgloss.Width(styledLine)
			linePadding := width - lineWidth - 3
			if linePadding < 0 {
				linePadding = 0
			}
			lines = append(lines, strings.Repeat(" ", linePadding)+"  "+styledLine)
		}

		return strings.Join(lines, "\n")

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
				sb.WriteString(m.styles.ThinkingBox.Render("💭 THINKING:\n" + msg.Thinking))
			} else {
				// Collapsed view
				sb.WriteString(m.styles.ThinkingCollapsed.Render("💭 " + truncate(thinkingPreview, 50) + " [...]"))
			}
			sb.WriteString("\n")
		}

		// Left-aligned AI response with styled bubble
		content := msg.Content
		if msg.IsStreaming {
			content += m.styles.Muted.Render(" ▌")
		}

		// Show AI label on its own line
		sb.WriteString(m.styles.AIMessage.Bold(true).Foreground(m.theme.Primary).Render("◆ IronGuard") + "\n")

		// Wrap and render content
		if len(content) > maxBubbleWidth {
			content = wrapText(content, maxBubbleWidth-2)
		}
		sb.WriteString(m.styles.AIBubble.Width(maxBubbleWidth).Render(content))

		return sb.String()

	case RoleSystem:
		// System messages are subtle, centered-ish notifications
		content := msg.Content

		// Add visual separator for important system messages
		if strings.HasPrefix(content, "Error:") || strings.HasPrefix(content, "⚠") {
			return m.styles.Error.Render("  ⚠ " + content)
		} else if strings.HasPrefix(content, "✓") || strings.HasPrefix(content, "✔") {
			return m.styles.Success.Render("  " + content)
		}

		// Regular system messages
		return m.styles.SystemMessage.Render("  ─ " + content)

	case RoleTool:
		var sb strings.Builder

		// Tool box width
		toolWidth := maxBubbleWidth - 4
		if toolWidth < 30 {
			toolWidth = 30
		}

		// Determine icon and status
		var icon, statusColor string
		if msg.ToolError != "" {
			icon = "✗"
			statusColor = "error"
		} else if msg.ToolOutput != "" {
			icon = "✓"
			statusColor = "success"
		} else {
			icon = "◌"
			statusColor = "pending"
		}

		// Collapsed view: compact single line
		if msg.Collapsed {
			line := fmt.Sprintf("  %s %s", icon, msg.ToolName)
			if msg.ToolOutput != "" && statusColor == "success" {
				preview := strings.ReplaceAll(msg.ToolOutput, "\n", " ")
				line += m.styles.Muted.Render(" → " + truncate(preview, 35))
			} else if msg.ToolError != "" {
				line += m.styles.Error.Render(" → error")
			}

			switch statusColor {
			case "error":
				return m.styles.Error.Render(line) + m.styles.Muted.Render(" [+]")
			case "success":
				return m.styles.Success.Render("  "+icon+" ") + m.styles.ToolCall.Render(msg.ToolName) + m.styles.Muted.Render(" → "+truncate(strings.ReplaceAll(msg.ToolOutput, "\n", " "), 35)+" [+]")
			default:
				return m.styles.Warning.Render("  "+icon+" ") + m.styles.ToolCall.Render(msg.ToolName) + m.styles.Muted.Render(" ...")
			}
		}

		// Expanded view: bordered box with details
		var boxContent strings.Builder

		// Header with tool name
		boxContent.WriteString(m.styles.ToolCall.Render("⚡ " + msg.ToolName))

		// Show input if present
		if msg.ToolInput != "" {
			boxContent.WriteString("\n" + m.styles.Muted.Render("Input: "))
			inputPreview := strings.ReplaceAll(msg.ToolInput, "\n", " ")
			boxContent.WriteString(m.styles.Muted.Render(truncate(inputPreview, toolWidth-10)))
		}

		// Show output
		if msg.ToolOutput != "" {
			boxContent.WriteString("\n" + m.styles.Label.Render("Output:"))
			outputLines := strings.Split(msg.ToolOutput, "\n")
			maxLines := 6
			for i, line := range outputLines {
				if i >= maxLines {
					boxContent.WriteString("\n" + m.styles.Muted.Render(fmt.Sprintf("... %d more lines", len(outputLines)-maxLines)))
					break
				}
				if strings.TrimSpace(line) != "" {
					boxContent.WriteString("\n" + m.styles.Value.Render(truncate(line, toolWidth-2)))
				}
			}
		}

		// Show error
		if msg.ToolError != "" {
			boxContent.WriteString("\n" + m.styles.Error.Render("Error: "+msg.ToolError))
		}

		// Wrap in tool box style
		sb.WriteString(m.styles.ToolBox.Width(toolWidth).Render(boxContent.String()))
		sb.WriteString(m.styles.Muted.Render(" [-]"))

		return sb.String()

	default:
		return msg.Content
	}
}

// wrapText wraps text to the specified width
func wrapText(text string, width int) string {
	if width <= 0 {
		return text
	}

	var result strings.Builder
	words := strings.Fields(text)
	lineLen := 0

	for i, word := range words {
		wordLen := len(word)

		if lineLen+wordLen+1 > width && lineLen > 0 {
			result.WriteString("\n")
			lineLen = 0
		}

		if lineLen > 0 {
			result.WriteString(" ")
			lineLen++
		}

		result.WriteString(word)
		lineLen += wordLen

		// Preserve explicit newlines in original text
		if i < len(words)-1 && strings.Contains(text, word+"\n") {
			result.WriteString("\n")
			lineLen = 0
		}
	}

	return result.String()
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

	// Clean input box styling
	inputBox := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(m.theme.Primary).
		Padding(0, 1).
		Width(width)

	sb.WriteString(inputBox.Render(m.input.View()))

	// Status line below input - show current directory and score
	cwd, _ := os.Getwd()
	if len(cwd) > 40 {
		cwd = "..." + cwd[len(cwd)-37:]
	}

	var statusParts []string
	statusParts = append(statusParts, m.styles.Muted.Render("📁 "+cwd))

	if m.currentScore > 0 {
		scoreStr := fmt.Sprintf("🎯 %d/100", m.currentScore)
		if m.currentScore >= 90 {
			statusParts = append(statusParts, m.styles.Success.Render(scoreStr))
		} else if m.currentScore >= 70 {
			statusParts = append(statusParts, m.styles.Warning.Render(scoreStr))
		} else {
			statusParts = append(statusParts, m.styles.Error.Render(scoreStr))
		}
	}

	if m.agentBusy {
		statusParts = append(statusParts, m.styles.Warning.Render("⚡ AI working..."))
	}

	sb.WriteString("\n  " + strings.Join(statusParts, "  │  "))

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

	// Show header based on what we're completing (skip for @ file mentions)
	if m.autocompleteForArgs && m.autocompleteCmdName != "@" {
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
	var leftParts []string
	shortCwd := shortenPath(m.cwd, 40)
	leftParts = append(leftParts, fmt.Sprintf("cwd %s", shortCwd))
	if m.agentBusy {
		leftParts = append(leftParts, "busy (/stop)")
	} else {
		leftParts = append(leftParts, "/help")
	}
	left := m.styles.Muted.Render(strings.Join(leftParts, " │ "))

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

	// Session tokens (always show)
	sessionStr := fmt.Sprintf("TOK %dk", stats.TotalTokens/1000)
	rightParts = append(rightParts, m.styles.Muted.Render(sessionStr))

	// Checkpoint/save count
	saveCount := m.agent.GetCheckpointManager().UndoableCount()
	if saveCount > 0 {
		rightParts = append(rightParts, m.styles.Muted.Render(fmt.Sprintf("SAVE %d", saveCount)))
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

// getModelOptionsForProvider returns model options for ALL providers, filtered by prefix.
// This enables the unified /model command to show and autocomplete models from any provider.
func (m *model) getModelOptionsForProvider(prefix string) []string {
	var allModels []string
	
	// Collect models from all providers
	for _, provider := range []llm.Provider{llm.ProviderClaude, llm.ProviderOpenAI, llm.ProviderGemini} {
		allModels = append(allModels, llm.ModelPresets[provider]...)
	}
	
	if prefix == "" {
		return allModels
	}
	
	var matches []string
	for _, model := range allModels {
		if strings.HasPrefix(model, prefix) {
			matches = append(matches, model)
		}
	}
	return matches
}

// shortenPath returns a shortened path by replacing the home directory and trimming middle segments.
func shortenPath(p string, maxLen int) string {
	if maxLen <= 0 {
		return p
	}
	home, _ := os.UserHomeDir()
	if home != "" && strings.HasPrefix(p, home) {
		p = filepath.Join("~", strings.TrimPrefix(p, home))
	}
	if len(p) <= maxLen {
		return p
	}
	parts := strings.Split(filepath.ToSlash(p), "/")
	if len(parts) <= 2 {
		return truncate(p, maxLen)
	}
	left := parts[0]
	right := parts[len(parts)-1]
	mid := "…"
	for len(left)+len(mid)+len(right) > maxLen && len(left) > 1 {
		left = left[:len(left)-1]
	}
	return left + mid + right
}
