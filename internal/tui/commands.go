package tui

import (
	"fmt"

	"github.com/tanav-malhotra/ironguard/internal/config"
)

// SlashCommand represents a TUI slash command.
type SlashCommand struct {
	Name        string
	Description string
	Args        string // e.g. "<provider>" or "" if no args
	Handler     func(m *model, args string) string
}

// CommandRegistry holds all available slash commands.
type CommandRegistry struct {
	commands []SlashCommand
}

// NewCommandRegistry creates the default command registry.
func NewCommandRegistry() *CommandRegistry {
	r := &CommandRegistry{}
	r.registerDefaults()
	return r
}

func (r *CommandRegistry) registerDefaults() {
	r.commands = []SlashCommand{
		{
			Name:        "help",
			Description: "Show available commands and keybindings",
			Handler:     cmdHelp,
		},
		{
			Name:        "provider",
			Description: "Switch AI provider",
			Args:        "<claude|openai|gemini>",
			Handler:     cmdProvider,
		},
		{
			Name:        "model",
			Description: "Set the model name",
			Args:        "<model-name>",
			Handler:     cmdModel,
		},
		{
			Name:        "confirm",
			Description: "Enable confirm mode (ask before actions)",
			Handler:     cmdConfirm,
		},
		{
			Name:        "autopilot",
			Description: "Enable autopilot mode (auto-run actions)",
			Handler:     cmdAutopilot,
		},
		{
			Name:        "clear",
			Description: "Clear the chat history",
			Handler:     cmdClear,
		},
		{
			Name:        "status",
			Description: "Show current configuration and status",
			Handler:     cmdStatus,
		},
		{
			Name:        "readme",
			Description: "Read the CyberPatriot README from Desktop",
			Handler:     cmdReadReadme,
		},
		{
			Name:        "forensics",
			Description: "Read forensics questions from Desktop",
			Handler:     cmdReadForensics,
		},
		{
			Name:        "answer",
			Description: "Write an answer to a forensics question",
			Args:        "<question-num> <answer>",
			Handler:     cmdAnswer,
		},
		{
			Name:        "run",
			Description: "Run a terminal command",
			Args:        "<command>",
			Handler:     cmdRun,
		},
		{
			Name:        "harden",
			Description: "Start the hardening assistant",
			Handler:     cmdHarden,
		},
		{
			Name:        "key",
			Description: "Set API key for current provider",
			Args:        "<api-key>",
			Handler:     cmdKey,
		},
		{
			Name:        "models",
			Description: "List available models for current provider",
			Handler:     cmdModels,
		},
		{
			Name:        "quit",
			Description: "Exit ironguard",
			Handler:     cmdQuit,
		},
		{
			Name:        "auto",
			Description: "Start autonomous mode - AI works until target score reached",
			Args:        "[target-score]",
			Handler:     cmdAuto,
		},
		{
			Name:        "stop",
			Description: "Stop autonomous mode",
			Handler:     cmdStop,
		},
		{
			Name:        "score",
			Description: "Check current CyberPatriot score",
			Handler:     cmdScore,
		},
		{
			Name:        "manual",
			Description: "Add a manual task for yourself",
			Args:        "<task description>",
			Handler:     cmdManualAdd,
		},
		{
			Name:        "done",
			Description: "Mark a manual task as done",
			Args:        "<task number>",
			Handler:     cmdManualDone,
		},
		{
			Name:        "undone",
			Description: "Mark a manual task as not done",
			Args:        "<task number>",
			Handler:     cmdManualUndone,
		},
		{
			Name:        "tasks",
			Description: "List all manual tasks",
			Handler:     cmdManualList,
		},
		{
			Name:        "search",
			Description: "Search the web for information",
			Args:        "<query>",
			Handler:     cmdSearch,
		},
		// Screen control commands
		{
			Name:        "screen",
			Description: "Set screen interaction mode",
			Args:        "<observe|control>",
			Handler:     cmdScreenMode,
		},
		{
			Name:        "screenshot",
			Description: "Take a screenshot of the desktop",
			Handler:     cmdScreenshot,
		},
		{
			Name:        "click",
			Description: "Click at screen coordinates",
			Args:        "<x> <y>",
			Handler:     cmdClick,
		},
		{
			Name:        "type",
			Description: "Type text at current cursor position",
			Args:        "<text>",
			Handler:     cmdType,
		},
		{
			Name:        "hotkey",
			Description: "Press a keyboard shortcut",
			Args:        "<keys> (e.g., ctrl+c, alt+tab)",
			Handler:     cmdHotkey,
		},
		// Competition mode commands
		{
			Name:        "mode",
			Description: "Set competition mode",
			Args:        "<harden|packet-tracer|quiz>",
			Handler:     cmdCompMode,
		},
		{
			Name:        "windows",
			Description: "List all open windows",
			Handler:     cmdListWindows,
		},
		{
			Name:        "focus",
			Description: "Focus a window by title",
			Args:        "<window title>",
			Handler:     cmdFocusWindow,
		},
	}
}

// All returns all registered commands.
func (r *CommandRegistry) All() []SlashCommand {
	return r.commands
}

// Find returns commands matching the prefix.
func (r *CommandRegistry) Find(prefix string) []SlashCommand {
	if prefix == "" {
		return r.commands
	}
	var matches []SlashCommand
	for _, cmd := range r.commands {
		if len(cmd.Name) >= len(prefix) && cmd.Name[:len(prefix)] == prefix {
			matches = append(matches, cmd)
		}
	}
	return matches
}

// Get returns the command with the exact name, or nil.
func (r *CommandRegistry) Get(name string) *SlashCommand {
	for _, cmd := range r.commands {
		if cmd.Name == name {
			return &cmd
		}
	}
	return nil
}

// Command handlers

func cmdHelp(m *model, _ string) string {
	help := "Available commands:\n"
	for _, cmd := range m.cmdRegistry.commands {
		line := "  /" + cmd.Name
		if cmd.Args != "" {
			line += " " + cmd.Args
		}
		line += " - " + cmd.Description + "\n"
		help += line
	}
	help += "\nKeybindings:\n"
	help += "  Ctrl+C       - Cancel/Quit\n"
	help += "  Ctrl+L       - Clear screen\n"
	help += "  Tab          - Cycle autocomplete\n"
	help += "  Enter        - Send message or run command\n"
	help += "  Up/Down      - Scroll history\n"
	help += "  Esc          - Cancel/Close\n"
	return help
}

func cmdProvider(m *model, args string) string {
	switch args {
	case "claude", "anthropic":
		m.cfg.Provider = config.ProviderAnthropic
		m.agent.SetProvider("claude")
		return "Switched to Claude (Anthropic)"
	case "openai", "gpt":
		m.cfg.Provider = config.ProviderOpenAI
		m.agent.SetProvider("openai")
		return "Switched to OpenAI"
	case "gemini", "google":
		m.cfg.Provider = config.ProviderGemini
		m.agent.SetProvider("gemini")
		return "Switched to Gemini (Google)"
	case "":
		return "Current provider: " + string(m.cfg.Provider) + "\nUsage: /provider <claude|openai|gemini>"
	default:
		return "Unknown provider: " + args + "\nAvailable: claude, openai, gemini"
	}
}

func cmdModel(m *model, args string) string {
	if args == "" {
		return "Current model: " + m.cfg.Model + "\nUsage: /model <model-name>\nUse /models to see available models"
	}
	m.cfg.Model = args
	return "Model set to: " + args
}

func cmdModels(m *model, _ string) string {
	models := ""
	switch m.cfg.Provider {
	case config.ProviderAnthropic:
		models = "Claude models:\n"
		models += "  claude-opus-4-5 ⭐ (default - most powerful)\n"
		models += "  claude-sonnet-4-5 (fast alternative)\n"
	case config.ProviderOpenAI:
		models = "OpenAI models:\n"
		models += "  gpt-5.1 ⭐ (default - latest flagship)\n"
		models += "  gpt-5.1-codex (coding-optimized variant)\n"
		models += "  gpt-5.1-codex-max (maximum capability - test availability)\n"
	case config.ProviderGemini:
		models = "Gemini models:\n"
		models += "  gemini-3-pro ⭐ (default)\n"
	}
	return models
}

func cmdConfirm(m *model, _ string) string {
	m.cfg.Mode = config.ModeConfirm
	return "Confirm mode enabled. I'll ask before running any commands."
}

func cmdAutopilot(m *model, _ string) string {
	m.cfg.Mode = config.ModeAutopilot
	return "⚠️ Autopilot mode enabled. Commands will run automatically!"
}

func cmdClear(m *model, _ string) string {
	m.messages = []Message{}
	m.agent.ClearHistory()
	return ""
}

func cmdStatus(m *model, _ string) string {
	status := "Current Status:\n"
	status += "  Provider: " + string(m.cfg.Provider) + "\n"
	status += "  Model: " + m.cfg.Model + "\n"
	status += "  Mode: " + string(m.cfg.Mode) + "\n"
	status += "  OS: " + m.cfg.OS + "/" + m.cfg.Architecture + "\n"

	keyStatus := "not set"
	if m.apiKeys[string(m.cfg.Provider)] != "" {
		keyStatus = "set"
	}
	status += "  API Key: " + keyStatus + "\n"

	if m.agentBusy {
		status += "  Agent: busy\n"
	} else {
		status += "  Agent: ready\n"
	}

	return status
}

func cmdReadReadme(m *model, _ string) string {
	m.pendingAction = &PendingAction{
		Type:        ActionReadReadme,
		Description: "Read README from Desktop",
	}
	return "Reading README..."
}

func cmdReadForensics(m *model, _ string) string {
	m.pendingAction = &PendingAction{
		Type:        ActionReadForensics,
		Description: "Read forensics questions",
	}
	return "Reading forensics questions..."
}

func cmdAnswer(m *model, args string) string {
	if args == "" {
		return "Usage: /answer <question-num> <answer>\nExample: /answer 1 The unauthorized user is jsmith"
	}
	m.pendingAction = &PendingAction{
		Type:        ActionWriteAnswer,
		Description: "Write forensics answer",
		Args:        args,
	}
	return "Writing answer..."
}

func cmdRun(m *model, args string) string {
	if args == "" {
		return "Usage: /run <command>\nExample: /run Get-LocalUser"
	}
	m.pendingAction = &PendingAction{
		Type:        ActionRunCommand,
		Description: "Run: " + args,
		Args:        args,
	}
	return "Running command..."
}

func cmdHarden(m *model, _ string) string {
	m.pendingAction = &PendingAction{
		Type:        ActionHarden,
		Description: "Start hardening assistant",
	}
	return "Starting hardening assistant..."
}

func cmdKey(m *model, args string) string {
	if args == "" {
		return "Usage: /key <api-key>\nThis sets the API key for the current provider (" + string(m.cfg.Provider) + ")"
	}
	m.apiKeys[string(m.cfg.Provider)] = args
	m.agent.SetAPIKey(string(m.cfg.Provider), args)
	return "API key set for " + string(m.cfg.Provider)
}

func cmdQuit(m *model, _ string) string {
	m.quitting = true
	return "Goodbye!"
}

func cmdAuto(m *model, args string) string {
	targetScore := 100
	if args != "" {
		if _, err := fmt.Sscanf(args, "%d", &targetScore); err != nil {
			return "Usage: /auto [target-score]\nExample: /auto 100"
		}
	}

	if m.apiKeys[string(m.cfg.Provider)] == "" {
		return "⚠️ Set your API key first with /key <api-key>"
	}

	m.pendingAction = &PendingAction{
		Type:        ActionAuto,
		Description: fmt.Sprintf("Start autonomous mode (target: %d pts)", targetScore),
		Args:        fmt.Sprintf("%d", targetScore),
	}
	return fmt.Sprintf("🤖 Starting AUTONOMOUS MODE - Target: %d/100 points\nThe AI will now work continuously until the target is reached.\nUse /stop to cancel.", targetScore)
}

func cmdStop(m *model, _ string) string {
	m.agent.StopAutonomous()
	return "⏹️ Autonomous mode stopped."
}

func cmdScore(m *model, _ string) string {
	m.pendingAction = &PendingAction{
		Type:        ActionCheckScore,
		Description: "Check current score",
	}
	return "Checking score..."
}

func cmdManualAdd(m *model, args string) string {
	if args == "" {
		return "Usage: /manual <task description>\nExample: /manual Enable Firefox tracking protection in Settings"
	}
	task := m.manualTasks.Add(args, "Added by user", "medium")
	return fmt.Sprintf("✅ Added task #%s: %s", task.ID, args)
}

func cmdManualDone(m *model, args string) string {
	if args == "" {
		return "Usage: /done <task number>\nExample: /done 1"
	}
	if m.manualTasks.Complete(args) {
		return fmt.Sprintf("✅ Task %s marked as done!", args)
	}
	return "Task not found or already done: " + args
}

func cmdManualUndone(m *model, args string) string {
	if args == "" {
		return "Usage: /undone <task number>\nExample: /undone 1"
	}
	if m.manualTasks.Uncomplete(args) {
		return fmt.Sprintf("↩️ Task %s marked as not done", args)
	}
	return "Task not found or not done: " + args
}

func cmdManualList(m *model, _ string) string {
	return m.manualTasks.FormatDetailed()
}

func cmdSearch(m *model, args string) string {
	if args == "" {
		return "Usage: /search <query>\nExample: /search how to enable UFW firewall ubuntu"
	}
	m.pendingAction = &PendingAction{
		Type:        ActionSearch,
		Description: "Search: " + args,
		Args:        args,
	}
	return "Searching..."
}

func cmdScreenMode(m *model, args string) string {
	switch args {
	case "observe":
		m.cfg.ScreenMode = config.ScreenModeObserve
		return "👁️ Screen mode: OBSERVE\nAI can view the screen but cannot control mouse/keyboard.\nUse /screenshot to capture the screen."
	case "control":
		m.cfg.ScreenMode = config.ScreenModeControl
		return "🖱️ Screen mode: CONTROL\n⚠️ AI now has full mouse/keyboard control!\nAI can click, type, and interact with any application."
	case "":
		mode := "OBSERVE"
		if m.cfg.ScreenMode == config.ScreenModeControl {
			mode = "CONTROL"
		}
		return fmt.Sprintf("Current screen mode: %s\nUsage: /screen <observe|control>", mode)
	default:
		return "Unknown screen mode. Use: /screen <observe|control>"
	}
}

func cmdScreenshot(m *model, _ string) string {
	m.pendingAction = &PendingAction{
		Type:        ActionScreenshot,
		Description: "Take screenshot",
	}
	return "📸 Taking screenshot..."
}

func cmdClick(m *model, args string) string {
	if m.cfg.ScreenMode != config.ScreenModeControl {
		return "⚠️ Screen control disabled. Use /screen control to enable."
	}
	if args == "" {
		return "Usage: /click <x> <y>\nExample: /click 500 300"
	}
	m.pendingAction = &PendingAction{
		Type:        ActionClick,
		Description: "Click at coordinates",
		Args:        args,
	}
	return "🖱️ Clicking..."
}

func cmdType(m *model, args string) string {
	if m.cfg.ScreenMode != config.ScreenModeControl {
		return "⚠️ Screen control disabled. Use /screen control to enable."
	}
	if args == "" {
		return "Usage: /type <text>\nExample: /type Hello World"
	}
	m.pendingAction = &PendingAction{
		Type:        ActionType_,
		Description: "Type text",
		Args:        args,
	}
	return "⌨️ Typing..."
}

func cmdHotkey(m *model, args string) string {
	if m.cfg.ScreenMode != config.ScreenModeControl {
		return "⚠️ Screen control disabled. Use /screen control to enable."
	}
	if args == "" {
		return "Usage: /hotkey <keys>\nExamples: /hotkey ctrl+c, /hotkey alt+tab, /hotkey enter"
	}
	m.pendingAction = &PendingAction{
		Type:        ActionHotkey,
		Description: "Press hotkey",
		Args:        args,
	}
	return "⌨️ Pressing hotkey..."
}

func cmdCompMode(m *model, args string) string {
	switch args {
	case "harden":
		m.cfg.CompMode = config.CompModeHarden
		return "🛡️ Competition mode: HARDENING\nOptimized for CyberPatriot image hardening (Windows/Linux)."
	case "packet-tracer", "pt":
		m.cfg.CompMode = config.CompModePacketTracer
		return "🌐 Competition mode: PACKET TRACER\nAI will help with Cisco Packet Tracer challenges.\nUse /screen control to enable AI screen interaction."
	case "quiz", "network-quiz":
		m.cfg.CompMode = config.CompModeNetworkQuiz
		return "📝 Competition mode: NETWORK QUIZ\nAI will help with networking quizzes.\nUse /screen control to enable AI screen interaction."
	case "":
		modes := map[config.CompetitionMode]string{
			config.CompModeHarden:       "HARDENING",
			config.CompModePacketTracer: "PACKET TRACER",
			config.CompModeNetworkQuiz:  "NETWORK QUIZ",
		}
		screenMode := "OBSERVE"
		if m.cfg.ScreenMode == config.ScreenModeControl {
			screenMode = "CONTROL"
		}
		return fmt.Sprintf("Current competition mode: %s\nScreen mode: %s\nUsage: /mode <harden|packet-tracer|quiz>", modes[m.cfg.CompMode], screenMode)
	default:
		return "Unknown mode. Use: /mode <harden|packet-tracer|quiz>"
	}
}

func cmdListWindows(m *model, _ string) string {
	m.pendingAction = &PendingAction{
		Type:        ActionListWindows,
		Description: "List windows",
	}
	return "🪟 Listing windows..."
}

func cmdFocusWindow(m *model, args string) string {
	if args == "" {
		return "Usage: /focus <window title>\nExample: /focus Firefox"
	}
	m.pendingAction = &PendingAction{
		Type:        ActionFocusWindow,
		Description: "Focus window",
		Args:        args,
	}
	return fmt.Sprintf("🪟 Focusing window: %s", args)
}

// ActionType represents a pending action type.
type ActionType int

const (
	ActionNone ActionType = iota
	ActionReadReadme
	ActionReadForensics
	ActionWriteAnswer
	ActionRunCommand
	ActionHarden
	ActionChat
	ActionAuto
	ActionCheckScore
	ActionSearch
	ActionScreenshot
	ActionClick
	ActionType_ // Using ActionType_ to avoid conflict with ActionType type
	ActionHotkey
	ActionListWindows
	ActionFocusWindow
)

// PendingAction represents an action waiting to be executed.
type PendingAction struct {
	Type        ActionType
	Description string
	Args        string
}
