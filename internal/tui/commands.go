package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tanav-malhotra/ironguard/internal/agent"
	"github.com/tanav-malhotra/ironguard/internal/config"
	"github.com/tanav-malhotra/ironguard/internal/llm"
	"github.com/tanav-malhotra/ironguard/internal/tools"
)

// syncScreenMode syncs the screen mode between config and tools package.
func syncScreenMode(mode config.ScreenMode) {
	tools.SetScreenMode(mode)
}

// SlashCommand represents a TUI slash command.
type SlashCommand struct {
	Name        string
	Description string
	Args        string   // e.g. "<provider>" or "" if no args
	ArgOptions  []string // Autocomplete options for arguments (e.g. ["claude", "openai", "gemini"])
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
			ArgOptions:  []string{"claude", "openai", "gemini"},
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
			Args:        "<windows|windows-server|linux|cisco|auto>",
			ArgOptions:  []string{"windows", "windows-server", "linux", "cisco", "auto"},
			Handler:     cmdHarden,
		},
		{
			Name:        "start",
			Description: "Start the hardening assistant (alias for /harden)",
			Args:        "<windows|windows-server|linux|cisco|auto>",
			ArgOptions:  []string{"windows", "windows-server", "linux", "cisco", "auto"},
			Handler:     cmdHarden,
		},
		{
			Name:        "key",
			Description: "Set API key for a provider",
			Args:        "<claude|openai|gemini> <api-key>",
			ArgOptions:  []string{"claude", "openai", "gemini"},
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
			ArgOptions:  []string{"observe", "control"},
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
		// Subagent commands
		{
			Name:        "subagents",
			Description: "Set max concurrent subagents or show current setting",
			Args:        "[max-count]",
			Handler:     cmdSubAgents,
		},
		// MCP server commands
		{
			Name:        "mcp-add",
			Description: "Add and connect to an MCP server",
			Args:        "<name> <command> [args...]",
			Handler:     cmdMCPAdd,
		},
		{
			Name:        "mcp-remove",
			Description: "Disconnect and remove an MCP server",
			Args:        "<name>",
			Handler:     cmdMCPRemove,
		},
		{
			Name:        "mcp-list",
			Description: "List connected MCP servers and their tools",
			Handler:     cmdMCPList,
		},
		{
			Name:        "mcp-tools",
			Description: "List all tools from a specific MCP server",
			Args:        "<server-name>",
			Handler:     cmdMCPTools,
		},
		// Context and token management
		{
			Name:        "compact",
			Description: "Toggle compact mode (brief AI responses)",
			Args:        "[on|off]",
			ArgOptions:  []string{"on", "off"},
			Handler:     cmdCompact,
		},
		{
			Name:        "summarize",
			Description: "Set summarization mode",
			Args:        "<smart|fast>",
			ArgOptions:  []string{"smart", "fast"},
			Handler:     cmdSummarize,
		},
		{
			Name:        "tokens",
			Description: "Show token usage statistics",
			Handler:     cmdTokens,
		},
		{
			Name:        "todos",
			Description: "Show AI's task list",
			Handler:     cmdTodos,
		},
		// Undo/checkpoint commands
		{
			Name:        "undo",
			Description: "Undo the last action",
			Handler:     cmdUndo,
		},
		{
			Name:        "history",
			Description: "Show action history (checkpoints)",
			Handler:     cmdHistory,
		},
		{
			Name:        "checkpoints",
			Description: "Manage checkpoints",
			Args:        "<create|list|restore|edit|delete|branch|branches|clear>",
			ArgOptions:  []string{"create", "list", "restore", "edit", "delete", "branch", "branches", "clear"},
			Handler:     cmdCheckpoints,
		},
		// Memory commands
		{
			Name:        "remember",
			Description: "Save something to persistent memory",
			Args:        "<category> <content>",
			ArgOptions:  []string{"vulnerability", "config", "command", "finding", "tip", "pattern"},
			Handler:     cmdRemember,
		},
		{
			Name:        "recall",
			Description: "Search persistent memory",
			Args:        "[query]",
			Handler:     cmdRecall,
		},
		{
			Name:        "forget",
			Description: "Clear persistent memory",
			Handler:     cmdForget,
		},
		// Connectivity check
		{
			Name:        "check",
			Description: "Check internet and API key connectivity",
			Handler:     cmdCheck,
		},
		// Display
		{
			Name:        "refresh",
			Description: "Redraw the screen (fixes UI glitches)",
			Handler:     cmdRefresh,
		},
		// Sound settings
		{
			Name:        "sound",
			Description: "Toggle sound effects",
			Args:        "[on|off]",
			ArgOptions:  []string{"on", "off"},
			Handler:     cmdSound,
		},
		{
			Name:        "sound-repeat",
			Description: "Toggle repeat sounds (multiple dings vs single)",
			Args:        "[on|off]",
			ArgOptions:  []string{"on", "off"},
			Handler:     cmdSoundRepeat,
		},
		{
			Name:        "sound-official",
			Description: "Toggle official CyberPatriot sound vs custom",
			Args:        "[on|off]",
			ArgOptions:  []string{"on", "off"},
			Handler:     cmdSoundOfficial,
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

// GetArgOptions returns argument options for a command, filtered by prefix.
func (r *CommandRegistry) GetArgOptions(cmdName, argPrefix string) []string {
	cmd := r.Get(cmdName)
	if cmd == nil || len(cmd.ArgOptions) == 0 {
		return nil
	}
	if argPrefix == "" {
		return cmd.ArgOptions
	}
	var matches []string
	for _, opt := range cmd.ArgOptions {
		if len(opt) >= len(argPrefix) && opt[:len(argPrefix)] == argPrefix {
			matches = append(matches, opt)
		}
	}
	return matches
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
	help += "  Enter        - Send message (queues if AI busy)\n"
	help += "  Ctrl+Enter   - Interrupt AI & send immediately\n"
	help += "  Tab          - Autocomplete / cycle options\n"
	help += "  ↑/↓          - Input history / autocomplete\n"
	help += "  PgUp/PgDn    - Scroll chat\n"
	help += "  Ctrl+L       - Clear input line\n"
	help += "  Ctrl+Z       - Undo clear (restore input)\n"
	help += "  Ctrl+R       - Refresh screen (fixes resize)\n"
	help += "  Right-click  - Open checkpoint viewer\n"
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
	// Notify AI of mode change
	m.pendingAction = &PendingAction{
		Type:        ActionSettingChanged,
		Description: "Mode changed to confirm",
		Args:        "confirm",
	}
	return "Confirm mode enabled. I'll ask before running any commands."
}

func cmdAutopilot(m *model, _ string) string {
	m.cfg.Mode = config.ModeAutopilot
	// Notify AI of mode change
	m.pendingAction = &PendingAction{
		Type:        ActionSettingChanged,
		Description: "Mode changed to autopilot",
		Args:        "autopilot",
	}
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

func cmdHarden(m *model, args string) string {
	// Check for API key first
	if m.apiKeys[string(m.cfg.Provider)] == "" {
		return "⚠️ Set your API key first with /key <api-key>"
	}

	// Parse arguments: /harden [mode] [target-score]
	// Modes: windows, windows-server, linux, cisco, auto
	parts := strings.Fields(args)
	
	mode := ""
	targetScore := 100
	
	for _, part := range parts {
		switch strings.ToLower(part) {
		case "windows", "win", "w":
			mode = "windows"
		case "windows-server", "server", "ws":
			mode = "windows-server"
		case "linux", "lin", "l":
			mode = "linux"
		case "cisco", "packet-tracer", "pt", "quiz", "network-quiz":
			mode = "cisco"
		case "auto", "detect":
			mode = "auto"
		default:
			// Try to parse as number
			if n, err := fmt.Sscanf(part, "%d", &targetScore); n == 1 && err == nil {
				continue
			}
		}
	}

	// If no mode specified, show selection menu
	if mode == "" {
		// Auto-detect OS
		osInfo := config.DetectOS()
		m.cfg.OSInfo = osInfo
		
		detectedOS := "Unknown"
		suggestedMode := "auto"
		
		switch osInfo.Type {
		case config.OSTypeWindows10:
			detectedOS = fmt.Sprintf("Windows 10 (%s)", osInfo.Version)
			suggestedMode = "windows"
		case config.OSTypeWindows11:
			detectedOS = fmt.Sprintf("Windows 11 (%s)", osInfo.Version)
			suggestedMode = "windows"
		case config.OSTypeWindowsServer:
			detectedOS = fmt.Sprintf("Windows Server (%s)", osInfo.Name)
			suggestedMode = "windows-server"
		case config.OSTypeUbuntu:
			detectedOS = fmt.Sprintf("Ubuntu %s", osInfo.Version)
			suggestedMode = "linux"
		case config.OSTypeDebian:
			detectedOS = fmt.Sprintf("Debian %s", osInfo.Version)
			suggestedMode = "linux"
		case config.OSTypeLinuxMint:
			detectedOS = fmt.Sprintf("Linux Mint %s", osInfo.Version)
			suggestedMode = "linux"
		case config.OSTypeFedora, config.OSTypeCentOS:
			detectedOS = osInfo.Name
			suggestedMode = "linux"
		case config.OSTypeLinuxOther:
			detectedOS = osInfo.Name
			suggestedMode = "linux"
		}

		return fmt.Sprintf(`🔍 DETECTED SYSTEM: %s

Choose hardening mode:

  /harden windows        - Windows 10/11 desktop
  /harden windows-server - Windows Server
  /harden linux          - Ubuntu/Debian/Linux Mint
  /harden cisco          - Cisco challenges (Packet Tracer/NetAcad quizzes)
  /harden auto           - Auto-detect and start (suggested: %s)

Example: /harden %s 100

💡 Tip: Add target score at the end (default: 100)`, detectedOS, suggestedMode, suggestedMode)
	}

	// Set competition mode based on selection
	switch mode {
	case "windows":
		m.cfg.CompMode = config.CompModeHarden
		m.cfg.OSInfo.Type = config.OSTypeWindows10
		m.cfg.HardenMode = "windows"
	case "windows-server":
		m.cfg.CompMode = config.CompModeHarden
		m.cfg.OSInfo.Type = config.OSTypeWindowsServer
		m.cfg.OSInfo.IsServer = true
		m.cfg.HardenMode = "windows-server"
	case "linux":
		m.cfg.CompMode = config.CompModeHarden
		// Keep detected Linux type or default to Ubuntu
		if m.cfg.OSInfo.Type == config.OSTypeUnknown {
			m.cfg.OSInfo.Type = config.OSTypeUbuntu
		}
		m.cfg.HardenMode = "linux"
	case "cisco":
		m.cfg.CompMode = config.CompModeCisco
		m.cfg.HardenMode = "cisco"
		if m.cfg.ScreenMode != config.ScreenModeControl {
			return `⚠️ CISCO MODE WORKS BEST WITH SCREEN CONTROL

The AI can observe and guide you, or take control to complete Cisco tasks.
For full autonomous mode, enable screen control:
  /screen control

Then run:
  /harden cisco

In OBSERVE mode: AI watches your screen and provides step-by-step guidance.
In CONTROL mode: AI can click, type, scroll, and complete tasks autonomously.`
		}
	case "auto":
		// Use auto-detected OS
		osInfo := config.DetectOS()
		m.cfg.OSInfo = osInfo
		m.cfg.CompMode = config.CompModeHarden
		m.cfg.HardenMode = "auto"
	}

	// Pin hardening target in a non-ephemeral system message so the AI never forgets
	osDesc := m.cfg.OSInfo.Type.String()
	if m.cfg.OSInfo.Version != "" {
		osDesc += " " + m.cfg.OSInfo.Version
	}
	m.agent.QueueSystemMessage(fmt.Sprintf("[SYSTEM] Hardening target locked: mode=%s os=%s", mode, osDesc))

	// Start autonomous hardening
	m.pendingAction = &PendingAction{
		Type:        ActionAuto,
		Description: fmt.Sprintf("Start autonomous hardening (target: %d pts, mode: %s)", targetScore, mode),
		Args:        fmt.Sprintf("%d", targetScore),
	}

	return fmt.Sprintf(`🛡️ IRONGUARD AUTONOMOUS HARDENING ACTIVATED

Mode: %s
Detected OS: %s
Target: %d/100 points

The AI will now AUTOMATICALLY:
  ✓ Read the README (authorized users, services, restrictions)
  ✓ Read and answer forensics questions (easy points!)
  ✓ Delete unauthorized users
  ✓ Fix security vulnerabilities
  ✓ Check score after each action
  ✓ Continue until target reached

Use /stop to cancel at any time.
Ctrl+C also pauses the AI (doesn't quit the app).`, strings.ToUpper(mode), osDesc, targetScore)
}

func cmdKey(m *model, args string) string {
	fields := strings.Fields(args)
	if len(fields) < 2 {
		return "Usage: /key <provider> <api-key>\nProviders: claude, openai, gemini"
	}

	targetProvider := fields[0]
	switch targetProvider {
	case "claude", "openai", "gemini":
	default:
		return "Unknown provider. Use: claude, openai, gemini"
	}

	key := strings.Join(fields[1:], " ")
	if key == "" {
		return "Missing API key. Usage: /key <provider> <api-key>"
	}

	// Save and apply the key
	m.apiKeys[targetProvider] = key
	m.agent.SetAPIKey(targetProvider, key)
	
	// If we updated the active provider, reset validation state
	if targetProvider == string(m.cfg.Provider) {
	m.apiKeyValidated = false
	m.apiKeyErr = nil
		m.checkingConn = true
	}
	
	return "API key set for " + targetProvider + "\nUse /check to validate connectivity."
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
		// Sync with tools package
		syncScreenMode(config.ScreenModeObserve)
		// Notify AI of screen mode change
		m.pendingAction = &PendingAction{
			Type:        ActionSettingChanged,
			Description: "Screen mode changed to observe",
			Args:        "screen_observe",
		}
		return "👁️ Screen mode: OBSERVE\nAI can view the screen but cannot control mouse/keyboard.\nUse /screenshot to capture the screen."
	case "control":
		m.cfg.ScreenMode = config.ScreenModeControl
		// Sync with tools package
		syncScreenMode(config.ScreenModeControl)
		// Notify AI of screen mode change
		m.pendingAction = &PendingAction{
			Type:        ActionSettingChanged,
			Description: "Screen mode changed to control",
			Args:        "screen_control",
		}
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
	ActionMCPAdd
	ActionMCPRemove
	ActionSubAgentLimitChanged
	ActionSettingChanged
	ActionRefresh // Redraw screen (fixes UI glitches)
)

// PendingAction represents an action waiting to be executed.
type PendingAction struct {
	Type        ActionType
	Description string
	Args        string
}

// Subagent command handlers

func cmdSubAgents(m *model, args string) string {
	if args == "" {
		max := m.agent.GetMaxSubAgents()
		running := len(m.agent.GetSubAgents())
		return fmt.Sprintf(`🤖 SUBAGENT SETTINGS

Current max concurrent subagents: %d
Currently running: %d

Usage: /subagents <max-count>
Example: /subagents 6

Valid range: 1-10
Default: 4

💡 More subagents = more parallel work but higher API costs`, max, running)
	}

	var newMax int
	if _, err := fmt.Sscanf(args, "%d", &newMax); err != nil {
		return "Invalid number. Usage: /subagents <max-count>\nExample: /subagents 6"
	}

	if newMax < 1 || newMax > 10 {
		return "Max subagents must be between 1 and 10."
	}

	oldMax := m.agent.GetMaxSubAgents()
	m.agent.SetMaxSubAgents(newMax)

	// Queue a system message to inform the AI about the change
	m.pendingAction = &PendingAction{
		Type:        ActionSubAgentLimitChanged,
		Description: fmt.Sprintf("Max subagents changed from %d to %d", oldMax, newMax),
		Args:        fmt.Sprintf("%d", newMax),
	}

	return fmt.Sprintf("✅ Max concurrent subagents changed: %d → %d\nThe AI has been notified of this change.", oldMax, newMax)
}

// MCP command handlers

func cmdMCPAdd(m *model, args string) string {
	if args == "" {
		return `Usage: /mcp-add <name> <command> [args...]
Examples:
  /mcp-add filesystem npx -y @modelcontextprotocol/server-filesystem /path/to/dir
  /mcp-add brave-search npx -y @anthropic/mcp-server-brave-search
  /mcp-add github npx -y @anthropic/mcp-server-github`
	}

	// Parse args: first word is name, rest is command
	parts := splitArgs(args)
	if len(parts) < 2 {
		return "Error: Need at least a name and command.\nUsage: /mcp-add <name> <command> [args...]"
	}

	name := parts[0]
	command := parts[1]
	cmdArgs := []string{}
	if len(parts) > 2 {
		cmdArgs = parts[2:]
	}

	m.pendingAction = &PendingAction{
		Type:        ActionMCPAdd,
		Description: fmt.Sprintf("Connect to MCP server: %s (%s)", name, command),
		Args:        fmt.Sprintf("%s|%s|%s", name, command, joinArgs(cmdArgs)),
	}
	return fmt.Sprintf("🔌 Connecting to MCP server '%s'...", name)
}

func cmdMCPRemove(m *model, args string) string {
	if args == "" {
		return "Usage: /mcp-remove <server-name>\nUse /mcp-list to see connected servers."
	}

	m.pendingAction = &PendingAction{
		Type:        ActionMCPRemove,
		Description: fmt.Sprintf("Disconnect MCP server: %s", args),
		Args:        args,
	}
	return fmt.Sprintf("🔌 Disconnecting MCP server '%s'...", args)
}

func cmdMCPList(m *model, _ string) string {
	if m.mcpManager == nil {
		return "No MCP manager configured. MCP servers are not available."
	}

	servers := m.mcpManager.ListServers()
	if len(servers) == 0 {
		return `No MCP servers connected.

Add servers with /mcp-add:
  /mcp-add filesystem npx -y @modelcontextprotocol/server-filesystem /path
  /mcp-add brave-search npx -y @anthropic/mcp-server-brave-search
  /mcp-add github npx -y @anthropic/mcp-server-github`
	}

	result := "Connected MCP Servers:\n"
	for _, name := range servers {
		info, err := m.mcpManager.GetServerInfo(name)
		if err != nil {
			result += fmt.Sprintf("  • %s (error: %s)\n", name, err)
			continue
		}
		result += fmt.Sprintf("  • %s - %d tools\n", info.Name, info.ToolCount)
	}

	totalTools := 0
	for _, t := range m.mcpManager.AllTools() {
		_ = t
		totalTools++
	}
	result += fmt.Sprintf("\nTotal MCP tools available: %d", totalTools)
	result += "\nUse /mcp-tools <server-name> to see tools from a specific server."

	return result
}

func cmdMCPTools(m *model, args string) string {
	if m.mcpManager == nil {
		return "No MCP manager configured."
	}

	if args == "" {
		// List all tools from all servers
		allTools := m.mcpManager.AllTools()
		if len(allTools) == 0 {
			return "No MCP tools available. Connect servers with /mcp-add first."
		}

		result := "All MCP Tools:\n"
		for _, tool := range allTools {
			result += fmt.Sprintf("  • %s - %s\n", tool.FullName, truncateString(tool.Description, 60))
		}
		return result
	}

	// List tools from specific server
	info, err := m.mcpManager.GetServerInfo(args)
	if err != nil {
		return fmt.Sprintf("Error: %s", err)
	}

	result := fmt.Sprintf("Tools from '%s':\n", args)
	for _, toolName := range info.Tools {
		result += fmt.Sprintf("  • %s/%s\n", args, toolName)
	}
	return result
}

// Helper functions for MCP commands

func splitArgs(s string) []string {
	var parts []string
	var current string
	inQuote := false
	quoteChar := rune(0)

	for _, r := range s {
		if (r == '"' || r == '\'') && !inQuote {
			inQuote = true
			quoteChar = r
		} else if r == quoteChar && inQuote {
			inQuote = false
			quoteChar = 0
		} else if r == ' ' && !inQuote {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(r)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func joinArgs(args []string) string {
	result := ""
	for i, arg := range args {
		if i > 0 {
			result += ","
		}
		result += arg
	}
	return result
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Compact mode command
func cmdCompact(m *model, args string) string {
	args = strings.ToLower(strings.TrimSpace(args))
	
	switch args {
	case "on", "true", "1":
		m.agent.SetCompactMode(true)
		// Notify AI
		m.agent.QueueSystemMessage("[SYSTEM] Compact mode ENABLED. Give brief, concise responses. Avoid verbose explanations unless asked.")
		return "✅ Compact mode enabled - AI will give brief responses"
	case "off", "false", "0":
		m.agent.SetCompactMode(false)
		m.agent.QueueSystemMessage("[SYSTEM] Compact mode DISABLED. You can give detailed responses again.")
		return "✅ Compact mode disabled - AI will give detailed responses"
	case "":
		// Toggle
		if m.agent.IsCompactMode() {
			m.agent.SetCompactMode(false)
			m.agent.QueueSystemMessage("[SYSTEM] Compact mode DISABLED. You can give detailed responses again.")
			return "✅ Compact mode disabled - AI will give detailed responses"
		} else {
			m.agent.SetCompactMode(true)
			m.agent.QueueSystemMessage("[SYSTEM] Compact mode ENABLED. Give brief, concise responses. Avoid verbose explanations unless asked.")
			return "✅ Compact mode enabled - AI will give brief responses"
		}
	default:
		return "Usage: /compact [on|off]\nToggles compact mode for brief AI responses."
	}
}

// Summarize mode command
func cmdSummarize(m *model, args string) string {
	args = strings.ToLower(strings.TrimSpace(args))
	
	switch args {
	case "smart":
		m.agent.SetSummarizeMode(config.SummarizeSmart)
		return "✅ Summarization mode: SMART (uses LLM with large context for intelligent summaries)"
	case "fast":
		m.agent.SetSummarizeMode(config.SummarizeFast)
		return "✅ Summarization mode: FAST (programmatic extraction, saves tokens)"
	case "":
		// Show current mode
		mode := m.agent.GetSummarizeMode()
		if mode == config.SummarizeSmart {
			return "Current summarization mode: SMART (LLM-based)\nUse /summarize fast to switch to token-saving mode."
		}
		return "Current summarization mode: FAST (programmatic)\nUse /summarize smart to switch to LLM-based mode."
	default:
		return "Usage: /summarize <smart|fast>\n  smart - Uses LLM for intelligent summaries (default)\n  fast  - Programmatic extraction (saves tokens)"
	}
}

// Token usage command
func cmdTokens(m *model, args string) string {
	stats := m.agent.GetTokenStats()
	
	return fmt.Sprintf(`📊 Token Usage Statistics

Current Context:
  • Tokens: ~%d / %d (%.1f%% of limit)

Session Totals:
  • Input tokens:  %d
  • Output tokens: %d
  • Total tokens:  %d

Summarization:
  • Times summarized: %d
  • Tokens saved:     ~%d

Note: Token counts are estimates (~3-4 chars per token).`,
		stats.CurrentContext,
		stats.ContextLimit,
		stats.ContextPercentage,
		stats.TotalInputTokens,
		stats.TotalOutputTokens,
		stats.TotalTokens,
		stats.SummaryCount,
		stats.TokensSavedBySummary,
	)
}

// Todos command - shows AI's task list
func cmdTodos(m *model, args string) string {
	todos := tools.GetAITodos()
	if len(todos) == 0 {
		return "📭 No AI tasks yet. The AI creates tasks when planning work."
	}

	var sb strings.Builder
	sb.WriteString("📋 AI TASK LIST\n")
	sb.WriteString("══════════════════════════════════════════════════════\n\n")

	// Status icons
	statusIcons := map[string]string{
		"pending":     "○",
		"in_progress": "◐",
		"completed":   "●",
		"cancelled":   "×",
	}

	priorityLabels := map[string]string{
		"high":   "[HIGH]",
		"medium": "[MED]",
		"low":    "[LOW]",
	}

	pending, inProgress, completed := 0, 0, 0
	for _, todo := range todos {
		icon := statusIcons[todo.Status]
		if icon == "" {
			icon = "○"
		}
		priority := priorityLabels[todo.Priority]
		if priority == "" {
			priority = "[MED]"
		}

		sb.WriteString(fmt.Sprintf(" %s %s #%d: %s\n", icon, priority, todo.ID, todo.Description))

		switch todo.Status {
		case "pending":
			pending++
		case "in_progress":
			inProgress++
		case "completed":
			completed++
		}
	}

	sb.WriteString(fmt.Sprintf("\n══════════════════════════════════════════════════════\n"))
	sb.WriteString(fmt.Sprintf("○ %d pending  ◐ %d active  ● %d done\n", pending, inProgress, completed))

	return sb.String()
}

// Undo command
func cmdUndo(m *model, args string) string {
	cp, err := m.agent.GetCheckpointManager().Undo()
	if err != nil {
		return fmt.Sprintf("❌ Cannot undo: %s", err)
	}
	
	// Notify AI about the undo
	m.agent.QueueSystemMessage(fmt.Sprintf("[SYSTEM] User used /undo to revert: %s", cp.Description))
	
	result := fmt.Sprintf("✅ Undone: %s\n", cp.Description)
	
	switch cp.Type {
	case agent.CheckpointFileEdit, agent.CheckpointFileCreate:
		if cp.FileExisted {
			result += fmt.Sprintf("   Restored: %s", cp.FilePath)
		} else {
			result += fmt.Sprintf("   Deleted: %s (was newly created)", cp.FilePath)
		}
	case agent.CheckpointFileDelete:
		result += fmt.Sprintf("   Restored: %s", cp.FilePath)
	case agent.CheckpointCommand:
		if cp.UndoCommand != "" {
			result += fmt.Sprintf("   Run this to fully undo: %s", cp.UndoCommand)
		}
	}
	
	return result
}

// History command - show checkpoints
func cmdHistory(m *model, args string) string {
	checkpoints := m.agent.GetCheckpointManager().ListUndoable()
	
	if len(checkpoints) == 0 {
		return "No actions to undo. History is empty."
	}
	
	result := fmt.Sprintf("📜 Action History (%d undoable):\n\n", len(checkpoints))
	
	for i, cp := range checkpoints {
		if i >= 10 {
			result += fmt.Sprintf("   ... and %d more\n", len(checkpoints)-10)
			break
		}
		
		typeIcon := "📝"
		switch cp.Type {
		case agent.CheckpointFileEdit:
			typeIcon = "✏️"
		case agent.CheckpointFileCreate:
			typeIcon = "📄"
		case agent.CheckpointFileDelete:
			typeIcon = "🗑️"
		case agent.CheckpointCommand:
			typeIcon = "⚡"
		case agent.CheckpointUserCreate, agent.CheckpointUserDelete, agent.CheckpointUserModify:
			typeIcon = "👤"
		case agent.CheckpointService:
			typeIcon = "⚙️"
		case agent.CheckpointFirewall:
			typeIcon = "🔥"
		case agent.CheckpointManual:
			typeIcon = "📌"
		case agent.CheckpointSession:
			typeIcon = "🚀"
		}
		
		timeAgo := formatTimeAgo(cp.Timestamp)
		result += fmt.Sprintf("  %d. %s %s (%s)\n", i+1, typeIcon, cp.Description, timeAgo)
	}
	
	result += "\nUse /undo to revert the most recent action, or /checkpoints for advanced options."
	return result
}

// Checkpoints command - manage checkpoints with subcommands
func cmdCheckpoints(m *model, args string) string {
	cm := m.agent.GetCheckpointManager()
	
	// Parse subcommand
	parts := strings.Fields(args)
	subCmd := ""
	subArgs := ""
	if len(parts) > 0 {
		subCmd = strings.ToLower(parts[0])
		if len(parts) > 1 {
			subArgs = strings.Join(parts[1:], " ")
		}
	}
	
	switch subCmd {
	case "", "view":
		// Default action: open popup viewer on checkpoints tab
		m.showPopup = true
		m.popupViewer = NewPopupViewer(cm, m.width, m.height, m.styles)
		m.popupViewer.SetTab(PopupTabCheckpoints)
		return "Opening checkpoint viewer..."
		
	case "create":
		desc := subArgs
		if desc == "" {
			desc = "Manual checkpoint"
		}
		node := cm.CreateManualCheckpoint(desc)
		return fmt.Sprintf("✅ Created checkpoint #%d: %s", node.ID, node.TimeLabel)
		
	case "list":
		nodes := cm.ListCheckpoints()
		if len(nodes) == 0 {
			return "No checkpoints yet."
		}
		
		result := fmt.Sprintf("📍 Checkpoints (%d total) [Branch: %s]\n\n", len(nodes), cm.GetCurrentBranch())
		current := cm.GetCurrentCheckpoint()
		
		for _, node := range nodes {
			marker := "  "
			if current != nil && node.ID == current.ID {
				marker = "► "
			}
			
			branchInfo := ""
			if node.BranchName != "main" {
				branchInfo = fmt.Sprintf(" [%s]", node.BranchName)
			}
			
			result += fmt.Sprintf("%s%d. %s%s\n", marker, node.ID, node.TimeLabel, branchInfo)
		}
		return result
		
	case "restore":
		if subArgs == "" {
			return "Usage: /checkpoints restore <id>"
		}
		var id int
		if _, err := fmt.Sscanf(subArgs, "%d", &id); err != nil {
			return fmt.Sprintf("Invalid checkpoint ID: %s", subArgs)
		}
		
		node, newBranch, err := cm.RestoreToCheckpoint(id)
		if err != nil {
			return fmt.Sprintf("❌ Failed to restore: %s", err)
		}
		
		result := fmt.Sprintf("✅ Restored to checkpoint #%d: %s", node.ID, node.Description)
		if newBranch != "" {
			result += fmt.Sprintf("\n   Created new branch: %s", newBranch)
		}
		
		// Notify AI about the restore
		m.agent.QueueSystemMessage(fmt.Sprintf("[SYSTEM] User restored to checkpoint #%d: %s", node.ID, node.Description))
		
		return result
		
	case "edit":
		parts := strings.SplitN(subArgs, " ", 2)
		if len(parts) < 2 {
			return "Usage: /checkpoints edit <id> <new description>"
		}
		
		var id int
		if _, err := fmt.Sscanf(parts[0], "%d", &id); err != nil {
			return fmt.Sprintf("Invalid checkpoint ID: %s", parts[0])
		}
		
		if err := cm.EditCheckpoint(id, parts[1]); err != nil {
			return fmt.Sprintf("❌ Failed to edit: %s", err)
		}
		
		return fmt.Sprintf("✅ Updated checkpoint #%d description", id)
		
	case "delete":
		if subArgs == "" {
			return "Usage: /checkpoints delete <id>"
		}
		var id int
		if _, err := fmt.Sscanf(subArgs, "%d", &id); err != nil {
			return fmt.Sprintf("Invalid checkpoint ID: %s", subArgs)
		}
		
		if err := cm.DeleteCheckpoint(id); err != nil {
			return fmt.Sprintf("❌ Failed to delete: %s", err)
		}
		
		return fmt.Sprintf("✅ Deleted checkpoint #%d", id)
		
	case "branch":
		return fmt.Sprintf("📍 Current branch: %s", cm.GetCurrentBranch())
		
	case "branches":
		branches := cm.ListBranches()
		if len(branches) == 0 {
			return "No branches yet."
		}
		
		result := "🌿 Branches:\n"
		current := cm.GetCurrentBranch()
		for _, branch := range branches {
			marker := "  "
			if branch == current {
				marker = "► "
			}
			result += fmt.Sprintf("%s%s\n", marker, branch)
		}
		return result
		
	case "clear":
		cm.Clear()
		cm.Initialize()
		return "✅ All checkpoints cleared. Started fresh."
		
	default:
		return `Usage: /checkpoints [subcommand]

Subcommands:
  (none)        Open checkpoint viewer
  create [desc] Create a manual checkpoint
  list          List all checkpoints
  restore <id>  Restore to a checkpoint (creates branch if needed)
  edit <id>     Edit checkpoint description
  delete <id>   Delete a checkpoint
  branch        Show current branch
  branches      List all branches
  clear         Clear all checkpoints and start fresh`
	}
}

// Remember command - save to persistent memory
func cmdRemember(m *model, args string) string {
	parts := strings.SplitN(args, " ", 2)
	if len(parts) < 2 {
		return `Usage: /remember <category> <content>

Categories: vulnerability, config, command, finding, tip
Example: /remember vulnerability "SSH allows root login by default on Ubuntu"
Example: /remember command "net user /add creates a new user on Windows"`
	}
	
	category := strings.ToLower(parts[0])
	content := parts[1]
	
	// Get current OS
	osType := m.cfg.OS
	if m.cfg.OSInfo.Name != "" {
		osType = m.cfg.OSInfo.Name
	}
	
	entry := m.agent.GetMemory().Add(category, content, "user", osType)
	
	// Save to disk
	if err := m.agent.SaveMemory(); err != nil {
		return fmt.Sprintf("⚠️ Remembered but failed to save: %s", err)
	}
	
	return fmt.Sprintf("✅ Remembered [%s]: %s\n   ID: %s", category, truncateString(content, 50), entry.ID)
}

// Recall command - search persistent memory
func cmdRecall(m *model, args string) string {
	memory := m.agent.GetMemory()
	
	if memory.Count() == 0 {
		return "No memories saved yet. Use /remember to save information."
	}
	
	var entries []agent.MemoryEntry
	if args == "" {
		// Show all
		entries = memory.Entries
	} else {
		// Search
		entries = memory.Search(args, "", "")
	}
	
	if len(entries) == 0 {
		return fmt.Sprintf("No memories found matching '%s'", args)
	}
	
	result := fmt.Sprintf("🧠 Memories (%d found):\n\n", len(entries))
	for i, mem := range entries {
		if i >= 15 {
			result += fmt.Sprintf("   ... and %d more\n", len(entries)-15)
			break
		}
		result += fmt.Sprintf("  [%s] %s\n    OS: %s | Used: %d times\n\n", 
			mem.Category, truncateString(mem.Content, 60), mem.OS, mem.UsedCount)
	}
	
	return result
}

// Forget command - clear memory
func cmdForget(m *model, args string) string {
	memory := m.agent.GetMemory()
	count := memory.Count()
	
	if count == 0 {
		return "No memories to forget."
	}
	
	memory.Clear()
	if err := m.agent.SaveMemory(); err != nil {
		return fmt.Sprintf("⚠️ Cleared but failed to save: %s", err)
	}
	
	return fmt.Sprintf("🧹 Cleared %d memories from persistent storage.", count)
}

// Check command - check connectivity and API key
func cmdCheck(m *model, _ string) string {
	var result strings.Builder
	result.WriteString("🔍 Connectivity Check\n")
	result.WriteString("─────────────────────\n\n")
	
	// Check internet
	result.WriteString("Internet: ")
	if err := llm.CheckInternet(); err != nil {
		m.internetOK = false
		m.internetErr = err
		result.WriteString("❌ " + err.Error() + "\n")
		result.WriteString("\n⚠️ Cannot check API key without internet connection.")
		return result.String()
	}
	m.internetOK = true
	m.internetErr = nil
	result.WriteString("✅ Connected\n")
	
	// Check API key
	result.WriteString(fmt.Sprintf("Provider: %s\n", m.cfg.Provider))
	result.WriteString("API Key:  ")
	
	if !m.agent.HasAPIKey() {
		result.WriteString("❌ Not configured\n")
		result.WriteString("\n💡 Set your API key with: /key <your-api-key>")
		return result.String()
	}
	
	// Validate API key with a test call
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	result.WriteString("🔄 Validating...")
	
	if err := m.agent.ValidateAPIKey(ctx); err != nil {
		m.apiKeyValidated = false
		m.apiKeyErr = err
		result.WriteString("\r") // Clear the "Validating..." line
		result.WriteString("API Key:  ❌ " + err.Error() + "\n")
		return result.String()
	}
	
	// Update model state - API key validated successfully
	m.apiKeyValidated = true
	m.apiKeyErr = nil
	
	result.WriteString("\r") // Clear the "Validating..." line  
	result.WriteString("API Key:  ✅ Valid\n")
	result.WriteString("\n🚀 Ready to go!")
	
	return result.String()
}

// Helper for time formatting
func formatTimeAgo(t time.Time) string {
	duration := time.Since(t)
	
	if duration < time.Minute {
		return "just now"
	} else if duration < time.Hour {
		mins := int(duration.Minutes())
		if mins == 1 {
			return "1 min ago"
		}
		return fmt.Sprintf("%d mins ago", mins)
	} else if duration < 24*time.Hour {
		hours := int(duration.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	}
	return t.Format("Jan 2 15:04")
}

// Helper to convert checkpoint type to string for display
func checkpointTypeString(ct agent.CheckpointType) string {
	return string(ct)
}

// Display command handlers

func cmdRefresh(m *model, _ string) string {
	m.pendingAction = &PendingAction{
		Type:        ActionRefresh,
		Description: "Redraw screen",
	}
	return "🔄 Refreshing display..."
}

// Sound command handlers

func cmdSound(m *model, args string) string {
	args = strings.ToLower(strings.TrimSpace(args))

	switch args {
	case "on", "true", "1":
		m.cfg.NoSound = false
		return "🔊 Sound effects enabled"
	case "off", "false", "0":
		m.cfg.NoSound = true
		return "🔇 Sound effects disabled"
	case "":
		// Show current status
		if m.cfg.NoSound {
			return "🔇 Sound effects: OFF\nUsage: /sound [on|off]"
		}
		return "🔊 Sound effects: ON\nUsage: /sound [on|off]"
	default:
		return "Usage: /sound [on|off]"
	}
}

func cmdSoundRepeat(m *model, args string) string {
	args = strings.ToLower(strings.TrimSpace(args))

	switch args {
	case "on", "true", "1":
		m.cfg.NoRepeatSound = false
		return "🔔 Repeat sounds enabled (multiple dings for multiple points)"
	case "off", "false", "0":
		m.cfg.NoRepeatSound = true
		return "🔔 Repeat sounds disabled (single ding regardless of points)"
	case "":
		// Show current status
		if m.cfg.NoRepeatSound {
			return "🔔 Repeat sounds: OFF (single ding)\nUsage: /sound-repeat [on|off]"
		}
		return "🔔 Repeat sounds: ON (multiple dings)\nUsage: /sound-repeat [on|off]"
	default:
		return "Usage: /sound-repeat [on|off]"
	}
}

func cmdSoundOfficial(m *model, args string) string {
	args = strings.ToLower(strings.TrimSpace(args))

	switch args {
	case "on", "true", "1":
		m.cfg.OfficialSound = true
		return "🎵 Using official CyberPatriot sound"
	case "off", "false", "0":
		m.cfg.OfficialSound = false
		return "🎵 Using custom IronGuard sound"
	case "":
		// Show current status
		if m.cfg.OfficialSound {
			return "🎵 Sound type: OFFICIAL CyberPatriot\nUsage: /sound-official [on|off]"
		}
		return "🎵 Sound type: CUSTOM IronGuard\nUsage: /sound-official [on|off]"
	default:
		return "Usage: /sound-official [on|off]"
	}
}
