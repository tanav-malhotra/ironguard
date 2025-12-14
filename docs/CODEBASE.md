# IronGuard Codebase Guide

A comprehensive guide for developers exploring or contributing to IronGuard.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Directory Structure](#directory-structure)
3. [Package Reference](#package-reference)
4. [Data Flow](#data-flow)
5. [Key Concepts](#key-concepts)
6. [Adding New Features](#adding-new-features)
7. [Testing](#testing)
8. [Building & Releasing](#building--releasing)

---

## Architecture Overview

IronGuard is a Go application with a layered architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                         TUI Layer                           │
│  (internal/tui) - User interface, commands, rendering       │
├─────────────────────────────────────────────────────────────┤
│                        Agent Layer                          │
│  (internal/agent) - AI orchestration, conversation, tools   │
├─────────────────────────────────────────────────────────────┤
│                        Tools Layer                          │
│  (internal/tools) - File ops, shell, screen, scoring        │
├──────────────────────┬──────────────────────────────────────┤
│     LLM Layer        │         Platform Layer               │
│  (internal/llm)      │  (internal/harden, internal/audio)   │
│  Claude/OpenAI/      │  OS-specific hardening, sound FX     │
│  Gemini providers    │                                      │
└──────────────────────┴──────────────────────────────────────┘
```

### Core Principles

1. **Single Binary**: Everything compiles into one executable (including audio assets)
2. **Provider Agnostic**: Swap between Claude, OpenAI, or Gemini without code changes
3. **Tool-Based AI**: AI interacts with the system through a defined tool registry
4. **Event-Driven TUI**: Bubble Tea framework for reactive terminal UI

---

## Directory Structure

```
ironguard/
├── cmd/ironguard/          # Application entry point
│   ├── main.go             # CLI flags, startup logic
│   ├── admin_windows.go    # Windows admin check
│   └── admin_unix.go       # Unix admin check
│
├── internal/               # Private packages (not importable externally)
│   ├── agent/              # AI agent orchestration
│   │   ├── agent.go        # Main Agent struct, Chat(), tool execution
│   │   ├── prompts.go      # System prompts for different modes
│   │   ├── subagent.go     # Parallel subagent management
│   │   ├── memory.go       # Persistent memory across sessions
│   │   ├── checkpoint.go   # Undo/restore system
│   │   ├── context.go      # Context window management
│   │   ├── tokens.go       # Token usage tracking
│   │   └── timer_adapter.go # Async timer notifications
│   │
│   ├── audio/              # Sound effects system
│   │   ├── sounds.go       # Audio playback (beep library)
│   │   └── assets/         # Embedded MP3/WAV files
│   │
│   ├── config/             # Configuration types
│   │   └── config.go       # Provider, Mode, ScreenMode enums
│   │
│   ├── cracker/            # Scoring engine interception
│   │   ├── cracker.go      # Main Cracker struct, RunStandalone()
│   │   ├── discovery.go    # Find scoring engine process (PID)
│   │   ├── interceptor_linux.go   # Linux strace-based interception
│   │   ├── interceptor_windows.go # Windows PowerShell monitoring
│   │   ├── interceptor_stub.go    # Stub for cross-compilation
│   │   └── output.go       # Format findings for console/AI
│   │
│   ├── harden/             # OS hardening and baseline scripts
│   │   ├── baseline.go     # Interactive baseline configuration
│   │   ├── baseline_linux.go  # Linux hardening implementation
│   │   ├── baseline_windows.go # Windows hardening implementation
│   │   └── harden.go       # Shell execution helpers
│   │
│   ├── llm/                # LLM provider implementations
│   │   ├── provider.go     # Client interface definition
│   │   ├── registry.go     # Provider switching, API key management
│   │   ├── claude.go       # Anthropic Claude implementation
│   │   ├── openai.go       # OpenAI GPT implementation
│   │   └── gemini.go       # Google Gemini implementation
│   │
│   ├── mcp/                # Model Context Protocol (experimental)
│   │   ├── manager.go      # MCP server connections
│   │   ├── client.go       # MCP protocol client
│   │   └── adapter.go      # Bridge MCP tools to agent
│   │
│   ├── tools/              # AI-callable tools
│   │   ├── tools.go        # Tool registry, read_file, write_file, list_dir
│   │   ├── shell_session.go# Persistent shell (PowerShell/bash)
│   │   ├── desktop_control.go # Mouse, keyboard automation
│   │   ├── screenshot.go   # Screen capture
│   │   ├── scoring.go      # CyberPatriot score reading
│   │   ├── harden_tools.go # Hardening-specific tools
│   │   ├── memory_tools.go # AI memory tools (remember, recall)
│   │   ├── ai_todos.go     # AI task tracking tools
│   │   ├── manual_tasks.go # Human task assignment
│   │   ├── subagent_tools.go # Spawn/manage subagents
│   │   ├── timing.go       # Wait and async timer tools
│   │   ├── software.go     # Software listing and removal tools
│   │   └── web.go          # Web search tool
│   │
│   └── tui/                # Terminal UI (Bubble Tea)
│       ├── root.go         # Main model, Update(), View()
│       ├── commands.go     # Slash command registry (/help, /harden, etc.)
│       ├── messages.go     # Message types (user, AI, system, tool)
│       ├── theme.go        # Colors and styles
│       ├── manual_tasks.go # Sidebar task manager
│       └── diff.go         # File diff rendering (unused currently)
│
├── docs/                   # Documentation
│   ├── FEATURES.md         # Feature specification
│   ├── CODE_SIGNING.md     # Code signing guide
│   └── CODEBASE.md         # This file
│
├── cpscripts/              # Legacy PowerShell/Bash scripts
├── cyberpatriot-lists/     # Training data (PDFs, answer keys)
│
├── go.mod                  # Go module definition
├── go.sum                  # Dependency checksums
├── README.md               # User-facing documentation
├── LICENSE                 # MIT License
└── checklist.md            # Competition checklist
```

---

## Package Reference

### `cmd/ironguard`

**Purpose**: Application entry point

**Key files**:
- `main.go` - Parses flags, creates config, starts TUI
- `admin_*.go` - Platform-specific privilege checks

**Important functions**:
```go
func main()                    // Entry point
func checkAdminPrivileges()    // Ensures running as admin/root
```

---

### `internal/agent`

**Purpose**: Core AI orchestration

**Key types**:

```go
// Agent manages conversation with LLM and tool execution
type Agent struct {
    cfg           *config.Config
    llmRegistry   *llm.Registry
    toolRegistry  *tools.Registry
    history       []llm.Message      // Conversation history
    memory        *Memory            // Persistent memory
    checkpoints   *CheckpointManager // Undo system
    tokenUsage    *TokenUsage        // Usage tracking
    subAgentMgr   *SubAgentManager   // Parallel agents
    eventChan     chan Event         // TUI communication
}

// Event types sent to TUI
const (
    EventStreamStart    // AI started responding
    EventStreamDelta    // Streaming token received
    EventStreamEnd      // AI finished responding
    EventToolCall       // Tool being executed
    EventToolResult     // Tool execution complete
    EventError          // Error occurred
    EventScoreUpdate    // Score changed
    EventStatusUpdate   // Status message
)
```

**Key methods**:
```go
func (a *Agent) Chat(ctx, userMessage) error  // Main conversation loop
func (a *Agent) executeTool(name, args)       // Run a tool
func (a *Agent) buildSystemPrompt() string    // Generate context-aware prompt
func (a *Agent) summarizeContextIfNeeded()    // Auto-compress history
```

**Files breakdown**:
| File | Purpose |
|------|---------|
| `agent.go` | Main agent logic, Chat loop, tool execution |
| `prompts.go` | System prompts for Windows, Linux, Cisco modes |
| `subagent.go` | Parallel subagent spawning and management |
| `memory.go` | Persistent memory store (JSON file) |
| `checkpoint.go` | Save/restore points for undo |
| `context.go` | Context window size management |
| `tokens.go` | Token counting and usage stats |
| `timer_adapter.go` | Async timer notifications |

---

### `internal/llm`

**Purpose**: LLM provider abstraction

**Key interface**:
```go
type Client interface {
    Chat(ctx, ChatRequest) (*ChatResponse, error)
    ChatStream(ctx, ChatRequest, callback) error
    Provider() Provider
    Models() []string
    SetAPIKey(key string)
    HasAPIKey() bool
    ValidateAPIKey(ctx) error
}
```

**Implementations**:
- `claude.go` - Anthropic Claude (Opus 4.5)
- `openai.go` - OpenAI GPT (GPT-5.1, Codex-Max)
- `gemini.go` - Google Gemini (Gemini 3 Pro)

**Registry** (`registry.go`):
```go
type Registry struct {
    clients  map[Provider]Client
    current  Provider
}

func (r *Registry) Current() Client      // Get active provider
func (r *Registry) SetCurrent(p)         // Switch provider
func (r *Registry) CheckInternet() error // Connectivity check
```

---

### `internal/tools`

**Purpose**: AI-callable tool implementations

**Tool Registry** (`tools.go`):
```go
type Registry struct {
    tools map[string]Tool
}

type Tool struct {
    Name        string
    Description string
    Parameters  json.RawMessage  // JSON Schema
    Handler     ToolHandler
    IsMutating  bool             // Triggers checkpoint
}

type ToolHandler func(ctx, args) (string, error)
```

**Core tools**:
| Tool | File | Purpose |
|------|------|---------|
| `read_file` | tools.go | Read file (with condensation for large files) |
| `write_file` | tools.go | Write/create files |
| `list_dir` | tools.go | Directory listing |
| `run_command` | shell_session.go | Execute shell commands |
| `get_shell_cwd` | shell_session.go | Get current directory |
| `new_shell_session` | shell_session.go | Reset shell |
| `take_screenshot` | screenshot.go | Capture screen |
| `mouse_click` | desktop_control.go | Click at coordinates |
| `mouse_move` | desktop_control.go | Move cursor |
| `keyboard_type` | desktop_control.go | Type text |
| `keyboard_hotkey` | desktop_control.go | Press key combo |
| `read_score_report` | scoring.go | Parse CyberPatriot score |
| `spawn_subagent` | subagent_tools.go | Create parallel agent |
| `remember` | memory_tools.go | Store persistent memory |
| `recall` | memory_tools.go | Retrieve memories |
| `web_search` | web.go | Search the internet |
| `wait` | timing.go | Block and wait for X seconds |
| `set_timer` | timing.go | Set async timer with notification |
| `list_timers` | timing.go | List active timers |
| `cancel_timer` | timing.go | Cancel an active timer |
| `list_installed_software` | software.go | List all installed packages |
| `remove_software` | software.go | Remove/uninstall a package |
| `search_prohibited_software` | software.go | Search for prohibited software by category |

**Shell Session** (`shell_session.go`):
```go
// Maintains persistent PowerShell/bash process
type shellSession struct {
    cmd     *exec.Cmd
    stdin   io.WriteCloser
    stdout  io.ReadCloser
    cwd     string
    mu      sync.Mutex
}

func (s *shellSession) Run(command string) (output string, err error)
func (s *shellSession) GetCwd() string
func (s *shellSession) Reset() error
```

---

### `internal/tui`

**Purpose**: Terminal user interface (Bubble Tea)

**Main model** (`root.go`):
```go
type model struct {
    cfg           config.Config
    messages      []Message        // Chat history
    input         textinput.Model  // Input field
    agent         *agent.Agent
    agentBusy     bool
    cmdRegistry   *CommandRegistry
    manualTasks   *ManualTaskManager
    // ... more fields
}

func (m model) Init() tea.Cmd      // Setup
func (m model) Update(msg) (model, tea.Cmd)  // Handle events
func (m model) View() string       // Render UI
```

**Commands** (`commands.go`):
```go
type SlashCommand struct {
    Name        string
    Description string
    Args        string           // e.g., "<api-key>"
    ArgOptions  []string         // Autocomplete options
    Handler     func(*model, string) string
}

// Example commands:
// /help, /harden, /stop, /key, /check, /provider, /model,
// /confirm, /autopilot, /screen, /score, /status, /quit,
// /remember, /recall, /forget, /undo, /history, /compact, etc.
```

**Message types** (`messages.go`):
```go
type Role string
const (
    RoleUser      Role = "user"
    RoleAssistant Role = "assistant"
    RoleSystem    Role = "system"
    RoleTool      Role = "tool"
)

type Message struct {
    Role      Role
    Content   string
    ToolCalls []ToolCallDisplay  // For AI tool calls
    Timestamp time.Time
}
```

---

### `internal/audio`

**Purpose**: Sound effects

```go
//go:embed assets/max_points_achieved.mp3
var maxPointsAchievedMP3 []byte

//go:embed assets/points_gained.mp3
var pointsGainedMP3 []byte

//go:embed assets/gain.wav
var officialGainWAV []byte

func SetOptions(noSound, noRepeat, official bool)
func Init() error
func PlayPointsGained()
func PlayPointsGainedMultiple(count int)
func PlayMaxPointsAchieved()
```

---

### `internal/config`

**Purpose**: Configuration types and defaults

```go
type Config struct {
    Provider        Provider        // claude, openai, gemini
    Model           string          // Model name override
    Mode            Mode            // confirm, autopilot
    ScreenMode      ScreenMode      // observe, control
    CompetitionMode CompetitionMode // harden, cisco
    OSType          OSType          // Detected OS
    NoSound         bool
    NoRepeatSound   bool
    OfficialSound   bool
}

func DefaultConfig() Config
func DetectOS() OSType
```

---

## Data Flow

### User Message Flow

```
User types message
        │
        ▼
┌───────────────┐
│  TUI (root.go)│
│  handleKeyMsg │
└───────┬───────┘
        │ startChat()
        ▼
┌───────────────┐
│ Agent.Chat()  │──────────────────┐
└───────┬───────┘                  │
        │ buildSystemPrompt()      │
        ▼                          │
┌───────────────┐                  │
│ LLM.ChatStream│                  │
│ (claude.go)   │                  │
└───────┬───────┘                  │
        │ StreamDelta              │
        ▼                          │
┌───────────────┐                  │
│ Parse response│                  │
│ Tool calls?   │──Yes──┐          │
└───────┬───────┘       │          │
        │No             ▼          │
        │      ┌────────────────┐  │
        │      │ executeTool()  │  │
        │      │ (tools.go)     │  │
        │      └───────┬────────┘  │
        │              │ result    │
        │              ▼           │
        │      ┌────────────────┐  │
        │      │ Append to      │  │
        │      │ history, loop  │──┘
        │      └────────────────┘
        ▼
┌───────────────┐
│ Send Event to │
│ TUI eventChan │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ TUI Update()  │
│ Re-render     │
└───────────────┘
```

### Tool Execution Flow

```
Agent receives tool_call from LLM
        │
        ▼
┌─────────────────────┐
│ toolRegistry.Get()  │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ tool.IsMutating?    │──Yes──▶ Create checkpoint
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ tool.Handler(args)  │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Return result string│
│ to LLM context      │
└─────────────────────┘
```

---

## Key Concepts

### 1. Persistent Shell Session

Unlike typical tool implementations that spawn a new shell per command, IronGuard maintains a **persistent shell process**:

```go
// shell_session.go
type shellSession struct {
    cmd   *exec.Cmd      // Long-running PowerShell/bash
    stdin io.WriteCloser // Send commands
    stdout io.ReadCloser // Read output
    cwd   string         // Track current directory
}
```

This allows:
- `cd` commands that persist
- Environment variables that persist
- Faster command execution (no process spawn overhead)

### 2. Context Management

The agent automatically summarizes old messages when approaching token limits:

```go
// context.go
func (a *Agent) summarizeContextIfNeeded() {
    usage := a.estimateTokenUsage()
    limit := a.getContextLimit()
    
    if float64(usage)/float64(limit) > 0.9 {
        // Keep 40% recent, summarize 60% old
        a.summarizeOldMessages()
    }
}
```

### 3. Checkpoint System

Before any mutating tool (write_file, run_command), a checkpoint is created:

```go
// checkpoint.go
type Checkpoint struct {
    ID        string
    Timestamp time.Time
    Type      CheckpointType
    State     CheckpointState  // File backups, memory snapshot
}

func (m *CheckpointManager) CreateCheckpoint(type) *Checkpoint
func (m *CheckpointManager) Restore(id string) error
```

### 4. Event-Driven Communication

Agent and TUI communicate via channels:

```go
// agent.go
type Event struct {
    Type       EventType
    Content    string
    ToolName   string
    ToolArgs   string
    ToolResult string
    Error      error
    // Score fields for EventScoreUpdate
    TotalScore int
    MaxScore   int
    VulnsFound int
    VulnsTotal int
}

// TUI listens
func (m model) listenToAgent() tea.Cmd {
    return func() tea.Msg {
        event := <-m.agent.Events()
        return AgentEventMsg{Event: event}
    }
}
```

### 5. Screen Control Modes

Two modes for desktop interaction:

- **Observe**: AI can take screenshots but NOT control mouse/keyboard
- **Control**: AI has full mouse/keyboard access

```go
// screen_mode.go
var currentScreenMode = config.ScreenModeObserve

func SetScreenMode(mode config.ScreenMode)
func ScreenModeError() string  // Returns error if control not enabled
```

---

## Adding New Features

### Adding a New Tool

1. **Define the tool** in `internal/tools/tools.go` or a new file:

```go
func init() {
    // In the appropriate file's init() or RegisterTools()
}

func toolMyNewTool(ctx context.Context, args json.RawMessage) (string, error) {
    var params struct {
        Param1 string `json:"param1"`
        Param2 int    `json:"param2,omitempty"`
    }
    if err := json.Unmarshal(args, &params); err != nil {
        return "", err
    }
    
    // Implementation
    result := doSomething(params.Param1, params.Param2)
    
    return result, nil
}
```

2. **Register the tool** in `RegisterTools()`:

```go
r.Register(Tool{
    Name:        "my_new_tool",
    Description: "Does something useful",
    Parameters: json.RawMessage(`{
        "type": "object",
        "properties": {
            "param1": {"type": "string", "description": "First parameter"},
            "param2": {"type": "integer", "description": "Optional second param"}
        },
        "required": ["param1"]
    }`),
    Handler:    toolMyNewTool,
    IsMutating: false,  // true if it changes system state
})
```

3. **Update prompts** in `internal/agent/prompts.go` if AI needs guidance on when to use it.

### Adding a New Slash Command

1. **Add to command list** in `internal/tui/commands.go`:

```go
{
    Name:        "mycommand",
    Description: "Does something for the user",
    Args:        "<arg1> [arg2]",  // Optional
    ArgOptions:  []string{"option1", "option2"},  // For autocomplete
    Handler:     cmdMyCommand,
},
```

2. **Implement handler**:

```go
func cmdMyCommand(m *model, args string) string {
    if args == "" {
        return "Usage: /mycommand <arg1>"
    }
    
    // Do something
    m.someField = args
    
    // Optionally notify AI
    m.agent.QueueSystemMessage("[SYSTEM] User changed something to: " + args)
    
    return "Command executed successfully"
}
```

### Adding a New LLM Provider

1. **Create provider file** `internal/llm/newprovider.go`:

```go
type NewProviderClient struct {
    apiKey string
    model  string
}

func NewNewProviderClient() *NewProviderClient {
    return &NewProviderClient{model: "default-model"}
}

func (c *NewProviderClient) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
    // Implementation
}

func (c *NewProviderClient) ChatStream(ctx context.Context, req ChatRequest, cb func(StreamDelta)) error {
    // Implementation
}

// ... implement rest of Client interface
```

2. **Register in registry** `internal/llm/registry.go`:

```go
func NewRegistry() *Registry {
    return &Registry{
        clients: map[Provider]Client{
            ProviderClaude:      NewClaudeClient(),
            ProviderOpenAI:      NewOpenAIClient(),
            ProviderGemini:      NewGeminiClient(),
            ProviderNewProvider: NewNewProviderClient(),  // Add here
        },
        current: ProviderClaude,
    }
}
```

3. **Add to config** `internal/config/config.go`:

```go
const (
    ProviderClaude      Provider = "claude"
    ProviderOpenAI      Provider = "openai"
    ProviderGemini      Provider = "gemini"
    ProviderNewProvider Provider = "newprovider"  // Add here
)
```

---

## Testing

### Running Tests

```bash
# All tests
go test ./...

# Verbose
go test -v ./...

# Specific package
go test -v ./internal/tools/...

# With coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Test Files

| Package | Test File | Coverage |
|---------|-----------|----------|
| agent | agent_test.go | Agent creation, busy state |
| config | config_test.go | Default config, provider parsing |
| llm | provider_test.go | Model presets, registry |
| tools | tools_test.go | File ops, list_dir |
| tools | shell_session_test.go | Shell persistence, cd commands |

### Writing Tests

```go
func TestMyNewFeature(t *testing.T) {
    // Setup
    tmpDir := t.TempDir()
    
    // Execute
    result, err := MyFunction(tmpDir)
    
    // Assert
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if result != expected {
        t.Errorf("got %v, want %v", result, expected)
    }
}
```

---

## Building & Releasing

### Local Build

```bash
# Windows
$env:GOOS="windows"; $env:GOARCH="amd64"
go build -o ironguard.exe ./cmd/ironguard

# Linux
GOOS=linux GOARCH=amd64 go build -o ironguard ./cmd/ironguard
```

### Release Build (with version)

```bash
go build -ldflags="-s -w -X main.version=v0.5.5" -o ironguard.exe ./cmd/ironguard
```

### CI/CD (GitHub Actions)

Releases are triggered on tags:

```bash
git tag v0.5.5
git push origin v0.5.5
```

The workflow (`.github/workflows/build.yml`):
1. Runs tests on Windows and Linux
2. Builds binaries for both platforms
3. Creates GitHub release with attached binaries

### Requirements

- **Windows**: No CGO needed
- **Linux**: CGO required for audio (`libasound2-dev`)

---

## Quick Reference

### Common Modifications

| Task | Files to Modify |
|------|-----------------|
| Add new tool | `internal/tools/*.go`, `internal/agent/prompts.go` |
| Add slash command | `internal/tui/commands.go` |
| Change AI behavior | `internal/agent/prompts.go` |
| Add LLM provider | `internal/llm/`, `internal/config/config.go` |
| Modify UI layout | `internal/tui/root.go`, `internal/tui/theme.go` |
| Add sound effect | `internal/audio/sounds.go`, `internal/audio/assets/` |
| Change default config | `internal/config/config.go` |

### Important Constants

| Constant | Location | Purpose |
|----------|----------|---------|
| Context limits | `agent/context.go` | Token limits per provider |
| Default models | `llm/*.go` | Default model per provider |
| Tool schemas | `tools/tools.go` | JSON schemas for tools |
| Theme colors | `tui/theme.go` | UI color palette |

---

## Getting Help

- **README.md** - User documentation
- **docs/FEATURES.md** - Feature specification
- **Issues** - GitHub issue tracker

Happy hacking! 🛡️

