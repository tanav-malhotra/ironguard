package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tanav-malhotra/ironguard/internal/config"
	"github.com/tanav-malhotra/ironguard/internal/llm"
	"github.com/tanav-malhotra/ironguard/internal/tools"
)

// Event types for TUI communication
type EventType int

const (
	EventStreamStart EventType = iota
	EventStreamDelta
	EventStreamEnd
	EventToolCall
	EventToolResult
	EventConfirmRequired
	EventError
	EventStatusUpdate
)

// Event is sent from the agent to the TUI.
type Event struct {
	Type    EventType
	Content string
	Tool    *ToolCallInfo
	Error   error
}

// ToolCallInfo contains information about a tool call.
type ToolCallInfo struct {
	ID          string
	Name        string
	Arguments   string
	Output      string
	Error       string
	NeedsConfirm bool
}

// ConfirmResponse is sent from TUI to agent for confirmation.
type ConfirmResponse struct {
	Approved bool
	ToolID   string
}

// Agent manages the conversation with the LLM and tool execution.
type Agent struct {
	cfg         *config.Config
	llmRegistry *llm.Registry
	toolRegistry *tools.Registry

	// Conversation state
	messages []llm.Message
	mu       sync.Mutex

	// Communication channels
	events   chan Event
	confirms chan ConfirmResponse
	cancel   context.CancelFunc

	// State
	busy       bool
	busyMu     sync.Mutex
	currentCtx context.Context

	// Autonomous mode
	autonomousMode bool
	targetScore    int
	currentScore   int
}

// New creates a new agent.
func New(cfg *config.Config) *Agent {
	return &Agent{
		cfg:          cfg,
		llmRegistry:  llm.NewRegistry(),
		toolRegistry: tools.NewRegistry(),
		events:       make(chan Event, 100),
		confirms:     make(chan ConfirmResponse, 10),
	}
}

// Events returns the event channel for TUI to listen on.
func (a *Agent) Events() <-chan Event {
	return a.events
}

// Confirm sends a confirmation response to the agent.
func (a *Agent) Confirm(resp ConfirmResponse) {
	select {
	case a.confirms <- resp:
	default:
	}
}

// IsBusy returns whether the agent is currently processing.
func (a *Agent) IsBusy() bool {
	a.busyMu.Lock()
	defer a.busyMu.Unlock()
	return a.busy
}

// SetAPIKey sets the API key for a provider.
func (a *Agent) SetAPIKey(provider string, key string) error {
	return a.llmRegistry.SetAPIKey(llm.Provider(provider), key)
}

// SetProvider sets the current provider.
func (a *Agent) SetProvider(provider string) error {
	return a.llmRegistry.SetCurrent(llm.Provider(provider))
}

// Cancel cancels the current operation.
func (a *Agent) Cancel() {
	if a.cancel != nil {
		a.cancel()
	}
}

// Chat sends a user message and processes the response.
func (a *Agent) Chat(ctx context.Context, userMessage string) {
	a.busyMu.Lock()
	if a.busy {
		a.busyMu.Unlock()
		a.events <- Event{Type: EventError, Error: fmt.Errorf("agent is busy")}
		return
	}
	a.busy = true
	a.busyMu.Unlock()

	defer func() {
		a.busyMu.Lock()
		a.busy = false
		a.busyMu.Unlock()
	}()

	// Create cancellable context
	ctx, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	a.currentCtx = ctx
	defer cancel()

	// Add user message
	a.mu.Lock()
	a.messages = append(a.messages, llm.Message{
		Role:    "user",
		Content: userMessage,
	})
	a.mu.Unlock()

	// Process conversation loop
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		response, err := a.callLLM(ctx)
		if err != nil {
			a.events <- Event{Type: EventError, Error: err}
			return
		}

		// Add assistant response to history
		a.mu.Lock()
		assistantMsg := llm.Message{
			Role:      "assistant",
			Content:   response.Content,
			ToolCalls: response.ToolCalls,
		}
		a.messages = append(a.messages, assistantMsg)
		a.mu.Unlock()

		// If no tool calls, we're done
		if len(response.ToolCalls) == 0 {
			a.events <- Event{Type: EventStreamEnd}
			return
		}

		// Process tool calls
		for _, tc := range response.ToolCalls {
			select {
			case <-ctx.Done():
				return
			default:
			}

			toolInfo := &ToolCallInfo{
				ID:        tc.ID,
				Name:      tc.Name,
				Arguments: string(tc.Arguments),
			}

			// Check if confirmation is needed
			needsConfirm := a.cfg.Mode == config.ModeConfirm && a.toolRegistry.IsMutating(tc.Name)
			toolInfo.NeedsConfirm = needsConfirm

			a.events <- Event{Type: EventToolCall, Tool: toolInfo}

			// Wait for confirmation if needed
			if needsConfirm {
				a.events <- Event{Type: EventConfirmRequired, Tool: toolInfo}

				select {
				case <-ctx.Done():
					return
				case resp := <-a.confirms:
					if !resp.Approved {
						toolInfo.Output = "User declined to execute this action"
						a.events <- Event{Type: EventToolResult, Tool: toolInfo}

						// Add tool result to messages
						a.mu.Lock()
						a.messages = append(a.messages, llm.Message{
							Role:       "tool",
							Content:    toolInfo.Output,
							ToolCallID: tc.ID,
							Name:       tc.Name,
						})
						a.mu.Unlock()
						continue
					}
				}
			}

			// Execute tool
			a.events <- Event{Type: EventStatusUpdate, Content: fmt.Sprintf("Running %s...", tc.Name)}

			output, err := a.toolRegistry.Execute(ctx, tc.Name, tc.Arguments)
			if err != nil {
				toolInfo.Error = err.Error()
				output = fmt.Sprintf("Error: %s", err.Error())
			}
			toolInfo.Output = output

			a.events <- Event{Type: EventToolResult, Tool: toolInfo}

			// Add tool result to messages
			a.mu.Lock()
			a.messages = append(a.messages, llm.Message{
				Role:       "tool",
				Content:    output,
				ToolCallID: tc.ID,
				Name:       tc.Name,
			})
			a.mu.Unlock()
		}

		// Continue the loop to get the next response
	}
}

func (a *Agent) callLLM(ctx context.Context) (*llm.ChatResponse, error) {
	client := a.llmRegistry.Current()

	// Build tool definitions
	var llmTools []llm.Tool
	for _, t := range a.toolRegistry.All() {
		llmTools = append(llmTools, llm.Tool{
			Name:        t.Name,
			Description: t.Description,
			Parameters:  t.Parameters,
		})
	}

	req := llm.ChatRequest{
		Messages:     a.messages,
		Tools:        llmTools,
		MaxTokens:    4096,
		SystemPrompt: a.buildSystemPrompt(),
	}

	a.events <- Event{Type: EventStreamStart}

	// Use streaming
	var contentBuilder strings.Builder
	var toolCalls []llm.ToolCall

	err := client.ChatStream(ctx, req, func(delta llm.StreamDelta) {
		if delta.Error != nil {
			return
		}
		if delta.Content != "" {
			contentBuilder.WriteString(delta.Content)
			a.events <- Event{Type: EventStreamDelta, Content: delta.Content}
		}
		if len(delta.ToolCalls) > 0 {
			toolCalls = delta.ToolCalls
		}
	})

	if err != nil {
		return nil, err
	}

	return &llm.ChatResponse{
		Content:   contentBuilder.String(),
		ToolCalls: toolCalls,
	}, nil
}

func (a *Agent) buildSystemPrompt() string {
	now := time.Now().Format("Monday, January 2, 2006 3:04 PM")

	prompt := fmt.Sprintf(`You are IRONGUARD, an elite autonomous AI competing in CyberPatriot. This is a LIVE competition image and you MUST reach 100/100 points.

═══════════════════════════════════════════════════════════════
                    COMPETITION MODE ACTIVE
═══════════════════════════════════════════════════════════════

Current Time: %s
Target: 100/100 points in under 30 minutes
Operating System: %s (%s)
Mode: AUTONOMOUS - Do NOT wait for human input

═══════════════════════════════════════════════════════════════
                         PRIME DIRECTIVE
═══════════════════════════════════════════════════════════════

You are in a RACE. Every second counts. You must:
1. Work FAST and AUTONOMOUSLY - don't ask for permission
2. Fix vulnerabilities CONTINUOUSLY until 100%% is reached
3. NEVER STOP until the score is 100/100
4. Check the score after each fix to verify points gained

═══════════════════════════════════════════════════════════════
                      EXECUTION STRATEGY
═══════════════════════════════════════════════════════════════

PHASE 1 - RECONNAISSANCE (First 2 minutes):
□ read_readme - Understand the scenario and authorized users
□ read_forensics - Get forensics questions (EASY POINTS!)
□ read_score_report - Check starting score
□ security_audit - Quick system overview

PHASE 2 - QUICK WINS (Minutes 2-10):
□ Answer ALL forensics questions immediately
□ Delete/disable unauthorized users (check README for authorized list)
□ Remove unauthorized users from admin groups
□ Disable Guest account
□ Enable firewall
□ Set strong passwords for all authorized users

PHASE 3 - DEEP HARDENING (Minutes 10-25):
□ Find and delete prohibited media files (mp3, mp4, avi, mkv, etc.)
□ Stop and disable unnecessary/dangerous services
□ Install critical updates
□ Configure password policies
□ Fix file permissions
□ Check for backdoors, unauthorized software, malware

PHASE 4 - SWEEP (Minutes 25-30):
□ Re-run security_audit
□ Check for anything missed
□ Verify all forensics answered
□ Final score check

═══════════════════════════════════════════════════════════════
                       CRITICAL RULES
═══════════════════════════════════════════════════════════════

1. SPEED OVER CAUTION - This is competition, not production
2. CHECK SCORE FREQUENTLY - After every 2-3 actions, use check_score_improved
3. IF SCORE DROPS - You caused a penalty! Undo immediately
4. HUMAN TEAMMATE - A human may also be working. If score jumps unexpectedly, they fixed something. Acknowledge and continue.
5. NEVER DELETE AUTHORIZED USERS - Read the README carefully!
6. FORENSICS = FREE POINTS - Answer them FIRST

═══════════════════════════════════════════════════════════════
                    COMMON VULNERABILITIES
═══════════════════════════════════════════════════════════════

USERS:
- Unauthorized users exist (DELETE them)
- Authorized users in admin group who shouldn't be (REMOVE from admins)
- Unauthorized users in admin group (DELETE user entirely)
- Weak/blank passwords (SET strong passwords)
- Guest account enabled (DISABLE it)

SERVICES (stop and disable these if running):
- telnet, ftp, tftp (insecure remote access)
- apache2, nginx, httpd (web servers unless needed)
- mysql, postgresql (databases unless needed)
- sshd with root login enabled
- Remote Desktop with weak settings

FILES:
- Media files in user directories (mp3, mp4, avi, mkv, wav, flac)
- Hacking tools
- Games
- Unauthorized software

SETTINGS:
- Firewall disabled
- Automatic updates disabled
- Password policy too weak
- Account lockout not configured

═══════════════════════════════════════════════════════════════

NOW BEGIN. Read the README first, then GO FAST. Do not stop until 100/100.
`, now, a.cfg.OS, a.cfg.Architecture)

	return prompt
}

// ClearHistory clears the conversation history.
func (a *Agent) ClearHistory() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.messages = nil
}

// StartAutonomous starts the agent in autonomous mode, working until target score is reached.
func (a *Agent) StartAutonomous(ctx context.Context, targetScore int) {
	a.autonomousMode = true
	a.targetScore = targetScore

	// Initial prompt for autonomous hardening
	initialPrompt := fmt.Sprintf(`🚀 AUTONOMOUS MODE ACTIVATED - TARGET: %d/100 POINTS

You are now in full autonomous competition mode. Work continuously until the target is reached.

IMMEDIATE ACTIONS (do these NOW, in order):
1. read_readme - Understand the scenario, authorized users, required services, and restrictions
2. read_score_report - Check current score (remember this number!)
3. read_forensics - Get all forensics questions

THEN EXECUTE THIS LOOP:
1. Answer forensics questions (EASY POINTS - do these first!)
2. Fix user issues (unauthorized users, admin group, passwords)
3. Enable firewall
4. Disable unnecessary services
5. Remove prohibited files
6. Check score with check_score_improved
7. If score < %d, continue fixing more issues
8. If score dropped (penalty!), investigate and undo last action
9. REPEAT until score >= %d

REMEMBER:
- Check the README before ANY destructive action
- The human teammate may also be working - if score jumps unexpectedly, acknowledge it
- NEVER STOP until target is reached
- Use web_search if you're unsure how to fix something
- Add manual tasks to sidebar for GUI-only items

START NOW. Read the README first.`, targetScore, targetScore, targetScore)

	go a.runAutonomousLoop(ctx, initialPrompt)
}

// runAutonomousLoop runs the autonomous mode loop with score tracking.
func (a *Agent) runAutonomousLoop(ctx context.Context, initialPrompt string) {
	// Start with initial prompt
	a.Chat(ctx, initialPrompt)

	// The agent will continue working through tool calls
	// The loop continues as long as autonomousMode is true
	// Score checking is handled by the AI through check_score_improved tool
}

// StopAutonomous stops autonomous mode.
func (a *Agent) StopAutonomous() {
	a.autonomousMode = false
	if a.cancel != nil {
		a.cancel()
	}
}

// IsAutonomous returns whether the agent is in autonomous mode.
func (a *Agent) IsAutonomous() bool {
	return a.autonomousMode
}

// GetHistory returns the current conversation history.
func (a *Agent) GetHistory() []llm.Message {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]llm.Message{}, a.messages...)
}

// ExecuteTool directly executes a tool (for slash commands).
func (a *Agent) ExecuteTool(ctx context.Context, name string, args map[string]interface{}) (string, error) {
	argsJSON, err := json.Marshal(args)
	if err != nil {
		return "", err
	}
	return a.toolRegistry.Execute(ctx, name, argsJSON)
}

