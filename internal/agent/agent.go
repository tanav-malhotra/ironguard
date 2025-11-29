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
	EventThinking        // AI is showing its reasoning
	EventSubAgentSpawned // A subagent was spawned
	EventSubAgentUpdate  // Subagent status changed
	EventScoreUpdate     // Score changed
)

// Event is sent from the agent to the TUI.
type Event struct {
	Type     EventType
	Content  string
	Tool     *ToolCallInfo
	Error    error
	Thinking string       // For EventThinking
	SubAgent *SubAgentInfo // For EventSubAgentSpawned/Update
	Score    int          // For EventScoreUpdate
}

// SubAgentInfo contains information about a subagent for events.
type SubAgentInfo struct {
	ID          string
	Task        string
	Status      string
	Result      string
	CurrentStep string
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

	// Subagent management
	subAgentManager *SubAgentManager
}

// New creates a new agent.
func New(cfg *config.Config) *Agent {
	llmReg := llm.NewRegistry()
	toolReg := tools.NewRegistry()
	
	a := &Agent{
		cfg:          cfg,
		llmRegistry:  llmReg,
		toolRegistry: toolReg,
		events:       make(chan Event, 100),
		confirms:     make(chan ConfirmResponse, 10),
	}
	
	// Initialize subagent manager
	a.subAgentManager = NewSubAgentManager(llmReg, toolReg)
	
	// Register subagent manager with tools package
	adapter := NewSubAgentManagerAdapter(a.subAgentManager)
	tools.SetSubAgentManager(adapter)
	
	return a
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

// SubAgentSummary is a simplified view of a subagent for the TUI.
type SubAgentSummary struct {
	ID          string
	Status      string
	CurrentStep string
	Task        string
}

// GetSubAgents returns summaries of all subagents.
func (a *Agent) GetSubAgents() []SubAgentSummary {
	if a.subAgentManager == nil {
		return nil
	}
	
	subAgents := a.subAgentManager.ListSubAgents()
	summaries := make([]SubAgentSummary, len(subAgents))
	for i, sa := range subAgents {
		result := sa.ToResult()
		summaries[i] = SubAgentSummary{
			ID:          result.ID,
			Status:      result.Status,
			CurrentStep: result.CurrentStep,
			Task:        result.Task,
		}
	}
	return summaries
}

// SetMaxSubAgents sets the maximum number of concurrent subagents.
func (a *Agent) SetMaxSubAgents(max int) {
	if a.subAgentManager != nil {
		a.subAgentManager.SetMaxAgents(max)
	}
}

// GetMaxSubAgents returns the current maximum number of concurrent subagents.
func (a *Agent) GetMaxSubAgents() int {
	if a.subAgentManager == nil {
		return 4 // default
	}
	return a.subAgentManager.GetMaxAgents()
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

// SetMCPManager sets the MCP manager for external tool support.
func (a *Agent) SetMCPManager(m tools.MCPManager) {
	a.toolRegistry.SetMCPManager(m)
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

// Context management constants
const (
	// Approximate token limit before we summarize (conservative to leave room)
	contextTokenLimit = 150000
	// Chars per token estimate (conservative)
	charsPerToken = 3
	// Number of recent messages to always keep
	recentMessagesToKeep = 10
)

// estimateTokens gives a rough estimate of tokens in the message history.
func (a *Agent) estimateTokens() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	totalChars := 0
	for _, msg := range a.messages {
		totalChars += len(msg.Content)
		for _, tc := range msg.ToolCalls {
			totalChars += len(tc.Name) + len(tc.Arguments)
		}
	}
	return totalChars / charsPerToken
}

// summarizeContextIfNeeded checks if context is too large and summarizes if so.
func (a *Agent) summarizeContextIfNeeded(ctx context.Context) error {
	estimatedTokens := a.estimateTokens()
	if estimatedTokens < contextTokenLimit {
		return nil // No summarization needed
	}

	a.events <- Event{
		Type:    EventStatusUpdate,
		Content: "📝 Context limit approaching, summarizing conversation...",
	}

	a.mu.Lock()
	messageCount := len(a.messages)

	// Keep recent messages
	keepFrom := messageCount - recentMessagesToKeep
	if keepFrom < 0 {
		keepFrom = 0
	}

	// Build summary of older messages
	var oldMessages []llm.Message
	if keepFrom > 0 {
		oldMessages = a.messages[:keepFrom]
	}
	recentMessages := a.messages[keepFrom:]
	a.mu.Unlock()

	if len(oldMessages) == 0 {
		return nil // Nothing to summarize
	}

	// Create summary of old messages
	summary := a.createContextSummary(oldMessages)

	// Build progress report
	progressReport := a.buildProgressReport()

	// Create new message history with summary
	summaryMessage := llm.Message{
		Role: "user",
		Content: fmt.Sprintf(`[CONTEXT SUMMARY - Previous conversation was summarized to save space]

%s

%s

[END SUMMARY - Recent conversation continues below]`, summary, progressReport),
	}

	a.mu.Lock()
	// Replace old messages with summary + recent
	a.messages = append([]llm.Message{summaryMessage}, recentMessages...)
	a.mu.Unlock()

	a.events <- Event{
		Type:    EventStatusUpdate,
		Content: fmt.Sprintf("✅ Context summarized: %d messages → %d messages", messageCount, len(a.messages)),
	}

	return nil
}

// createContextSummary creates a summary of older messages.
func (a *Agent) createContextSummary(messages []llm.Message) string {
	var sb strings.Builder
	sb.WriteString("=== CONVERSATION SUMMARY ===\n\n")

	// Track key information
	var toolsUsed []string
	var keyFindings []string
	var actionsCompleted []string
	toolCounts := make(map[string]int)

	for _, msg := range messages {
		switch msg.Role {
		case "assistant":
			// Track tool calls
			for _, tc := range msg.ToolCalls {
				toolCounts[tc.Name]++
				if len(toolsUsed) < 20 { // Limit to avoid huge summaries
					toolsUsed = append(toolsUsed, tc.Name)
				}
			}
			// Extract key content (first 200 chars of significant responses)
			if len(msg.Content) > 50 && len(keyFindings) < 10 {
				content := msg.Content
				if len(content) > 200 {
					content = content[:200] + "..."
				}
				keyFindings = append(keyFindings, content)
			}
		case "tool":
			// Track significant tool results
			if strings.Contains(msg.Content, "Successfully") ||
				strings.Contains(msg.Content, "Found") ||
				strings.Contains(msg.Content, "Score") {
				if len(actionsCompleted) < 15 {
					result := msg.Content
					if len(result) > 150 {
						result = result[:150] + "..."
					}
					actionsCompleted = append(actionsCompleted, fmt.Sprintf("[%s] %s", msg.Name, result))
				}
			}
		}
	}

	// Write summary
	sb.WriteString("TOOLS USED:\n")
	for tool, count := range toolCounts {
		sb.WriteString(fmt.Sprintf("  - %s: %d times\n", tool, count))
	}

	if len(actionsCompleted) > 0 {
		sb.WriteString("\nKEY ACTIONS COMPLETED:\n")
		for _, action := range actionsCompleted {
			sb.WriteString(fmt.Sprintf("  • %s\n", action))
		}
	}

	if len(keyFindings) > 0 {
		sb.WriteString("\nKEY FINDINGS/RESPONSES:\n")
		for _, finding := range keyFindings {
			sb.WriteString(fmt.Sprintf("  • %s\n", finding))
		}
	}

	return sb.String()
}

// buildProgressReport creates a report of current progress for context continuation.
func (a *Agent) buildProgressReport() string {
	var sb strings.Builder
	sb.WriteString("=== CURRENT PROGRESS ===\n\n")

	// Add score info if available
	if a.currentScore > 0 {
		sb.WriteString(fmt.Sprintf("CURRENT SCORE: %d/100\n", a.currentScore))
		if a.targetScore > 0 {
			sb.WriteString(fmt.Sprintf("TARGET SCORE: %d/100\n", a.targetScore))
			remaining := a.targetScore - a.currentScore
			if remaining > 0 {
				sb.WriteString(fmt.Sprintf("POINTS NEEDED: %d more\n", remaining))
			}
		}
	}

	// Add subagent status
	if a.subAgentManager != nil {
		subagents := a.subAgentManager.ListSubAgents()
		if len(subagents) > 0 {
			sb.WriteString("\nSUBAGENT STATUS:\n")
			for _, sa := range subagents {
				result := sa.ToResult()
				sb.WriteString(fmt.Sprintf("  - %s: %s", result.ID, result.Status))
				if result.Status == "completed" && result.Result != "" {
					resultPreview := result.Result
					if len(resultPreview) > 100 {
						resultPreview = resultPreview[:100] + "..."
					}
					sb.WriteString(fmt.Sprintf(" - %s", resultPreview))
				}
				sb.WriteString("\n")
			}
		}
	}

	sb.WriteString("\nCONTINUE WORKING - Pick up where you left off!\n")
	sb.WriteString("Remember to check score periodically and use subagents for parallel work.\n")

	return sb.String()
}

func (a *Agent) callLLM(ctx context.Context) (*llm.ChatResponse, error) {
	// Check if we need to summarize context before calling LLM
	if err := a.summarizeContextIfNeeded(ctx); err != nil {
		// Log but don't fail - try to continue anyway
		a.events <- Event{Type: EventStatusUpdate, Content: fmt.Sprintf("Warning: context summarization failed: %v", err)}
	}

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
	// Use the detailed prompts from prompts.go
	osName := a.cfg.OSInfo.Name
	if osName == "" {
		osName = a.cfg.OS
	}
	
	// Build base prompt from prompts.go
	builder := NewSystemPromptBuilder(osName, a.cfg.CompMode)
	basePrompt := builder.Build()
	
	// Add dynamic runtime information
	now := time.Now().Format("Monday, January 2, 2006 3:04 PM")
	
	// Build OS info string
	osInfo := a.cfg.OSInfo
	osDesc := osInfo.Type.String()
	if osInfo.Name != "" {
		osDesc = osInfo.Name
	}
	if osInfo.Version != "" && !strings.Contains(osDesc, osInfo.Version) {
		osDesc += " " + osInfo.Version
	}
	if osInfo.IsServer {
		osDesc += " (Server)"
	}
	if osInfo.Kernel != "" {
		osDesc += " - Kernel: " + osInfo.Kernel
	}

	// Screen mode info
	screenModeDesc := "OBSERVE ONLY - Cannot control mouse/keyboard"
	if a.cfg.ScreenMode == config.ScreenModeControl {
		screenModeDesc = "CONTROL ENABLED - Can use mouse/keyboard"
	}

	// Execution mode info
	execModeDesc := "AUTOPILOT - Actions execute automatically"
	if a.cfg.Mode == config.ModeConfirm {
		execModeDesc = "CONFIRM - User must approve each action"
	}

	dynamicInfo := fmt.Sprintf(`
═══════════════════════════════════════════════════════════════════════════════
                         CURRENT SESSION INFO
═══════════════════════════════════════════════════════════════════════════════

Current Time: %s
Operating System: %s
Architecture: %s
Screen Mode: %s
Execution Mode: %s
Max Concurrent Subagents: %d

═══════════════════════════════════════════════════════════════════════════════
`, now, osDesc, a.cfg.Architecture, screenModeDesc, execModeDesc, a.GetMaxSubAgents())

	return basePrompt + dynamicInfo
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

