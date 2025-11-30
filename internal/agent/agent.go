package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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
	
	// Pending system messages (queued to be processed after current step)
	pendingSystemMsgs []string
	pendingMsgsMu     sync.Mutex
	
	// Token tracking
	tokenUsage *TokenUsage
	
	// Checkpoint/Undo system
	checkpoints *CheckpointManager
	
	// Persistent memory
	memory *Memory
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
		tokenUsage:   NewTokenUsage(),
		checkpoints:  NewCheckpointManager(),
		memory:       NewMemory(),
	}
	
	// Load persistent memory
	if err := a.memory.Load(); err != nil {
		// Non-fatal, just log
		a.events <- Event{Type: EventStatusUpdate, Content: "Note: Could not load memory from previous sessions"}
	}
	
	// Initialize subagent manager
	a.subAgentManager = NewSubAgentManager(llmReg, toolReg)
	
	// Set up completion callback to notify main AI when subagents finish
	a.subAgentManager.SetCompletionCallback(func(id, task string, status SubAgentStatus, result string) {
		a.handleSubAgentCompletion(id, task, status, result)
	})
	
	// Register subagent manager with tools package
	adapter := NewSubAgentManagerAdapter(a.subAgentManager)
	tools.SetSubAgentManager(adapter)
	
	// Register memory manager with tools package
	memAdapter := NewMemoryManagerAdapter(a.memory)
	tools.SetMemoryManager(memAdapter)
	
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

// GetTokenStats returns current token usage statistics.
func (a *Agent) GetTokenStats() TokenStats {
	return a.tokenUsage.GetStats()
}

// GetCheckpointManager returns the checkpoint manager.
func (a *Agent) GetCheckpointManager() *CheckpointManager {
	return a.checkpoints
}

// GetMemory returns the memory manager.
func (a *Agent) GetMemory() *Memory {
	return a.memory
}

// SaveMemory saves the memory to disk.
func (a *Agent) SaveMemory() error {
	return a.memory.Save()
}

// SetCompactMode sets whether the AI should give brief responses.
func (a *Agent) SetCompactMode(compact bool) {
	a.cfg.CompactMode = compact
}

// IsCompactMode returns whether compact mode is enabled.
func (a *Agent) IsCompactMode() bool {
	return a.cfg.CompactMode
}

// SetSummarizeMode sets the summarization mode.
func (a *Agent) SetSummarizeMode(mode config.SummarizeMode) {
	a.cfg.SummarizeMode = mode
}

// GetSummarizeMode returns the current summarization mode.
func (a *Agent) GetSummarizeMode() config.SummarizeMode {
	return a.cfg.SummarizeMode
}

// handleSubAgentCompletion is called when a subagent finishes and injects a notification into the chat.
func (a *Agent) handleSubAgentCompletion(id, task string, status SubAgentStatus, result string) {
	// Truncate task and result for the notification
	taskPreview := task
	if len(taskPreview) > 80 {
		taskPreview = taskPreview[:77] + "..."
	}
	
	resultPreview := result
	if len(resultPreview) > 200 {
		resultPreview = resultPreview[:197] + "..."
	}
	
	var statusEmoji string
	var statusText string
	switch status {
	case SubAgentStatusCompleted:
		statusEmoji = "✅"
		statusText = "COMPLETED"
	case SubAgentStatusFailed:
		statusEmoji = "❌"
		statusText = "FAILED"
	case SubAgentStatusCancelled:
		statusEmoji = "🚫"
		statusText = "CANCELLED"
	default:
		statusEmoji = "ℹ️"
		statusText = string(status)
	}
	
	notification := fmt.Sprintf(`[SYSTEM] %s SUBAGENT %s (%s)
Task: %s
Result Preview: %s

Use check_subagent("%s") to see full results, or cleanup_subagent("%s") to free the slot.`, 
		statusEmoji, statusText, id, taskPreview, resultPreview, id, id)
	
	// Inject as a user message so the AI sees it
	a.mu.Lock()
	a.messages = append(a.messages, llm.Message{
		Role:    "user",
		Content: notification,
	})
	a.mu.Unlock()
	
	// Also send an event to the TUI
	a.events <- Event{
		Type: EventSubAgentUpdate,
		SubAgent: &SubAgentInfo{
			ID:     id,
			Task:   task,
			Status: string(status),
			Result: resultPreview,
		},
	}
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

// QueueSystemMessage queues a system message to be sent after the current AI step completes.
// This does NOT interrupt the AI - the message will be processed when the AI is ready.
func (a *Agent) QueueSystemMessage(msg string) {
	a.pendingMsgsMu.Lock()
	a.pendingSystemMsgs = append(a.pendingSystemMsgs, msg)
	a.pendingMsgsMu.Unlock()
	
	// If AI is not busy, process immediately
	if !a.IsBusy() {
		a.processPendingSystemMessages()
	}
}

// processPendingSystemMessages processes any queued system messages.
func (a *Agent) processPendingSystemMessages() {
	a.pendingMsgsMu.Lock()
	msgs := a.pendingSystemMsgs
	a.pendingSystemMsgs = nil
	a.pendingMsgsMu.Unlock()
	
	if len(msgs) == 0 {
		return
	}
	
	// Add all pending messages to conversation
	a.mu.Lock()
	for _, msg := range msgs {
		a.messages = append(a.messages, llm.Message{
			Role:    "user",
			Content: msg,
		})
	}
	a.mu.Unlock()
	
	// Notify TUI that messages were added
	for _, msg := range msgs {
		a.events <- Event{
			Type:    EventStatusUpdate,
			Content: fmt.Sprintf("📨 System message queued: %s", truncateString(msg, 50)),
		}
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
		
		// Process any pending system messages now that AI is done
		a.processPendingSystemMessages()
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

			// Create checkpoint for file-modifying operations
			var checkpoint *Checkpoint
			if tc.Name == "write_file" || tc.Name == "edit_file" || tc.Name == "search_replace" {
				// Extract file path from arguments
				var fileArgs struct {
					Path     string `json:"path"`
					FilePath string `json:"file_path"`
				}
				if err := json.Unmarshal(tc.Arguments, &fileArgs); err == nil {
					filePath := fileArgs.Path
					if filePath == "" {
						filePath = fileArgs.FilePath
					}
					if filePath != "" {
						checkpoint, _ = a.checkpoints.CreateFileCheckpoint(filePath, fmt.Sprintf("Edit %s", filePath))
					}
				}
			}

			output, err := a.toolRegistry.Execute(ctx, tc.Name, tc.Arguments)
			if err != nil {
				toolInfo.Error = err.Error()
				output = fmt.Sprintf("Error: %s", err.Error())
			} else if checkpoint != nil {
				// Update checkpoint with new content
				var fileArgs struct {
					Path     string `json:"path"`
					FilePath string `json:"file_path"`
				}
				if err := json.Unmarshal(tc.Arguments, &fileArgs); err == nil {
					filePath := fileArgs.Path
					if filePath == "" {
						filePath = fileArgs.FilePath
					}
					if filePath != "" {
						if newContent, err := os.ReadFile(filePath); err == nil {
							a.checkpoints.UpdateCheckpointNewContent(checkpoint.ID, newContent)
						}
					}
				}
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
	// Chars per token estimate (conservative)
	charsPerToken = 3
	// Number of recent messages to always keep
	recentMessagesToKeep = 10
	// Percentage of context limit at which to trigger summarization (90%)
	summarizationThreshold = 0.90
)

// getContextLimit returns the context limit for the current provider.
// This is based on the MAIN model being used (e.g., opus-4-5 for Claude).
// For summarization, we may use a different model with larger context.
func getContextLimit(provider config.Provider) int {
	switch provider {
	case config.ProviderGemini:
		return 1000000 // gemini-3-pro: 1M tokens
	case config.ProviderAnthropic:
		return 200000 // claude-opus-4-5: 200K tokens (main model)
	case config.ProviderOpenAI:
		return 272000 // gpt-5.1: 272K tokens
	default:
		return 150000 // Conservative default
	}
}

// Summarization model configuration per provider.
// These are the models with the LARGEST context windows for each provider.
// Used specifically for summarization to ensure all context fits.
const (
	// Claude: Use sonnet-4-5 for summarization (1M context with extended pricing)
	// even though opus-4-5 is the main model (only 200K context)
	// TODO: Switch to opus-4-5 when Anthropic increases its context to 1M
	claudeSummarizationModel = "claude-sonnet-4-5"
	
	// Gemini: gemini-3-pro has 1M+ context
	geminiSummarizationModel = "gemini-3-pro"
	
	// OpenAI: gpt-5.1 has 272K context
	openaiSummarizationModel = "gpt-5.1"
)

// getSummarizationModel returns the model to use for summarization for the given provider.
func getSummarizationModel(provider llm.Provider) string {
	switch provider {
	case llm.ProviderGemini:
		return geminiSummarizationModel
	case llm.ProviderClaude:
		return claudeSummarizationModel
	case llm.ProviderOpenAI:
		return openaiSummarizationModel
	default:
		return "" // Use provider's default
	}
}

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
	
	// Get context limit for current provider
	contextLimit := getContextLimit(a.cfg.Provider)
	triggerThreshold := int(float64(contextLimit) * summarizationThreshold)
	
	// Update token tracking
	a.tokenUsage.SetContextLimit(contextLimit)
	a.tokenUsage.AddInput(estimatedTokens)
	
	if estimatedTokens < triggerThreshold {
		return nil // No summarization needed
	}

	modeStr := "smart (LLM)"
	if a.cfg.SummarizeMode == config.SummarizeFast {
		modeStr = "fast (programmatic)"
	}
	
	a.events <- Event{
		Type:    EventStatusUpdate,
		Content: fmt.Sprintf("📝 Context limit approaching, summarizing conversation (%s)...", modeStr),
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

	// Create summary based on mode
	var summary string
	var err error
	
	if a.cfg.SummarizeMode == config.SummarizeSmart {
		// Use LLM for intelligent summarization
		summary, err = a.createSmartSummary(ctx, oldMessages)
		if err != nil {
			// Fall back to fast mode on error
			a.events <- Event{Type: EventStatusUpdate, Content: fmt.Sprintf("⚠️ Smart summary failed (%v), using fast mode", err)}
			summary = a.createFastSummary(oldMessages)
		}
	} else {
		// Fast programmatic summarization
		summary = a.createFastSummary(oldMessages)
	}

	// Build progress report
	progressReport := a.buildProgressReport()

	// Calculate tokens saved
	oldTokens := 0
	for _, msg := range oldMessages {
		oldTokens += EstimateTokens(msg.Content)
	}
	newTokens := EstimateTokens(summary)
	tokensSaved := oldTokens - newTokens
	a.tokenUsage.RecordSummary(tokensSaved)

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
		Content: fmt.Sprintf("✅ Context summarized: %d messages → %d messages (saved ~%d tokens)", messageCount, len(a.messages), tokensSaved),
	}

	return nil
}

// createSmartSummary uses an LLM with large context window to intelligently summarize.
func (a *Agent) createSmartSummary(ctx context.Context, messages []llm.Message) (string, error) {
	// Build the conversation text to summarize
	var conversationText strings.Builder
	conversationText.WriteString("Summarize this CyberPatriot hardening session conversation. Preserve:\n")
	conversationText.WriteString("1. ALL [SYSTEM] messages (setting changes, subagent notifications)\n")
	conversationText.WriteString("2. Files that were edited and what changes were made\n")
	conversationText.WriteString("3. Vulnerabilities found and fixed\n")
	conversationText.WriteString("4. Current score progress\n")
	conversationText.WriteString("5. Pending tasks or issues\n")
	conversationText.WriteString("6. Key commands run and their results\n")
	conversationText.WriteString("7. Subagent tasks and results\n\n")
	conversationText.WriteString("=== CONVERSATION TO SUMMARIZE ===\n\n")
	
	for _, msg := range messages {
		role := msg.Role
		if role == "assistant" {
			role = "AI"
		} else if role == "user" {
			role = "USER"
		} else if role == "tool" {
			role = fmt.Sprintf("TOOL[%s]", msg.Name)
		}
		
		conversationText.WriteString(fmt.Sprintf("[%s]: %s\n", role, msg.Content))
		
		// Include tool calls
		for _, tc := range msg.ToolCalls {
			conversationText.WriteString(fmt.Sprintf("  → Called: %s\n", tc.Name))
		}
	}
	
	// Use the current provider for summarization, but with the largest context model.
	// This ensures the full conversation (at 90% of main model's limit) fits.
	//
	// Summarization models per provider (largest context, high reasoning):
	// - Gemini:    gemini-3-pro (1M+ tokens)
	// - Claude:    claude-sonnet-4-5 (1M tokens with extended pricing)
	//              Note: opus-4-5 is the main model but only has 200K context
	//              TODO: Switch to opus-4-5 when Anthropic increases its context to 1M
	// - OpenAI:    gpt-5.1 (272K tokens)
	currentProvider := llm.Provider(a.cfg.Provider)
	summarizeClient, err := a.llmRegistry.Get(currentProvider)
	if err != nil {
		return "", fmt.Errorf("no summarization client available: %w", err)
	}
	
	// Get the appropriate summarization model for this provider
	summarizeModel := getSummarizationModel(currentProvider)
	
	req := llm.ChatRequest{
		Messages: []llm.Message{
			{Role: "user", Content: conversationText.String()},
		},
		Model:          summarizeModel, // Use the large-context model for summarization
		MaxTokens:      4000,
		ReasoningLevel: llm.ReasoningHigh, // Always use high reasoning for accurate summarization
		SystemPrompt: `You are summarizing a CyberPatriot cybersecurity competition session.
Create a comprehensive but concise summary that allows the AI to continue working without losing context.

CRITICAL - ALWAYS PRESERVE:
- [SYSTEM] messages verbatim (these are user setting changes)
- Subagent completion notifications
- Current score and progress
- Files that were edited (with paths)
- Vulnerabilities found and their status (fixed/pending)
- Any errors or issues encountered

FORMAT:
=== SESSION SUMMARY ===

SETTING CHANGES:
• [list any [SYSTEM] messages about settings]

SCORE PROGRESS:
• Current: X/100, Target: Y/100

SUBAGENTS:
• [list subagent tasks and results]

FILES MODIFIED:
• /path/to/file - [what was changed]

VULNERABILITIES ADDRESSED:
• [list what was found and fixed]

KEY ACTIONS:
• [important commands and results]

PENDING/ISSUES:
• [anything still to do or problems]

Be thorough but concise. The AI needs this to continue the session effectively.`,
	}
	
	resp, err := summarizeClient.Chat(ctx, req)
	if err != nil {
		return "", fmt.Errorf("summarization request failed: %w", err)
	}
	
	return resp.Content, nil
}

// createFastSummary creates a programmatic summary of older messages (no LLM call).
func (a *Agent) createFastSummary(messages []llm.Message) string {
	var sb strings.Builder
	sb.WriteString("=== CONVERSATION SUMMARY ===\n\n")

	// Track key information
	var systemMessages []string      // [SYSTEM] notifications - ALWAYS preserve
	var filesEdited []string         // Files that were modified
	var filesChecked []string        // Files that were read/analyzed  
	var actionsCompleted []string    // Successful actions
	var keyFindings []string         // Important discoveries
	var settingChanges []string      // User setting changes
	var subagentNotifications []string // Subagent completions
	toolCounts := make(map[string]int)

	for _, msg := range messages {
		switch msg.Role {
		case "user":
			// Preserve ALL [SYSTEM] messages - these are critical notifications
			if strings.HasPrefix(msg.Content, "[SYSTEM]") {
				// Categorize system messages
				if strings.Contains(msg.Content, "SUBAGENT") {
					if len(subagentNotifications) < 20 {
						subagentNotifications = append(subagentNotifications, msg.Content)
					}
				} else if strings.Contains(msg.Content, "mode changed") || 
				          strings.Contains(msg.Content, "changed to") ||
				          strings.Contains(msg.Content, "limit has been") {
					if len(settingChanges) < 10 {
						settingChanges = append(settingChanges, msg.Content)
					}
				} else {
					if len(systemMessages) < 15 {
						systemMessages = append(systemMessages, msg.Content)
					}
				}
			}
		case "assistant":
			// Track tool calls
			for _, tc := range msg.ToolCalls {
				toolCounts[tc.Name]++
				argsStr := string(tc.Arguments)
				
				// Track file operations specifically
				if tc.Name == "write_file" || tc.Name == "edit_file" || tc.Name == "search_replace" {
					// Try to extract filename from arguments
					if strings.Contains(argsStr, "file") {
						if len(filesEdited) < 30 {
							// Extract a preview of what was edited
							preview := argsStr
							if len(preview) > 100 {
								preview = preview[:100] + "..."
							}
							filesEdited = append(filesEdited, preview)
						}
					}
				}
				if tc.Name == "read_file" {
					if len(filesChecked) < 30 {
						preview := argsStr
						if len(preview) > 80 {
							preview = preview[:80] + "..."
						}
						filesChecked = append(filesChecked, preview)
					}
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
				strings.Contains(msg.Content, "Score") ||
				strings.Contains(msg.Content, "Created") ||
				strings.Contains(msg.Content, "Deleted") ||
				strings.Contains(msg.Content, "Modified") {
				if len(actionsCompleted) < 20 {
					result := msg.Content
					if len(result) > 150 {
						result = result[:150] + "..."
					}
					actionsCompleted = append(actionsCompleted, fmt.Sprintf("[%s] %s", msg.Name, result))
				}
			}
		}
	}

	// Write summary - CRITICAL INFO FIRST
	
	// 1. System messages (most critical - user setting changes, notifications)
	if len(settingChanges) > 0 {
		sb.WriteString("SETTING CHANGES (from user):\n")
		for _, change := range settingChanges {
			sb.WriteString(fmt.Sprintf("  • %s\n", change))
		}
		sb.WriteString("\n")
	}
	
	// 2. Subagent status
	if len(subagentNotifications) > 0 {
		sb.WriteString("SUBAGENT NOTIFICATIONS:\n")
		for _, notif := range subagentNotifications {
			sb.WriteString(fmt.Sprintf("  • %s\n", notif))
		}
		sb.WriteString("\n")
	}
	
	// 3. Other system messages
	if len(systemMessages) > 0 {
		sb.WriteString("SYSTEM MESSAGES:\n")
		for _, msg := range systemMessages {
			sb.WriteString(fmt.Sprintf("  • %s\n", msg))
		}
		sb.WriteString("\n")
	}
	
	// 4. Files edited (critical for knowing what was changed)
	if len(filesEdited) > 0 {
		sb.WriteString("FILES EDITED:\n")
		for _, f := range filesEdited {
			sb.WriteString(fmt.Sprintf("  • %s\n", f))
		}
		sb.WriteString("\n")
	}
	
	// 5. Files checked
	if len(filesChecked) > 0 {
		sb.WriteString("FILES ANALYZED:\n")
		// Group by unique file paths to reduce noise
		seen := make(map[string]bool)
		for _, f := range filesChecked {
			if !seen[f] {
				seen[f] = true
				sb.WriteString(fmt.Sprintf("  • %s\n", f))
			}
		}
		sb.WriteString("\n")
	}

	// 6. Tool usage summary
	sb.WriteString("TOOLS USED:\n")
	for tool, count := range toolCounts {
		sb.WriteString(fmt.Sprintf("  - %s: %d times\n", tool, count))
	}
	sb.WriteString("\n")

	// 7. Actions completed
	if len(actionsCompleted) > 0 {
		sb.WriteString("KEY ACTIONS COMPLETED:\n")
		for _, action := range actionsCompleted {
			sb.WriteString(fmt.Sprintf("  • %s\n", action))
		}
		sb.WriteString("\n")
	}

	// 8. Key findings
	if len(keyFindings) > 0 {
		sb.WriteString("KEY FINDINGS/RESPONSES:\n")
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

