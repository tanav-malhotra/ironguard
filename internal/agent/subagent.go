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

// SubAgentStatus represents the status of a subagent.
type SubAgentStatus string

const (
	SubAgentStatusPending   SubAgentStatus = "pending"
	SubAgentStatusRunning   SubAgentStatus = "running"
	SubAgentStatusCompleted SubAgentStatus = "completed"
	SubAgentStatusFailed    SubAgentStatus = "failed"
	SubAgentStatusCancelled SubAgentStatus = "cancelled"
)

// SubAgentEvent represents an event from a subagent.
type SubAgentEvent struct {
	AgentID   string
	Type      SubAgentEventType
	Content   string
	Tool      *ToolCallInfo
	Thinking  string
	Error     error
}

// SubAgentEventType represents the type of subagent event.
type SubAgentEventType int

const (
	SubAgentEventStarted SubAgentEventType = iota
	SubAgentEventThinking
	SubAgentEventStreaming
	SubAgentEventToolCall
	SubAgentEventToolResult
	SubAgentEventCompleted
	SubAgentEventFailed
	SubAgentEventCancelled
)

// SubAgent represents a child agent spawned for a specific task.
type SubAgent struct {
	ID           string
	ParentID     string // ID of parent agent/subagent that spawned this
	Task         string
	SystemPrompt string
	Model        string
	Provider     config.Provider
	Status       SubAgentStatus
	Result       string
	Error        string
	StartedAt    time.Time
	CompletedAt  time.Time
	
	// Progress tracking
	CurrentStep  string
	StepsTotal   int
	StepsDone    int
	Thinking     string // Current thinking/reasoning
	
	// Tool execution history
	ToolCalls    []ToolCallInfo
	
	// Internal
	client       llm.Client
	toolRegistry *tools.Registry
	cancelFunc   context.CancelFunc
	events       chan SubAgentEvent
	messages     []llm.Message
	mu           sync.Mutex
}

// SubAgentCompletionCallback is called when a subagent completes.
type SubAgentCompletionCallback func(id string, task string, status SubAgentStatus, result string)

// SubAgentManager manages child agents.
type SubAgentManager struct {
	agents             map[string]*SubAgent
	mu                 sync.RWMutex
	registry           *llm.Registry
	toolRegistry       *tools.Registry
	maxAgents          int
	events             chan SubAgentEvent // Global event channel for all subagent events
	completionCallback SubAgentCompletionCallback
}

// NewSubAgentManager creates a new subagent manager.
func NewSubAgentManager(llmRegistry *llm.Registry, toolRegistry *tools.Registry) *SubAgentManager {
	return &SubAgentManager{
		agents:       make(map[string]*SubAgent),
		registry:     llmRegistry,
		toolRegistry: toolRegistry,
		maxAgents:    4, // Max concurrent subagents
		events:       make(chan SubAgentEvent, 100),
	}
}

// Events returns the event channel for listening to all subagent events.
func (m *SubAgentManager) Events() <-chan SubAgentEvent {
	return m.events
}

// SetCompletionCallback sets the callback that is called when subagents complete.
func (m *SubAgentManager) SetCompletionCallback(cb SubAgentCompletionCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.completionCallback = cb
}

// SpawnSubAgent creates a new subagent for a specific task.
func (m *SubAgentManager) SpawnSubAgent(ctx context.Context, task string, systemPrompt string, opts ...SubAgentOption) (*SubAgent, error) {
	m.mu.Lock()
	
	// Check max agents
	runningCount := 0
	for _, a := range m.agents {
		if a.Status == SubAgentStatusRunning {
			runningCount++
		}
	}
	if runningCount >= m.maxAgents {
		m.mu.Unlock()
		return nil, fmt.Errorf("maximum concurrent subagents (%d) reached", m.maxAgents)
	}
	
	// Create subagent with defaults
	id := fmt.Sprintf("sub_%d", time.Now().UnixNano()%100000)
	subCtx, cancel := context.WithCancel(ctx)
	
	agent := &SubAgent{
		ID:           id,
		Task:         task,
		SystemPrompt: systemPrompt,
		Provider:     config.ProviderAnthropic,
		Model:        "claude-sonnet-4-5", // Use faster model for subagents
		Status:       SubAgentStatusPending,
		StartedAt:    time.Now(),
		toolRegistry: m.toolRegistry,
		cancelFunc:   cancel,
		events:       make(chan SubAgentEvent, 50),
		messages:     []llm.Message{},
		ToolCalls:    []ToolCallInfo{},
	}
	
	// Apply options
	for _, opt := range opts {
		opt(agent)
	}
	
	// Get client for the specified provider
	client, err := m.registry.Get(llm.Provider(agent.Provider))
	if err != nil {
		m.mu.Unlock()
		cancel()
		return nil, fmt.Errorf("failed to get client for provider %s: %w", agent.Provider, err)
	}
	agent.client = client
	
	m.agents[id] = agent
	m.mu.Unlock()
	
	// Run the subagent in background
	go m.runSubAgent(subCtx, agent)
	
	return agent, nil
}

// SubAgentOption configures a subagent.
type SubAgentOption func(*SubAgent)

// WithProvider sets the provider for the subagent.
func WithProvider(p config.Provider) SubAgentOption {
	return func(a *SubAgent) {
		a.Provider = p
	}
}

// WithModel sets the model for the subagent.
func WithModel(model string) SubAgentOption {
	return func(a *SubAgent) {
		a.Model = model
	}
}

// WithParent sets the parent ID for the subagent.
func WithParent(parentID string) SubAgentOption {
	return func(a *SubAgent) {
		a.ParentID = parentID
	}
}

// runSubAgent executes the subagent's task with full tool support.
func (m *SubAgentManager) runSubAgent(ctx context.Context, agent *SubAgent) {
	agent.mu.Lock()
	agent.Status = SubAgentStatusRunning
	agent.mu.Unlock()
	
	// Emit started event
	m.emitEvent(SubAgentEvent{
		AgentID: agent.ID,
		Type:    SubAgentEventStarted,
		Content: agent.Task,
	})
	
	// Add initial user message
	agent.messages = append(agent.messages, llm.Message{
		Role:    "user",
		Content: agent.Task,
	})
	
	// Build tool definitions
	var llmTools []llm.Tool
	for _, t := range agent.toolRegistry.All() {
		// Skip certain tools for subagents (like spawning more subagents)
		if t.Name == "spawn_subagent" {
			continue
		}
		llmTools = append(llmTools, llm.Tool{
			Name:        t.Name,
			Description: t.Description,
			Parameters:  t.Parameters,
		})
	}
	
	// Conversation loop
	maxIterations := 20 // Prevent infinite loops
	for i := 0; i < maxIterations; i++ {
		select {
		case <-ctx.Done():
			agent.mu.Lock()
			agent.Status = SubAgentStatusCancelled
			agent.CompletedAt = time.Now()
			task := agent.Task
			agent.mu.Unlock()
			m.emitEvent(SubAgentEvent{
				AgentID: agent.ID,
				Type:    SubAgentEventCancelled,
			})
			// Notify main agent
			m.notifyCompletion(agent.ID, task, SubAgentStatusCancelled, "Cancelled")
			return
		default:
		}
		
		// Call LLM
		req := llm.ChatRequest{
			Messages:     agent.messages,
			Tools:        llmTools,
			SystemPrompt: agent.SystemPrompt,
			MaxTokens:    4096,
		}
		
		var contentBuilder strings.Builder
		var toolCalls []llm.ToolCall
		var thinkingContent string
		
		err := agent.client.ChatStream(ctx, req, func(delta llm.StreamDelta) {
			if delta.Error != nil {
				return
			}
			if delta.Content != "" {
				contentBuilder.WriteString(delta.Content)
				m.emitEvent(SubAgentEvent{
					AgentID: agent.ID,
					Type:    SubAgentEventStreaming,
					Content: delta.Content,
				})
			}
			if delta.Thinking != "" {
				thinkingContent += delta.Thinking
				agent.mu.Lock()
				agent.Thinking = thinkingContent
				agent.mu.Unlock()
				m.emitEvent(SubAgentEvent{
					AgentID:  agent.ID,
					Type:     SubAgentEventThinking,
					Thinking: delta.Thinking,
				})
			}
			if len(delta.ToolCalls) > 0 {
				toolCalls = delta.ToolCalls
			}
		})
		
		if err != nil {
			agent.mu.Lock()
			agent.Status = SubAgentStatusFailed
			agent.Error = err.Error()
			agent.CompletedAt = time.Now()
			task := agent.Task
			errMsg := agent.Error
			agent.mu.Unlock()
			m.emitEvent(SubAgentEvent{
				AgentID: agent.ID,
				Type:    SubAgentEventFailed,
				Error:   err,
			})
			// Notify main agent
			m.notifyCompletion(agent.ID, task, SubAgentStatusFailed, errMsg)
			return
		}
		
		// Add assistant response to history
		assistantMsg := llm.Message{
			Role:      "assistant",
			Content:   contentBuilder.String(),
			ToolCalls: toolCalls,
		}
		agent.messages = append(agent.messages, assistantMsg)
		
		// If no tool calls, we're done
		if len(toolCalls) == 0 {
			agent.mu.Lock()
			agent.Status = SubAgentStatusCompleted
			agent.Result = contentBuilder.String()
			agent.CompletedAt = time.Now()
			task := agent.Task
			result := agent.Result
			agent.mu.Unlock()
			m.emitEvent(SubAgentEvent{
				AgentID: agent.ID,
				Type:    SubAgentEventCompleted,
				Content: result,
			})
			// Notify main agent
			m.notifyCompletion(agent.ID, task, SubAgentStatusCompleted, result)
			return
		}
		
		// Process tool calls
		for _, tc := range toolCalls {
			select {
			case <-ctx.Done():
				return
			default:
			}
			
			toolInfo := ToolCallInfo{
				ID:        tc.ID,
				Name:      tc.Name,
				Arguments: string(tc.Arguments),
			}
			
			m.emitEvent(SubAgentEvent{
				AgentID: agent.ID,
				Type:    SubAgentEventToolCall,
				Tool:    &toolInfo,
			})
			
			// Execute tool
			agent.mu.Lock()
			agent.CurrentStep = fmt.Sprintf("Running %s...", tc.Name)
			agent.mu.Unlock()
			
			output, err := agent.toolRegistry.Execute(ctx, tc.Name, tc.Arguments)
			if err != nil {
				toolInfo.Error = err.Error()
				output = fmt.Sprintf("Error: %s", err.Error())
			}
			toolInfo.Output = output
			
			// Track tool call
			agent.mu.Lock()
			agent.ToolCalls = append(agent.ToolCalls, toolInfo)
			agent.StepsDone++
			agent.mu.Unlock()
			
			m.emitEvent(SubAgentEvent{
				AgentID: agent.ID,
				Type:    SubAgentEventToolResult,
				Tool:    &toolInfo,
			})
			
			// Add tool result to messages
			agent.messages = append(agent.messages, llm.Message{
				Role:       "tool",
				Content:    output,
				ToolCallID: tc.ID,
				Name:       tc.Name,
			})
		}
	}
	
	// Max iterations reached
	agent.mu.Lock()
	agent.Status = SubAgentStatusCompleted
	agent.Result = "Task completed (max iterations reached)"
	agent.CompletedAt = time.Now()
	task := agent.Task
	result := agent.Result
	agent.mu.Unlock()
	m.emitEvent(SubAgentEvent{
		AgentID: agent.ID,
		Type:    SubAgentEventCompleted,
		Content: result,
	})
	// Notify main agent
	m.notifyCompletion(agent.ID, task, SubAgentStatusCompleted, result)
}

// emitEvent sends an event to the global channel.
func (m *SubAgentManager) emitEvent(event SubAgentEvent) {
	select {
	case m.events <- event:
	default:
		// Channel full - this can happen during high activity.
		// Events are non-critical UI updates, so dropping is acceptable
		// but we should be aware of it during debugging.
	}
}

// notifyCompletion calls the completion callback if set.
func (m *SubAgentManager) notifyCompletion(id, task string, status SubAgentStatus, result string) {
	m.mu.RLock()
	cb := m.completionCallback
	m.mu.RUnlock()
	
	if cb != nil {
		cb(id, task, status, result)
	}
}

// GetSubAgent returns a subagent by ID.
func (m *SubAgentManager) GetSubAgent(id string) (*SubAgent, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	agent, ok := m.agents[id]
	return agent, ok
}

// ListSubAgents returns all subagents.
func (m *SubAgentManager) ListSubAgents() []*SubAgent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	agents := make([]*SubAgent, 0, len(m.agents))
	for _, a := range m.agents {
		agents = append(agents, a)
	}
	return agents
}

// ListRunningSubAgents returns only running subagents.
func (m *SubAgentManager) ListRunningSubAgents() []*SubAgent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	var agents []*SubAgent
	for _, a := range m.agents {
		if a.Status == SubAgentStatusRunning {
			agents = append(agents, a)
		}
	}
	return agents
}

// CancelSubAgent cancels a running subagent.
func (m *SubAgentManager) CancelSubAgent(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	agent, ok := m.agents[id]
	if !ok {
		return fmt.Errorf("subagent %s not found", id)
	}
	
	if agent.Status != SubAgentStatusRunning {
		return fmt.Errorf("subagent %s is not running (status: %s)", id, agent.Status)
	}
	
	agent.cancelFunc()
	return nil
}

// CancelAllSubAgents cancels all running subagents.
func (m *SubAgentManager) CancelAllSubAgents() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	for _, agent := range m.agents {
		if agent.Status == SubAgentStatusRunning {
			agent.cancelFunc()
		}
	}
}

// WaitForSubAgent waits for a subagent to complete.
func (m *SubAgentManager) WaitForSubAgent(ctx context.Context, id string) (*SubAgent, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			agent, ok := m.GetSubAgent(id)
			if !ok {
				return nil, fmt.Errorf("subagent %s not found", id)
			}
			if agent.Status != SubAgentStatusRunning && agent.Status != SubAgentStatusPending {
				return agent, nil
			}
		}
	}
}

// WaitForAllSubAgents waits for all subagents to complete.
func (m *SubAgentManager) WaitForAllSubAgents(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			running := m.ListRunningSubAgents()
			if len(running) == 0 {
				return nil
			}
		}
	}
}

// CleanupCompleted removes completed/failed/cancelled subagents.
func (m *SubAgentManager) CleanupCompleted() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	count := 0
	for id, agent := range m.agents {
		if agent.Status != SubAgentStatusRunning && agent.Status != SubAgentStatusPending {
			delete(m.agents, id)
			count++
		}
	}
	return count
}

// SetMaxAgents sets the maximum number of concurrent subagents.
func (m *SubAgentManager) SetMaxAgents(max int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if max < 1 {
		max = 1
	}
	if max > 10 {
		max = 10 // Hard cap for safety
	}
	m.maxAgents = max
}

// GetMaxAgents returns the current maximum number of concurrent subagents.
func (m *SubAgentManager) GetMaxAgents() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.maxAgents
}

// SubAgentResult is returned when checking subagent status.
type SubAgentResult struct {
	ID          string        `json:"id"`
	Task        string        `json:"task"`
	Status      string        `json:"status"`
	Result      string        `json:"result,omitempty"`
	Error       string        `json:"error,omitempty"`
	Duration    string        `json:"duration,omitempty"`
	CurrentStep string        `json:"current_step,omitempty"`
	StepsDone   int           `json:"steps_done"`
	ToolCalls   int           `json:"tool_calls"`
	Thinking    string        `json:"thinking,omitempty"`
}

// ToResult converts a SubAgent to a SubAgentResult.
func (a *SubAgent) ToResult() SubAgentResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	result := SubAgentResult{
		ID:          a.ID,
		Task:        a.Task,
		Status:      string(a.Status),
		Result:      a.Result,
		Error:       a.Error,
		CurrentStep: a.CurrentStep,
		StepsDone:   a.StepsDone,
		ToolCalls:   len(a.ToolCalls),
	}
	
	// Truncate thinking for display
	if len(a.Thinking) > 200 {
		result.Thinking = a.Thinking[:200] + "..."
	} else {
		result.Thinking = a.Thinking
	}
	
	if !a.CompletedAt.IsZero() {
		result.Duration = a.CompletedAt.Sub(a.StartedAt).Round(time.Millisecond).String()
	} else if a.Status == SubAgentStatusRunning {
		result.Duration = time.Since(a.StartedAt).Round(time.Millisecond).String() + " (running)"
	}
	
	return result
}

// FormatSubAgentList formats a list of subagents for display.
func FormatSubAgentList(agents []*SubAgent) string {
	if len(agents) == 0 {
		return "No subagents spawned."
	}
	
	var sb strings.Builder
	sb.WriteString("🤖 SUBAGENTS:\n")
	
	for _, a := range agents {
		result := a.ToResult()
		
		statusIcon := map[string]string{
			"pending":   "⏸️",
			"running":   "⏳",
			"completed": "✅",
			"failed":    "❌",
			"cancelled": "⏹️",
		}[result.Status]
		
		sb.WriteString(fmt.Sprintf("\n  %s %s\n", statusIcon, result.ID))
		sb.WriteString(fmt.Sprintf("     Task: %s\n", truncateString(result.Task, 60)))
		sb.WriteString(fmt.Sprintf("     Status: %s | Duration: %s | Tools: %d\n", 
			result.Status, result.Duration, result.ToolCalls))
		
		if result.CurrentStep != "" && result.Status == "running" {
			sb.WriteString(fmt.Sprintf("     Current: %s\n", result.CurrentStep))
		}
		
		if result.Status == "completed" && result.Result != "" {
			sb.WriteString(fmt.Sprintf("     Result: %s\n", truncateString(result.Result, 100)))
		}
		if result.Status == "failed" && result.Error != "" {
			sb.WriteString(fmt.Sprintf("     Error: %s\n", result.Error))
		}
	}
	
	return sb.String()
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// MarshalJSON for SubAgent.
func (a *SubAgent) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.ToResult())
}
