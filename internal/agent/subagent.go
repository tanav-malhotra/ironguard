package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/tanav-malhotra/ironguard/internal/config"
	"github.com/tanav-malhotra/ironguard/internal/llm"
)

// SubAgent represents a child agent spawned for a specific task.
type SubAgent struct {
	ID          string
	Task        string
	Model       string
	Provider    config.Provider
	Status      string // "running", "completed", "failed", "cancelled"
	Result      string
	Error       string
	StartedAt   time.Time
	CompletedAt time.Time
	
	client     llm.Client
	cancelFunc context.CancelFunc
}

// SubAgentManager manages child agents.
type SubAgentManager struct {
	agents    map[string]*SubAgent
	mu        sync.RWMutex
	registry  *llm.Registry
	maxAgents int
}

// NewSubAgentManager creates a new subagent manager.
func NewSubAgentManager(registry *llm.Registry) *SubAgentManager {
	return &SubAgentManager{
		agents:    make(map[string]*SubAgent),
		registry:  registry,
		maxAgents: 4, // Max concurrent subagents
	}
}

// SpawnSubAgent creates a new subagent for a specific task.
func (m *SubAgentManager) SpawnSubAgent(ctx context.Context, task string, provider config.Provider, model string, systemPrompt string) (*SubAgent, error) {
	m.mu.Lock()
	
	// Check max agents
	runningCount := 0
	for _, a := range m.agents {
		if a.Status == "running" {
			runningCount++
		}
	}
	if runningCount >= m.maxAgents {
		m.mu.Unlock()
		return nil, fmt.Errorf("maximum concurrent subagents (%d) reached", m.maxAgents)
	}
	
	// Get client for the specified provider
	client, err := m.registry.Get(llm.Provider(provider))
	if err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("failed to get client for provider %s: %w", provider, err)
	}
	
	// Create subagent
	id := fmt.Sprintf("subagent_%d", time.Now().UnixNano())
	subCtx, cancel := context.WithCancel(ctx)
	
	agent := &SubAgent{
		ID:         id,
		Task:       task,
		Model:      model,
		Provider:   provider,
		Status:     "running",
		StartedAt:  time.Now(),
		client:     client,
		cancelFunc: cancel,
	}
	
	m.agents[id] = agent
	m.mu.Unlock()
	
	// Run the subagent in background
	go func() {
		result, err := m.runSubAgent(subCtx, agent, systemPrompt)
		
		m.mu.Lock()
		agent.CompletedAt = time.Now()
		if err != nil {
			agent.Status = "failed"
			agent.Error = err.Error()
		} else {
			agent.Status = "completed"
			agent.Result = result
		}
		m.mu.Unlock()
	}()
	
	return agent, nil
}

// runSubAgent executes the subagent's task.
func (m *SubAgentManager) runSubAgent(ctx context.Context, agent *SubAgent, systemPrompt string) (string, error) {
	req := llm.ChatRequest{
		Messages: []llm.Message{
			{Role: "user", Content: agent.Task},
		},
		SystemPrompt: systemPrompt,
		MaxTokens:    4096,
	}
	
	resp, err := agent.client.Chat(ctx, req)
	if err != nil {
		return "", err
	}
	
	return resp.Content, nil
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

// CancelSubAgent cancels a running subagent.
func (m *SubAgentManager) CancelSubAgent(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	agent, ok := m.agents[id]
	if !ok {
		return fmt.Errorf("subagent %s not found", id)
	}
	
	if agent.Status != "running" {
		return fmt.Errorf("subagent %s is not running", id)
	}
	
	agent.cancelFunc()
	agent.Status = "cancelled"
	agent.CompletedAt = time.Now()
	return nil
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
			if agent.Status != "running" {
				return agent, nil
			}
		}
	}
}

// SubAgentResult is returned when checking subagent status.
type SubAgentResult struct {
	ID        string `json:"id"`
	Task      string `json:"task"`
	Status    string `json:"status"`
	Result    string `json:"result,omitempty"`
	Error     string `json:"error,omitempty"`
	Duration  string `json:"duration,omitempty"`
}

// ToResult converts a SubAgent to a SubAgentResult.
func (a *SubAgent) ToResult() SubAgentResult {
	result := SubAgentResult{
		ID:     a.ID,
		Task:   a.Task,
		Status: a.Status,
		Result: a.Result,
		Error:  a.Error,
	}
	
	if !a.CompletedAt.IsZero() {
		result.Duration = a.CompletedAt.Sub(a.StartedAt).String()
	} else if a.Status == "running" {
		result.Duration = time.Since(a.StartedAt).String() + " (running)"
	}
	
	return result
}

// RegisterSubAgentTools adds tools for spawning and managing subagents.
func RegisterSubAgentTools(registry interface{ Register(t interface{}) }, manager *SubAgentManager, allowedProviders []config.Provider) {
	// Note: This is a placeholder - actual registration would need the tools.Registry type
	// The tools will be registered in the tools package
}

// SubAgentToolsJSON returns the JSON schema for subagent tools.
func SubAgentToolsJSON() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name":        "spawn_subagent",
			"description": "Spawn a child AI agent to work on a specific task in parallel. The subagent will work independently and report back when done. Use this for tasks that can be done in parallel.",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"task": map[string]interface{}{
						"type":        "string",
						"description": "The task for the subagent to complete",
					},
					"provider": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"claude", "openai", "gemini"},
						"description": "Which AI provider to use (default: same as parent)",
					},
					"model": map[string]interface{}{
						"type":        "string",
						"description": "Which model to use (default: provider's default)",
					},
				},
				"required": []string{"task"},
			},
		},
		{
			"name":        "check_subagent",
			"description": "Check the status and result of a spawned subagent.",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "string",
						"description": "The subagent ID to check",
					},
				},
				"required": []string{"id"},
			},
		},
		{
			"name":        "list_subagents",
			"description": "List all spawned subagents and their status.",
			"parameters": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			"name":        "cancel_subagent",
			"description": "Cancel a running subagent.",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "string",
						"description": "The subagent ID to cancel",
					},
				},
				"required": []string{"id"},
			},
		},
		{
			"name":        "wait_for_subagent",
			"description": "Wait for a subagent to complete and get its result.",
			"parameters": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "string",
						"description": "The subagent ID to wait for",
					},
				},
				"required": []string{"id"},
			},
		},
	}
}

// FormatSubAgentList formats a list of subagents for display.
func FormatSubAgentList(agents []*SubAgent) string {
	if len(agents) == 0 {
		return "No subagents spawned."
	}
	
	result := "🤖 SUBAGENTS:\n"
	for _, a := range agents {
		statusIcon := map[string]string{
			"running":   "⏳",
			"completed": "✅",
			"failed":    "❌",
			"cancelled": "⏹️",
		}[a.Status]
		
		result += fmt.Sprintf("  %s %s [%s/%s]\n", statusIcon, a.ID, a.Provider, a.Model)
		result += fmt.Sprintf("     Task: %s\n", truncateString(a.Task, 60))
		result += fmt.Sprintf("     Status: %s\n", a.Status)
		
		if a.Status == "completed" && a.Result != "" {
			result += fmt.Sprintf("     Result: %s\n", truncateString(a.Result, 100))
		}
		if a.Status == "failed" && a.Error != "" {
			result += fmt.Sprintf("     Error: %s\n", a.Error)
		}
	}
	
	return result
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

