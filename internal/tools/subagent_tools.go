package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// SubAgentManager interface for subagent operations.
// This is implemented by agent.SubAgentManager.
type SubAgentManager interface {
	SpawnSubAgent(ctx context.Context, task string, systemPrompt string, opts ...interface{}) (SubAgentInfo, error)
	GetSubAgent(id string) (SubAgentInfo, bool)
	ListSubAgents() []SubAgentInfo
	CancelSubAgent(id string) error
	WaitForSubAgent(ctx context.Context, id string) (SubAgentInfo, error)
}

// SubAgentInfo represents information about a subagent.
type SubAgentInfo struct {
	ID          string
	Task        string
	Status      string
	Result      string
	Error       string
	CurrentStep string
	StepsDone   int
	ToolCalls   int
	Duration    string
}

// Global subagent manager reference (set by agent package)
var (
	globalSubAgentManager SubAgentManager
	subAgentMu            sync.RWMutex
)

// SetSubAgentManager sets the global subagent manager.
func SetSubAgentManager(m SubAgentManager) {
	subAgentMu.Lock()
	defer subAgentMu.Unlock()
	globalSubAgentManager = m
}

// GetSubAgentManager returns the global subagent manager.
func GetSubAgentManager() SubAgentManager {
	subAgentMu.RLock()
	defer subAgentMu.RUnlock()
	return globalSubAgentManager
}

// RegisterSubAgentTools registers tools for spawning and managing subagents.
func (r *Registry) RegisterSubAgentTools() {
	r.Register(&Tool{
		Name: "spawn_subagent",
		Description: `Spawn a child AI agent to work on a specific task in parallel. 
The subagent will work independently with full tool access and report back when done.
Use this for tasks that can be done in parallel with your main work.

BEST PRACTICES:
- Give clear, specific tasks with all needed context
- Don't spawn subagents for quick tasks (do them yourself)
- Use for: forensics research, file searches, service audits, user audits
- Each subagent has its own conversation and tool access
- Maximum 4 concurrent subagents`,
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"task": map[string]interface{}{
					"type":        "string",
					"description": "The complete task description with all context needed. Be specific!",
				},
				"focus": map[string]interface{}{
					"type":        "string",
					"description": "What the subagent should focus on (e.g., 'forensics', 'users', 'services', 'files')",
				},
			},
			"required": []string{"task"},
		},
		Handler:  toolSpawnSubAgent,
		Mutating: false,
	})

	r.Register(&Tool{
		Name:        "check_subagent",
		Description: "Check the status and result of a spawned subagent. Returns current status, progress, and result if completed.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "The subagent ID to check",
				},
			},
			"required": []string{"id"},
		},
		Handler:  toolCheckSubAgent,
		Mutating: false,
	})

	r.Register(&Tool{
		Name:        "list_subagents",
		Description: "List all spawned subagents and their current status. Shows running, completed, and failed subagents.",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler:  toolListSubAgents,
		Mutating: false,
	})

	r.Register(&Tool{
		Name:        "cancel_subagent",
		Description: "Cancel a running subagent. Use if the task is no longer needed or taking too long.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "The subagent ID to cancel",
				},
			},
			"required": []string{"id"},
		},
		Handler:  toolCancelSubAgent,
		Mutating: true,
	})

	r.Register(&Tool{
		Name:        "wait_for_subagent",
		Description: "Wait for a subagent to complete and get its final result. Blocks until the subagent finishes.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "The subagent ID to wait for",
				},
				"timeout_seconds": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum seconds to wait (default: 120)",
				},
			},
			"required": []string{"id"},
		},
		Handler:  toolWaitForSubAgent,
		Mutating: false,
	})
}

func toolSpawnSubAgent(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Task  string `json:"task"`
		Focus string `json:"focus"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	if params.Task == "" {
		return "", fmt.Errorf("task is required")
	}

	manager := GetSubAgentManager()
	if manager == nil {
		return "", fmt.Errorf("subagent manager not available")
	}

	// Build system prompt based on focus
	systemPrompt := buildSubAgentPrompt(params.Focus)

	// Spawn the subagent
	info, err := manager.SpawnSubAgent(ctx, params.Task, systemPrompt)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(`✅ Subagent spawned successfully!

ID: %s
Task: %s
Status: %s

The subagent is now working independently. Use check_subagent or wait_for_subagent to get results.`, 
		info.ID, truncate(params.Task, 80), info.Status), nil
}

func toolCheckSubAgent(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	manager := GetSubAgentManager()
	if manager == nil {
		return "", fmt.Errorf("subagent manager not available")
	}

	info, found := manager.GetSubAgent(params.ID)
	if !found {
		return "", fmt.Errorf("subagent %s not found", params.ID)
	}

	return formatSubAgentInfo(info), nil
}

func toolListSubAgents(ctx context.Context, args json.RawMessage) (string, error) {
	manager := GetSubAgentManager()
	if manager == nil {
		return "", fmt.Errorf("subagent manager not available")
	}

	agents := manager.ListSubAgents()
	if len(agents) == 0 {
		return "No subagents spawned yet.", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🤖 SUBAGENTS (%d total):\n\n", len(agents)))

	for _, info := range agents {
		sb.WriteString(formatSubAgentInfo(info))
		sb.WriteString("\n---\n")
	}

	return sb.String(), nil
}

func toolCancelSubAgent(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	manager := GetSubAgentManager()
	if manager == nil {
		return "", fmt.Errorf("subagent manager not available")
	}

	if err := manager.CancelSubAgent(params.ID); err != nil {
		return "", err
	}

	return fmt.Sprintf("✅ Subagent %s cancelled.", params.ID), nil
}

func toolWaitForSubAgent(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		ID             string `json:"id"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	manager := GetSubAgentManager()
	if manager == nil {
		return "", fmt.Errorf("subagent manager not available")
	}

	timeout := params.TimeoutSeconds
	if timeout <= 0 {
		timeout = 120
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	info, err := manager.WaitForSubAgent(ctx, params.ID)
	if err != nil {
		return "", fmt.Errorf("wait failed: %w", err)
	}

	return formatSubAgentInfo(info), nil
}

func formatSubAgentInfo(info SubAgentInfo) string {
	statusIcon := map[string]string{
		"pending":   "⏸️",
		"running":   "⏳",
		"completed": "✅",
		"failed":    "❌",
		"cancelled": "⏹️",
	}[info.Status]
	if statusIcon == "" {
		statusIcon = "❓"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s Subagent: %s\n", statusIcon, info.ID))
	sb.WriteString(fmt.Sprintf("   Task: %s\n", truncate(info.Task, 80)))
	sb.WriteString(fmt.Sprintf("   Status: %s\n", info.Status))
	sb.WriteString(fmt.Sprintf("   Duration: %s\n", info.Duration))
	sb.WriteString(fmt.Sprintf("   Tool Calls: %d\n", info.ToolCalls))

	if info.CurrentStep != "" && info.Status == "running" {
		sb.WriteString(fmt.Sprintf("   Current: %s\n", info.CurrentStep))
	}

	if info.Status == "completed" && info.Result != "" {
		sb.WriteString(fmt.Sprintf("\n   📋 RESULT:\n   %s\n", info.Result))
	}

	if info.Status == "failed" && info.Error != "" {
		sb.WriteString(fmt.Sprintf("\n   ❌ ERROR: %s\n", info.Error))
	}

	return sb.String()
}

func buildSubAgentPrompt(focus string) string {
	base := `You are a SUBAGENT of IRONGUARD, working on a specific task assigned by the main agent.

RULES:
1. Focus ONLY on your assigned task
2. Work quickly and efficiently
3. Use tools to gather information and make changes
4. Report your findings clearly when done
5. Don't start new unrelated tasks

`

	switch strings.ToLower(focus) {
	case "forensics":
		return base + `FOCUS: FORENSICS QUESTIONS
- Read forensics question files
- Research answers using available tools
- Write answers to the question files
- Be thorough - each question is worth 5-10 points`

	case "users":
		return base + `FOCUS: USER MANAGEMENT
- List all users and compare to authorized list
- Identify unauthorized users
- Check admin group membership
- Check for weak/blank passwords
- Report findings but let main agent decide on deletions`

	case "services":
		return base + `FOCUS: SERVICE AUDIT
- List all running services
- Identify dangerous/unnecessary services (telnet, ftp, etc.)
- Check service configurations
- Report findings for main agent to act on`

	case "files":
		return base + `FOCUS: FILE SEARCH
- Search for prohibited files (media, hacking tools, etc.)
- Check common locations (/home, /tmp, C:\Users, etc.)
- Report file paths for deletion`

	default:
		return base + `Complete your assigned task thoroughly and report back with findings.`
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

