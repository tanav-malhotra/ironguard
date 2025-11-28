package agent

import (
	"context"

	"github.com/tanav-malhotra/ironguard/internal/tools"
)

// SubAgentManagerAdapter adapts SubAgentManager to the tools.SubAgentManager interface.
type SubAgentManagerAdapter struct {
	manager *SubAgentManager
}

// NewSubAgentManagerAdapter creates a new adapter.
func NewSubAgentManagerAdapter(m *SubAgentManager) *SubAgentManagerAdapter {
	return &SubAgentManagerAdapter{manager: m}
}

// SpawnSubAgent implements tools.SubAgentManager.
func (a *SubAgentManagerAdapter) SpawnSubAgent(ctx context.Context, task string, systemPrompt string, opts ...interface{}) (tools.SubAgentInfo, error) {
	// Convert opts if needed (for now, we ignore them as the tools package doesn't use typed options)
	subagent, err := a.manager.SpawnSubAgent(ctx, task, systemPrompt)
	if err != nil {
		return tools.SubAgentInfo{}, err
	}
	return toToolsSubAgentInfo(subagent), nil
}

// GetSubAgent implements tools.SubAgentManager.
func (a *SubAgentManagerAdapter) GetSubAgent(id string) (tools.SubAgentInfo, bool) {
	subagent, found := a.manager.GetSubAgent(id)
	if !found {
		return tools.SubAgentInfo{}, false
	}
	return toToolsSubAgentInfo(subagent), true
}

// ListSubAgents implements tools.SubAgentManager.
func (a *SubAgentManagerAdapter) ListSubAgents() []tools.SubAgentInfo {
	subagents := a.manager.ListSubAgents()
	result := make([]tools.SubAgentInfo, len(subagents))
	for i, sa := range subagents {
		result[i] = toToolsSubAgentInfo(sa)
	}
	return result
}

// CancelSubAgent implements tools.SubAgentManager.
func (a *SubAgentManagerAdapter) CancelSubAgent(id string) error {
	return a.manager.CancelSubAgent(id)
}

// WaitForSubAgent implements tools.SubAgentManager.
func (a *SubAgentManagerAdapter) WaitForSubAgent(ctx context.Context, id string) (tools.SubAgentInfo, error) {
	subagent, err := a.manager.WaitForSubAgent(ctx, id)
	if err != nil {
		return tools.SubAgentInfo{}, err
	}
	return toToolsSubAgentInfo(subagent), nil
}

// toToolsSubAgentInfo converts a SubAgent to tools.SubAgentInfo.
func toToolsSubAgentInfo(sa *SubAgent) tools.SubAgentInfo {
	result := sa.ToResult()
	return tools.SubAgentInfo{
		ID:          result.ID,
		Task:        result.Task,
		Status:      result.Status,
		Result:      result.Result,
		Error:       result.Error,
		CurrentStep: result.CurrentStep,
		StepsDone:   result.StepsDone,
		ToolCalls:   result.ToolCalls,
		Duration:    result.Duration,
	}
}

