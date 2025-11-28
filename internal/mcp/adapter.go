package mcp

import (
	"context"
	"encoding/json"

	"github.com/tanav-malhotra/ironguard/internal/tools"
)

// ToolsAdapter wraps the MCP Manager to implement tools.MCPManager interface.
type ToolsAdapter struct {
	manager *Manager
}

// NewToolsAdapter creates a new adapter for the tools package.
func NewToolsAdapter(m *Manager) *ToolsAdapter {
	return &ToolsAdapter{manager: m}
}

// AllTools implements tools.MCPManager.
func (a *ToolsAdapter) AllTools() []tools.MCPToolInfo {
	mcpTools := a.manager.AllTools()
	result := make([]tools.MCPToolInfo, len(mcpTools))
	for i, t := range mcpTools {
		result[i] = tools.MCPToolInfo{
			ServerName:  t.ServerName,
			Name:        t.Name,
			FullName:    t.FullName,
			Description: t.Description,
			InputSchema: t.InputSchema,
		}
	}
	return result
}

// CallToolByFullName implements tools.MCPManager.
func (a *ToolsAdapter) CallToolByFullName(ctx context.Context, fullName string, argsJSON json.RawMessage) (string, error) {
	return a.manager.CallToolByFullName(ctx, fullName, argsJSON)
}

// ListServers implements tools.MCPManager.
func (a *ToolsAdapter) ListServers() []string {
	return a.manager.ListServers()
}

// Manager returns the underlying MCP manager.
func (a *ToolsAdapter) Manager() *Manager {
	return a.manager
}

