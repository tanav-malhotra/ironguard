package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// ServerConfig holds configuration for an MCP server.
type ServerConfig struct {
	Name    string   `json:"name"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Env     []string `json:"env,omitempty"`
}

// Manager manages multiple MCP server connections.
type Manager struct {
	servers map[string]*Client
	configs map[string]ServerConfig
	mu      sync.RWMutex
}

// NewManager creates a new MCP manager.
func NewManager() *Manager {
	return &Manager{
		servers: make(map[string]*Client),
		configs: make(map[string]ServerConfig),
	}
}

// AddServer adds and connects to an MCP server.
func (m *Manager) AddServer(cfg ServerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already connected
	if _, exists := m.servers[cfg.Name]; exists {
		return fmt.Errorf("server %q already connected", cfg.Name)
	}

	// Create client
	client, err := NewClient(cfg.Command, cfg.Args...)
	if err != nil {
		return fmt.Errorf("failed to start MCP server %q: %w", cfg.Name, err)
	}

	// Initialize
	if err := client.Initialize(); err != nil {
		client.Close()
		return fmt.Errorf("failed to initialize MCP server %q: %w", cfg.Name, err)
	}

	// List tools to cache them
	if _, err := client.ListTools(); err != nil {
		client.Close()
		return fmt.Errorf("failed to list tools from %q: %w", cfg.Name, err)
	}

	m.servers[cfg.Name] = client
	m.configs[cfg.Name] = cfg

	return nil
}

// RemoveServer disconnects and removes an MCP server.
func (m *Manager) RemoveServer(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	client, exists := m.servers[name]
	if !exists {
		return fmt.Errorf("server %q not found", name)
	}

	if err := client.Close(); err != nil {
		return fmt.Errorf("failed to close server %q: %w", name, err)
	}

	delete(m.servers, name)
	delete(m.configs, name)

	return nil
}

// GetServer returns a connected MCP server by name.
func (m *Manager) GetServer(name string) (*Client, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	client, ok := m.servers[name]
	return client, ok
}

// ListServers returns all connected server names.
func (m *Manager) ListServers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.servers))
	for name := range m.servers {
		names = append(names, name)
	}
	return names
}

// MCPToolInfo represents a tool from an MCP server with server context.
// This matches the interface expected by tools.MCPManager.
type MCPToolInfo struct {
	ServerName  string
	Name        string
	FullName    string // serverName/toolName
	Description string
	InputSchema map[string]interface{}
}

// ToToolsInfo converts to the tools package MCPToolInfo type.
func (m MCPToolInfo) ToToolsInfo() interface{} {
	return m
}

// AllTools returns all tools from all connected MCP servers.
// Tools are prefixed with the server name to avoid conflicts.
// Implements tools.MCPManager interface.
func (m *Manager) AllTools() []MCPToolInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var allTools []MCPToolInfo
	for serverName, client := range m.servers {
		for _, tool := range client.Tools() {
			allTools = append(allTools, MCPToolInfo{
				ServerName:  serverName,
				Name:        tool.Name,
				FullName:    fmt.Sprintf("%s/%s", serverName, tool.Name),
				Description: tool.Description,
				InputSchema: tool.InputSchema,
			})
		}
	}
	return allTools
}

// CallTool calls a tool on a specific server.
func (m *Manager) CallTool(ctx context.Context, serverName, toolName string, args map[string]interface{}) (string, error) {
	m.mu.RLock()
	client, exists := m.servers[serverName]
	m.mu.RUnlock()

	if !exists {
		return "", fmt.Errorf("MCP server %q not connected", serverName)
	}

	return client.CallTool(toolName, args)
}

// CallToolByFullName calls a tool using the full name (serverName/toolName).
func (m *Manager) CallToolByFullName(ctx context.Context, fullName string, argsJSON json.RawMessage) (string, error) {
	// Parse server/tool name
	var serverName, toolName string
	for i := 0; i < len(fullName); i++ {
		if fullName[i] == '/' {
			serverName = fullName[:i]
			toolName = fullName[i+1:]
			break
		}
	}

	if serverName == "" || toolName == "" {
		return "", fmt.Errorf("invalid MCP tool name %q (expected serverName/toolName)", fullName)
	}

	// Parse arguments
	var args map[string]interface{}
	if len(argsJSON) > 0 {
		if err := json.Unmarshal(argsJSON, &args); err != nil {
			return "", fmt.Errorf("failed to parse arguments: %w", err)
		}
	}

	return m.CallTool(ctx, serverName, toolName, args)
}

// Close closes all MCP server connections.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error
	for name, client := range m.servers {
		if err := client.Close(); err != nil {
			lastErr = fmt.Errorf("failed to close %q: %w", name, err)
		}
	}

	m.servers = make(map[string]*Client)
	m.configs = make(map[string]ServerConfig)

	return lastErr
}

// ServerInfo returns information about a connected server.
type ServerInfo struct {
	Name      string
	Command   string
	ToolCount int
	Tools     []string
}

// GetServerInfo returns information about a connected server.
func (m *Manager) GetServerInfo(name string) (*ServerInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	client, exists := m.servers[name]
	if !exists {
		return nil, fmt.Errorf("server %q not found", name)
	}

	cfg := m.configs[name]
	tools := client.Tools()
	toolNames := make([]string, len(tools))
	for i, t := range tools {
		toolNames[i] = t.Name
	}

	return &ServerInfo{
		Name:      name,
		Command:   cfg.Command,
		ToolCount: len(tools),
		Tools:     toolNames,
	}, nil
}

