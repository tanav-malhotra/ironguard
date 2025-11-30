package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// Tool represents an executable tool that the AI can call.
type Tool struct {
	Name        string
	Description string
	Parameters  map[string]interface{} // JSON Schema
	Handler     ToolHandler
	Mutating    bool // If true, requires confirmation in confirm mode
}

// ToolHandler is a function that executes a tool.
type ToolHandler func(ctx context.Context, args json.RawMessage) (string, error)

// Registry holds all available tools.
type Registry struct {
	tools      map[string]*Tool
	mcpManager MCPManager // Optional MCP manager for external tools
}

// MCPManager interface for MCP tool integration.
// Implemented by mcp.Manager.
type MCPManager interface {
	AllTools() []MCPToolInfo
	CallToolByFullName(ctx context.Context, fullName string, argsJSON json.RawMessage) (string, error)
	ListServers() []string
}

// MCPToolInfo represents a tool from an MCP server.
type MCPToolInfo struct {
	ServerName  string
	Name        string
	FullName    string
	Description string
	InputSchema map[string]interface{}
}

// MCPToolCount returns the number of MCP tools available.
func (r *Registry) MCPToolCount() int {
	if r.mcpManager == nil {
		return 0
	}
	return len(r.mcpManager.AllTools())
}

// MCPServers returns the list of connected MCP server names.
func (r *Registry) MCPServers() []string {
	if r.mcpManager == nil {
		return nil
	}
	return r.mcpManager.ListServers()
}

// NewRegistry creates a new tool registry with default tools.
func NewRegistry() *Registry {
	r := &Registry{
		tools: make(map[string]*Tool),
	}
	r.registerDefaults()
	r.RegisterHardenTools()         // Add CyberPatriot hardening tools
	r.RegisterScoringTools()        // Add scoring report tools
	r.RegisterWebTools()            // Add web search and URL fetching
	r.RegisterManualTaskTools()     // Add manual task management
	r.RegisterScreenshotTools()     // Add screenshot and image tools
	r.RegisterDesktopControlTools() // Add mouse/keyboard control for full desktop interaction
	r.RegisterAITodoTools()         // Add AI todo list management
	r.RegisterSubAgentTools()       // Add subagent spawning and management
	registerMemoryTools(r)          // Add persistent memory tools
	return r
}

// Register adds a tool to the registry.
func (r *Registry) Register(t *Tool) {
	r.tools[t.Name] = t
}

// Get returns a tool by name.
func (r *Registry) Get(name string) (*Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

// All returns all registered tools (including MCP tools).
func (r *Registry) All() []*Tool {
	var tools []*Tool
	for _, t := range r.tools {
		tools = append(tools, t)
	}

	// Add MCP tools if available
	if r.mcpManager != nil {
		for _, mcpTool := range r.mcpManager.AllTools() {
			tools = append(tools, &Tool{
				Name:        mcpTool.FullName,
				Description: fmt.Sprintf("[MCP:%s] %s", mcpTool.ServerName, mcpTool.Description),
				Parameters:  mcpTool.InputSchema,
				Mutating:    true, // Assume MCP tools are mutating for safety
			})
		}
	}

	return tools
}

// SetMCPManager sets the MCP manager for external tool support.
func (r *Registry) SetMCPManager(m MCPManager) {
	r.mcpManager = m
}

// GetMCPManager returns the current MCP manager.
func (r *Registry) GetMCPManager() MCPManager {
	return r.mcpManager
}

// ToLLMTools converts the registry to LLM tool definitions.
func (r *Registry) ToLLMTools() []map[string]interface{} {
	var tools []map[string]interface{}
	for _, t := range r.tools {
		tools = append(tools, map[string]interface{}{
			"name":        t.Name,
			"description": t.Description,
			"parameters":  t.Parameters,
		})
	}
	return tools
}

// Execute runs a tool by name with the given arguments.
func (r *Registry) Execute(ctx context.Context, name string, args json.RawMessage) (string, error) {
	tool, ok := r.tools[name]
	if ok {
		return tool.Handler(ctx, args)
	}

	// Check if it's an MCP tool (format: serverName/toolName)
	if r.mcpManager != nil {
		for _, mcpTool := range r.mcpManager.AllTools() {
			if mcpTool.FullName == name {
				return r.mcpManager.CallToolByFullName(ctx, name, args)
			}
		}
	}

	return "", fmt.Errorf("unknown tool: %s", name)
}

// IsMutating returns true if the tool modifies system state.
func (r *Registry) IsMutating(name string) bool {
	tool, ok := r.tools[name]
	if !ok {
		return true // Assume mutating if unknown
	}
	return tool.Mutating
}

func (r *Registry) registerDefaults() {
	// Read file tool
	r.Register(&Tool{
		Name:        "read_file",
		Description: "Read the contents of a file at the specified path",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "The file path to read",
				},
			},
			"required": []string{"path"},
		},
		Handler:  toolReadFile,
		Mutating: false,
	})

	// Write file tool
	r.Register(&Tool{
		Name:        "write_file",
		Description: "Write content to a file at the specified path",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "The file path to write to",
				},
				"content": map[string]interface{}{
					"type":        "string",
					"description": "The content to write",
				},
			},
			"required": []string{"path", "content"},
		},
		Handler:  toolWriteFile,
		Mutating: true,
	})

	// List directory tool
	r.Register(&Tool{
		Name:        "list_dir",
		Description: "List files and directories in the specified path",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "The directory path to list",
				},
			},
			"required": []string{"path"},
		},
		Handler:  toolListDir,
		Mutating: false,
	})

	// Run command tool with persistent shell session
	r.Register(&Tool{
		Name:        "run_command",
		Description: "Execute a shell command in a persistent shell session. The shell maintains state (working directory, environment variables, aliases) across commands. Use PowerShell on Windows, bash on Linux. Set new_session=true to start a fresh shell.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"command": map[string]interface{}{
					"type":        "string",
					"description": "The command to execute",
				},
				"new_session": map[string]interface{}{
					"type":        "boolean",
					"description": "If true, terminate the current shell and start a fresh session. Useful if the shell gets into a bad state. Default: false",
					"default":    false,
				},
			},
			"required": []string{"command"},
		},
		Handler:  toolRunCommand,
		Mutating: true,
	})

	// Get shell working directory tool
	r.Register(&Tool{
		Name:        "get_shell_cwd",
		Description: "Get the current working directory of the persistent shell session",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler:  toolGetShellCwd,
		Mutating: false,
	})

	// Reset shell session tool
	r.Register(&Tool{
		Name:        "reset_shell",
		Description: "Terminate the current shell session and prepare for a fresh start. Use this if the shell gets into a bad state or you need a clean environment.",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler:  toolResetShell,
		Mutating: false,
	})

	// Read README tool (CyberPatriot specific)
	r.Register(&Tool{
		Name:        "read_readme",
		Description: "Read the CyberPatriot README file from the current user's Desktop",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler:  toolReadReadme,
		Mutating: false,
	})

	// Read forensics questions tool
	r.Register(&Tool{
		Name:        "read_forensics",
		Description: "Read all forensics question files from the Desktop",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler:  toolReadForensics,
		Mutating: false,
	})

	// Write forensics answer tool
	r.Register(&Tool{
		Name:        "write_answer",
		Description: "Write an answer to a forensics question file. The answer will be appended in the correct format.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"question_file": map[string]interface{}{
					"type":        "string",
					"description": "The forensics question filename (e.g., 'Forensics Question 1.txt')",
				},
				"answer": map[string]interface{}{
					"type":        "string",
					"description": "The answer to write",
				},
			},
			"required": []string{"question_file", "answer"},
		},
		Handler:  toolWriteAnswer,
		Mutating: true,
	})

	// Get system info tool
	r.Register(&Tool{
		Name:        "get_system_info",
		Description: "Get information about the current system (OS, architecture, hostname, users, etc.)",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler:  toolGetSystemInfo,
		Mutating: false,
	})

	// Search files tool
	r.Register(&Tool{
		Name:        "search_files",
		Description: "Search for files matching a pattern in a directory",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{
					"type":        "string",
					"description": "The directory to search in",
				},
				"pattern": map[string]interface{}{
					"type":        "string",
					"description": "The glob pattern to match (e.g., '*.txt', '*.log')",
				},
			},
			"required": []string{"path", "pattern"},
		},
		Handler:  toolSearchFiles,
		Mutating: false,
	})
}

// Tool implementations

func toolReadFile(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	content, err := os.ReadFile(params.Path)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	return string(content), nil
}

func toolWriteFile(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(params.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(params.Path, []byte(params.Content), 0644); err != nil {
		return "", fmt.Errorf("failed to write file: %w", err)
	}

	return fmt.Sprintf("Successfully wrote %d bytes to %s", len(params.Content), params.Path), nil
}

func toolListDir(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	entries, err := os.ReadDir(params.Path)
	if err != nil {
		return "", fmt.Errorf("failed to list directory: %w", err)
	}

	var lines []string
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		typeStr := "file"
		if entry.IsDir() {
			typeStr = "dir"
		}
		lines = append(lines, fmt.Sprintf("[%s] %s (%d bytes)", typeStr, entry.Name(), info.Size()))
	}

	return strings.Join(lines, "\n"), nil
}

func toolRunCommand(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Command    string `json:"command"`
		NewSession bool   `json:"new_session"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	return RunCommand(ctx, params.Command, params.NewSession)
}

func toolGetShellCwd(ctx context.Context, args json.RawMessage) (string, error) {
	cwd, err := GetShellCwd(ctx)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Current shell working directory: %s", cwd), nil
}

func toolResetShell(ctx context.Context, args json.RawMessage) (string, error) {
	ResetShellSession()
	return "Shell session has been reset. A fresh shell will be started on the next command.", nil
}

func toolReadReadme(ctx context.Context, args json.RawMessage) (string, error) {
	desktop := getDesktopPath()

	// CyberPatriot README is always an HTML file on Desktop
	patterns := []string{
		filepath.Join(desktop, "README.html"),
		filepath.Join(desktop, "README.htm"),
		filepath.Join(desktop, "Readme.html"),
		filepath.Join(desktop, "readme.html"),
		filepath.Join(desktop, "*README*.html"),
		filepath.Join(desktop, "*[Rr]eadme*.html"),
		filepath.Join(desktop, "*[Rr]eadme*.htm"),
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			content, err := os.ReadFile(match)
			if err == nil {
				// Strip HTML tags for easier reading
				text := stripHTML(string(content))
				return fmt.Sprintf("=== %s ===\n%s", filepath.Base(match), text), nil
			}
		}
	}

	return "", fmt.Errorf("no README.html file found on Desktop at %s", desktop)
}

func toolReadForensics(ctx context.Context, args json.RawMessage) (string, error) {
	desktop := getDesktopPath()

	// CyberPatriot forensics questions are always TXT files on Desktop
	patterns := []string{
		filepath.Join(desktop, "Forensics Question *.txt"),
		filepath.Join(desktop, "Forensics*.txt"),
		filepath.Join(desktop, "forensics*.txt"),
		filepath.Join(desktop, "*[Ff]orensic*.txt"),
		filepath.Join(desktop, "*[Qq]uestion*.txt"),
	}

	var results []string
	seen := make(map[string]bool)

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			if seen[match] {
				continue
			}
			// Only process .txt files
			if !strings.HasSuffix(strings.ToLower(match), ".txt") {
				continue
			}
			seen[match] = true

			content, err := os.ReadFile(match)
			if err != nil {
				continue
			}
			results = append(results, fmt.Sprintf("=== %s ===\n%s", filepath.Base(match), string(content)))
		}
	}

	if len(results) == 0 {
		return "", fmt.Errorf("no forensics .txt files found on Desktop at %s", desktop)
	}

	return strings.Join(results, "\n\n"), nil
}

func toolWriteAnswer(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		QuestionFile string `json:"question_file"`
		Answer       string `json:"answer"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	desktop := getDesktopPath()
	filePath := filepath.Join(desktop, params.QuestionFile)

	// Read existing content
	existing, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read question file: %w", err)
	}

	// Check if ANSWER: line already exists
	content := string(existing)
	if strings.Contains(content, "ANSWER:") {
		// Replace existing answer
		lines := strings.Split(content, "\n")
		var newLines []string
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "ANSWER:") {
				newLines = append(newLines, "ANSWER: "+params.Answer)
			} else {
				newLines = append(newLines, line)
			}
		}
		content = strings.Join(newLines, "\n")
	} else {
		// Append answer
		content = strings.TrimRight(content, "\n") + "\n\nANSWER: " + params.Answer + "\n"
	}

	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("failed to write answer: %w", err)
	}

	return fmt.Sprintf("Answer written to %s", params.QuestionFile), nil
}

func toolGetSystemInfo(ctx context.Context, args json.RawMessage) (string, error) {
	info := []string{
		fmt.Sprintf("OS: %s", runtime.GOOS),
		fmt.Sprintf("Architecture: %s", runtime.GOARCH),
	}

	hostname, err := os.Hostname()
	if err == nil {
		info = append(info, fmt.Sprintf("Hostname: %s", hostname))
	}

	// Get current user
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command", "$env:USERNAME")
		if output, err := cmd.Output(); err == nil {
			info = append(info, fmt.Sprintf("Current User: %s", strings.TrimSpace(string(output))))
		}

		// Get all users
		cmd = exec.Command("powershell", "-NoProfile", "-Command", "Get-LocalUser | Select-Object Name, Enabled | Format-Table -AutoSize")
		if output, err := cmd.Output(); err == nil {
			info = append(info, fmt.Sprintf("\nLocal Users:\n%s", string(output)))
		}
	} else {
		cmd := exec.Command("whoami")
		if output, err := cmd.Output(); err == nil {
			info = append(info, fmt.Sprintf("Current User: %s", strings.TrimSpace(string(output))))
		}

		// Get all users
		cmd = exec.Command("bash", "-c", "cut -d: -f1 /etc/passwd | head -20")
		if output, err := cmd.Output(); err == nil {
			info = append(info, fmt.Sprintf("\nSystem Users:\n%s", string(output)))
		}
	}

	return strings.Join(info, "\n"), nil
}

func toolSearchFiles(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Path    string `json:"path"`
		Pattern string `json:"pattern"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	var matches []string
	err := filepath.Walk(params.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		matched, err := filepath.Match(params.Pattern, info.Name())
		if err != nil {
			return nil
		}
		if matched {
			matches = append(matches, path)
		}
		return nil
	})

	if err != nil {
		return "", fmt.Errorf("search failed: %w", err)
	}

	if len(matches) == 0 {
		return "No files found matching pattern", nil
	}

	return strings.Join(matches, "\n"), nil
}

// Helper functions

func getDesktopPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}

	if runtime.GOOS == "windows" {
		return filepath.Join(home, "Desktop")
	}
	// Linux - try common locations
	desktop := filepath.Join(home, "Desktop")
	if _, err := os.Stat(desktop); err == nil {
		return desktop
	}
	return filepath.Join(home, "desktop")
}

// stripHTML removes HTML tags and decodes common entities for easier reading.
func stripHTML(html string) string {
	// Remove script and style blocks entirely
	scriptRegex := regexp.MustCompile(`(?is)<script.*?</script>`)
	html = scriptRegex.ReplaceAllString(html, "")
	styleRegex := regexp.MustCompile(`(?is)<style.*?</style>`)
	html = styleRegex.ReplaceAllString(html, "")

	// Replace common block elements with newlines
	blockRegex := regexp.MustCompile(`(?i)</(p|div|br|tr|li|h[1-6])>`)
	html = blockRegex.ReplaceAllString(html, "\n")
	brRegex := regexp.MustCompile(`(?i)<br\s*/?>`)
	html = brRegex.ReplaceAllString(html, "\n")

	// Remove all remaining HTML tags
	tagRegex := regexp.MustCompile(`<[^>]*>`)
	html = tagRegex.ReplaceAllString(html, "")

	// Decode common HTML entities
	html = strings.ReplaceAll(html, "&nbsp;", " ")
	html = strings.ReplaceAll(html, "&amp;", "&")
	html = strings.ReplaceAll(html, "&lt;", "<")
	html = strings.ReplaceAll(html, "&gt;", ">")
	html = strings.ReplaceAll(html, "&quot;", "\"")
	html = strings.ReplaceAll(html, "&#39;", "'")
	html = strings.ReplaceAll(html, "&apos;", "'")

	// Clean up excessive whitespace
	spaceRegex := regexp.MustCompile(`[ \t]+`)
	html = spaceRegex.ReplaceAllString(html, " ")
	newlineRegex := regexp.MustCompile(`\n{3,}`)
	html = newlineRegex.ReplaceAllString(html, "\n\n")

	return strings.TrimSpace(html)
}
