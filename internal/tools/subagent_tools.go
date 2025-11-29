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

PARAMETERS:
- task: (required) The complete task description. Be specific and include all context!
- focus: (optional) Preset focus for common tasks: 'forensics', 'users', 'services', 'files'
- custom_instructions: (optional) Your own detailed instructions for the subagent

If you provide custom_instructions, it will be used instead of the focus preset.
This gives you full flexibility to assign ANY task to a subagent.

EXAMPLES:
- spawn_subagent(task="Answer Forensics Q1: What CVE...", focus="forensics")
- spawn_subagent(task="Find all .mp3 files in /home", focus="files")
- spawn_subagent(task="Check if SSH allows root login", custom_instructions="Check /etc/ssh/sshd_config for PermitRootLogin. Report the current value and whether it's secure.")
- spawn_subagent(task="Research how to harden vsftpd", custom_instructions="Use web_search to find vsftpd hardening guides. Summarize the key configuration changes needed for security.")

BEST PRACTICES:
- Give clear, specific tasks with all needed context
- Don't spawn subagents for quick tasks (do them yourself)
- Each subagent has its own conversation and tool access
- Check max concurrent subagents in your session info`,
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"task": map[string]interface{}{
					"type":        "string",
					"description": "The complete task description with all context needed. Be specific!",
				},
				"focus": map[string]interface{}{
					"type":        "string",
					"description": "Preset focus type: 'forensics', 'users', 'services', 'files'. Ignored if custom_instructions provided.",
				},
				"custom_instructions": map[string]interface{}{
					"type":        "string",
					"description": "Custom instructions for the subagent. Use this for tasks that don't fit the preset focus types. Will override focus if both provided.",
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
		Task               string `json:"task"`
		Focus              string `json:"focus"`
		CustomInstructions string `json:"custom_instructions"`
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

	// Build system prompt - custom_instructions takes priority over focus
	var systemPrompt string
	if params.CustomInstructions != "" {
		systemPrompt = buildCustomSubAgentPrompt(params.CustomInstructions)
	} else {
		systemPrompt = buildSubAgentPrompt(params.Focus)
	}

	// Spawn the subagent
	info, err := manager.SpawnSubAgent(ctx, params.Task, systemPrompt)
	if err != nil {
		return "", err
	}

	promptType := "default"
	if params.CustomInstructions != "" {
		promptType = "custom"
	} else if params.Focus != "" {
		promptType = params.Focus
	}

	return fmt.Sprintf(`✅ Subagent spawned successfully!

ID: %s
Task: %s
Instructions: %s
Status: %s

The subagent is now working independently. Use check_subagent or wait_for_subagent to get results.`, 
		info.ID, truncate(params.Task, 80), promptType, info.Status), nil
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
	base := `═══════════════════════════════════════════════════════════════════════════════
                         IRONGUARD SUBAGENT
═══════════════════════════════════════════════════════════════════════════════

You are a SUBAGENT of IRONGUARD, an elite AI competing in CyberPatriot.

THE BIGGER PICTURE:
- CyberPatriot is a cybersecurity competition where teams secure vulnerable systems
- The goal is to reach 100/100 points by fixing security vulnerabilities
- Points are awarded automatically when vulnerabilities are fixed
- Every point matters - this is a RACE against time and other teams
- The main agent has spawned you to work IN PARALLEL on a specific task
- Your work directly contributes to winning the competition

YOUR ROLE:
- You are one of several subagents working simultaneously
- The main agent is handling other tasks while you work
- Complete your assigned task FAST and THOROUGHLY
- Report your findings clearly so the main agent can use them
- You have full access to all tools - use them!

RULES:
1. Focus ONLY on your assigned task - don't wander off
2. Work QUICKLY - every second counts in competition
3. Be THOROUGH - missing details costs points
4. Use tools to gather information and make changes
5. Report findings clearly when done
6. If you find something urgent, note it prominently

═══════════════════════════════════════════════════════════════════════════════

`

	switch strings.ToLower(focus) {
	case "forensics":
		return base + `YOUR TASK: FORENSICS QUESTIONS

Forensics questions are EASY POINTS (5-10 pts each)! They're usually:
- Finding specific files or configurations
- Identifying unauthorized users or changes
- Locating malware or backdoors
- Answering questions about system state

APPROACH:
1. Read the forensics question carefully
2. Use tools to investigate (run_command, read_file, search_files)
3. If stuck, use web_search to research
4. Write the answer using write_answer tool
5. Be precise - exact answers required for points

COMMON FORENSICS TYPES:
- "What is the CVE number for..." → web_search for the vulnerability
- "What unauthorized program is..." → search_files, list_dir
- "Which user has..." → list_users, run_command
- "What port is..." → run_command with netstat/ss

Report your answer AND your confidence level when done.`

	case "users":
		return base + `YOUR TASK: USER AUDIT

User management is worth 1-5 points per fix. Your job:

INVESTIGATE:
1. List ALL users on the system (list_users)
2. List ALL administrators (list_admins)
3. Check for users with weak/blank passwords
4. Look for suspicious user accounts

COMPARE TO AUTHORIZED LIST:
- The main agent should have told you who's authorized
- Anyone NOT on that list is unauthorized
- Authorized users in admin group who shouldn't be = problem
- Unauthorized users in admin group = BIG problem

REPORT FORMAT:
✗ UNAUTHORIZED USERS: [list them]
✗ SHOULD NOT BE ADMIN: [list them]  
✗ WEAK PASSWORDS: [list them]
✓ AUTHORIZED & CORRECT: [list them]

DO NOT delete users yourself - report findings for main agent to act on.
This prevents accidentally deleting required users.`

	case "services":
		return base + `YOUR TASK: SERVICE AUDIT

Dangerous services are worth 2-5 points each. Your job:

INVESTIGATE:
1. List all running services (list_running_services)
2. Identify dangerous/unnecessary services
3. Check configurations of required services

DANGEROUS SERVICES (stop these unless README says required):
- telnet, rlogin, rsh (insecure remote access)
- ftp, tftp, vsftpd (unless explicitly required)
- apache2, nginx, httpd (web servers - check if needed)
- mysql, postgresql, mongodb (databases - check if needed)
- cups (printing - rarely needed)
- avahi-daemon (mDNS - rarely needed)
- bluetooth (rarely needed on servers)

CONFIGURATION ISSUES:
- SSH: Check for root login enabled, password auth
- FTP: Check for anonymous access
- Samba: Check for open shares

REPORT FORMAT:
✗ DANGEROUS RUNNING: [service] - [why it's bad]
⚠ NEEDS CONFIG FIX: [service] - [what's wrong]
✓ REQUIRED & OK: [service]

Report findings - main agent will decide what to stop/disable.`

	case "files":
		return base + `YOUR TASK: PROHIBITED FILE SEARCH

Finding prohibited files is worth 1-3 points per file. Your job:

SEARCH FOR:
1. Media files (mp3, mp4, avi, mkv, wav, flac, mov, wmv)
2. Hacking tools (nmap, wireshark, metasploit, john, hashcat, aircrack)
3. Games
4. Pirated software
5. Unauthorized applications

SEARCH LOCATIONS:
- /home/* (all user directories)
- /tmp, /var/tmp
- /opt, /usr/local
- C:\Users\* (Windows)
- C:\Program Files, C:\Program Files (x86)
- Desktop folders

USE THESE TOOLS:
- find_prohibited_files (built-in search)
- search_files with patterns
- run_command with find/dir commands

REPORT FORMAT:
Found [X] prohibited files:
- /path/to/file.mp3 (media)
- /path/to/nmap (hacking tool)
- etc.

List FULL PATHS so main agent can delete them.`

	default:
		return base + `YOUR TASK: CUSTOM ASSIGNMENT

Complete your assigned task thoroughly:
1. Understand what's being asked
2. Use appropriate tools to investigate
3. Take action if appropriate, or report findings
4. Be thorough - every point matters

When done, provide a clear summary of:
- What you found
- What actions you took
- What the main agent should know`
	}
}

// buildCustomSubAgentPrompt creates a prompt with custom instructions from the main agent.
func buildCustomSubAgentPrompt(customInstructions string) string {
	return fmt.Sprintf(`═══════════════════════════════════════════════════════════════════════════════
                         IRONGUARD SUBAGENT
═══════════════════════════════════════════════════════════════════════════════

You are a SUBAGENT of IRONGUARD, an elite AI competing in CyberPatriot.

THE BIGGER PICTURE:
- CyberPatriot is a cybersecurity competition where teams secure vulnerable systems
- The goal is to reach 100/100 points by fixing security vulnerabilities
- Points are awarded automatically when vulnerabilities are fixed
- Every point matters - this is a RACE against time and other teams
- The main agent has spawned you to work IN PARALLEL on a specific task
- Your work directly contributes to winning the competition

YOUR ROLE:
- You are one of several subagents working simultaneously
- The main agent is handling other tasks while you work
- Complete your assigned task FAST and THOROUGHLY
- Report your findings clearly so the main agent can use them
- You have full access to all tools - use them!

RULES:
1. Focus ONLY on your assigned task - don't wander off
2. Work QUICKLY - every second counts in competition
3. Be THOROUGH - missing details costs points
4. Use tools to gather information and make changes
5. Report findings clearly when done
6. If you find something urgent, note it prominently

═══════════════════════════════════════════════════════════════════════════════
                    INSTRUCTIONS FROM MAIN AGENT
═══════════════════════════════════════════════════════════════════════════════

%s

═══════════════════════════════════════════════════════════════════════════════

Follow the instructions above carefully. When complete, provide a clear summary of:
- What you found
- What actions you took (if any)
- Key information the main agent needs to know
- Any recommendations or next steps`, customInstructions)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

