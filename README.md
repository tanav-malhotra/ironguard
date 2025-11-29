# IRONGUARD 🛡️

**The AI-Powered CyberPatriot Competition Dominator**

A fully autonomous AI agent that can harden CyberPatriot images and achieve 100/100 in under 30 minutes.

![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

## Features

### Core Capabilities
- **🤖 Fully Autonomous**: Just type `/harden` and the AI does everything - reads README, answers forensics, fixes vulnerabilities
- **📊 Score Tracking**: Monitors score after each action, automatically undoes if penalties occur
- **🎯 Competition-Optimized**: Trained on every past CyberPatriot scoring report and answer key
- **💬 Multi-Provider AI**: Claude (default), OpenAI GPT, or Google Gemini
- **🔧 Native Tools**: 50+ built-in hardening tools - no external scripts needed
- **👥 Team-Friendly**: Ctrl+C pauses AI (doesn't quit), safe for teammates copying text

### Claude Code-Style UI
- **🖥️ Beautiful TUI**: Claude Code-inspired terminal interface with real-time streaming
- **💭 Thinking Display**: See the AI's reasoning process as it works (collapsible)
- **🤖 Sub-Agents**: AI can spawn parallel workers for faster completion
- **📁 Collapsible Output**: Tool outputs collapse automatically, expand on demand
- **📊 Progress Indicators**: Visual feedback on long-running operations
- **📝 Diff View**: See file changes before they're applied

### Advanced Features
- **🖱️ Screen Observation**: AI can see your screen (optional control mode for Packet Tracer)
- **🔌 MCP Support**: Connect external MCP servers to give AI even more capabilities
- **📋 Manual Tasks**: AI can assign GUI-only tasks to human teammates

## Quick Start

### 1. Download

```bash
# Windows (PowerShell as Admin)
Invoke-WebRequest -Uri "https://github.com/tanav-malhotra/ironguard/releases/latest/download/ironguard-windows-amd64.exe" -OutFile "ironguard.exe"

# Linux
curl -L -o ironguard https://github.com/tanav-malhotra/ironguard/releases/latest/download/ironguard-linux-amd64
chmod +x ironguard
```

### 2. Run

```bash
# Windows (as Administrator!)
.\ironguard.exe

# Linux (as root!)
sudo ./ironguard
```

### 3. Set API Key & Start

```
/key sk-your-anthropic-api-key
/harden
```

When you run `/harden` without arguments, it will **auto-detect your OS** and show options:

```
🔍 DETECTED SYSTEM: Windows 10 (19045)

Choose hardening mode:
  /harden windows        - Windows 10/11 desktop
  /harden windows-server - Windows Server
  /harden linux          - Ubuntu/Debian/Linux Mint
  /harden packet-tracer  - Cisco Packet Tracer (needs /screen control)
  /harden auto           - Auto-detect and start
```

**That's it!** The AI will now automatically:
- ✅ Read the README (authorized users, services, restrictions)
- ✅ Read and answer forensics questions (5-10 pts each!)
- ✅ Delete unauthorized users
- ✅ Fix all vulnerabilities
- ✅ Check score after each action
- ✅ Keep working until 100/100

## Commands Reference

### Essential Commands

| Command | Description |
|---------|-------------|
| `/harden` | **Show OS detection and mode selection** |
| `/harden windows` | Start hardening for Windows 10/11 |
| `/harden windows-server` | Start hardening for Windows Server |
| `/harden linux` | Start hardening for Ubuntu/Debian/Linux |
| `/harden packet-tracer` | Start Packet Tracer mode (requires `/screen control`) |
| `/harden auto` | Auto-detect OS and start immediately |
| `/auto [target]` | Same as `/harden auto`, optionally set target score (default: 100) |
| `/stop` | Stop the AI |
| `/key <api-key>` | Set API key for current provider |
| `/score` | Check current score |
| `/help` | Show all commands |
| `/quit` | Exit ironguard |

### Manual Commands (if you want to guide the AI)

| Command | Description |
|---------|-------------|
| `/readme` | Read the CyberPatriot README |
| `/forensics` | Read forensics questions |
| `/answer <num> <answer>` | Write answer to forensics question |
| `/run <command>` | Run a terminal command |
| `/search <query>` | Web search for help |

### Configuration Commands

| Command | Description |
|---------|-------------|
| `/provider <claude\|openai\|gemini>` | Switch AI provider |
| `/model <name>` | Set the model |
| `/models` | List available models |
| `/confirm` | Enable confirm mode (ask before actions) |
| `/autopilot` | Enable autopilot mode (default) |
| `/screen <observe\|control>` | Set screen interaction mode |
| `/mode <harden\|packet-tracer\|quiz>` | Set competition mode |
| `/status` | Show current configuration |

### Task Management

| Command | Description |
|---------|-------------|
| `/manual <task>` | Add a manual task for human teammate |
| `/tasks` | List manual tasks |
| `/done <num>` | Mark manual task as done |

### MCP Server Commands

| Command | Description |
|---------|-------------|
| `/mcp-add <name> <command> [args...]` | Connect to an MCP server |
| `/mcp-remove <name>` | Disconnect an MCP server |
| `/mcp-list` | List connected MCP servers |
| `/mcp-tools [server]` | List tools from MCP servers |

## Keybindings

| Key | Action |
|-----|--------|
| **Ctrl+C** | **Pause AI** (doesn't quit! Safe for copying text) |
| **Ctrl+Q** | Quit ironguard |
| **Esc** | Cancel current action / Close autocomplete |
| **Ctrl+L** | Clear screen |
| **Tab** | Cycle autocomplete suggestions |
| **Enter** | Send message |
| **Up/Down** | Scroll chat history |

> ⚠️ **Note for teammates**: Ctrl+C does NOT quit the app! It only pauses the AI. Use Ctrl+Q or `/quit` to exit.

## Competition Modes

### 1. Hardening Mode (Default)
For Windows/Linux CyberPatriot images. The AI will:
- Read README and forensics automatically
- Fix users, services, policies, files
- Track score and avoid penalties

```
/mode harden
/harden
```

### 2. Packet Tracer Mode
For Cisco Packet Tracer challenges. Requires screen control because the AI needs to see and interact with the GUI:

```
/screen control
/harden packet-tracer
```

The AI will:
- Take frequent screenshots to see the topology
- Click on devices and configure them
- Use keyboard to enter commands
- Navigate the Packet Tracer interface

### 3. Network Quiz Mode
For NetAcad and similar quizzes:

```
/mode quiz
/screen control
```

## AI Tools Reference

The AI has access to **40+ built-in tools** that it uses automatically during hardening. Understanding these tools helps you know what the AI can do and when to step in manually.

### CyberPatriot Competition Tools

| Tool | Description | When AI Uses It |
|------|-------------|-----------------|
| `read_readme` | Reads the README.html/README.txt from the Desktop | **First thing** - to understand authorized users, services, and restrictions |
| `read_forensics` | Finds and reads all Forensics Question files from Desktop | Early - forensics are easy points (5-10 pts each) |
| `write_answer` | Writes an answer to a forensics question file | After figuring out the answer to a forensics question |
| `read_score_report` | Reads the CyberPatriot scoring report HTML file | Frequently - to check current score and see what's been fixed |
| `check_score_improved` | Compares current score to previous score | After every 2-3 actions to verify points gained, not lost |
| `security_audit` | Runs a comprehensive security scan of the system | At start and end to find vulnerabilities |

### User Management Tools

| Tool | Description | When AI Uses It |
|------|-------------|-----------------|
| `list_users` | Lists all user accounts on the system | To compare against README's authorized users list |
| `list_admins` | Lists all users in the Administrators/sudo group | To find unauthorized admins |
| `disable_user` | Disables a user account (doesn't delete) | When unsure if user should be deleted |
| `delete_user` | Permanently deletes a user account | For clearly unauthorized users not in README |
| `set_password` | Sets or changes a user's password | For users with weak/blank passwords |
| `remove_from_admins` | Removes a user from admin/sudo group | For users who are authorized but shouldn't be admins |

### Service Management Tools

| Tool | Description | When AI Uses It |
|------|-------------|-----------------|
| `list_services` | Lists all services (running and stopped) | To audit what's installed |
| `list_running_services` | Lists only currently running services | To find services that should be stopped |
| `stop_service` | Stops a running service | For dangerous services like telnet, ftp |
| `disable_service` | Prevents a service from starting at boot | After stopping unnecessary services |

### System Hardening Tools

| Tool | Description | When AI Uses It |
|------|-------------|-----------------|
| `enable_firewall` | Enables Windows Firewall or UFW | Early - quick points, important security |
| `check_updates` | Checks for available system updates | To see if updates are needed |
| `install_updates` | Installs system updates | If README allows updates |
| `set_password_policy` | Configures password complexity, length, history | For password policy vulnerabilities |
| `disable_guest` | Disables the Guest account | Early - almost always gives points |
| `find_prohibited_files` | Searches for media files (mp3, mp4, avi, etc.) | To find prohibited files in user directories |

### File Operations Tools

| Tool | Description | When AI Uses It |
|------|-------------|-----------------|
| `read_file` | Reads the contents of any file | To examine config files, logs, scripts |
| `write_file` | Creates or overwrites a file | To fix config files (sshd_config, etc.) |
| `list_dir` | Lists contents of a directory | To explore directories for prohibited files |
| `search_files` | Searches for files by name pattern | To find specific files or file types |
| `delete_file` | Deletes a file | To remove prohibited media files, malware |

### Screen Interaction Tools (Packet Tracer/Quiz Mode)

| Tool | Description | When AI Uses It |
|------|-------------|-----------------|
| `take_screenshot` | Captures the current screen | To see Packet Tracer topology or quiz questions |
| `mouse_click` | Clicks at specific screen coordinates | To interact with GUI applications |
| `keyboard_type` | Types text into the focused application | To enter commands or answers |
| `keyboard_hotkey` | Presses key combinations (Ctrl+S, etc.) | For shortcuts in applications |
| `list_windows` | Lists all open windows | To find the right application window |
| `focus_window` | Brings a window to the foreground | To switch between applications |

> ⚠️ **Note**: Screen control tools only work when `/screen control` is enabled. Default is observe-only.
> 
> If the AI tries to use these tools in observe mode, it will receive a clear error message explaining that screen control is disabled and how to enable it.

### Web & Research Tools

| Tool | Description | When AI Uses It |
|------|-------------|-----------------|
| `web_search` | Searches the web using DuckDuckGo | When stuck on a forensics question or unfamiliar vulnerability |
| `fetch_url` | Fetches and reads a webpage | To get detailed information from a specific URL |

### Team Collaboration Tools

| Tool | Description | When AI Uses It |
|------|-------------|-----------------|
| `add_manual_task` | Adds a task to the sidebar for human teammate | For GUI-only tasks the AI can't do (like Windows Settings) |
| `list_manual_tasks` | Shows all pending manual tasks | To check what needs human attention |

### Sub-Agent Tools (Parallel Execution)

| Tool | Description | When AI Uses It |
|------|-------------|-----------------|
| `spawn_subagent` | Creates a child AI to work on a task in parallel | For tasks that can run independently (forensics research, file searches) |
| `check_subagent` | Checks status and result of a subagent | To see if a parallel task is done |
| `list_subagents` | Lists all spawned subagents | To track parallel work |
| `wait_for_subagent` | Waits for a subagent to complete | When main agent needs subagent's result |
| `cancel_subagent` | Cancels a running subagent | If task is no longer needed |

> **How Sub-Agents Work**: The AI can spawn up to 4 parallel workers. Each subagent has full tool access and works independently. This enables faster completion - e.g., one agent handles forensics while another audits users.

### Shell Session Tools

| Tool | Description | When AI Uses It |
|------|-------------|-----------------|
| `run_command` | Runs a command in the persistent shell session | For anything not covered by specific tools |
| `get_shell_cwd` | Gets the current working directory of the shell | To check where commands will run |
| `reset_shell` | Terminates and resets the shell session | If the shell gets into a bad state |

> **Persistent Shell Sessions**: The `run_command` tool maintains a persistent shell session where the working directory persists across commands. If you `cd /some/path` and then run another command, it will execute in `/some/path`. Use `new_session: true` parameter to start a fresh shell if needed.

### General Tools

| Tool | Description | When AI Uses It |
|------|-------------|-----------------|
| `get_system_info` | Gets OS version, architecture, hostname | At start to determine which hardening steps to use |

## MCP Server Integration

IRONGUARD supports the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) for extending AI capabilities with external tools. MCP servers provide additional tools that the AI can use automatically.

### Connecting MCP Servers

```bash
# Add a filesystem server (gives AI access to a specific directory)
/mcp-add filesystem npx -y @modelcontextprotocol/server-filesystem /path/to/dir

# Add Brave Search (web search capabilities)
/mcp-add brave-search npx -y @anthropic/mcp-server-brave-search

# Add GitHub integration
/mcp-add github npx -y @anthropic/mcp-server-github

# Add Puppeteer for browser automation
/mcp-add puppeteer npx -y @anthropic/mcp-server-puppeteer
```

### Managing MCP Servers

```bash
# List connected servers and their tool counts
/mcp-list

# See all tools from a specific server
/mcp-tools filesystem

# See all MCP tools from all servers
/mcp-tools

# Disconnect a server
/mcp-remove filesystem
```

### How MCP Tools Work

When you connect an MCP server, its tools are automatically available to the AI:

1. **Tool Discovery**: IRONGUARD queries the MCP server for available tools
2. **Automatic Registration**: Tools appear as `serverName/toolName` (e.g., `filesystem/read_file`)
3. **Seamless Integration**: AI can call MCP tools just like built-in tools
4. **Confirmation Mode**: MCP tools respect your safety settings (`/confirm` vs `/autopilot`)

### Popular MCP Servers

| Server | Package | Description |
|--------|---------|-------------|
| Filesystem | `@modelcontextprotocol/server-filesystem` | Read/write files in specific directories |
| Brave Search | `@anthropic/mcp-server-brave-search` | Web search via Brave |
| GitHub | `@anthropic/mcp-server-github` | GitHub repository operations |
| Puppeteer | `@anthropic/mcp-server-puppeteer` | Browser automation |
| Slack | `@anthropic/mcp-server-slack` | Slack messaging |
| Memory | `@anthropic/mcp-server-memory` | Persistent memory/notes |

> **Note**: MCP servers require Node.js/npx to be installed. Most competition images don't have this, so MCP is primarily useful for practice/development.

## Supported AI Models

### Anthropic Claude (Default)
- `claude-opus-4-5` - Most powerful (default)
- `claude-sonnet-4-5` - Fast alternative

### OpenAI
- `gpt-5.1` - Flagship model
- `gpt-5.1-codex` - Optimized for coding
- `gpt-5.1-codex-max` - Long-horizon tasks

### Google Gemini
- `gemini-3-pro` - Latest flagship

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | API key for Claude |
| `OPENAI_API_KEY` | API key for OpenAI |
| `GEMINI_API_KEY` | API key for Gemini |
| `GOOGLE_API_KEY` | Alternative for Gemini |

## Building from Source

```bash
# Clone
git clone https://github.com/tanav-malhotra/ironguard.git
cd ironguard

# Build for current platform
go build -o ironguard ./cmd/ironguard

# Cross-compile
GOOS=windows GOARCH=amd64 go build -o ironguard.exe ./cmd/ironguard
GOOS=linux GOARCH=amd64 go build -o ironguard ./cmd/ironguard
```

## Competition Day Checklist

### Before Competition
- [ ] Download ironguard binary to USB drive
- [ ] Have API key ready (written down securely)
- [ ] Test that ironguard runs on a practice image

### On Each Image
1. [ ] Copy ironguard to Desktop
2. [ ] Run as **Administrator** (Windows) or **sudo** (Linux)
3. [ ] `/key <your-api-key>`
4. [ ] `/harden`
5. [ ] Let AI work, help with GUI tasks if it asks
6. [ ] Monitor score - should hit 100/100 in ~30 min

### If Something Goes Wrong
- **AI stuck?** → `/stop` then `/harden` to restart
- **Score dropped?** → AI should auto-undo, but check manually
- **Need to quit?** → `Ctrl+Q` or `/quit`
- **AI not responding?** → Check API key with `/status`

## How It Works

IRONGUARD uses a sophisticated system prompt trained on:
- Every past CyberPatriot scoring report
- Official answer keys and walkthroughs
- Vulnerability categories and point values
- Common forensics question patterns

When you run `/harden`, the AI:
1. **Reconnaissance** (0-2 min): Reads README, forensics, checks initial score
2. **Quick Wins** (2-10 min): Forensics answers, user fixes, firewall
3. **Deep Hardening** (10-25 min): Services, policies, files, updates
4. **Sweep** (25-30 min): Re-audit, verify all forensics, final checks

The AI checks the score after every 2-3 actions and immediately undoes anything that causes a penalty.

## UI Features (Claude Code Style)

IRONGUARD's interface is inspired by Claude Code, with several advanced features:

### Thinking Display
When the AI is reasoning through a problem, you'll see its thinking process in a collapsible "💭 THINKING" section. This helps you understand what the AI is considering and why it makes certain decisions.

### Sub-Agents Panel
The sidebar shows active sub-agents with their current status:
- ⏳ Running sub-agents show their current step
- ✅ Completed sub-agents show result summaries
- Maximum 4 concurrent sub-agents

### Collapsible Tool Output
Tool calls show as collapsed by default with a preview:
```
⚡ list_users [-] → Found 12 users
```
Expand to see full output. This keeps the chat clean during long operations.

### Progress Indicators
Long-running operations show progress bars and spinners. The sidebar displays:
- Current score with delta (e.g., "87/100 (+5)")
- AI status (Working/Ready)
- Queue count for pending messages

### Message Queue
If the AI is busy, your messages are queued and sent automatically when ready:
- **Enter**: Queue message (sends when AI is free)
- **Ctrl+Enter**: Interrupt AI and send immediately

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please open an issue or PR.

---

**Good luck at CyberPatriot! 🏆**

*Built by competitors, for competitors.*
