# IRONGUARD

**Autonomous AI Agent for CyberPatriot Competition**

IRONGUARD is a fully autonomous AI-powered tool designed to secure CyberPatriot competition images. It reads the scenario, answers forensics questions, fixes vulnerabilities, and tracks your score—all without manual intervention. Built by competitors, for competitors.

![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)

---

## Why IRONGUARD?

CyberPatriot competitions are a race against time. Teams have 4 hours to secure multiple images, answer forensics questions, and maximize their score. IRONGUARD automates the tedious parts so you can focus on learning and strategy.

**What it does:**
- Reads the README to understand authorized users, required services, and restrictions
- Answers forensics questions automatically (5-10 points each—easy wins)
- Identifies and removes unauthorized users
- Stops dangerous services and enables security features
- Finds and deletes prohibited files
- Monitors your score and rolls back changes that cause penalties

**What it doesn't do:**
- Replace understanding—watch it work and learn from its approach
- Handle GUI-only tasks—it assigns those to you via the sidebar
- Break competition rules—it respects README restrictions

---

## Getting Started

### Prerequisites

- An API key from [Anthropic](https://console.anthropic.com/), [OpenAI](https://platform.openai.com/), or [Google AI](https://aistudio.google.com/)
- Administrator/root access on the competition image

### Installation

**Windows (PowerShell as Administrator):**
```powershell
Invoke-WebRequest -Uri "https://github.com/tanav-malhotra/ironguard/releases/latest/download/ironguard-windows-amd64.exe" -OutFile "ironguard.exe"
.\ironguard.exe
```

**Linux:**
```bash
curl -L -o ironguard https://github.com/tanav-malhotra/ironguard/releases/latest/download/ironguard-linux-amd64
chmod +x ironguard
sudo ./ironguard
```

### First Run

1. Start IRONGUARD and set your API key:
   ```
   /key sk-your-api-key-here
   ```

2. Begin autonomous hardening:
   ```
   /harden
   ```

3. The AI will auto-detect your operating system and begin working. You can also specify a mode:
   ```
   /harden windows        # Windows 10/11
   /harden windows-server # Windows Server
   /harden linux          # Ubuntu, Debian, Linux Mint
   /harden packet-tracer  # Cisco Packet Tracer (requires /screen control)
   ```

That's it. The AI handles the rest.

---

## How It Works

IRONGUARD operates in four phases:

| Phase | Time | Activities |
|-------|------|------------|
| **Reconnaissance** | 0-2 min | Read README, forensics questions, initial score |
| **Quick Wins** | 2-10 min | Answer forensics, fix users, enable firewall |
| **Deep Hardening** | 10-25 min | Services, policies, prohibited files, updates |
| **Sweep** | 25-30 min | Re-audit, verify forensics, final checks |

The AI checks the score after every few actions. If the score drops (indicating a penalty), it investigates and attempts to undo the problematic change.

### Parallel Execution

IRONGUARD can spawn sub-agents to work on multiple tasks simultaneously:

```
Main Agent                    Sub-Agents (parallel)
    │
    ├──► Spawn ──────────────► Forensics Q1
    ├──► Spawn ──────────────► Forensics Q2  
    ├──► Spawn ──────────────► User Audit
    │
    ├──► Continue working...
    │
    └──► Collect results
```

Configure the maximum number of concurrent sub-agents with `/subagents <max>` (default: 4, range: 1-10).

---

## Commands

### Core Commands

| Command | Description |
|---------|-------------|
| `/harden [mode]` | Start autonomous hardening (modes: windows, linux, packet-tracer, auto) |
| `/stop` | Pause the AI |
| `/key <api-key>` | Set API key for the current provider |
| `/score` | Check current score |
| `/status` | Show current configuration |
| `/help` | List all commands |
| `/quit` | Exit IRONGUARD |

### Configuration

| Command | Description |
|---------|-------------|
| `/provider <name>` | Switch AI provider (claude, openai, gemini) |
| `/model <name>` | Set the model |
| `/confirm` | Enable confirmation mode (approve each action) |
| `/autopilot` | Enable autonomous mode (default) |
| `/screen <mode>` | Set screen interaction (observe, control) |
| `/subagents [max]` | Set max concurrent sub-agents |
| `/compact [on\|off]` | Toggle brief AI responses |
| `/summarize <smart\|fast>` | Set context summarization mode |

### Undo & Memory

| Command | Description |
|---------|-------------|
| `/undo` | Revert the last file edit |
| `/history` | Show undoable actions |
| `/remember <cat> <text>` | Save to persistent memory |
| `/recall [query]` | Search persistent memory |
| `/forget` | Clear all memories |
| `/tokens` | Show token usage statistics |

### Manual Interaction

| Command | Description |
|---------|-------------|
| `/readme` | Read the competition README |
| `/forensics` | Read forensics questions |
| `/answer <num> <text>` | Submit a forensics answer |
| `/run <command>` | Execute a shell command |
| `/search <query>` | Search the web |
| `/manual <task>` | Add a task for yourself to the sidebar |
| `/tasks` | List pending manual tasks |
| `/done <num>` | Mark a manual task complete |

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+L` | Clear screen |
| `Tab` | Cycle autocomplete suggestions |

---

## Features

### Persistent Shell Sessions

Commands maintain state across executions. If you run `cd /etc` followed by `cat passwd`, it reads `/etc/passwd` as expected. Use the `new_session` parameter to start fresh if needed.

### Context Management

Long sessions are handled automatically. When the conversation approaches token limits, IRONGUARD summarizes older messages while preserving:
- Recent context (last 10 messages)
- Key actions and findings
- Current score and progress
- Sub-agent status

**Summarization Modes:**
- **Smart** (default): Uses the provider's largest-context model for intelligent summarization
  - Claude: Uses Sonnet 4.5 (1M context) even when Opus is the main model
  - Gemini: Uses Gemini 3 Pro (1M+ context)
  - OpenAI: Uses GPT-5.1 (272K context)
- **Fast**: Programmatic extraction (saves tokens, slightly less intelligent)

Change with `/summarize smart` or `/summarize fast`.

### Persistent Memory

The AI can remember information across sessions:
- Vulnerabilities discovered
- Useful commands learned
- Configuration patterns that work
- Tips from web searches

Memory is stored in `~/.ironguard/memory.json` and persists between sessions. Both you (`/remember`) and the AI (`remember` tool) can add to it.

### Undo System

Every file edit is automatically checkpointed. Use `/undo` to revert the last change. View history with `/history`.

### Token Tracking

The status bar shows current context usage: `📊 45k/200k`. Use `/tokens` for detailed statistics including session totals and tokens saved by summarization.

### Screen Interaction

For Packet Tracer and GUI-based challenges:

```
/screen control    # Enable mouse/keyboard control
/harden packet-tracer
```

The AI can take screenshots, click on elements, type text, and navigate applications.

### Setting Notifications

When you change settings like `/confirm`, `/autopilot`, or `/screen control`, the AI is automatically notified so it can adjust its behavior accordingly.

---

## Supported Platforms

### Operating Systems
- Windows 10/11
- Windows Server 2016/2019/2022
- Ubuntu 18.04, 20.04, 22.04
- Debian 10, 11, 12
- Linux Mint 20, 21

### AI Providers
| Provider | Models |
|----------|--------|
| Anthropic (default) | claude-opus-4-5, claude-sonnet-4-5 |
| OpenAI | gpt-5.1, gpt-5.1-codex |
| Google | gemini-3-pro |

Set your provider with `/provider <name>` and model with `/model <name>`.

---

## Competition Day Checklist

### Before the Competition
- [ ] Download IRONGUARD to a USB drive
- [ ] Have your API key written down securely
- [ ] Test on a practice image

### On Each Image
1. Copy IRONGUARD to the Desktop
2. Run as Administrator (Windows) or with sudo (Linux)
3. `/key <your-api-key>`
4. `/harden`
5. Monitor progress; assist with GUI tasks if requested
6. Target: 100/100 in under 30 minutes

### Troubleshooting

| Issue | Solution |
|-------|----------|
| AI stuck | `/stop` then `/harden` to restart |
| Score dropped | AI should auto-undo; verify manually if needed |
| Not responding | Check `/status` for API key and connection |
| Need to exit | `Ctrl+Q` or `/quit` |

---

## Building from Source

```bash
git clone https://github.com/tanav-malhotra/ironguard.git
cd ironguard

# Build for current platform
go build -o ironguard ./cmd/ironguard

# Cross-compile for Windows
GOOS=windows GOARCH=amd64 go build -o ironguard.exe ./cmd/ironguard

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o ironguard ./cmd/ironguard
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | API key for Claude |
| `OPENAI_API_KEY` | API key for OpenAI |
| `GEMINI_API_KEY` | API key for Gemini |

You can also set keys at runtime with `/key`.

---

## MCP Server Integration

IRONGUARD supports the [Model Context Protocol](https://modelcontextprotocol.io/) for extending capabilities:

```bash
/mcp-add filesystem npx -y @modelcontextprotocol/server-filesystem /path
/mcp-add brave-search npx -y @anthropic/mcp-server-brave-search
/mcp-list
/mcp-remove filesystem
```

MCP tools appear automatically alongside built-in tools.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes or submit a pull request.

---

**Good luck at CyberPatriot.**

*Built by competitors, for competitors.*
