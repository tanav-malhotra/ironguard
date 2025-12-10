# IronGuard

**Autonomous AI Agent for CyberPatriot Competition**

IronGuard is a fully autonomous AI-powered tool designed to secure CyberPatriot competition images. It reads the scenario, answers forensics questions, fixes vulnerabilities, and tracks your score—all without manual intervention. Built by competitors, for competitors.

![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)

---

## Why IronGuard?

CyberPatriot competitions are a race against time. Teams have 4 hours to secure multiple images, answer forensics questions, and maximize their score. IronGuard automates the tedious parts so you can focus on learning and strategy.

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

1. Start IronGuard and set your API key:
   ```
   /key sk-your-api-key-here
   ```
   The sidebar will show `READY` once internet and API key are validated (automatic check at startup).

2. Begin autonomous hardening:
   ```
   /harden
   ```

3. The AI will auto-detect your operating system and begin working. You can also specify a mode:
   ```
   /harden windows        # Windows 10/11
   /harden windows-server # Windows Server
   /harden linux          # Ubuntu, Debian, Linux Mint
   /harden cisco          # Cisco Packet Tracer & NetAcad quizzes
   ```

That's it. The AI handles the rest.

---

## How It Works

IronGuard operates in four phases:

| Phase | Time | Activities |
|-------|------|------------|
| **Reconnaissance** | 0-2 min | Read README, forensics questions, initial score |
| **Quick Wins** | 2-10 min | Answer forensics, fix users, enable firewall |
| **Deep Hardening** | 10-25 min | Services, policies, prohibited files, updates |
| **Sweep** | 25-30 min | Re-audit, verify forensics, final checks |

The AI checks the score after every few actions. If the score drops (indicating a penalty), it investigates and attempts to undo the problematic change.

### Parallel Execution

IronGuard can spawn sub-agents to work on multiple tasks simultaneously:

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
| `/harden [mode]` | Start autonomous hardening (modes: windows, linux, cisco, auto) |
| `/stop` | Pause the AI |
| `/key <api-key>` | Set API key for the current provider |
| `/check` | Check internet connectivity and validate API key |
| `/score` | Check current score |
| `/status` | Show current configuration |
| `/help` | List all commands |
| `/quit` | Exit IronGuard |

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
| `/sound [on\|off]` | Toggle sound effects |
| `/sound-repeat [on\|off]` | Toggle multiple dings vs single |
| `/sound-official [on\|off]` | Toggle official vs custom sound |

### Checkpoints & Undo

| Command | Description |
|---------|-------------|
| `/checkpoints` | Open checkpoint viewer (or right-click) |
| `/checkpoints create [desc]` | Create a manual checkpoint |
| `/checkpoints list` | List all checkpoints |
| `/checkpoints restore <id>` | Restore to a checkpoint (auto-branches) |
| `/checkpoints edit <id> <desc>` | Edit checkpoint description |
| `/checkpoints delete <id>` | Delete a checkpoint |
| `/checkpoints branch` | Show current branch |
| `/checkpoints branches` | List all branches |
| `/checkpoints clear` | Clear all checkpoints |
| `/undo` | Revert the last file edit |
| `/history` | Show undoable actions |

### Memory

| Command | Description |
|---------|-------------|
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
| `Ctrl+L` | Clear input line |
| `Ctrl+Z` | Undo input (restore previous text) |
| `Ctrl+R` | Refresh/redraw screen (fixes resize issues) |
| `Ctrl+C` | Copy (terminal passthrough) |
| `Ctrl+V` | Paste (terminal passthrough) |
| `Tab` | Cycle autocomplete suggestions |
| `↑/↓` | Navigate input history |
| `PgUp/PgDn` | Scroll chat |
| `Right-click` | Open checkpoint viewer |

> **Note:** After resizing your terminal window, press `Ctrl+R` to refresh the display. Windows Terminal doesn't always send resize events automatically.

---

## Features

### Persistent Shell Sessions

Commands maintain state across executions. If you run `cd /etc` followed by `cat passwd`, it reads `/etc/passwd` as expected. Use the `new_session` parameter to start fresh if needed.

### Context Management

Long sessions are handled automatically. When the conversation approaches 90% of the token limit, IronGuard summarizes the **oldest 60%** of messages while keeping the **most recent 40%** intact. This preserves conversation relevance and natural flow.

**What's preserved:**
- Recent messages (40% of conversation, minimum 10 messages)
- Key actions and findings in summary
- Current score and progress
- Sub-agent status

**Notifications:**
- Both user and AI are notified when summarization occurs
- The AI receives a system message so it knows context was compressed

**Summarization Modes:**
- **Smart** (default): Uses the provider's largest-context model for intelligent summarization
  - Claude: Uses Sonnet 4.5 (1M context) even when Opus is the main model
  - Gemini: Uses Gemini 3 Pro (1M+ context)
  - OpenAI: Uses GPT-5.1 (272K context)
- **Fast**: Programmatic extraction (saves tokens, slightly less intelligent)

Change with `/summarize smart` or `/summarize fast`.

### File Condensation

Large files (>100KB) are automatically condensed to show only structural elements:
- **Go**: Package, imports, type definitions, function signatures
- **Python**: Imports, class definitions, function definitions
- **JavaScript/TypeScript**: Imports, exports, classes, functions
- **Shell scripts**: Shebang, function definitions, section comments

Use `read_file` with `start_line`/`end_line` parameters to read specific sections of **any** file:
```
read_file(path="/var/log/auth.log", start_line=500, end_line=550)
```
This works on all files, not just condensed ones—useful for focusing on relevant parts of logs, configs, or code.

### Document & Binary File Support

IronGuard includes native parsers for common forensics file formats—no external dependencies needed:

| Format | Tool | Description |
|--------|------|-------------|
| **PCAP/PCAPNG** | `analyze_pcap` | Parse network captures, extract credentials, protocols, connections |
| **PDF** | `read_pdf` | Extract text from PDF documents |
| **DOCX** | `read_docx` | Extract text from Microsoft Word files |
| **Images** | `read_image` | Read images for vision model analysis |

These tools are compiled into the binary—they work even if Wireshark, pdftotext, or Microsoft Office aren't installed.

### Persistent Memory

The AI can remember information across sessions:
- Vulnerabilities discovered
- Useful commands learned
- Configuration patterns that work
- Tips from web searches

Memory is stored in `~/.ironguard/memory.json` and persists between sessions. Both you (`/remember`) and the AI (`remember` tool) can add to it.

### Timing & Wait Tools

Control execution timing and handle scoring engine delays:

**Blocking Wait:**
- `wait(seconds)` — Pause execution for X seconds (blocks the AI)

**Async Timers (Recommended):**
- `set_timer(seconds, label)` — Set a timer and continue working
- When the timer expires, the AI receives a `[SYSTEM]` notification
- `list_timers` / `cancel_timer` — Manage active timers

**CyberPatriot Scoring Strategy:**
The scoring engine has a **1-2 minute delay**. Instead of waiting around:
1. Make a fix
2. `set_timer(90, "check score after fix")`
3. Continue working on other tasks
4. Check score when the timer notification arrives

This maximizes productivity by keeping the AI working while waiting for score updates.

### Checkpoint System

IronGuard maintains a tree-structured checkpoint system that tracks all file modifications:

**Automatic Checkpoints:**
- Every file edit creates a checkpoint automatically
- Checkpoints are persisted to `~/.ironguard/checkpoints.json`
- Previous sessions' checkpoints are restored on startup

**Tree Structure with Branches:**
- Restoring an old checkpoint creates a new branch (like Git)
- Multiple parallel timelines are preserved
- Navigate between branches with `/checkpoints branches`

**Checkpoint Viewer:**
- Open with `/checkpoints` or right-click anywhere
- Navigate with ↑/↓, restore with Enter, delete with D

**Backups:**
- Checkpoint tree is backed up to `~/.ironguard/backups/` on every modification
- Last 10 backups are kept for recovery

Use `--fresh` flag to start without loading saved checkpoints.

### Token Tracking

The status bar shows current context usage: `📊 45k/200k`. Use `/tokens` for detailed statistics including session totals and tokens saved by summarization.

### Sound Effects

IronGuard plays satisfying audio feedback when you score points:
- **Ding!** — Plays once for each vulnerability found/fixed
- **Victory sound** — Plays when you achieve 100/100 (perfect score)

Sound files are embedded in the binary—no external files needed. If audio initialization fails (e.g., no audio device), IronGuard continues silently.

**Command-line flags:**
- `--no-sound` — Disable all sound effects
- `--no-repeat-sound` — Play a single ding instead of multiple (e.g., 7 vulns = 1 ding instead of 7)
- `--official-sound` — Use official CyberPatriot sound instead of custom mp3
- `--fresh` — Start with fresh checkpoints (ignore saved state from previous sessions)

### Screen Interaction

For Cisco challenges (Packet Tracer and NetAcad quizzes) and GUI-based tasks:

```
/mode cisco        # Set Cisco mode
/screen control    # Enable mouse/keyboard control
/harden cisco      # Start autonomous Cisco challenge assistance
```

**Capabilities:**
- **Screenshots**: See the current screen state
- **Mouse**: Click, double-click, right-click, drag, scroll, move cursor
- **Keyboard**: Type text, press hotkeys (Ctrl+C, Tab, Enter, etc.)
- **Window management**: Focus windows, list open windows

**Modes:**
- **Observe** (default): AI watches and provides step-by-step guidance
- **Control**: AI can interact directly with the screen

**Platform Support:**
- **Windows**: Native PowerShell/.NET automation
- **Linux X11**: xdotool
- **Linux Wayland**: ydotool, dotool, wtype, grim (auto-detected)

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
- [ ] Download IronGuard to a USB drive
- [ ] Have your API key written down securely
- [ ] Test on a practice image

### On Each Image
1. Copy IronGuard to the Desktop
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
| Need to exit | `/quit` |

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

IronGuard supports the [Model Context Protocol](https://modelcontextprotocol.io/) for extending capabilities:

```bash
/mcp-add filesystem npx -y @modelcontextprotocol/server-filesystem /path
/mcp-add brave-search npx -y @anthropic/mcp-server-brave-search
/mcp-list
/mcp-remove filesystem
```

MCP tools appear automatically alongside built-in tools.

---

## Disclaimer

**USE AT YOUR OWN RISK.** This software is provided "as is" without warranty of any kind. The authors and contributors:

- **Are not responsible** for any loss of points, penalties, or disqualifications during CyberPatriot or any other competition
- **Are not liable** for any damage to systems, data loss, or unintended consequences from using this tool
- **Make no guarantees** about the accuracy, reliability, or effectiveness of the AI's actions
- **Do not warrant** that the software will meet your requirements or operate error-free

By using IronGuard, you accept full responsibility for:
- Verifying all changes made by the AI
- Understanding competition rules and ensuring compliance
- Any consequences resulting from the use of this software

**This tool is meant to assist and educate, not replace human judgment.** Always review what the AI does and be prepared to intervene.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes or submit a pull request.

---

**Good luck at CyberPatriot.**

*Built by competitors, for competitors.*
