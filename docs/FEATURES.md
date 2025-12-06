# IronGuard Feature Specification

## Core AI Capabilities

### 1. Web Search 🔍
The AI can search the web for:
- Unknown vulnerabilities and CVEs
- How to fix specific issues
- Documentation for services (vsftpd, SSH, Docker, MySQL, etc.)
- CyberPatriot-specific tips and tricks

**Implementation:**
- Uses DuckDuckGo for web search
- AI can invoke `web_search` tool with a query
- Results are parsed and summarized for context
- Can also `fetch_url` to read specific pages

### 2. Manual Task Sidebar 📋
A sidebar panel for tasks the AI can't do via terminal:
- Browser settings (Firefox, Chrome policies via GUI)
- OS settings that require GUI (some Windows settings)
- Things that would take too long to script

**Features:**
- AI adds items with description and priority
- User can check off completed items with `/done <num>`
- User can add their own items with `/manual <task>`
- Items persist during session
- AI acknowledges when user checks something off

**Example items:**
- "Open Firefox > Settings > Privacy > Enable Tracking Protection"
- "Open Windows Defender Security Center > Virus & threat protection > Check for updates"
- "Open Local Security Policy > Account Policies > Password Policy"

### 3. Screenshot & Screen Control 📸
Full desktop interaction capabilities for Windows and Linux (X11 and Wayland):

**Observe Mode (default):**
- `take_screenshot` - Capture the current screen
- AI can analyze screenshots for:
  - Score reports
  - Error messages
  - GUI settings
  - Cisco Packet Tracer topology
  - NetAcad quiz questions

**Control Mode (`/screen control`):**
- `mouse_click` - Click at coordinates (left/right/middle, single/double)
- `mouse_move` - Move cursor to specific coordinates
- `mouse_scroll` - Scroll up/down/left/right to see more content
- `mouse_drag` - Drag elements or select text
- `keyboard_type` - Type text
- `keyboard_hotkey` - Press key combinations (Ctrl+C, Alt+Tab, etc.)
- `list_windows` - List all open windows
- `focus_window` - Bring a window to foreground

**Platform Support:**
- **Windows**: Native PowerShell/.NET automation
- **Linux X11**: xdotool (requires `xdotool` package)
- **Linux Wayland**: Auto-detects and uses available tools:
  - `ydotool` - Recommended, most compatible
  - `dotool` - Alternative option
  - `wtype` - For keyboard input
  - `wlrctl` - For wlroots compositors (Sway, etc.)
  - `grim` - For screenshots

**Wayland Installation (if needed):**
```bash
# Ubuntu/Debian
sudo apt install ydotool grim

# Fedora
sudo dnf install ydotool grim

# Arch
sudo pacman -S ydotool grim
```

**Use cases:**
- Cisco challenges (Packet Tracer and NetAcad quizzes)
- Settings that require GUI
- Any GUI-based task

### 4. Sub-Agents (Parallel Execution) 🤖
The AI can spawn child agents to work in parallel:

**Features:**
- Up to 10 concurrent subagents (configurable via `/subagents <max>`)
- Each subagent has full tool access
- Works independently with its own conversation
- Reports results back to main agent

**Tools:**
- `spawn_subagent` - Create a child agent for a task
- `check_subagent` - Check status/result
- `list_subagents` - List all subagents
- `wait_for_subagent` - Block until complete
- `cancel_subagent` - Cancel a running subagent

**Spawning Options:**

1. **Preset Focus** - Use predefined prompts optimized for common tasks:
   ```
   spawn_subagent(task="Answer Forensics Q1...", focus="forensics")
   spawn_subagent(task="Audit all users", focus="users")
   spawn_subagent(task="Find media files", focus="files")
   spawn_subagent(task="Check running services", focus="services")
   ```

2. **Custom Instructions** - Full flexibility for any task:
   ```
   spawn_subagent(
     task="Research vsftpd hardening",
     custom_instructions="Use web_search to find vsftpd security guides. Summarize key config changes needed."
   )
   
   spawn_subagent(
     task="Check SSH configuration",
     custom_instructions="Read /etc/ssh/sshd_config. Check for: PermitRootLogin, PasswordAuthentication, X11Forwarding. Report security issues."
   )
   ```

**Strategy:**
```
Main Agent spawns:
├── Subagent 1: Answer Forensics Q1 (focus="forensics")
├── Subagent 2: Answer Forensics Q2 (focus="forensics")
├── Subagent 3: Audit user accounts (focus="users")
├── Subagent 4: Research MySQL hardening (custom_instructions="...")
└── Subagent 5: Check cron jobs for backdoors (custom_instructions="...")

All work simultaneously while main agent handles quick wins!
```

### 5. Persistent Shell Sessions 🖥️
The `run_command` tool maintains state across commands:

- Working directory persists (`cd /path` then `ls` works correctly)
- Environment variables persist
- Use `new_session: true` parameter to start fresh
- Use `get_shell_cwd` to check current directory
- Use `reset_shell` to completely reset

**Example:**
```
run_command("cd /home/user")
run_command("ls -la")           # Lists /home/user
run_command("cd Documents")     # Now in /home/user/Documents
run_command("pwd")              # Shows /home/user/Documents
```

### 6. Context Management 🧠
Automatic handling of long conversations:

- Monitors token usage during sessions
- Triggers summarization at 90% of provider's context limit
- **Only summarizes oldest 60%** of messages, keeping **40% recent** intact
- This preserves conversation flow and relevance
- Provider-specific limits:
  - Gemini: 1M tokens (gemini-3-pro)
  - Claude: 200K tokens (opus-4-5 main model)
  - OpenAI: 272K tokens (gpt-5.1)
- Preserves:
  - Recent messages (40% of conversation, minimum 10)
  - Key actions completed
  - Important findings
  - Current score and target
  - Subagent status
- **Notifications**: Both user and AI are notified when summarization occurs
- AI continues seamlessly without losing track

**Summarization Modes:**
- **Smart** (default): Uses provider's largest-context model for intelligent summarization
  - Claude: Uses Sonnet 4.5 (1M context) even when Opus is main model
  - Gemini: Uses Gemini 3 Pro (1M+ context)
  - OpenAI: Uses GPT-5.1 (272K context)
- **Fast**: Programmatic extraction (saves tokens)

Toggle with `/summarize smart` or `/summarize fast`.

**Token Tracking:**
- Status bar shows: `📊 45k/200k` (current/limit)
- `/tokens` command shows detailed statistics
- Tracks tokens saved by summarization

### 6.1. File Condensation 📄
Automatic handling of large files (>100KB):

- Large files are automatically condensed to show structure only
- Shows key elements based on file type:
  - **Go**: package, imports, type definitions, function signatures
  - **Python**: imports, class definitions, function definitions
  - **JavaScript/TypeScript**: imports, exports, classes, functions
  - **Shell scripts**: shebang, function definitions, section comments
  - **Other**: First 20 lines + last 10 lines
- Helps AI understand large files without consuming entire context

**Reading Specific Sections:**
Use `read_file` with `start_line`/`end_line` to read specific sections of ANY file:
```
read_file(path="/var/log/auth.log", start_line=100, end_line=150)
read_file(path="/etc/ssh/sshd_config", start_line=1, end_line=30)
```
This works on all files, not just condensed ones—useful for:
- Focusing on relevant parts of log files
- Reading specific config sections
- Inspecting particular functions in code

### 6.2. Document & Binary File Parsing 📄
Native support for common forensics file formats (no external dependencies!):

**PCAP/PCAPNG Analysis:**
- `analyze_pcap` - Pure Go packet capture parser
- Extracts protocols, IP addresses, ports, connections
- Automatically finds FTP credentials, HTTP passwords
- Detects sensitive data in plaintext traffic
- Works without Wireshark or tshark installed

**PDF Text Extraction:**
- `read_pdf` - Pure Go PDF parser
- Extracts text content from PDF documents
- Handles common PDF encodings
- No pdftotext or external tools needed

**DOCX Text Extraction:**
- `read_docx` - Pure Go Word document parser
- DOCX files are ZIP archives with XML inside
- Extracts all text content, headers, footers
- No Microsoft Office needed

**Image Reading:**
- `read_image` - Returns base64 for vision models
- Supports PNG, JPG, GIF, WebP, BMP
- Works with vision-capable AI models

### 7. Persistent Memory 🧠
Remember information across sessions:

**AI Tools:**
- `remember(category, content, os)` - Save to memory
- `recall(query, category, os)` - Search memory
- `list_memories(category)` - List all memories
- `forget(id)` - Delete a memory

**User Commands:**
- `/remember <category> <content>` - Save to memory
- `/recall [query]` - Search memory
- `/forget` - Clear all memories

**Categories:** vulnerability, config, command, finding, tip, pattern

**Storage:** `~/.ironguard/memory.json`

### 8. Checkpoint System ↩️
IronGuard maintains a tree-structured checkpoint system for undo/restore capabilities:

**Automatic Checkpoints:**
- Every file edit, create, or delete creates a checkpoint automatically
- Checkpoints include file content before and after modification
- All checkpoints persist to `~/.ironguard/checkpoints.json`

**Tree Structure with Branches:**
- Restoring to an old checkpoint creates a new branch (like Git)
- Original timeline is preserved, not overwritten
- Multiple parallel timelines can exist
- Branches are named: `main`, `branch-1`, `branch-2`, etc.

**Checkpoint Viewer UI:**
- Open with `/checkpoints` or right-click anywhere in the TUI
- Navigate with ↑/↓ arrow keys
- Press Enter to restore, D to delete, E to edit
- Current position highlighted with `►`
- Different checkpoint types have icons: ✏️ edit, 📄 create, 🗑️ delete, 📌 manual

**Commands:**
| Command | Description |
|---------|-------------|
| `/checkpoints` | Open checkpoint viewer |
| `/checkpoints create [desc]` | Create a manual checkpoint |
| `/checkpoints list` | List all checkpoints (text output) |
| `/checkpoints restore <id>` | Restore to checkpoint (auto-branches) |
| `/checkpoints edit <id> <desc>` | Edit checkpoint description |
| `/checkpoints delete <id>` | Delete checkpoint (renumbers remaining) |
| `/checkpoints branch` | Show current branch name |
| `/checkpoints branches` | List all branches |
| `/checkpoints clear` | Clear all checkpoints and start fresh |
| `/undo` | Undo the last change (shortcut) |
| `/history` | Show undoable actions (shortcut) |

**Backup System:**
- Checkpoint tree is backed up to `~/.ironguard/backups/` on every modification
- Last 10 backups are kept
- Fallback recovery if main checkpoint file corrupts

**Persistence:**
- Checkpoints are loaded from disk on startup
- Use `--fresh` flag to start without loading saved state
- Use `/checkpoints clear` to reset during a session

**AI Notifications:**
- AI is notified when user restores or undoes
- AI can create checkpoints before destructive actions

### 9. Compact Mode 📝
Toggle brief AI responses:

- `/compact on` - Brief, concise responses
- `/compact off` - Detailed responses (default)
- AI is notified via [SYSTEM] message

### 10. Setting Change Notifications 📢
AI is automatically notified when user changes settings:

- `/confirm` → AI told to wait for approval
- `/autopilot` → AI told to work autonomously
- `/screen observe` → AI told mouse/keyboard tools will fail
- `/screen control` → AI told it has full access
- `/subagents <n>` → AI told the new limit

### 11. Smart Autocomplete ⌨️
Intelligent command completion:

- Type `/` to see all available commands
- Tab/Enter to select a command
- After selecting a command, see its argument options
- Example: `/screen` → shows `observe` and `control` options
- Example: `/provider` → shows `claude`, `openai`, `gemini`
- Example: `/harden` → shows `windows`, `linux`, `cisco`, `auto`

Works with:
- `/provider` - AI providers
- `/screen` - observe/control modes
- `/mode` - competition modes
- `/harden` - OS and mode options
- `/compact` - on/off
- `/summarize` - smart/fast
- `/remember` - memory categories

### 12. Sound Effects 🔊
Satisfying audio feedback for scoring:

- **Points gained**: Plays a "ding" sound for each vulnerability found/fixed
  - If you go from 5 vulns to 12 vulns, plays 7 dings
  - Sounds are spaced 100ms apart for a satisfying cascade
- **Perfect score**: Victory sound plays when achieving 100/100

**Command-line flags:**
- `--no-sound` — Disable all sound effects completely
- `--no-repeat-sound` — Play single ding instead of multiple (less noisy)
- `--official-sound` — Use official CyberPatriot gain.wav instead of custom mp3

**TUI commands (change during runtime):**
- `/sound [on|off]` — Toggle sound effects
- `/sound-repeat [on|off]` — Toggle multiple dings vs single
- `/sound-official [on|off]` — Toggle official vs custom sound

**Technical details:**
- MP3 files are embedded in the binary using Go's `//go:embed`
- No external files needed—single executable
- Uses `github.com/gopxl/beep` for cross-platform audio
- Gracefully handles missing audio devices (silent operation)
- Sound playback is non-blocking (doesn't interrupt AI work)
- Volume boosted 2.5x for audibility

### 13. Keyboard Shortcuts ⌨️
Quick access to common actions:

| Key | Action |
|-----|--------|
| `Ctrl+L` | Clear input line |
| `Ctrl+Z` | Undo input (restores previous text) |
| `Ctrl+R` | Refresh/redraw screen (required after resize on Windows) |
| `Tab` | Cycle autocomplete suggestions |
| `Shift+Tab` | Cycle autocomplete backwards |
| `↑/↓` | Navigate input history (when input empty) |
| `PgUp/PgDn` | Scroll chat up/down |
| `Home/End` | Scroll to top/bottom of chat |
| `Right-click` | Open checkpoint viewer |
| `Enter` | Send message (queues if AI busy) |
| `Ctrl+Enter` | Send message and interrupt AI |
| `Esc` | Close autocomplete dropdown |

**Input Undo (Ctrl+Z):**
Tracks your input changes and lets you undo them:
- Saves state when you type a space (word boundary)
- Saves state before clearing input (Ctrl+L)
- Saves state when deleting multiple characters
- Up to 50 undo states stored

**Rotating Placeholders:**
The input field shows rotating motivational messages:
- "Reporting for duty..." (initial)
- "Awaiting orders..."
- "Ready when you are..."
- "Systems online..."
- "*cracks knuckles*"

Placeholder changes each time you send a message or clear input.

**Note on Terminal Resize:**
Windows Terminal doesn't always send resize events to TUI applications. After resizing your terminal window, press `Ctrl+R` to update the display. The `/refresh` command also works.

### 14. Connectivity Check 🌐
Verify internet and API key before starting:

**Automatic Check at Startup:**
The sidebar STATUS reflects real connectivity:
- `CHECKING...` - Connectivity check in progress
- `NO INTERNET` - Cannot reach internet
- `NO API KEY` - No API key configured
- `INVALID KEY` - API key validation failed
- `PROCESSING` - AI is working
- `READY` - Internet connected AND API key validated ✅

**Manual Check with `/check`:**
```
🔍 Connectivity Check
─────────────────────

Internet: ✅ Connected
Provider: claude
API Key:  ✅ Valid

🚀 Ready to go!
```

**What's checked:**
1. **Internet connectivity** - Pings Google, Anthropic, and OpenAI endpoints
2. **API key validity** - Makes a minimal API call to verify the key works

**Error handling:**
- No internet: Shows error and skips API check
- No API key: Prompts to use `/key <api-key>`
- Invalid API key: Shows specific error (invalid, rate-limited, permission denied)
- 10-second timeout for validation calls

---

## TUI Layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│ IRONGUARD v1.0.0 | claude-opus-4-5 | autopilot | Score: 85/100 (+5)     │
├───────────────────────────────────────────────┬─────────────────────────┤
│                                               │ 📋 MANUAL TASKS         │
│  [System] Welcome to IRONGUARD!               │                         │
│  Your mission: achieve 100/100 points.        │ ☐ Enable Firefox        │
│                                               │   tracking protection   │
│  💭 THINKING [-]                              │   (Settings > Privacy)  │
│  > Analyzing README for authorized users...   │                         │
│                                               │ ☑ Set strong password   │
│  [AI] I'll start by reading the README...     │   for admin account     │
│                                               │                         │
│  ⚡ read_readme [-] → Found README.html       │ ─────────────────────── │
│                                               │ 🤖 SUBAGENTS            │
│  [AI] Spawning subagents for parallel work... │                         │
│                                               │ ⏳ sub_12345: Forensics │
│  ⚡ spawn_subagent [-] → Created sub_12345    │    Researching Q1...    │
│  ⚡ spawn_subagent [-] → Created sub_12346    │ ✅ sub_12346: Users     │
│                                               │    Found 3 unauthorized │
│  [You] Also check if anonymous FTP is on      │                         │
│                                               │ ─────────────────────── │
│                                               │ 📊 STATUS               │
│                                               │ Score: 85/100 (+5)      │
│                                               │ Forensics: 2/3          │
├───────────────────────────────────────────────┴─────────────────────────┤
│ > Reporting for duty...                                    [autopilot]  │
│                                                                         │
│ /stop: Stop AI | /quit: Exit | Ctrl+R: Refresh | Tab: Autocomplete     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Slash Commands

### Essential Commands
| Command | Description |
|---------|-------------|
| `/harden` | Show OS detection and mode selection |
| `/harden windows` | Start hardening for Windows 10/11 |
| `/harden windows-server` | Start hardening for Windows Server |
| `/harden linux` | Start hardening for Ubuntu/Debian/Linux |
| `/harden cisco` | Start Cisco mode (Packet Tracer & NetAcad quizzes) |
| `/harden auto` | Auto-detect OS and start immediately |
| `/auto [target]` | Same as `/harden auto`, optionally set target score |
| `/stop` | Stop the AI |
| `/key <api-key>` | Set API key for current provider |
| `/check` | Check internet connectivity and validate API key |
| `/score` | Check current score |
| `/help` | Show all commands |
| `/quit` | Exit ironguard |

### Manual Commands
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
| `/mode <harden\|cisco>` | Set competition mode |
| `/subagents [max]` | Set max concurrent subagents (1-10, default: 4) |
| `/compact [on\|off]` | Toggle brief AI responses |
| `/summarize <smart\|fast>` | Set context summarization mode |
| `/sound [on\|off]` | Toggle sound effects |
| `/sound-repeat [on\|off]` | Toggle multiple dings vs single |
| `/sound-official [on\|off]` | Toggle official vs custom sound |
| `/status` | Show current configuration |
| `/clear` | Clear chat history |

### Checkpoints & Undo
| Command | Description |
|---------|-------------|
| `/checkpoints` | Open checkpoint viewer (or right-click) |
| `/checkpoints create [desc]` | Create a manual checkpoint |
| `/checkpoints list` | List all checkpoints |
| `/checkpoints restore <id>` | Restore to checkpoint (auto-branches) |
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

### Task Management
| Command | Description |
|---------|-------------|
| `/manual <task>` | Add a manual task for human teammate |
| `/tasks` | List manual tasks |
| `/done <num>` | Mark manual task as done |
| `/undone <num>` | Mark manual task as not done |

### Screen Control Commands
| Command | Description |
|---------|-------------|
| `/screenshot` | Take a screenshot |
| `/click <x> <y>` | Click at coordinates (requires `/screen control`) |
| `/type <text>` | Type text (requires `/screen control`) |
| `/hotkey <keys>` | Press hotkey like ctrl+c (requires `/screen control`) |
| `/windows` | List all open windows |
| `/focus <title>` | Focus a window by title |

### MCP Server Commands
| Command | Description |
|---------|-------------|
| `/mcp-add <name> <command> [args...]` | Connect to an MCP server |
| `/mcp-remove <name>` | Disconnect an MCP server |
| `/mcp-list` | List connected MCP servers |
| `/mcp-tools [server]` | List tools from MCP servers |

---

## AI Tools

### CyberPatriot Essentials
| Tool | Description |
|------|-------------|
| `read_readme` | Read and parse README.html from Desktop |
| `read_forensics` | Read all forensics .txt files from Desktop |
| `write_answer` | Write forensics answer to file |
| `read_score_report` | Read and parse score report HTML |
| `check_score_improved` | Compare current score to previous |
| `security_audit` | Run comprehensive security audit |

### User Management
| Tool | Description |
|------|-------------|
| `list_users` | List all users on system |
| `list_admins` | List all administrators/sudo users |
| `delete_user` | Delete a user account |
| `disable_user` | Disable user account |
| `set_password` | Set user password |
| `remove_from_admins` | Remove user from admin/sudo group |

### Service Management
| Tool | Description |
|------|-------------|
| `list_services` | List all services and status |
| `list_running_services` | List only running services |
| `stop_service` | Stop a service |
| `disable_service` | Disable service at boot |

### System Hardening
| Tool | Description |
|------|-------------|
| `enable_firewall` | Enable system firewall |
| `check_updates` | Check for available updates |
| `install_updates` | Install system updates |
| `set_password_policy` | Configure password policy |
| `disable_guest` | Disable the guest account |
| `find_prohibited_files` | Search for media files |

### File Operations
| Tool | Description |
|------|-------------|
| `read_file` | Read file contents |
| `write_file` | Write/modify file |
| `list_dir` | List directory contents |
| `search_files` | Search for files by pattern |
| `delete_file` | Delete a file |

### Document & Binary Files
| Tool | Description |
|------|-------------|
| `analyze_pcap` | Parse PCAP/PCAPNG files, extract protocols, credentials |
| `read_pdf` | Extract text from PDF files |
| `read_docx` | Extract text from Microsoft Word (.docx) files |
| `read_image` | Read image file as base64 for vision analysis |

### Shell Session
| Tool | Description |
|------|-------------|
| `run_command` | Execute command in persistent shell (supports `new_session` param) |
| `get_shell_cwd` | Get current working directory |
| `reset_shell` | Reset shell session to clean state |

### Web/Research
| Tool | Description |
|------|-------------|
| `web_search` | Search the web for information |
| `fetch_url` | Fetch and parse URL content |

### Persistent Memory
| Tool | Description |
|------|-------------|
| `remember` | Save information to persistent memory |
| `recall` | Search memory for previously saved info |
| `list_memories` | List all memory entries |
| `forget` | Delete a memory entry by ID |

### Screen Interaction
| Tool | Description |
|------|-------------|
| `take_screenshot` | Capture the screen |
| `mouse_click` | Click at coordinates (requires control mode) |
| `mouse_scroll` | Scroll up/down/left/right (requires control mode) |
| `mouse_drag` | Drag from one point to another (requires control mode) |
| `double_click` | Double-click at coordinates (requires control mode) |
| `right_click` | Right-click at coordinates (requires control mode) |
| `keyboard_type` | Type text (requires control mode) |
| `keyboard_hotkey` | Press key combination (requires control mode) |
| `list_windows` | List all open windows |
| `focus_window` | Focus a specific window |

### Sub-Agents
| Tool | Description |
|------|-------------|
| `spawn_subagent` | Spawn a child AI for parallel work |
| `check_subagent` | Check subagent status/result |
| `list_subagents` | List all spawned subagents |
| `wait_for_subagent` | Wait for subagent to complete |
| `cancel_subagent` | Cancel a running subagent |

### Manual Tasks
| Tool | Description |
|------|-------------|
| `add_manual_task` | Add task to sidebar for user |
| `list_manual_tasks` | List all manual tasks |

---

## Autonomous Mode Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     AUTONOMOUS MODE                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. RECONNAISSANCE + SPAWN SUBAGENTS                             │
│     ├─ read_readme (authorized users, services, restrictions)    │
│     ├─ read_forensics (get all questions)                        │
│     ├─ SPAWN subagents for each forensics question               │
│     ├─ SPAWN subagent for user audit                             │
│     ├─ SPAWN subagent for file search                            │
│     └─ read_score_report (baseline)                              │
│                                                                  │
│  2. QUICK WINS (while subagents work)                            │
│     ├─ Disable Guest account                                     │
│     ├─ Enable firewall                                           │
│     ├─ Delete obvious unauthorized users                         │
│     └─ Check score                                               │
│                                                                  │
│  3. COLLECT SUBAGENT RESULTS                                     │
│     ├─ Check forensics answers                                   │
│     ├─ Get user audit findings                                   │
│     ├─ Get prohibited file locations                             │
│     └─ Act on findings                                           │
│                                                                  │
│  4. DEEP HARDENING                                               │
│     ├─ Services (stop/disable dangerous ones)                    │
│     ├─ Password policies                                         │
│     ├─ Delete prohibited files                                   │
│     ├─ Install updates (if README allows)                        │
│     └─ Check score after each batch                              │
│                                                                  │
│  5. SWEEP                                                        │
│     ├─ Re-run security_audit                                     │
│     ├─ Check for missed items                                    │
│     ├─ Verify all forensics answered                             │
│     └─ Final score check                                         │
│                                                                  │
│  LOOP until score == 100 or user stops                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Score Tracking

The AI maintains:
- Current score
- Previous score
- Score history with timestamps
- Actions taken and their score impact

**After each action:**
1. Wait ~30 seconds for scoring engine
2. Check new score
3. Calculate delta
4. If negative: flag for investigation, consider undo
5. If positive: note what worked
6. Continue to next item

---

## Safety Features

### Confirm Mode (`/confirm`)
- Every destructive action requires user approval
- Shows exactly what will be executed
- User can approve or deny
- AI is paused while waiting for approval

### Autopilot Mode (`/autopilot`)
- AI runs autonomously (default)
- Still respects README restrictions
- Checks score after each batch of changes
- Stops if score drops significantly (penalty detected)

### Emergency Stop
- `/stop` immediately halts AI
- Current operation is cancelled
- State is preserved
- Can resume with another message

### Screen Control Safety
- Disabled by default (observe mode)
- Must explicitly enable with `/screen control`
- AI is notified of mode changes
- Tools fail gracefully with helpful error in observe mode

---

## Context Management

When conversations get long:
1. **Monitors** estimated token count before each LLM call
2. **Triggers** summarization at ~150k tokens
3. **Preserves**:
   - Last 10 messages (recent context)
   - Tools used and counts
   - Key actions completed
   - Important findings
   - Current score and target
   - Subagent status
4. **Continues** seamlessly - AI picks up where it left off

---

## MCP Server Integration

Extend AI capabilities with Model Context Protocol servers:

```bash
# Add filesystem access
/mcp-add filesystem npx -y @modelcontextprotocol/server-filesystem /path

# Add Brave Search
/mcp-add brave-search npx -y @anthropic/mcp-server-brave-search

# Add GitHub integration
/mcp-add github npx -y @anthropic/mcp-server-github
```

MCP tools appear automatically and work like built-in tools.

---

## Supported Platforms

### Operating Systems
- Windows 10/11
- Windows Server 2016/2019/2022
- Ubuntu 18.04/20.04/22.04
- Debian 10/11/12
- Linux Mint 20/21
- Fedora (basic support)
- CentOS/RHEL (basic support)

### AI Providers
- **Anthropic Claude** (default): claude-opus-4-5, claude-sonnet-4-5
- **OpenAI**: gpt-5.1, gpt-5.1-codex, gpt-5.1-codex-max
- **Google Gemini**: gemini-3-pro

---

## Future Enhancements

- [x] ~~Packet Tracer mode (screenshot analysis for networking)~~
- [x] ~~Sub-agents for parallel execution~~
- [x] ~~Persistent shell sessions~~
- [x] ~~Context management/summarization~~
- [ ] Team collaboration (multiple users, shared session)
- [ ] Offline mode (cached knowledge base)
- [ ] Custom tool plugins
- [ ] Score prediction model
- [ ] Automated practice mode with virtual images
