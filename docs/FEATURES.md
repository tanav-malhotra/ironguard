# IRONGUARD Feature Specification

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
Full desktop interaction capabilities:

**Observe Mode (default):**
- `take_screenshot` - Capture the current screen
- AI can analyze screenshots for:
  - Score reports
  - Error messages
  - GUI settings
  - Packet Tracer topology

**Control Mode (`/screen control`):**
- `mouse_click` - Click at coordinates
- `keyboard_type` - Type text
- `keyboard_hotkey` - Press key combinations (Ctrl+C, Alt+Tab, etc.)
- `list_windows` - List all open windows
- `focus_window` - Bring a window to foreground

**Use cases:**
- Packet Tracer challenges (full GUI interaction)
- Network quizzes
- Settings that require GUI

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
- When approaching limits (~150k tokens), automatically summarizes
- Preserves:
  - Recent messages (last 10)
  - Key actions completed
  - Important findings
  - Current score and target
  - Subagent status
- AI continues seamlessly without losing track

### 7. Setting Change Notifications 📢
AI is automatically notified when user changes settings:

- `/confirm` → AI told to wait for approval
- `/autopilot` → AI told to work autonomously
- `/screen observe` → AI told mouse/keyboard tools will fail
- `/screen control` → AI told it has full access
- `/subagents <n>` → AI told the new limit

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
│ > Type message... (@file, /command)                        [autopilot]  │
│                                                                         │
│ Ctrl+Q: Quit | Ctrl+C: Cancel AI | Ctrl+L: Clear | Tab: Autocomplete   │
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
| `/harden packet-tracer` | Start Packet Tracer mode (requires `/screen control`) |
| `/harden auto` | Auto-detect OS and start immediately |
| `/auto [target]` | Same as `/harden auto`, optionally set target score |
| `/stop` | Stop the AI |
| `/key <api-key>` | Set API key for current provider |
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
| `/mode <harden\|packet-tracer\|quiz>` | Set competition mode |
| `/subagents [max]` | Set max concurrent subagents (1-10, default: 4) |
| `/status` | Show current configuration |
| `/clear` | Clear chat history |

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

### Screen Interaction
| Tool | Description |
|------|-------------|
| `take_screenshot` | Capture the screen |
| `mouse_click` | Click at coordinates (requires control mode) |
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
- `Ctrl+C` or `/stop` immediately halts AI
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
