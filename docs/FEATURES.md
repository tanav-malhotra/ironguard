# IRONGUARD Feature Specification

## Core AI Capabilities

### 1. Web Search 🔍
The AI can search the web for:
- Unknown vulnerabilities and CVEs
- How to fix specific issues
- Documentation for services (vsftpd, SSH, Docker, MySQL, etc.)
- CyberPatriot-specific tips and tricks

**Implementation:**
- Use a search API (Google Custom Search, Brave Search, or DuckDuckGo)
- AI can invoke `web_search` tool with a query
- Results are parsed and summarized for context

### 2. Manual Task Sidebar 📋
A sidebar panel for tasks the AI can't do via terminal:
- Browser settings (Firefox, Chrome policies via GUI)
- OS settings that require GUI (some Windows settings)
- Things that would take too long to script

**Features:**
- AI adds items with description and priority
- User can check off completed items
- User can add their own items
- Items persist during session
- AI acknowledges when user checks something off

**Example items:**
- "Open Firefox > Settings > Privacy > Enable Tracking Protection"
- "Open Windows Defender Security Center > Virus & threat protection > Check for updates"
- "Open Local Security Policy > Account Policies > Password Policy"

### 3. Image/Screenshot Support 📸
Users can provide visual context:
- Paste screenshots directly into chat
- Reference images with `@image.png`
- AI can analyze:
  - Score reports (parse current score)
  - Error messages
  - GUI settings
  - README screenshots

**Implementation:**
- Use vision-capable models (Claude 3.5, GPT-4V, Gemini Pro Vision)
- Convert images to base64 for API calls
- Support common formats: PNG, JPG, GIF, WebP

### 4. File @Mentions 📁
Reference files directly in chat:
- `@README.html` - Include file contents in context
- `@/etc/ssh/sshd_config` - Reference system files
- `@Forensics Question 1.txt` - Include forensics question

**Features:**
- Autocomplete for file paths
- Preview file contents before sending
- Support for relative and absolute paths
- Automatic detection of Desktop files

### 5. URL/Documentation Parsing 🌐
Parse online documentation:
- `@https://docs.example.com/security` - Fetch and parse URL
- Extract relevant information from docs
- Summarize long documentation

**Use cases:**
- Looking up official hardening guides
- Reading CVE details
- Checking software documentation

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
│  [AI] I'll start by reading the README...     │   (Settings > Privacy)  │
│                                               │                         │
│  [Tool] read_readme                           │ ☐ Check Windows         │
│  > Found README.html on Desktop               │   Defender is enabled   │
│  > Authorized users: alice, bob, admin        │   (Security Center)     │
│  > Required services: vsftpd, mysql           │                         │
│  > Restrictions: DO NOT UPDATE                │ ☑ Set strong password   │
│                                               │   for admin account     │
│  [AI] I see vsftpd and mysql are required.    │                         │
│  I'll check if they're properly configured... │ ─────────────────────── │
│                                               │ 📊 STATUS               │
│  [Tool] run_command                           │                         │
│  > cat /etc/vsftpd.conf                       │ Current: 85/100         │
│  > ssl_enable=NO  ⚠️ INSECURE!                │ Last change: +5 pts     │
│                                               │ Time: 45:32 remaining   │
│  [AI] Found it! SSL is disabled for FTP.      │                         │
│  This is a common vulnerability. Fixing...    │ Forensics: 2/3 done     │
│                                               │ Users: ✓ fixed          │
│  [You] Also check if anonymous is disabled    │ Services: in progress   │
│                                               │                         │
├───────────────────────────────────────────────┴─────────────────────────┤
│ > Type message... (@file, /command, or paste image)        [autopilot] │
│                                                                         │
│ /help  /provider  /model  /confirm  /autopilot  /stop  /score  /manual │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Slash Commands

| Command | Description |
|---------|-------------|
| `/help` | Show all commands |
| `/provider [name]` | Switch AI provider (claude, openai, gemini) |
| `/model [name]` | Switch model |
| `/confirm` | Enable confirmation mode |
| `/autopilot` | Enable autopilot mode |
| `/stop` | Stop current autonomous operation |
| `/score` | Check current score |
| `/manual [task]` | Add a manual task to sidebar |
| `/done [id]` | Mark manual task as done |
| `/clear` | Clear chat history |
| `/export` | Export session log |
| `/search [query]` | Search the web |
| `/key [provider] [key]` | Set API key |

---

## AI Tools

### System Tools
| Tool | Description |
|------|-------------|
| `run_command` | Execute shell command (PowerShell/Bash) |
| `read_file` | Read file contents |
| `write_file` | Write/modify file |
| `list_dir` | List directory contents |
| `search_files` | Search for files by pattern |
| `delete_file` | Delete a file |

### CyberPatriot Tools
| Tool | Description |
|------|-------------|
| `read_readme` | Read and parse README.html from Desktop |
| `read_forensics` | Read all forensics .txt files from Desktop |
| `write_answer` | Write forensics answer to file |
| `read_score_report` | Read and parse score report HTML |
| `get_current_score` | Get current score from report |
| `check_score_improved` | Compare current score to previous |

### User Management Tools
| Tool | Description |
|------|-------------|
| `list_users` | List all users on system |
| `list_admins` | List all administrators/sudo users |
| `delete_user` | Delete a user account |
| `add_user` | Create a new user |
| `set_password` | Set user password |
| `add_to_group` | Add user to group |
| `remove_from_group` | Remove user from group |
| `disable_user` | Disable user account |

### Service Tools
| Tool | Description |
|------|-------------|
| `list_services` | List all services and status |
| `start_service` | Start a service |
| `stop_service` | Stop a service |
| `enable_service` | Enable service at boot |
| `disable_service` | Disable service at boot |

### Security Tools
| Tool | Description |
|------|-------------|
| `enable_firewall` | Enable system firewall |
| `firewall_allow` | Allow port/service through firewall |
| `firewall_deny` | Block port/service |
| `set_password_policy` | Configure password policy |
| `security_audit` | Run comprehensive security audit |
| `find_prohibited_files` | Search for media/prohibited files |

### Web/Research Tools
| Tool | Description |
|------|-------------|
| `web_search` | Search the web for information |
| `fetch_url` | Fetch and parse URL content |

### Manual Task Tools
| Tool | Description |
|------|-------------|
| `add_manual_task` | Add task to sidebar for user |
| `list_manual_tasks` | List all manual tasks |
| `complete_manual_task` | Mark task as done |

---

## Autonomous Mode Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     AUTONOMOUS MODE                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. READ README                                                  │
│     ├─ Extract authorized users                                  │
│     ├─ Extract required services                                 │
│     ├─ Extract restrictions (no updates, etc.)                   │
│     └─ Store for reference                                       │
│                                                                  │
│  2. CHECK INITIAL SCORE                                          │
│     └─ Record baseline                                           │
│                                                                  │
│  3. FORENSICS (Low risk, easy points)                            │
│     ├─ Read all forensics questions                              │
│     ├─ Investigate each question                                 │
│     └─ Write answers                                             │
│                                                                  │
│  4. USER MANAGEMENT                                              │
│     ├─ List all users                                            │
│     ├─ Compare to authorized list                                │
│     ├─ Delete unauthorized users                                 │
│     ├─ Fix admin group membership                                │
│     └─ Check score                                               │
│                                                                  │
│  5. SERVICES                                                     │
│     ├─ List running services                                     │
│     ├─ Disable unnecessary (check README!)                       │
│     ├─ Harden required services                                  │
│     └─ Check score                                               │
│                                                                  │
│  6. FIREWALL                                                     │
│     ├─ Enable firewall                                           │
│     ├─ Allow required services                                   │
│     └─ Check score                                               │
│                                                                  │
│  7. SECURITY SETTINGS                                            │
│     ├─ Password policy                                           │
│     ├─ UAC/sudo settings                                         │
│     ├─ Audit policies                                            │
│     └─ Check score                                               │
│                                                                  │
│  8. PROHIBITED FILES                                             │
│     ├─ Search for media files                                    │
│     ├─ Delete prohibited files                                   │
│     └─ Check score                                               │
│                                                                  │
│  9. PERSISTENCE/BACKDOORS                                        │
│     ├─ Check scheduled tasks/cron                                │
│     ├─ Check startup items                                       │
│     ├─ Check for suspicious services                             │
│     └─ Check score                                               │
│                                                                  │
│  10. UPDATES (if README allows!)                                 │
│      ├─ Install security updates                                 │
│      └─ Check score                                              │
│                                                                  │
│  11. DEEP SCAN                                                   │
│      ├─ Run security audit                                       │
│      ├─ Check for missed items                                   │
│      ├─ Web search for unknown issues                            │
│      └─ Add manual tasks for GUI-only items                      │
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

## Session Persistence

- Chat history saved to `~/.ironguard/sessions/`
- Manual tasks saved and restored
- Score history tracked
- Can resume previous session

---

## Error Handling

When the AI encounters an error:
1. Log the error
2. Try alternative approach if available
3. If stuck, add to manual tasks for user
4. Continue with other items
5. Come back to failed items later

---

## Safety Features

### Confirm Mode
- Every destructive action requires user approval
- Shows exactly what will be executed
- User can modify command before running

### Autopilot Mode
- AI runs autonomously
- Still respects README restrictions
- Checks score after each batch of changes
- Stops if score drops significantly (penalty detected)

### Emergency Stop
- `Ctrl+C` or `/stop` immediately halts AI
- Current operation is cancelled
- State is preserved

---

## Future Enhancements (Post-MVP)

- [ ] Packet Tracer mode (screenshot analysis for networking)
- [ ] Team collaboration (multiple users, shared session)
- [ ] Offline mode (cached knowledge base)
- [ ] Custom tool plugins
- [ ] Score prediction model
- [ ] Automated practice mode with virtual images

