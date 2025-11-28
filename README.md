# ironguard

A powerful CLI tool with an AI-powered TUI for CyberPatriot competition system hardening.

![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

## Features

- **AI-Powered Assistant**: Chat with Claude, OpenAI GPT, or Google Gemini to get help hardening your system
- **Beautiful TUI**: Claude Code-inspired terminal interface with real-time streaming
- **Cross-Platform**: Single binary works on both Windows and Linux CyberPatriot images
- **Native Tools**: Built-in hardening tools - no external scripts or dependencies needed
- **Safety Modes**: Choose between confirm mode (ask before each action) or autopilot mode
- **Forensics Helper**: Read forensics questions and write answers in the correct format

## Quick Start

### Installation

Download the latest release for your platform:

```bash
# Windows (PowerShell as Admin)
Invoke-WebRequest -Uri "https://github.com/tanav-malhotra/ironguard/releases/latest/download/ironguard-windows-amd64.exe" -OutFile "ironguard.exe"

# Linux
curl -L -o ironguard https://github.com/tanav-malhotra/ironguard/releases/latest/download/ironguard-linux-amd64
chmod +x ironguard
```

### Running

Simply run the binary - no flags or configuration needed:

```bash
# Windows
.\ironguard.exe

# Linux
./ironguard
```

### Setting Up Your API Key

On first run, set your API key for your preferred provider:

```
/key sk-your-anthropic-api-key-here
```

Or set via environment variable before running:

```bash
# Windows PowerShell
$env:ANTHROPIC_API_KEY = "sk-your-key"

# Linux/macOS
export ANTHROPIC_API_KEY="sk-your-key"
```

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `/help` | Show all commands and keybindings |
| `/provider <claude\|openai\|gemini>` | Switch AI provider |
| `/model <name>` | Set the model to use |
| `/models` | List available models for current provider |
| `/key <api-key>` | Set API key for current provider |
| `/confirm` | Enable confirm mode (ask before actions) |
| `/autopilot` | Enable autopilot mode (auto-run actions) |
| `/readme` | Read the CyberPatriot README from Desktop |
| `/forensics` | Read forensics questions from Desktop |
| `/answer <num> <answer>` | Write answer to a forensics question |
| `/run <command>` | Run a terminal command |
| `/harden` | Start the hardening assistant |
| `/status` | Show current configuration |
| `/clear` | Clear chat history |
| `/quit` | Exit ironguard |

### Keybindings

| Key | Action |
|-----|--------|
| `Ctrl+C` | Cancel current action / Quit |
| `Ctrl+L` | Clear screen |
| `Tab` | Cycle autocomplete suggestions |
| `Enter` | Send message or run command |
| `Up/Down` | Scroll chat history |
| `Esc` | Cancel / Close |

### Example Workflow

1. **Start ironguard** and set your API key
2. **Read the README**: `/readme` or ask "Read the README and tell me what needs to be done"
3. **Start hardening**: `/harden` or ask "Start hardening this system"
4. **Answer forensics**: `/forensics` to read questions, then `/answer 1 The unauthorized user is jsmith`
5. **Run specific tasks**: Ask the AI to do specific things like "Remove all unauthorized users" or "Enable the firewall"

## Available AI Tools

The AI has access to these built-in tools:

### File Operations
- `read_file` - Read file contents
- `write_file` - Write to files
- `list_dir` - List directory contents
- `search_files` - Search for files by pattern
- `delete_file` - Delete files

### CyberPatriot Specific
- `read_readme` - Read README from Desktop
- `read_forensics` - Read forensics questions
- `write_answer` - Write forensics answers
- `security_audit` - Perform comprehensive security audit

### User Management
- `list_users` - List all users
- `list_admins` - List administrators
- `disable_user` - Disable a user account
- `delete_user` - Delete a user account
- `set_password` - Set user password
- `remove_from_admins` - Remove from admin group

### Service Management
- `list_services` - List all services
- `list_running_services` - List running services
- `stop_service` - Stop a service
- `disable_service` - Disable a service

### System Hardening
- `enable_firewall` - Enable system firewall
- `check_updates` - Check for updates
- `install_updates` - Install system updates
- `set_password_policy` - Configure password policy
- `disable_guest` - Disable guest account
- `find_prohibited_files` - Find media files

### General
- `run_command` - Run any shell command
- `get_system_info` - Get system information

## Building from Source

```bash
# Clone the repository
git clone https://github.com/tanav-malhotra/ironguard.git
cd ironguard

# Build for current platform
go build -o ironguard ./cmd/ironguard

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o ironguard.exe ./cmd/ironguard

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o ironguard ./cmd/ironguard
```

## Code Signing (For Competition)

To run ironguard on competition machines without security warnings:

### Windows
1. Get a code signing certificate (self-signed for testing):
   ```powershell
   New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=IronGuard" -CertStoreLocation Cert:\CurrentUser\My
   ```
2. Sign the executable:
   ```powershell
   Set-AuthenticodeSignature -FilePath .\ironguard.exe -Certificate (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)
   ```

### Linux
Linux binaries don't require signing, but you may need to:
```bash
chmod +x ironguard
```

## Competition Day Checklist

1. ✅ Download ironguard binary to a USB drive
2. ✅ Have your API key ready (written down or in a secure note)
3. ✅ Copy ironguard to the Desktop of each image
4. ✅ Run as Administrator (Windows) or with sudo (Linux)
5. ✅ Set your API key with `/key`
6. ✅ Start with `/readme` to understand the scenario
7. ✅ Use `/harden` to begin systematic hardening
8. ✅ Answer forensics with `/forensics` and `/answer`

## Supported Models

### Anthropic Claude
- `claude-opus-4-5` - Most powerful
- `claude-sonnet-4-5` - Best for coding (default)

### OpenAI
- `gpt-5.1` - Flagship model
- `gpt-5.1-codex` - Optimized for coding
- `gpt-5.1-codex-max` - Long-horizon coding

### Google Gemini
- `gemini-3-pro` - Latest flagship

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | API key for Claude |
| `OPENAI_API_KEY` | API key for OpenAI |
| `GEMINI_API_KEY` | API key for Gemini |
| `GOOGLE_API_KEY` | Alternative for Gemini |

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please open an issue or PR.

---

**Good luck at CyberPatriot! 🏆**

