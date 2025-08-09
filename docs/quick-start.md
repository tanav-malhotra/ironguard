# 🚀 IronGuard Quick Start Guide

## 🎯 60-Second Competition Victory

### Step 1: Install IronGuard (10 seconds)
```bash
# Linux/macOS
curl -sSL https://raw.githubusercontent.com/tanav-malhotra/ironguard/main/install.sh | bash

# Windows PowerShell
Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tanav-malhotra/ironguard/main/install.ps1").Content
```

### Step 2: Maximum Automation (30 seconds)
```bash
# Ultimate one-command solution
ironguard scan --auto-fix --parallel
```

### Step 3: Comprehensive Hardening (20 seconds)
```bash
# Run all professional hardening scripts
ironguard scripts run-all --parallel
```

**🏆 Congratulations! You've just secured a competition VM in under 60 seconds!**

---

## 🎮 For Your Teammates (Zero Technical Knowledge Required)

### The Magic Command
```bash
ironguard scan --auto-fix --parallel
```

**That's it!** This single command:
- ✅ Scans the entire system for vulnerabilities
- ✅ Automatically fixes safe issues
- ✅ Runs everything in parallel for speed
- ✅ Shows clear results with priorities

### If They Need More Control
```bash
# Interactive interface with tabs
ironguard tui
```

### Emergency Help
```bash
# Show all available commands
ironguard --help

# List all hardening scripts
ironguard scripts list

# Get help on specific command
ironguard scan --help
```

---

## 🏆 Competition Day Workflow

### Immediate Start (First 2 minutes)
```bash
# Get instant points while others read the README
ironguard scan --auto-fix --parallel
```

### Background Tasks (Next 5 minutes)
```bash
# Run comprehensive hardening while doing manual work
ironguard scripts run-all --parallel
```

### Organized Management (Throughout competition)
```bash
# Use TUI for complex scenario management
ironguard tui
```

### Final Verification (Last 10 minutes)
```bash
# Final scan to ensure everything is secure
ironguard scan --parallel
```

---

## 📊 Understanding the Output

### Vulnerability Levels
- 🔴 **Critical**: Major security issues (0 passwords, etc.)
- 🟠 **High**: Significant risks (dangerous services)
- 🟡 **Medium**: Important issues (firewall misconfiguration)
- 🔵 **Low**: Minor problems (unnecessary software)
- ⚪ **Info**: Informational findings

### Fix Status
- 🔧 **Auto-fixable**: IronGuard can fix automatically
- 🔍 **Manual fix required**: Needs human intervention

### Example Output
```
🛡️  IronGuard Security Scan Results
═══════════════════════════════════════
📊 Summary:
  🔴 Critical: 0
  🟠 High: 2
  🟡 Medium: 5
  🔵 Low: 3
  ⚪ Info: 1

🟠 [HIGH] Dangerous service 'telnet' is running
    The telnet service should be disabled
    🔧 Auto-fixable

🟡 [MEDIUM] Dangerous port 21 (FTP) is open
    Port 21 (FTP) should be closed or secured
    🔧 Auto-fixable
```

---

## 🔧 Essential Commands Reference

### Scanning
```bash
ironguard scan                    # Basic scan
ironguard scan --auto-fix         # Scan + fixes
ironguard scan --parallel         # Faster scanning
ironguard scan --auto-fix --parallel  # Maximum automation
```

### Scripts
```bash
ironguard scripts list           # Show available scripts
ironguard scripts run firewall_config  # Run specific script
ironguard scripts run-all        # Run all scripts
ironguard scripts run-all --parallel   # Parallel execution
```

### Interface
```bash
ironguard tui                    # Interactive interface
ironguard --help                 # Command help
ironguard config edit           # Edit configuration
```

### Emergency
```bash
ironguard rollback              # Undo recent changes
ironguard docs                  # View documentation
ironguard status                # Check system status
```

---

## ⚡ Speed Tips

### Maximum Speed Commands
```bash
# Fastest possible comprehensive security
ironguard scan --auto-fix --parallel && ironguard scripts run-all --parallel
```

### Parallel Everything
- Always use `--parallel` flag when available
- Run multiple terminals for different tasks
- Use TUI to manage multiple operations

### Keyboard Shortcuts (TUI)
- `Tab` / `Shift+Tab` - Navigate between tabs
- `Enter` - Select/Execute
- `r` - Run scan
- `f` - Apply fixes
- `q` - Quit

---

## 🎯 Pro Tips for 100 Points

### Before Competition
1. **Practice the magic command**: `ironguard scan --auto-fix --parallel`
2. **Memorize essential scripts**: `ironguard scripts run-all --parallel`
3. **Understand TUI navigation**: Practice using tabs

### During Competition
1. **Start immediately**: Don't read README first, scan while reading
2. **Use background tasks**: Run scripts while handling manual requirements
3. **Re-scan frequently**: Catch issues you missed initially
4. **Stay organized**: Use TUI tabs for complex scenarios

### Emergency Situations
1. **Something broke**: Use `ironguard rollback`
2. **Confused teammate**: Show them `ironguard tui`
3. **Time running out**: Focus on `ironguard scan --auto-fix --parallel`

---

## 🏁 Ready to Win?

You now have everything needed to dominate CyberPatriot competitions:

- ✅ **One-command installation**
- ✅ **Zero-knowledge teammate operation**
- ✅ **Professional security scanning**
- ✅ **Automatic vulnerability fixing**
- ✅ **Comprehensive hardening scripts**
- ✅ **Organized TUI interface**

**Go forth and achieve 100 points every time! 🏆**

---

*Need more details? Check out the [complete documentation](README.md) or jump to [competition strategy](strategy.md).*