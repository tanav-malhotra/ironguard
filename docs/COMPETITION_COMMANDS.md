# 🏆 IronGuard v2.0 - Competition Command Reference

## 🚀 QUICK START FOR TEAMMATES

### **OPTION 1: MAXIMUM AUTOMATION (Recommended)**
```bash
# One command - does EVERYTHING automatically  
ironguard scan --auto-fix --parallel

# Then run all hardening scripts in parallel
ironguard scripts run-all --parallel
```

### **OPTION 2: TUI INTERFACE (For Organization)**
```bash
# Interactive tabbed interface
ironguard tui
```

### **OPTION 3: TARGETED SCRIPTS**
```bash
# List available scripts
ironguard scripts list

# Run specific script
ironguard scripts run firewall_config --parallel

# Run specific combination
ironguard scripts run password_policy
ironguard scripts run network_secure
```

## 📚 FULL COMMAND REFERENCE

### **Scanning Commands:**
```bash
ironguard scan                    # Basic scan
ironguard scan --auto-fix         # Scan + automatic fixes
ironguard scan --parallel         # Parallel scanning (faster)
ironguard scan --auto-fix --parallel  # Maximum automation
```

### **Script Commands:**
```bash
ironguard scripts list           # Show all available scripts
ironguard scripts run <name>     # Run single script
ironguard scripts run <name> --parallel  # Run with parallel processing
ironguard scripts run-all        # Run all scripts sequentially  
ironguard scripts run-all --parallel     # Run all scripts in parallel (FAST!)
```

### **Available Scripts:**
- `hardening_baseline` - Apply standard security hardening
- `password_policy` - Enforce strong password policies
- `firewall_config` - Configure secure firewall rules
- `user_audit` - Audit user accounts and permissions
- `service_lockdown` - Disable unnecessary services
- `audit_enable` - Enable comprehensive audit logging
- `network_secure` - Secure network configurations
- `software_cleanup` - Remove unauthorized software
- `encryption_check` - Verify encryption settings

### **TUI Interface:**
```bash
ironguard tui                    # Launch interactive interface
```

**TUI Features:**
- 📋 Tab 1: Security Scan
- 🔧 Tab 2: Auto-Fix Vulnerabilities  
- 📜 Tab 3: Manual Scripts
- ⚙️ Tab 4: System Configuration
- 📊 Tab 5: Reports & Analytics

## 🎯 COMPETITION STRATEGIES

### **Start of Competition (First 5 minutes):**
```bash
# Get immediate points while others are reading
ironguard scan --auto-fix --parallel
```

### **Background Hardening (While doing manual work):**
```bash
# Run in separate terminal/tab
ironguard scripts run-all --parallel
```

### **Scenario-Specific Work:**
```bash
# Use TUI for organized management of complex requirements
ironguard tui
```

### **Final Verification:**
```bash
# Re-scan to verify all improvements
ironguard scan --parallel
```

## 🔥 SPEED OPTIMIZATION

### **Parallel Processing:**
- Always use `--parallel` flag for maximum speed
- Run scripts in background while doing manual work
- Use TUI to manage multiple tasks simultaneously

### **Strategic Timing:**
1. **Immediate**: `ironguard scan --auto-fix --parallel` (2-3 minutes)
2. **Background**: `ironguard scripts run-all --parallel` (5-10 minutes)  
3. **Manual**: Handle scenario-specific requirements
4. **Final**: `ironguard scan --parallel` for verification

## 💡 PRO TIPS

### **For Maximum Points:**
- Run auto-fix scan immediately upon starting
- Use parallel script execution while reading scenario
- Re-run scans periodically to catch new issues
- Use TUI for complex scenario management

### **For Teammates:**
- Memorize: `ironguard scan --auto-fix --parallel`
- If confused, use: `ironguard tui` 
- When in doubt: `ironguard scripts run-all --parallel`
- Always check: `ironguard scripts list` for available options

## 🏆 COMPETITIVE ADVANTAGES

**Your team now has:**
- ✅ Instant vulnerability detection and fixing
- ✅ Professional hardening script arsenal  
- ✅ Parallel processing for maximum speed
- ✅ Organized TUI for complex scenarios
- ✅ Fool-proof operation for any skill level

**While other teams are still figuring out the image, you're already scoring points! 🎯**

---

*Dominate CyberPatriot with IronGuard v2.0!* 🛡️