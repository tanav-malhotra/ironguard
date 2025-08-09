# 🚀 IronGuard Quick Start

## Immediate Use (Simplified Version)

Your team can start using IronGuard **right now** with this simplified but functional version:

### 1. Build the Simple Version

```bash
# Copy the simple configuration
cp Cargo_simple.toml Cargo.toml

# Build the simplified version
cargo build --release

# Test it works
./target/release/ironguard scan
```

### 2. Competition Usage

```bash
# Run with elevated privileges (IMPORTANT!)
# Windows (as Administrator):
./target/release/ironguard.exe scan

# Linux (with sudo):
sudo ./target/release/ironguard scan

# Auto-fix vulnerabilities
./target/release/ironguard scan --auto-fix

# Fix specific vulnerability
./target/release/ironguard fix vulnerability-id-here
```

### 3. What It Does

✅ **Works immediately** - Compiles and runs without issues  
✅ **Real vulnerability detection** - Finds actual security issues  
✅ **Auto-fix capability** - Fixes common problems automatically  
✅ **Cross-platform** - Windows and Linux support  
✅ **Elevated privilege detection** - Warns if not running as admin  
✅ **Scoring system** - Shows potential point improvements  

### 4. Sample Output

```
🛡️  Starting IronGuard security scan...
👥 Scanning User Management...
⚙️ Scanning Services...
🌐 Scanning Network Security...
📁 Scanning File System...
📦 Scanning Software...
🖥️ Scanning System Config...
✅ Scan completed! Found 3 vulnerabilities

🛡️  IronGuard Security Scan Results
═══════════════════════════════════════
📊 Summary:
  🔴 Critical: 0
  🟠 High: 2
  🟡 Medium: 1
  🔵 Low: 0
  ⚪ Info: 0

🟠 HIGH [HIGH] Guest account is enabled
    The Guest account should be disabled for security
    🔧 Auto-fixable (Score: +10)

🟠 HIGH [HIGH] Dangerous service 'telnet' is running
    The telnet service should be disabled
    🔧 Auto-fixable (Score: +8)

🟡 MEDIUM [MEDIUM] Dangerous port 139 is open
    Port 139 should be closed or secured
    🔍 Manual fix required (Score: +6)

🏆 Potential score improvement: 24 points
💡 Tip: Run with --auto-fix to automatically fix 2 vulnerabilities
```

## Next Steps (Full Version)

Once this is working, you can enhance it:

1. **Add more scanners** - Expand the detection capabilities
2. **Improve auto-fix** - Add more automated fixes
3. **Add TUI interface** - Beautiful interactive interface
4. **Competition templates** - Pre-configured for common scenarios
5. **Reporting system** - Generate detailed reports

## Competition Strategy

1. **Speed**: Run `ironguard scan` immediately when you start
2. **Prioritize**: Fix CRITICAL and HIGH vulnerabilities first
3. **Auto-fix**: Use `--auto-fix` for safe, well-tested fixes
4. **Manual review**: Check manual fixes for scenario-specific requirements
5. **Documentation**: Keep logs for scoring evidence

## Troubleshooting

### Permission Issues
```bash
# Windows: Run PowerShell as Administrator
# Linux: Use sudo
sudo ./target/release/ironguard scan
```

### Build Issues
```bash
# Update Rust
rustup update

# Clean and rebuild
cargo clean
cargo build --release
```

### No Vulnerabilities Found
- Run as Administrator/root
- Check if system is already hardened
- Review scan output for any errors

---

**You now have a working CyberPatriot advantage! 🏆**

This simplified version gives you immediate functionality while you can enhance the full version over time.