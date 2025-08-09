# 🛡️ IronGuard - CyberPatriot Security Scanner

**The ultimate automated security hardening tool for CyberPatriot competitions.**

IronGuard is a comprehensive, automated security scanner and hardening tool designed specifically for CyberPatriot competitions. It automatically detects vulnerabilities and can apply fixes, giving your team a significant competitive advantage.

## 🚀 Quick Start

### Prerequisites

- **Administrator/Root privileges** (REQUIRED)
- Rust 1.70+ installed
- Windows 10+ or modern Linux distribution

### Installation

```bash
# Clone and build
git clone <your-repo-url>
cd CyberPatriotUtility
cargo build --release

# Run with interactive TUI
./target/release/ironguard scan --interactive

# Or run automated scan with fixes
./target/release/ironguard scan --auto-fix
```

## 🎯 Features

### Core Capabilities

- **🔍 Comprehensive Scanning**: Detects 100+ common CyberPatriot vulnerabilities
- **🔧 Automated Fixes**: One-click remediation for most issues
- **🖥️ Interactive TUI**: Beautiful terminal interface for real-time monitoring
- **📊 Detailed Reports**: Professional reporting with evidence collection
- **⚡ Competition-Optimized**: Designed for speed and CyberPatriot scenarios

### Scanner Modules

1. **👥 User Management Scanner**
   - Weak/empty passwords
   - Unauthorized users
   - Privilege escalation vulnerabilities
   - Sudo misconfigurations

2. **⚙️ Service Configuration Scanner**
   - Unnecessary/dangerous services
   - SSH hardening
   - Service-specific security configs

3. **🌐 Network Security Scanner**
   - Open ports analysis
   - Firewall configuration
   - Network shares audit

4. **📁 File System Scanner**
   - File permissions audit
   - Sensitive file detection
   - Ownership verification

5. **📦 Software Scanner**
   - Outdated packages
   - Vulnerable software
   - Malware detection

6. **🖥️ System Configuration Scanner**
   - Security policies
   - Registry settings (Windows)
   - Audit configurations

## 🏁 Competition Usage

### Before the Competition

1. **Practice Setup**:
   ```bash
   # Generate default config
   ./target/release/ironguard config init
   
   # Test on practice images
   ./target/release/ironguard scan --interactive
   ```

2. **Team Training**:
   - Train teammates on the interactive interface
   - Practice with the configuration system
   - Understand auto-fix capabilities

### During Competition

1. **Read the README First**: Always check for scenario-specific requirements

2. **Configure for Scenario**:
   ```bash
   # Edit ironguard.toml
   nano ironguard.toml
   
   # Example customizations:
   # - Set custom SSH port if specified
   # - Add allowed users from scenario
   # - Configure required/forbidden services
   ```

3. **Run Initial Scan**:
   ```bash
   # Interactive mode for real-time monitoring
   ./target/release/ironguard scan --interactive
   ```

4. **Review and Fix**:
   - Use TUI to review vulnerabilities
   - Apply fixes selectively or automatically
   - Generate reports for documentation

### Competition Strategy

1. **Speed**: Let IronGuard handle the bulk scanning while you focus on manual tasks
2. **Safety**: Use auto-fix only for well-tested vulnerability types
3. **Documentation**: Generate reports for scoring evidence
4. **Backup**: All fixes create backups for quick rollback

## 🔧 Configuration

### Basic Configuration

Edit `ironguard.toml` for each competition scenario:

```toml
[competition]
# Customize based on scenario README
custom_ssh_port = 6639  # If specified in scenario
allowed_users = ["admin", "user1", "user2"]
forbidden_software = ["wireshark", "nmap"]
```

### Advanced Configuration

```toml
[fixes]
auto_fix_enabled = true  # DANGER: Use carefully!
auto_fix_categories = ["user_management", "services"]
require_confirmation = true

[scanners]
# Disable specific scanners if needed
software = false  # Skip if time-consuming
```

## 📱 Interface Guide

### Interactive TUI Mode

```bash
./target/release/ironguard scan --interactive
```

**Key Controls**:
- `S` - Start scan
- `F` - Fix selected vulnerability
- `A` - Auto-fix all fixable issues
- `↑↓` - Navigate vulnerability list
- `Q` - Quit
- `H` - Help

### CLI Mode

```bash
# Full automated scan with fixes
./target/release/ironguard scan --auto-fix

# Scan only (no fixes)
./target/release/ironguard scan

# Fix specific vulnerability
./target/release/ironguard fix VULN-ID-12345

# Generate reports
./target/release/ironguard report --format html --output report.html
```

## 🔒 Security Considerations

### Auto-Fix Safety

- **Test First**: Always test auto-fixes in practice environment
- **Selective Use**: Enable only for well-understood vulnerability types
- **Backup System**: All fixes create backups in `./ironguard_backups/`
- **Rollback Ready**: Can quickly restore if needed

### Privilege Requirements

IronGuard requires administrator/root privileges because:
- System configuration changes
- Service management
- User account modifications
- Network configuration updates

### Data Privacy

- No data sent to external servers
- All scanning and fixing happens locally
- Database stored locally in `./ironguard.db`

## 🎯 Competition Tips

### Team Coordination

1. **Designate Scanner Operator**: One person runs IronGuard
2. **Manual Tasks Parallel**: Others handle manual requirements
3. **Communication**: TUI shows real-time progress
4. **Documentation**: Generate reports for scoring

### Scenario Adaptation

1. **Read README Carefully**: Look for specific requirements
2. **User Lists**: Update allowed_users in config
3. **Service Requirements**: Configure required/forbidden services
4. **Port Changes**: Set custom ports if specified
5. **Software Requirements**: Add to required/forbidden lists

### Time Management

1. **Initial Scan**: 2-5 minutes for complete scan
2. **Review Results**: 2-3 minutes to understand issues
3. **Apply Fixes**: 1-10 minutes depending on scope
4. **Verification**: 2-3 minutes to verify fixes

### Scoring Optimization

1. **High-Impact First**: Fix critical/high severity issues first
2. **Auto-Fixable**: Use auto-fix for safe, high-scoring vulnerabilities
3. **Documentation**: Generate reports for evidence
4. **Manual Verification**: Double-check critical fixes

## 🛠️ Development

### Building from Source

```bash
# Development build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug ./target/debug/ironguard scan
```

### Architecture

- **Modular Scanners**: Each vulnerability type has its own module
- **Async Engine**: Concurrent scanning for speed
- **Database Storage**: SQLite for results persistence
- **TUI Framework**: Ratatui for interactive interface
- **Cross-Platform**: Windows and Linux support

## 📄 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

This tool is designed for CyberPatriot success. Contributions welcome:

1. New scanner modules
2. Additional auto-fix capabilities
3. Competition scenario templates
4. Performance improvements

## ⚡ Troubleshooting

### Common Issues

1. **Permission Denied**: Run with administrator/root privileges
2. **Scan Timeout**: Increase timeout in config file
3. **Fix Failures**: Check logs and try manual fixes
4. **Missing Dependencies**: Ensure Rust 1.70+ installed

### Debug Mode

```bash
# Enable detailed logging
RUST_LOG=debug ./target/release/ironguard scan

# Check configuration
./target/release/ironguard config validate
```

### Getting Help

1. Check this README
2. Use built-in help: `./target/release/ironguard --help`
3. Review configuration: `./target/release/ironguard config show`

---

**Good luck in your CyberPatriot competitions! 🏆**

*Remember: IronGuard gives you the foundation, but CyberPatriot success requires understanding, strategy, and teamwork.*