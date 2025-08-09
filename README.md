# 🛡️ IronGuard Ultimate - Professional CyberPatriot Security Scanner

[![Rust](https://img.shields.io/badge/rust-stable-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![CyberPatriot](https://img.shields.io/badge/CyberPatriot-Ready-green)](https://www.uscyberpatriot.org/)

**The ultimate automated security scanner designed to dominate CyberPatriot competitions and achieve 100-point perfection every time!**

## 🚀 One-Command Installation

### Linux/macOS:
```bash
curl -sSL https://raw.githubusercontent.com/tanav-malhotra/ironguard/main/install.sh | bash
```

### Windows PowerShell:
```powershell
Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tanav-malhotra/ironguard/main/install.ps1").Content
```

## ⚡ Quick Start (60 Seconds to Victory)

```bash
# Ultimate automation - scans and fixes everything automatically
ironguard scan --auto-fix --parallel

# Comprehensive hardening - runs all professional security scripts
ironguard scripts run-all --parallel

# Interactive management - organized interface for complex scenarios
ironguard tui
```

## 🎯 For Your Teammates (Zero Technical Knowledge Required)

**The Magic Command:**
```bash
ironguard scan --auto-fix --parallel
```

That's it! This single command automatically:
- ✅ Scans the entire system for vulnerabilities
- ✅ Fixes security issues safely and automatically  
- ✅ Runs everything in parallel for maximum speed
- ✅ Shows clear results with actionable priorities

## 🏆 Competition Features

### 🔍 **Comprehensive Security Scanning**
- **👥 User Management**: Password policies, admin accounts, unauthorized users
- **⚙️ Services**: Dangerous services, SSH config, startup management
- **🌐 Network Security**: Port scanning, firewall config, network shares
- **📁 File System**: Permission auditing, dangerous files, integrity checks
- **📦 Software**: Unauthorized programs, required software, updates
- **🖥️ System Config**: Security policies, audit logging, system hardening
- **🛡️ Advanced Security**: Encryption, certificates, advanced threats
- **🖥️ Windows Server**: IIS, Active Directory, DNS, DHCP, specialized roles

### 🔧 **Professional Hardening Scripts**
```bash
# List all available scripts
ironguard scripts list

# Available professional hardening scripts:
📋 hardening_baseline    - Apply standard security hardening
🔒 password_policy       - Enforce strong password policies
🛡️ firewall_config       - Configure secure firewall rules
👥 user_audit           - Audit user accounts and permissions
⚙️ service_lockdown     - Disable unnecessary services
📝 audit_enable         - Enable comprehensive audit logging
🌐 network_secure       - Secure network configurations
📦 software_cleanup     - Remove unauthorized software
🔐 encryption_check     - Verify encryption settings
```

### 🎮 **Interactive TUI Interface**
```bash
ironguard tui
```

**Organized tabs for complex management:**
- 📋 **Tab 1**: Security Scan with real-time progress
- 🔧 **Tab 2**: Auto-Fix Vulnerabilities with confirmation
- 📜 **Tab 3**: Manual Scripts with parallel execution
- ⚙️ **Tab 4**: System Configuration management
- 📊 **Tab 5**: Reports & Analytics with scoring

### 🚀 **Parallel Processing**
- **Concurrent scanning**: Multiple security checks simultaneously
- **Parallel script execution**: Run all hardening scripts at once
- **Background processing**: Scan while handling manual requirements
- **Speed optimization**: Maximum efficiency for time-critical competitions

## 🎯 Competition Strategy

### **Start of Competition (First 2 minutes):**
```bash
# Get immediate points while others read the README
ironguard scan --auto-fix --parallel
```

### **Background Tasks (Next 5 minutes):**
```bash
# Run comprehensive hardening while doing manual work
ironguard scripts run-all --parallel
```

### **Organized Management (Throughout competition):**
```bash
# Use TUI for complex scenario management
ironguard tui
```

### **Final Verification (Last 10 minutes):**
```bash
# Final scan to ensure everything is secure
ironguard scan --parallel
```

## 📚 Complete Documentation

- **[Quick Start Guide](docs/quick-start.md)** - Get running in 60 seconds
- **[Competition Commands](COMPETITION_COMMANDS.md)** - Essential command reference
- **[Enhanced Features](ENHANCED_FEATURES.md)** - Complete feature overview
- **[Windows Server Guide](WINDOWS_SERVER.md)** - Server-specific security
- **[Installation Guide](INSTALL.md)** - Detailed installation instructions
- **[Complete Documentation](docs/)** - Comprehensive guides and references

## 🛠️ Technical Specifications

### **System Requirements**
- **OS**: Windows 10/11, Windows Server 2016+, Linux (Ubuntu/Debian/CentOS/RHEL)
- **Rust**: 1.70+ (automatically installed if missing)
- **Privileges**: Administrator (Windows) or sudo (Linux) for full functionality
- **Memory**: 50MB RAM minimum
- **Storage**: 10MB for installation

### **Performance**
- **Scan Speed**: 2-5 minutes for comprehensive system scan
- **Parallel Processing**: Up to 16 concurrent operations
- **Memory Efficient**: Optimized for competition VM constraints
- **Cross-Platform**: Native Windows and Linux support

### **Safety Features**
- **Automatic Backups**: All changes backed up for rollback
- **System Restore Points**: Windows restore points before major changes
- **Confirmation Prompts**: Ask before making system modifications
- **Rollback Capability**: Undo changes if something goes wrong
- **Safe Auto-Fix**: Only applies verified safe fixes automatically

## 🔧 Configuration

### **Automatic Configuration**
IronGuard automatically downloads a comprehensive configuration file during installation. If the download fails, it falls back to interactive prompts.

### **Manual Configuration**
```bash
# Edit main configuration
ironguard config edit

# Configuration location
~/.ironguard/ironguard.toml
```

### **Competition Customization**
The configuration file includes extensive documentation for customizing IronGuard for specific competition scenarios:
- Required/forbidden services
- Allowed users and admin accounts
- Custom ports and network settings
- Required/unauthorized software
- Security policy requirements

## 🧪 Testing & Development

### **Run Tests**
```bash
# Run all tests
cargo test

# Run benchmarks
cargo bench

# Test specific module
cargo test test_user_scanner
```

### **Performance Benchmarks**
```bash
# Run performance benchmarks
cargo bench

# Individual scanner benchmarks
cargo bench bench_user_scanner
cargo bench bench_complete_scan
```

## 🏆 Competition Advantages

### **What Your Team Gets:**
- ✅ **Professional-grade** security scanning (9+ categories)
- ✅ **Automatic vulnerability fixing** with smart safety checks
- ✅ **Hardening script arsenal** of 10+ professional tools
- ✅ **Parallel processing** for maximum competition speed
- ✅ **TUI organization** for complex scenario management
- ✅ **Zero-knowledge operation** - anyone can contribute

### **Competitive Edge:**
While other teams manually hunt for vulnerabilities:
- 🚀 **Your team gets instant points** with automated scanning
- 🎯 **Handles complex scenarios** with organized TUI interface
- ⚡ **Executes professional hardening** in parallel
- 🎖️ **Focuses energy** on scenario-specific requirements

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🎖️ Acknowledgments

- Built for CyberPatriot competition excellence
- Inspired by real competition scenarios and challenges
- Designed with input from successful CyberPatriot teams
- Optimized for maximum point achievement

---

## 🚀 Ready to Dominate?

**Install IronGuard and start achieving 100-point perfection in every CyberPatriot competition!**

```bash
# One command to rule them all
curl -sSL https://raw.githubusercontent.com/tanav-malhotra/ironguard/main/install.sh | bash
```

**Go forth and conquer! 🏆**

---

*For questions, issues, or feature requests, please open an issue on GitHub.*