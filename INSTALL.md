# 🛡️ IronGuard Installation Guide

## 🚀 Quick Install (Recommended)

### **Step 1: Install IronGuard**
```bash
# Clone and install in one command
git clone https://github.com/tanav-malhotra/ironguard.git
cd ironguard
cargo install --path .
```

### **Step 2: Verify Installation**
```bash
# Now you can use 'ironguard' from anywhere!
ironguard --help
ironguard scan --auto-fix
```

## 🎯 For Your Teammates

### **Simple Copy-Paste Instructions:**
```bash
# 1. Clone the repo
git clone https://github.com/tanav-malhotra/ironguard.git

# 2. Go into the directory  
cd ironguard

# 3. Install IronGuard globally
cargo install --path .

# 4. Test it works
ironguard scan --auto-fix
```

## 🏆 Competition Setup

### **On Competition VMs:**
1. **Download and install Rust** (if not available):
   ```bash
   # Windows: Download from https://rustup.rs/
   # Linux: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Install IronGuard**:
   ```bash
   git clone https://github.com/tanav-malhotra/ironguard.git
   cd ironguard
   cargo install --path .
   ```

3. **Start winning**:
   ```bash
   ironguard scan --auto-fix --parallel
   ironguard scripts run-all --parallel
   ```

## 💡 Benefits of `cargo install --path .`

- ✅ **Global access**: Type `ironguard` from anywhere
- ✅ **No path issues**: Don't need `./target/release/ironguard`
- ✅ **Teammate friendly**: Easy to remember
- ✅ **Competition ready**: Quick setup on any VM

## 🔧 Development Setup

### **For Contributing:**
```bash
git clone https://github.com/tanav-malhotra/ironguard.git
cd ironguard
cargo build --release
cargo test
```

### **For Testing Changes:**
```bash
# Install your local changes
cargo install --path . --force

# Test immediately
ironguard --version
```

## 🛡️ System Requirements

- **Rust**: 1.70+ (latest stable recommended)
- **OS**: Windows 10/11, Windows Server 2016+, Linux (Ubuntu/Debian/CentOS/RHEL)
- **Privileges**: Run as Administrator (Windows) or with sudo (Linux) for full functionality
- **Memory**: 50MB RAM minimum
- **Disk**: 10MB storage

## ⚡ First Run

```bash
# Basic scan
ironguard scan

# Automatic fixes (competition mode)
ironguard scan --auto-fix --parallel

# TUI interface
ironguard tui

# List all hardening scripts
ironguard scripts list
```

Ready to dominate CyberPatriot! 🏆