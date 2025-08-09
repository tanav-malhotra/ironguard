# IronGuard Ultimate Installation Script for Windows
# One-command install: Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tanav-malhotra/ironguard/main/install.ps1").Content

# Set error action
$ErrorActionPreference = "Stop"

# Colors for Windows Terminal
function Write-ColorText {
    param(
        [string]$Text,
        [string]$Color = "White"
    )
    Write-Host $Text -ForegroundColor $Color
}

# IronGuard Logo
function Show-Logo {
    Write-Host ""
    Write-ColorText "██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ " "White"
    Write-ColorText "██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗" "White"
    Write-ColorText "██║██████╔╝██║   ██║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║" "White"
    Write-ColorText "██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║" "White"
    Write-ColorText "██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝" "White"
    Write-ColorText "╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ " "White"
    Write-Host ""
    Write-ColorText "🛡️  ULTIMATE CYBERPATRIOT SECURITY SCANNER 🛡️" "Cyan"
    #Write-ColorText "🏆 Your path to 100-point CyberPatriot domination! 🏆" "Yellow"
    Write-Host ""
}

# Print step
function Write-Step {
    param([string]$Message)
    Write-ColorText "[STEP] $Message" "Blue"
}

# Print success
function Write-Success {
    param([string]$Message)
    Write-ColorText "[SUCCESS] $Message" "Green"
}

# Print warning
function Write-Warning {
    param([string]$Message)
    Write-ColorText "[WARNING] $Message" "Yellow"
}

# Print error
function Write-Error {
    param([string]$Message)
    Write-ColorText "[ERROR] $Message" "Red"
}

# Check if command exists
function Test-Command {
    param([string]$Command)
    $null = Get-Command $Command -ErrorAction SilentlyContinue
    return $?
}

# Check system requirements
function Test-Requirements {
    Write-Step "Checking system requirements..."
    
    # Check for git
    if (-not (Test-Command "git")) {
        Write-Error "git is required but not installed. Please install Git for Windows first."
        exit 1
    }
    
    # Check for Rust
    if (-not (Test-Command "cargo")) {
        Write-Warning "Rust/Cargo not found. Please install Rust from https://rustup.rs/"
        Write-Warning "After installing Rust, rerun this script."
        exit 1
    }
    
    Write-Success "All requirements satisfied!"
}

# Install IronGuard
function Install-IronGuard {
    Write-Step "Installing IronGuard Ultimate..."
    
    # Create temporary directory
    $TempDir = New-TemporaryFile | ForEach-Object { Remove-Item $_; New-Item -ItemType Directory -Path $_ }
    Set-Location $TempDir
    
    # Clone repository
    Write-Step "Downloading IronGuard source code..."
    git clone https://github.com/tanav-malhotra/ironguard.git
    Set-Location ironguard
    
    # Install IronGuard to PATH
    Write-Step "Building and installing IronGuard..."
    cargo install --path . --force
    
    # Create config directory
    $ConfigDir = "$env:USERPROFILE\.ironguard"
    if (-not (Test-Path $ConfigDir)) {
        New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    }
    
    # Download comprehensive config
    Write-Step "Installing comprehensive configuration..."
    try {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tanav-malhotra/ironguard/main/ironguard.toml" -OutFile "$ConfigDir\ironguard.toml"
        Write-Success "Configuration installed to $ConfigDir\ironguard.toml"
    } catch {
        Write-Warning "Failed to download config. IronGuard will use interactive prompts."
    }
    
    # Install documentation
    Write-Step "Installing documentation..."
    $DocDir = "$ConfigDir\docs"
    if (-not (Test-Path $DocDir)) {
        New-Item -ItemType Directory -Path $DocDir -Force | Out-Null
    }
    
    # Download all documentation
    $docs = @("README.md", "ENHANCED_FEATURES.md", "COMPETITION_COMMANDS.md", "WINDOWS_SERVER.md", "INSTALL.md")
    foreach ($doc in $docs) {
        try {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tanav-malhotra/ironguard/main/$doc" -OutFile "$DocDir\$doc"
            Write-Host "  ✓ $doc"
        } catch {
            # Silent fail for missing docs
        }
    }
    
    Write-Success "Documentation installed to $DocDir\"
    
    # Cleanup
    Set-Location \
    Remove-Item $TempDir -Recurse -Force
}

# Test installation
function Test-Installation {
    Write-Step "Testing IronGuard installation..."
    
    if (Test-Command "ironguard") {
        Write-Success "IronGuard is installed and accessible globally!"
        Write-Host ""
        Write-ColorText "🎯 Quick Start:" "Cyan"
        Write-ColorText "  ironguard scan --auto-fix --parallel    # Ultimate automation" "White"
        Write-ColorText "  ironguard scripts run-all --parallel     # All hardening scripts" "White"
        Write-ColorText "  ironguard tui                            # Interactive interface" "White"
        Write-ColorText "  ironguard --help                         # Full command reference" "White"
        Write-Host ""
        Write-ColorText "📚 Documentation:" "Cyan"
        Write-ColorText "  ~/.ironguard/docs/                       # All documentation" "White"
        Write-ColorText "  ironguard docs                           # View docs in terminal" "White"
        Write-Host ""
        Write-ColorText "⚙️  Configuration:" "Cyan"
        Write-ColorText "  ~/.ironguard/ironguard.toml              # Main configuration" "White"
        Write-ColorText "  ironguard config edit                    # Edit configuration" "White"
    } else {
        Write-Error "Installation failed. IronGuard command not found."
        exit 1
    }
}

# Main installation flow
function Main {
    Show-Logo
    
    Write-ColorText "🚀 Starting IronGuard Ultimate Installation..." "Magenta"
    Write-Host ""
    
    Test-Requirements
    Install-IronGuard
    Test-Installation
    
    Write-Host ""
    Write-ColorText "🎉 INSTALLATION COMPLETE! 🎉" "Green"
    Write-Host ""
    Write-ColorText "🏆 Ready to dominate CyberPatriot competitions!" "Yellow"
    Write-ColorText "   Run 'ironguard scan --auto-fix --parallel' to start winning!" "Cyan"
    Write-Host ""
    Write-ColorText "💡 Pro tip: Share this install command with your team:" "White"
    Write-ColorText "   Invoke-Expression (Invoke-WebRequest -Uri `"https://raw.githubusercontent.com/tanav-malhotra/ironguard/main/install.ps1`").Content" "Cyan"
    Write-Host ""
}

# Run installation
Main