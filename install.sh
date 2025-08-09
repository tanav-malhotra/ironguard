#!/bin/bash

# IronGuard Ultimate Installation Script
# One-command install: curl -sSL https://raw.githubusercontent.com/tanav-malhotra/ironguard/main/install.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# IronGuard Logo using block characters
show_logo() {
    echo ""
    echo -e "${BOLD}${WHITE}██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ${NC}"
    echo -e "${BOLD}${WHITE}██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗${NC}"
    echo -e "${BOLD}${WHITE}██║██████╔╝██║   ██║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║${NC}"
    echo -e "${BOLD}${WHITE}██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║${NC}"
    echo -e "${BOLD}${WHITE}██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝${NC}"
    echo -e "${BOLD}${WHITE}╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ${NC}"
    echo ""
    echo -e "${BOLD}${CYAN}🛡️  ULTIMATE CYBERPATRIOT SECURITY SCANNER 🛡️${NC}"
    #echo -e "${BOLD}${YELLOW}🏆 Your path to 100-point CyberPatriot domination! 🏆${NC}"
    echo ""
}

# Progress indicator
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Print step
print_step() {
    echo -e "${BOLD}${BLUE}[STEP]${NC} $1"
}

# Print success
print_success() {
    echo -e "${BOLD}${GREEN}[SUCCESS]${NC} $1"
}

# Print warning
print_warning() {
    echo -e "${BOLD}${YELLOW}[WARNING]${NC} $1"
}

# Print error
print_error() {
    echo -e "${BOLD}${RED}[ERROR]${NC} $1"
}

# Check system requirements
check_requirements() {
    print_step "Checking system requirements..."
    
    # Check for curl
    if ! command_exists curl; then
        print_error "curl is required but not installed. Please install curl first."
        exit 1
    fi
    
    # Check for git
    if ! command_exists git; then
        print_error "git is required but not installed. Please install git first."
        exit 1
    fi
    
    # Check for Rust
    if ! command_exists cargo; then
        print_warning "Rust/Cargo not found. Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source $HOME/.cargo/env
        
        if ! command_exists cargo; then
            print_error "Failed to install Rust. Please install manually from https://rustup.rs/"
            exit 1
        fi
    fi
    
    print_success "All requirements satisfied!"
}

# Install IronGuard
install_ironguard() {
    print_step "Installing IronGuard Ultimate..."
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Clone repository
    print_step "Downloading IronGuard source code..."
    git clone https://github.com/tanav-malhotra/ironguard.git
    cd ironguard
    
    # Install IronGuard to PATH
    print_step "Building and installing IronGuard..."
    cargo install --path . --force
    
    # Create config directory
    CONFIG_DIR="$HOME/.ironguard"
    mkdir -p "$CONFIG_DIR"
    
    # Download comprehensive config
    print_step "Installing comprehensive configuration..."
    if curl -sSL "https://raw.githubusercontent.com/tanav-malhotra/ironguard/main/ironguard.toml" -o "$CONFIG_DIR/ironguard.toml"; then
        print_success "Configuration installed to $CONFIG_DIR/ironguard.toml"
    else
        print_warning "Failed to download config. IronGuard will use interactive prompts."
    fi
    
    # Install documentation
    print_step "Installing documentation..."
    DOC_DIR="$CONFIG_DIR/docs"
    mkdir -p "$DOC_DIR"
    
    # Download all documentation
    docs=("README.md" "ENHANCED_FEATURES.md" "COMPETITION_COMMANDS.md" "WINDOWS_SERVER.md" "INSTALL.md")
    for doc in "${docs[@]}"; do
        if curl -sSL "https://raw.githubusercontent.com/tanav-malhotra/ironguard/main/$doc" -o "$DOC_DIR/$doc" 2>/dev/null; then
            echo "  ✓ $doc"
        fi
    done
    
    print_success "Documentation installed to $DOC_DIR/"
    
    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"
}

# Test installation
test_installation() {
    print_step "Testing IronGuard installation..."
    
    if command_exists ironguard; then
        print_success "IronGuard is installed and accessible globally!"
        echo ""
        echo -e "${BOLD}${CYAN}🎯 Quick Start:${NC}"
        echo -e "${WHITE}  ironguard scan --auto-fix --parallel${NC}    # Ultimate automation"
        echo -e "${WHITE}  ironguard scripts run-all --parallel${NC}     # All hardening scripts"
        echo -e "${WHITE}  ironguard tui${NC}                            # Interactive interface"
        echo -e "${WHITE}  ironguard --help${NC}                         # Full command reference"
        echo ""
        echo -e "${BOLD}${CYAN}📚 Documentation:${NC}"
        echo -e "${WHITE}  ~/.ironguard/docs/${NC}                       # All documentation"
        echo -e "${WHITE}  ironguard docs${NC}                           # View docs in terminal"
        echo ""
        echo -e "${BOLD}${CYAN}⚙️  Configuration:${NC}"
        echo -e "${WHITE}  ~/.ironguard/ironguard.toml${NC}              # Main configuration"
        echo -e "${WHITE}  ironguard config edit${NC}                    # Edit configuration"
    else
        print_error "Installation failed. IronGuard command not found."
        exit 1
    fi
}

# Main installation flow
main() {
    show_logo
    
    echo -e "${BOLD}${PURPLE}🚀 Starting IronGuard Ultimate Installation...${NC}"
    echo ""
    
    check_requirements
    install_ironguard
    test_installation
    
    echo ""
    echo -e "${BOLD}${GREEN}🎉 INSTALLATION COMPLETE! 🎉${NC}"
    echo ""
    echo -e "${BOLD}${YELLOW}🏆 Ready to dominate CyberPatriot competitions!${NC}"
    echo -e "${BOLD}${CYAN}   Run 'ironguard scan --auto-fix --parallel' to start winning!${NC}"
    echo ""
    echo -e "${BOLD}${WHITE}💡 Pro tip: Share this install command with your team:${NC}"
    echo -e "${CYAN}   curl -sSL https://raw.githubusercontent.com/tanav-malhotra/ironguard/main/install.sh | bash${NC}"
    echo ""
}

# Run installation
main "$@"