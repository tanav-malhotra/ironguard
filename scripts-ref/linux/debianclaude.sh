#!/bin/bash
######################################################################################
# Author: Tanav Malhotra (GitHub: https://github.com/tanav-malhotra)
# Email: tanavm2009@gmail.com
# License: GNU General Public License v3.0
# Copyright (c) 2024 Tanav Malhotra
#
# This script is licensed under the GNU General Public License v3.0.
# You may obtain a copy of the license at:
#   https://www.gnu.org/licenses/gpl-3.0.html
#
# The script is provided "as-is", without any warranty of any kind,
# express or implied, including but not limited to the implied warranties
# of merchantability and fitness for a particular purpose. See the GPL-3.0
# for full details.
#
# You can also view the license by running this script
# with the '--license' option.
######################################################################################

##### IMPORTANT VARS #####
unalias -a
version="v1.7.9"
start_time=$(date +"%Y-%m-%d, %I:%M:%S %p")
start_secs=$(date +%s.%N)
LOGFILE="./linux_script.log"
output_file="./linux_script_output.log"
starting_dir=$(pwd)
distro_id=$(grep '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
NETWORK=$(ip route | grep -oP '(?<=src )[\d.]+(?=/)' | head -1)/$(ip route | grep -oP '(?<=dev ).*(?= proto)' | awk '{ print $1 }' | head -1) # Get the network and subnet dynamically
distro_codename=$(grep '^VERSION_CODENAME=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
debug=0
help=0
license=0
version_arg=0

##### FUNCTIONS #####
banner() {
    cat << 'EOF'
 _____  _    _   _    ___     __
|_   _|/ \  | \ | |  / \ \   / /
  | | / _ \ |  \| | / _ \ \ / / 
  | |/ ___ \| |\  |/ ___ \ V /  
  |_/_/   \_\_| \_/_/   \_\_/   
 __  __    _    _     _   _  ___ _____ ____      _    
|  \/  |  / \  | |   | | | |/ _ \_   _|  _ \    / \   
| |\/| | / _ \ | |   | |_| | | | || | | |_) |  / _ \  
| |  | |/ ___ \| |___|  _  | |_| || | |  _ <  / ___ \ 
|_|  |_/_/   \_\_____|_| |_|\___/ |_| |_| \_\/_/   \_\
EOF
    echo
}
log() {
    echo "$@" >> "$LOGFILE"
    echo "$@"
}
log_info() { # does not print out to terminal
    echo "$@" >> "$LOGFILE"
    if [[ $debug -eq 1 ]]; then
        echo "$@" >> "$output_file"
    fi
}
ring_bell() {
    # for i in {1..10}; do
    #     echo -e "\a"
    #     sleep 0.1                                                    
    # done &
    echo -e "\a" &
}

##### CHECK FOR SUDO #####
log_info "Checking for \`sudo\` access..."
if [[ $EUID -ne 0 ]]; then
    log "\`sudo\` access is required. Please run \`sudo !!\`"
    exit 1
fi

##### MANAGE ARGS #####
if [ $# -gt 0 ]; then
    for arg in "$@"; do
        case "$arg" in
            --help)
                help=1
            ;;
            --version)
                version_arg=1
            ;;
            --license)
                license=1
            ;;
            --debug)
                debug=1
            ;;
            *)
            echo "Unknown option: $arg"
            exit 1
            ;;
        esac
    done
fi
if [[ $help -eq 1 ]]; then
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "    --debug      Enable debug mode"
    echo "    --help       Display this help message"
    echo "    --license    Show license information"
    echo "    --version    Show version information"
    echo ""
    echo "Description: A sophisticated script for Debian-based Linux systems, designed for CyberPatriot competitions."
    exit 0
elif [[ $version_arg -eq 1 ]]; then
    echo "$0 $version"
    exit 0
elif [[ $license -eq 1 ]]; then
    curl https://www.gnu.org/licenses/gpl-3.0.txt | less
    exit 0
elif [[ $debug -eq 1 ]]; then
    set -x
    touch "$LOGFILE"
    touch $output_file
    # Redirect both stdout and stderr to tee
    exec > >(tee -a "$output_file") 2>&1
    
    # Display debug information
    log "Debug mode enabled."
    log
    log "Info:"
    log "Current Directory: $starting_dir"
    log "Start: $start_time"
    log "Distro ID: $distro_id"
    log "Distro Codename: $distro_codename"
    if [[ -x "$(command -v systemctl)" ]]; then
        log "Systemd detected..."
    fi
    sleep 5
else
    touch "$LOGFILE"
    log_info "Start time: $start_time" # log start time
fi

##### START SCRIPT #####
clear
banner
log "Created by Tanav Malhotra, Thomas A. Edison Career & Technical Education High School, New York City, NY, USA"
sleep 3
log "CyberPatriot Linux Script $version"
sleep 1
log "Starting..."
log;log;
sleep 1

##### MAKE SURE USER IS READY TO RUN SCRIPT #####
ring_bell
read -r -p "Do you want to make all of the bash scripts in this directory executable? (Y/n): " confirmation
if [[ $confirmation =~ ^[Nn].* ]]; then
    log "Make sure you manually run \`sudo chmod +x\` on any script you want to run."
else
    chmod +x ./*.sh
fi
ring_bell
read -r -p "Have all of the Forensics Questions been answered? (Y/n): " confirmation
if [[ $confirmation =~ ^[Nn].* ]]; then
    log "error: Please complete these first and only then rerun the script."
    exit 1
fi
ring_bell
read -r -p "Have you created the required users.txt & admins.txt files in the current directory? (Y/n): " confirmation
if [[ $confirmation =~ ^[Nn].* ]]; then
    log "error: Please create these files first by using the information from the README file located on your desktop."
    exit 1
fi

##### UPDATE APT REPOSITORIES #####
log "Updating APT repositories..."
cp /etc/apt/sources.list /etc/apt/sources.list.bak
if [[ $distro_id == "linuxmint" ]]; then
    {
        echo "deb http://packages.linuxmint.com $distro_codename main upstream import backport";
        echo "deb-src http://packages.linuxmint.com $distro_codename main upstream import backport";
    } > /etc/apt/sources.list
elif [[ $distro_id == "ubuntu" ]]; then # EOF was causing errors saying "unexpected token `elif`"
    {
        echo "deb https://mirrors.kernel.org/ubuntu/ $distro_codename main restricted universe multiverse";
        echo "deb https://mirrors.kernel.org/ubuntu/ $distro_codename-updates main restricted universe multiverse";
        echo "deb https://security.ubuntu.com/ubuntu/ $distro_codename-security main restricted universe multiverse";

        echo "deb-src http://archive.ubuntu.com/ubuntu $distro_codename main restricted universe multiverse";
        echo "deb-src http://archive.ubuntu.com/ubuntu $distro_codename-updates main restricted universe multiverse";
        echo "deb-src http://archive.ubuntu.com/ubuntu $distro_codename-backports main restricted universe multiverse";

        echo "deb http://security.ubuntu.com/ubuntu/ $distro_codename-security main restricted universe multiverse";
        echo "deb-src http://security.ubuntu.com/ubuntu/ $distro_codename-security main restricted universe multiverse";
    } > /etc/apt/sources.list
elif [[ $distro_id == "debian" ]]; then
    {
        echo "deb     http://deb.debian.org/debian/ $distro_codename main contrib non-free non-free-firmware";
        echo "deb-src http://deb.debian.org/debian/ $distro_codename main contrib non-free non-free-firmware";
        echo "deb     http://security.debian.org/debian-security $distro_codename-security main contrib non-free non-free-firmware";
        echo "deb-src http://security.debian.org/debian-security $distro_codename-security main contrib non-free non-free-firmware";
        echo "deb     http://deb.debian.org/debian/ $distro_codename-updates main contrib non-free non-free-firmware";
        echo "deb-src http://deb.debian.org/debian/ $distro_codename-updates main contrib non-free non-free-firmware";
    } > /etc/apt/sources.list
else
    log "error: Unsupported distro: $distro_id $distro_codename"
fi
# Configure apt to always verify package signatures
echo 'APT::Get::AllowUnauthenticated "false";' > /etc/apt/apt.conf.d/99verify-peer
# Get list of verified packages
dpkg --verify > /var/log/package-verification.log 2>&1
debsums -c >> /var/log/package-verification.log 2>&1
cp /var/log/package-verification.log ./package_verification.log
# Add additional repositories (PPAs)
add-apt-repository ppa:oisf/suricata-stable -y

##### UPDATE #####
log "Updating system..."
apt purge -y snapd # TODO: ask user whether to remove snap or not
apt update
apt upgrade -y
apt full-upgrade -y
apt autoremove -y --purge

##### SOFTWARE MANAGEMENT #####
apt list --installed > ./software_that_was_installed.log
log "Installing software..."
apps=("fail2ban" "bum" "mawk" "chkrootkit" "rkhunter" "auditd" "vim" "neovim" "iptables" "ufw" "lightdm" "deborphan" "libpam-cracklib" "debsums" "software-properties-gtk" "apt-listbugs" "apt-listchanges" "libpam-tmpdin" "libpam-usb" "libpam-pwquality" "apparmor" "rsyslog" "rsyslog" "USBGaurdd" "usb-storage" "net-tools" "lynis" "debian-archive-keyring" "ubuntu-keyring" "haveged" "acct" "ntp" "debsums" "apt-show-versions" "dnscrypt-proxy" "resolvconf" "debsigs" "libpam-shield" "libpam-tmpdir" "libpam-usb" "clamav" "clamav-daemon" "apparmor-profiles" "apparmor-utils" "apparmor-profiles-extra" "sysdig" "firejail" "tcpd" "knockd" "suricata" "quota" "quotatool" "attr" "libcap2-bin" "ntopng" "cmake" "make" "gcc" "g++" "flex" "bison" "libpcap-dev" "libssl-dev" "python3" "python3-dev" "swig" "zlib1g-dev" "nftables" "iptables-persistent" "libapache2-mod-security2" "osquery" "vlan" "bridge-utils")
for app in "${apps[@]}"; do
    log "Installing $app..."
    apt-get install -y "$app"
done
log "Removing prohibited software and hacking tools (and making sure \`snapd\` was removed)..."
apps=("openssh-server" "wireshark" "telnet" "vsftpd" "proftpd" "snmpd" "mysql-server" "mysql-client" "postgresql" "xrdp" "tightvncserver" "samba" "nmap" "php" "apache2*" "*nginx*" "lighttpd" "tcpdump" "netcat-traditional" "nikto" "ophcrack" "ettercap*" "deluge" "dovecot-core" "*netcat*" "john" "vuze" "frostwire" "aircrack-ng" "metasploit-framework" "nessus" "snort" "kismet" "yersinia" "burp-suite" "burpsuite" "hydra" "oclhashcat" "hashcat" "maltego" "zaproxy" "cain" "*angryip*" "ipscan" "medusa" "xinetd" "openbsd-inetd" "inetutils-inetd" "avahi-daemon" "snapd" "telnet" "postfix")
for app in "${apps[@]}"; do
    log "Removing $app..."
    apt-get purge -y "$app"
done
hacking_tools=("john" "nmap" "vuze" "frostwire" "kismet" "freeciv" "minetest" "minetest-server" "medusa" "hydra" "truecrack" "ophcrack" "nikto" "cryptcat" "nc" "netcat" "tightvncserver" "x11vnc" "nfs" "xinetd" "samba" "postgresql" "sftpd" "vsftpd" "apache" "apache2" "ftp" "mysql" "php" "snmp" "pop3" "icmp" "sendmail" "dovecot" "bind9" "nginx" "telnet" "rlogind" "rshd" "rcmd" "rexecd" "rbootd" "rquotad" "rstatd" "rusersd" "rwalld" "rexd" "fingerd" "tftpd")
for tool in "${hacking_tools[@]}"; do
    log "Removing $tool..."
    apt-get purge -y "$tool"
done
log "Removing games..."
games=("gnome-games" "iagno" "lightsoff" "four-in-a-row" "gnome-robots" "pegsolitaire" "gnome-2048" "hitori" "gnome-klotski" "gnome-mines" "gnome-mahjongg" "gnome-sudoku" "quadrapassel" "swell-foop" "gnome-tetravex" "gnome-taquin" "aisleriot" "gnome-chess" "five-or-more" "gnome-nibbles" "tali" "freeciv" "wesnoth")
# games=$(dpkg -l | grep "game" | awk '{print $2}') # find "game" in package descriptions
for game in "${games[@]}"; do
    log "Removing $game..."
    apt-get purge -y "$game"
done
dpkg --configure -a
apt --fix-broken install
apt autoremove -y --purge
apt-key adv --refresh-keys

##### APT SETTINGS #####
log "Checking for updates daily..."
touch /etc/apt/apt.conf.d/10periodic
touch /etc/apt/apt.conf.d/10removal
touch /etc/apt/apt.conf.d/20auto-upgrades
touch /etc/apt/apt.conf.d/50unattended-upgrades
cp /etc/apt/apt.conf.d/10periodic /etc/apt/apt.conf.d/10periodic.bak
cp /etc/apt/apt.conf.d/10removal /etc/apt/apt.conf.d/10removal.bak
cp /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/20auto-upgrades.bak
cp /etc/apt/apt.conf.d/50unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades.bak
dpkg-reconfigure unattended-upgrades
echo 'APT::Periodic::AutocleanInterval "7";' >> /etc/apt/apt.conf.d/10periodic
echo 'APT::Get::Remove-Unused "true";' >> /etc/apt/apt.conf.d/10removal
cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat >> /etc/apt/apt.conf.d/50unattended-upgrades << EOF
# Unattended-Upgrade::Allowed-Origins {
# 	"${distro_id} stable";
# 	"${distro_id} ${distro_codename}-security";
# 	"${distro_id} ${distro_codename}-updates";
# };
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
cat > /etc/apt/apt.conf.d/52unattended-upgrades-local << EOF
# Unattended-Upgrade::Allowed-Origins {
# 	"${distro_id} stable";
# 	"${distro_id} ${distro_codename}-security";
# 	"${distro_id} ${distro_codename}-updates";
# };
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
# Create package manifest
dpkg --get-selections > /root/package-manifest.txt
chmod 600 /root/package-manifest.txt

##### FIREWALL #####
log "Setting up firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp
ufw logging on
ufw logging high
ufw enable

##### APPLICATION-SPECIFIC HARDENING & SECURITY ##### 
### SSH ###
if command -v sshd &> /dev/null; then
    log "Configuring SSH..."
    sshd_config="/etc/ssh/sshd_config"
    log "Creating SSH config backup located at ${sshd_config}.bak"
    cp "$sshd_config" "${sshd_config}.bak"
    # Function to ensure a line is set in the configuration
    set_sshd_setting() {
        local setting="$1"
        local value="$2"
        # Check if the setting exists and update or add accordingly
        if grep -q "^$setting" "$sshd_config"; then
            sed -i "s/^$setting.*/$setting $value/" "$sshd_config"
            log "Updated $setting to $value."
        else
            log "$setting $value" >> "$sshd_config"
            log "Added $setting with value $value."
        fi
    }
    if [[ ! -f $sshd_config ]]; then
        log "Creating a basic sshd_config file (with secure settings)..."
        touch $sshd_config
    fi
    set_sshd_setting "PermitRootLogin" "no"
    set_sshd_setting "Port" "22"
    set_sshd_setting "PasswordAuthentication" "no"
    set_sshd_setting "ChallengeResponseAuthentication" "no"
    set_sshd_setting "UsePAM" "yes"
    set_sshd_setting "HostbasedAuthentication" "no"
    set_sshd_setting "Protocol" "2"
    set_sshd_setting "LogLevel" "VERBOSE"
    set_sshd_setting "X11Forwarding" "no"
    set_sshd_setting "MaxAuthTries" "3"
    set_sshd_setting "PermitEmptyPasswords" "no"
    set_sshd_setting "ClientAliveInterval" "300"
    set_sshd_setting "ClientAliveCountMax" "0"
    set_sshd_setting "IgnoreRhosts" "yes"
    # Extract the current port from the configuration
    current_port=$(grep -Eo '^Port [0-9]+' "$sshd_config" | awk '{print $2}')
    if [[ -z "$current_port" ]]; then
        current_port=22  # Default to 22 if no port is found
    fi
    # Ask if the user wants to change the SSH port
    ring_bell
    read -r -p "Do you want to change the SSH port? (y/N): " change_port
    if [[ $change_port =~ ^[Yy].* ]]; then
        while true; do
            ring_bell
            read -r -p "Enter the new SSH port (1-65535): " new_port
            
            # Validate the input
            if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1 ] && [ "$new_port" -le 65535 ]; then
                break
            else
                log "Invalid port number. Please enter a number between 1 and 65535."
            fi
        done

        # Update the SSHD configuration with the new port
        # sed -i "s/^Port .*/Port $new_port/" $sshd_config
        set_sshd_setting "Port" "$new_port"
        log "SSH port changed to $new_port."
        
        # Allow the new port in UFW
        ufw delete allow "$current_port"/tcp
        log "Blocked old SSH port."
        ufw allow "$new_port"/tcp
        ufw allow ssh
        log "UFW allowed port $new_port."
    else
        log "Keeping the default SSH port (22)."
        ufw allow "$current_port"/tcp
        ufw allow ssh
    fi
    # Check ssh config
    if sshd -t; then
        log "SSH configuration is correct. Restarting SSH service..."
        if [[ -x "$(command -v systemctl)" ]]; then
            systemctl enable sshd
            systemctl start sshd
            systemctl restart sshd
        elif [[ -x "$(command -v service)" ]]; then
            update-rc.d sshd defaults
            service sshd start
            service sshd restart
        else
            log "error: Unable to restart sshd service."
        fi
    else
        log "error: SSH configuration has errors. Please fix them before restarting the ssh service."
    fi
    # Network Security Enhancements
    echo "sshd: $NETWORK" >> /etc/hosts.allow  # Modify for your network # TODO: do for other services, too
    # SSH keys
    log "Creating new SSH keys..."
    # Define variables
    KEY_NAME="id_ed25519"
    KEY_DIR="/home/$USER/.ssh"
    AUTHORIZED_KEYS="$KEY_DIR/authorized_keys"
    # Check if the .ssh directory exists; if not, create it
    if [ ! -d "$KEY_DIR" ]; then
        mkdir -p "$KEY_DIR"
        chmod 700 "$KEY_DIR"
    fi
    if ssh-keygen -t ed25519 -f "$KEY_DIR/$KEY_NAME" -N ""; then
        log "Ed25519 SSH key generated successfully."
    else
        log "error: Failed to generate SSH key."
    fi
    # Append the public key to authorized_keys
    cat "$KEY_DIR/$KEY_NAME.pub" >> "$AUTHORIZED_KEYS"
    # Set the correct permissions for the authorized_keys file
    chmod 600 "$AUTHORIZED_KEYS"
    log "Public key added to $AUTHORIZED_KEYS."
fi
### DOCKER SECURITY ###
# Container Security (if Docker is installed)
if command -v docker &> /dev/null; then
    # Create default seccomp profile
    mkdir -p /etc/docker/seccomp
    curl -o /etc/docker/seccomp/default.json \
    https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json

    # Configure Docker daemon with security options
    cat > /etc/docker/daemon.json << EOF
{
    "userns-remap": "default",
    "no-new-privileges": true,
    "seccomp-profile": "/etc/docker/seccomp/default.json",
    "selinux-enabled": true,
    "userland-proxy": false,
    "live-restore": true,
    "default-ulimits": {
        "nofile": {
            "Name": "nofile",
            "Hard": 64000,
            "Soft": 64000
        }
    }
}
EOF
    if [[ -x "$(command -v systemctl)" ]]; then
        systemctl restart docker
    elif [[ -x "$(command -v service)" ]]; then
        service docker restart
    else
        log "error: Unable to restart docker service."
    fi
fi
### APACHE2 ###
if command -v apache2 &> /dev/null; then
    # Install mod_security
    cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
    
    # Configure mod_security
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
    
    # Download OWASP ModSecurity Core Rule Set
    cd /etc/modsecurity/
    wget https://github.com/coreruleset/coreruleset/archive/v3.3.2.tar.gz
    tar xvf v3.3.2.tar.gz
    mv coreruleset-3.3.2 owasp-crs
    cp owasp-crs/crs-setup.conf.example owasp-crs/crs-setup.conf
    cd "$starting_dir"
    
    # Configure Apache security settings
    cat > /etc/apache2/conf-available/security.conf << EOF
ServerTokens Prod
ServerSignature Off
TraceEnable Off
FileETag None
Header set X-Content-Type-Options nosniff
Header set X-Frame-Options SAMEORIGIN
Header set X-XSS-Protection "1; mode=block"
Header set Content-Security-Policy "default-src 'self';"
EOF

    a2enmod headers
    a2enconf security
    if [[ -x "$(command -v systemctl)" ]]; then
        systemctl enable apache2
        systemctl start apache2
        systemctl restart apache2
    elif [[ -x "$(command -v service)" ]]; then
        update-rc.d apache2 defaults
        service apache2 start
        service apache2 restart
    else
        log "error: Unable to restart apache2 service."
    fi
fi
### MYSQL/MariaDB ###
if command -v mysql &> /dev/null; then
    # Create secure MySQL configuration
    cat > /etc/mysql/conf.d/hardening.cnf << EOF
[mysqld]
local-infile=0
skip-show-database
skip-symbolic-links
safe-user-create=1
secure-file-priv=/var/lib/mysql-files
explicit_defaults_for_timestamp=1
EOF

    # Run MySQL secure installation
    mysql_secure_installation

    if [[ -x "$(command -v systemctl)" ]]; then
        systemctl enable mysql
        systemctl start mysql
        systemctl restart mysql
    elif [[ -x "$(command -v service)" ]]; then
        update-rc.d mysql defaults
        service mysql start
        service mysql restart
    else
        log "error: Unable to restart mysql service."
    fi
fi
### POSTGRESQL ###
if command -v psql &> /dev/null; then
    cat >> /etc/postgresql/*/main/postgresql.conf << EOF
ssl = on
ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil.key'
password_encryption = scram-sha-256
log_connections = on
log_disconnections = on
log_duration = on
log_hostname = on
EOF

    if [[ -x "$(command -v systemctl)" ]]; then
        systemctl enable psql
        systemctl start psql
        systemctl restart psql
    elif [[ -x "$(command -v service)" ]]; then
        update-rc.d psql defaults
        service psql start
        service psql restart
    else
        log "error: Unable to restart psql service."
    fi
fi
#TODO: add more services plus set up and install and prompt user for critical service selection before purging software

##### IP BANNING (fail2ban) #####
log "Ban IPs with too many incorrect login attempts..."
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
if [[ -x "$(command -v systemctl)" ]]; then
    systemctl enable fail2ban
    systemctl start fail2ban
    systemctl restart fail2ban
elif [[ -x "$(command -v service)" ]]; then
    update-rc.d fail2ban defaults
    service fail2ban start
    service fail2ban restart
else
    log "error: Unable to restart fail2ban service."
fi

##### INTERFACE SETTINGS (e.g. USB, FireWire, Thunderbolt, Bluetooth) #####
log "Setting USB settings..."
if [[ -x "$(command -v systemctl)" ]]; then
    systemctl stop autofs
    systemctl disable autofs
    systemctl mask autofs
elif [[ -x "$(command -v service)" ]]; then
    service autofs stop
    update-rc.d autofs remove
else
    log "error: Unable to stop autofs service."
fi
if [[ -x "$(command -v systemctl)" ]]; then
    systemctl enable USBGaurdd
    systemctl start USBGaurdd
    systemctl restart USBGaurdd
elif [[ -x "$(command -v service)" ]]; then
    update-rc.d USBGaurdd defaults
    service USBGaurdd start
    service USBGaurdd restart
else
    log "error: Unable to restart USBGaurdd service."
fi
log "Disabling USB, FireWire, & Thunderbolt..."
echo "install usb-storage /bin/true" >> /etc/modprobe.d/disable-usb-storage.conf
echo "blacklist firewire-core" >> /etc/modprobe.d/firewire.conf
echo "blacklist thunderbolt" >> /etc/modprobe.d/thunderbolt.conf
{
    echo "blacklist bluetooth"
    echo "blacklist usb-storage"
    echo "blacklist uas"
    echo "blacklist xhci_hcd"
    echo "blacklist ehci_hcd"
    echo "blacklist uhci_hcd"
    echo "blacklist ohci_hcd"
    echo "blacklist thunderbolt"
    echo "blacklist firewire-core"
    echo "blacklist firewire-ohci"
    echo "blacklist ieee1394"
    echo "blacklist ohci1394"
} >> /etc/modprobe.d/blacklist.conf
# Remove unused network protocols
log "Disabling unused network protocols..."
{
    echo "install dccp /bin/true"
    echo "install sctp /bin/true"
    echo "install rds /bin/true"
    echo "install tipc /bin/true"
} >> /etc/modprobe.d/disable-protocols.conf
update-initramfs -u
cat > /etc/udev/rules.d/99-disable-interfaces.rules << EOF
ACTION=="add", SUBSYSTEM=="usb", ENV{MODALIAS}!="", RUN="/bin/false"
ACTION=="add", SUBSYSTEM=="thunderbolt", ENV{MODALIAS}!="", RUN="/bin/false"
ACTION=="add", SUBSYSTEM=="firewire", ENV{MODALIAS}!="", RUN="/bin/false"
EOF
udevadm control --reload-rules
if [[ -x "$(command -v systemctl)" ]]; then
    systemctl disable avahi-daemon
    systemctl stop avahi-daemon
    systemctl disable cups
    systemctl stop cups
    systemctl disable bluetooth
    systemctl stop bluetooth
elif [[ -x "$(command -v service)" ]]; then
    service avail-daemon disable
    service avahi-daemon stop
    service cups disable
    service cups stop
    service bluetooth disable
    service bluetooth stop
else
    log "error: Unable to disable bluetooth, cups, & avahi-daemon services."
fi

##### REMOVING BASH ALIASES #####
log "Removing all bash aliases..."
find / -type f -name "*bashrc" 2>/dev/null | while read -r bashrc_file; do
    if [ -f "$bashrc_file" ]; then
        cp "$bashrc_file" "$bashrc_file.bak"
        sed -i '/alias /d' "$bashrc_file"
        if ! diff "$bashrc_file" "$bashrc_file.bak" >/dev/null; then
            log "Aliases removed from $bashrc_file."
        else
            log "No aliases found in $bashrc_file."
        fi
    fi
done

#### FILE/DIR PERMS/OWNERSHIP #####
log "Setting home directory permissions..."
for i in $(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd); do [ -d /home/${i} ] && chmod -R 750 /home/${i}; done
find /home -type d -name '.ssh' -exec chmod 700 {} \;
log "Changing permissions (and owners) of commonly exploited files..."
# Files related to authentication and configuration
chown root:root /etc/securetty
chown root:shadow /etc/shadow
chmod 0600 /etc/securetty
chmod 600 /etc/shadow
chmod 0440 /etc/sudoers
chmod 644 /etc/crontab
chmod 640 /etc/ftpusers
chmod 440 /etc/inetd.conf
chmod 440 /etc/xinetd.conf
chmod 400 /etc/inetd.d
chmod 644 /etc/hosts.allow
# Root and important system directories
chown root:root /
chmod 755 /
chown root:root /bin
chmod 755 /bin
chown root:root /boot
chmod 755 /boot
chown root:root /etc
chmod 755 /etc
chown root:root /lib
chmod 755 /lib
chown root:root /lib64
chmod 755 /lib64
chown root:root /opt
chmod 755 /opt
chown root:root /sbin
chmod 755 /sbin
chown root:root /usr
chmod 755 /usr
chown root:root /var
chmod 755 /var
# Password and shadow files
chown root:root /etc/passwd
chmod 644 /etc/passwd
chown root:shadow /etc/shadow
chmod 600 /etc/shadow
chown root:root /etc/group
chmod 644 /etc/group
chown root:shadow /etc/gshadow
chmod 600 /etc/gshadow
# SSH keys and directories
chown root:root /etc/ssh/ssh_host_*_key
chmod 600 /etc/ssh/ssh_host_*_key
chown root:root /etc/ssh/ssh_host_*_key.pub
chmod 644 /etc/ssh/ssh_host_*_key.pub
# Root user and sensitive directories
chown root:root /root
chmod 700 /root
chown root:root /tmp
chmod 1777 /tmp

##### CRON SETTINGS #####
log "Changing cron settings..."
cp /etc/rc.local /etc/rc.local.bak
# Prevent kernel module loading after boot
cat > /etc/rc.local << EOF
#!/bin/bash
# Disable dynamic module loading
echo 1 > /proc/sys/kernel/modules_disabled
exit 0
EOF
chmod +x /etc/rc.local
cp /etc/cron.deny /etc/cron.deny.bak
echo "ALL" >> /etc/cron.deny

##### SYSTEM/APPLICATION/NETWORK SECURITY SETTINGS (Kernel Hardening, IP settings, application sandboxing, advanced process monitoring, DNS configs, network namespaces, etc.) #####
log "Enabling syn cookie protection..."
sysctl -n net.ipv4.tcp_syncookies
log "Disabling IP Forwarding..."
cp /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv4/ip_forward.bak
echo 0 | tee /proc/sys/net/ipv4/ip_forward
log "Preventing IP Spoofing..."
iptables -A INPUT -s 10.0.0.0/8 -i eth0 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -i eth0 -j DROP
iptables -A INPUT -s 192.168.0.0/16 -i eth0 -j DROP
iptables -A INPUT -i eth0 -m limit --limit 2/min -j LOG --log-prefix "Dropped Packet: "
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m state --state NEW -j DROP
log "Kernel Hardening..."
cp /etc/sysctl.conf /etc/sysctl.conf.bak
cat > /etc/sysctl.conf << EOF
fs.file-max = 65535
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.exec-shield = 1
kernel.sysrq = 0
kernel.randomize_va_space = 2
kernel.pid_max = 65536
kernel.kptr_restrict=2
kernel.perf_event_paranoid=3
kernel.unprivileged_bpf_disabled=1
kernel.yama.ptrace_scope = 3
kernel.kexec_load_disabled = 1
kernel.unprivileged_userns_clone = 0
kernel.seccomp.actions_avail = kill_process,kill_thread,trap,errno,trace,log
vm.mmap_min_addr=65536
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_rmem = 10240 87380 12582912
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_wmem = 10240 87380 12582912
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0
net.ipv4.ip_local_port_range = 2000 65000
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_timestamps = 9
# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
# Incase IPv6 is necessary
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.rp_filter = 1
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1
net.ipv6.conf.default.rp_filter = 1
EOF
sysctl -p
# Configure system-wide umask
log "Configuring system-wide umask..."
echo "umask 027" >> /etc/profile
# Disable core dumps
log "Disabling core dumps..."
echo "* soft core 0" >> /etc/security/limits.conf
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
mkdir -p /etc/systemd/coredump.conf.d/
cat > /etc/systemd/coredump.conf.d/custom.conf << EOF
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
# Secure shared memory
log "Securing shared memory..."
echo "tmpfs     /run/shm     tmpfs     defaults,noexec,nosuid     0     0" >> /etc/fstab
# System-wide security limits
cat >> /etc/security/limits.conf << EOF
* hard core 0
* soft nproc 100
* hard nproc 150
EOF
# Add entropy gathering, process accounting (for tracking unusual behavior), and DNS security
if [[ -x "$(command -v systemctl)" ]]; then
    systemctl enable haveged # entropy gathering
    systemctl start haveged
    systemctl enable acct # process accounting for debian
    systemctl start acct
    systemctl enable dnscrypt-proxy # DNS security
    systemctl start dnscrypt-proxy
elif [[ -x "$(command -v service)" ]]; then
    update-rc.d haveged defaults # entropy gathering
    service haveged start
    update-rc.d acct defaults # process accounting for debian
    service acct start
    update-rc.d dnscrypt-proxy defaults # DNS security
    service dnscrypt-proxy start
else
    log "error: Unable to start haveged, acct, and dnscrypt-proxy services."
fi
# Protect against time-based attacks
sed -i "s/RUNASUSER=ntp/RUNASUSER=_ntp/" /etc/init.d/ntp
# Detect unauthorized SUID/SGID binaries
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; > ./suid_sgid_binaries.log
# Harden dynamic loader configuration
echo "# Block loading of shared libraries from current directory" > /etc/ld.so.preload
# Secure tmp directories with noexec
echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
echo "tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
# Restrict special filesystem mounting
cat >> /etc/modprobe.d/disable-filesystems.conf << EOF
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF
# Configure system to log all executed commands
{
    echo "export PROMPT_COMMAND=\"history -a; $PROMPT_COMMAND\""
    echo "readonly PROMPT_COMMAND"
    echo "readonly HISTFILE"
    echo "readonly HISTFILESIZE"
    echo "readonly HISTSIZE"
    echo "readonly HISTTIMEFORMAT"
    echo "export HISTTIMEFORMAT=\"%F %T \""
    echo "export HISTFILESIZE=10000"
    echo "export HISTSIZE=10000"
} >> /etc/bash.bashrc
# Configure systemd to create crash dumps for analysis
mkdir -p /var/crash
chmod 700 /var/crash
echo 'kernel.core_pattern = |/usr/share/apport/apport %p %s %c %d %P %E' > /etc/sysctl.d/10-core-dump.conf
# Configure systemd protection mechanisms
mkdir -p /etc/systemd/system.conf.d/
cat > /etc/systemd/system.conf.d/protection.conf << EOF
[Manager]
DynamicUser=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
NoNewPrivileges=yes
EOF
# Configure systemd sandboxing for all services
mkdir -p /etc/systemd/system.conf.d/
cat > /etc/systemd/system.conf.d/sandbox.conf << EOF
[Service]
CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_SYS_PTRACE
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
EOF
# Configure DNS over HTTPS
cat > /etc/dnscrypt-proxy/dnscrypt-proxy.toml << EOF
server_names = ['cloudflare', 'google']
listen_addresses = ['127.0.0.1:53']
max_clients = 250
ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = true
doh_servers = true
require_dnssec = true
require_nolog = true
require_nofilter = true
force_tcp = false
timeout = 2500
keepalive = 30
EOF
# Update resolv.conf to use local DNSCrypt proxy
echo "nameserver 127.0.0.1" > /etc/resolv.conf
chattr +i /etc/resolv.conf  # Prevent modification
# Harden dynamic loader configuration
echo "# Block loading of shared libraries from current directory" > /etc/ld.so.preload # clears the file
# Configure advanced process monitoring with sysdig
/usr/bin/sysdig -w "/var/log/sysdig/$(date +%Y%m%d_%H%M%S).scap" -M 600 "not port 22"
mkdir -p /var/log/sysdig
chmod 750 /var/log/sysdig
# Install and configure firejail for application sandboxing
firecfg --fix-sound
firecfg --fix-desktop
# Create default firejail profile
cat > /etc/firejail/default.local << EOF
ignore noexec \${HOME}
ignore noexec /tmp
whitelist \${HOME}/.config
EOF
# Network Security Enhancements
echo "ALL: ALL" >> /etc/hosts.deny
# Install and configure port knocking
cat > /etc/knockd.conf << EOF
[options]
    UseSyslog

[openSSH]
    sequence    = 7000,8000,9000
    seq_timeout = 5
    command     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
    tcpflags    = syn
    cmd_timeout = 10
    stop_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT

[closeSSH]
    sequence    = 9000,8000,7000
    seq_timeout = 5
    command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
EOF
if [[ -x "$(command -v systemctl)" ]]; then
    systemctl enable knockd
    systemctl start knockd
elif [[ -x "$(command -v service)" ]]; then
    update-rc.d knockd defaults
    service knockd start
else
    log "error: Unable to start knockd service."
fi
# Setup network namespaces
ip netns add isolated
ip link add veth0 type veth peer name veth1
ip link set veth1 netns isolated
ip netns exec isolated ip link set veth1 up
ip netns exec isolated ip addr add 192.168.100.2/24 dev veth1
# Setup package verification hooks (ntopng - Traffic Analysis Tool)
cat > /etc/ntopng/ntopng.conf << EOF
-i=eth0
-w=3000
--community
--redis-mode=1
EOF
if [[ -x "$(command -v systemctl)" ]]; then
    systemctl enable ntopng
    systemctl start ntopng
elif [[ -x "$(command -v service)" ]]; then
    update-rc.d ntopng defaults
    service ntopng start
else
    log "error: Unable to start ntopng service."
fi
# Configure Suricata IDS (Intrusion Detection System)
cat > /etc/suricata/suricata.yaml << EOF
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - ssh

app-layer:
  protocols:
    tls:
      enabled: yes
    ssh:
      enabled: yes
    dns:
      tcp:
        enabled: yes
      udp:
        enabled: yes
EOF
if [[ -x "$(command -v systemctl)" ]]; then
    systemctl enable suricata
    systemctl start suricata
elif [[ -x "$(command -v service)" ]]; then
    update-rc.d suricata defaults
    service suricata start
else
    log "error: Unable to start suricata service."
fi
# Download and install custom rules
wget https://rules.emergingthreats.net/open/suricata-5.0/emerging.rules.tar.gz
tar xzf emerging.rules.tar.gz -C /etc/suricata/rules/
rm emerging.rules.tar.gz
# Configure custom IDS rules
cat >> /etc/suricata/suricata.yaml << EOF
rule-files:
  - emerging-exploit.rules
  - emerging-malware.rules
  - emerging-scan.rules
  - emerging-dos.rules
  - emerging-attack_response.rules
  - emerging-web_specific_apps.rules
EOF
# Install and configure Zeek (formerly Bro) IDS (Intrusion Detection System)
git clone --recursive https://github.com/zeek/zeek
cd zeek
./configure && make && make install
cd .. && rm -rf zeek
cd "$starting_dir"
# Configure Zeek
cat > /usr/local/zeek/share/zeek/site/local.zeek << EOF
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ftp
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh
@load base/frameworks/intel
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

redef Intel::read_files += {
    "/usr/local/zeek/share/zeek/intel/intel.dat"
};
EOF
# Create Zeek service
cat > /etc/systemd/system/zeek.service << EOF
[Unit]
Description=Zeek Network Security Monitor
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/zeek/bin/zeekctl start
ExecStop=/usr/local/zeek/bin/zeekctl stop
RestartSec=10s
Restart=always

[Install]
WantedBy=multi-user.target
EOF
if [[ -x "$(command -v systemctl)" ]]; then
    systemctl enable zeek
    systemctl start zeek
elif [[ -x "$(command -v service)" ]]; then
    update-rc.d zeek defaults
    service zeek start
else
    log "error: Unable to start zeek service."
fi
# Custom Network Filtering Rules
# Create comprehensive nftables ruleset
cat > /etc/nftables.conf << EOF
#!/usr/sbin/nftables -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority -1; policy drop;
        
        # Accept established/related connections
        ct state established,related accept
        
        # Accept loopback traffic
        iif lo accept
        
        # Accept ICMP and IGMP
        ip protocol icmp accept
        ip5 nexthdr icmpv6 accept
        ip protocol igmp accept
        
        # Accept SSH (after port knocking)
        tcp dport ssh ct state new accept

        # TODO: add other supported critical services here
        
        # Custom application rules
        tcp dport { http, https } ct state new accept
        
        # Rate limiting for connections
        tcp flags syn tcp dport { ssh, http, https } meter flood { ip saddr timeout 9s limit rate over 10/second } drop
        
        # Advanced protocol filtering
        ip protocol { udp, tcp } ct state new jump PROTOCOLS
    }

    chain forward {
        type filter hook forward priority -1; policy drop;
    }

    chain output {
        type filter hook output priority -1; policy accept;
    }

    chain PROTOCOLS {
        # Allow DNS queries
        udp dport 52 accept
        tcp dport 52 accept
        
        # Allow NTP
        udp dport 122 accept
        
        # Block commonly abused ports
        tcp dport { telnet, smtp, pop2, imap } drop
        
        # Block known malware ports
        tcp dport { 444, 135, 137, 138, 139 } drop
    }
}

# Enable connection tracking
table raw {
    chain prerouting {
        type filter hook prerouting priority -301;
        ct state invalid drop
        tcp flags & (fin|syn|rst|ack) != syn ct state new drop
    }
}
EOF
if [[ -x "$(command -v systemctl)" ]]; then
    systemctl enable nftables
    systemctl start nftables
elif [[ -x "$(command -v service)" ]]; then
    update-rc.d nftables defaults
    service nftables start
else
    log "error: Unable to start nftables service."
fi
# Monitor network traffic
nethogs -t | grep -v "localhost" > ./traffic_monitor.log # Monitor suspicious connections
iftop -t -s 10 > ./bandwidth_usage.log # Monitor packet statistics
netstat -tulpn | grep LISTEN > ./open_ports.log # Check for unusual ports
tcpdump -i any port 53 > ./dns_queries.log # Monitor DNS queries
# Configure osquery
cat > /etc/osquery/osquery.conf << EOF
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "schedule_splay_percent": 10
  },
  "schedule": {
    "process_events": {
      "query": "SELECT * FROM process_events;",
      "interval": 60
    },
    "socket_events": {
      "query": "SELECT * FROM socket_events;",
      "interval": 60
    },
    "file_events": {
      "query": "SELECT * FROM file_events;",
      "interval": 60
    },
    "unusual_processes": {
      "query": "SELECT name, path, cmdline FROM processes WHERE on_disk = 0 OR parent = 0;",
      "interval": 3600
    }
  },
  "decorators": {
    "load": [
      "SELECT uuid AS host_uuid FROM system_info;",
      "SELECT user AS username FROM logged_in_users ORDER BY time DESC LIMIT 1;"
    ]
  },
  "file_paths": {
    "binaries": [
      "/bin/%",
      "/sbin/%",
      "/usr/bin/%",
      "/usr/sbin/%"
    ],
    "config_files": [
      "/etc/%%"
    ]
  }
}
EOF
# Scan for anomalies
log "Scanning for anomalies..."
# Check for unusual system load
log "Checking for unusual system load..."
load=$(cat /proc/loadavg | cut -d ' ' -f1)
if (( $(echo "$load > 10" | bc -l) )); then
    log "High system load detected: $load"
    log "High system load detected: $load" > ./high_system_load.log
fi
# Check for unusual network connections
log "Checking for unusual network connections..."
netstat -ant | grep -c ESTABLISHED | while read -r connections; do
    if [ "$connections" -gt 100 ]; then
        log "Unusual number of connections: $connections"
        log "Unusual number of connections: $connections" > ./unusual_network_connections.log
    fi
done
# Check for large files in /tmp
log "Checking for large files in /tmp..."
large_files_in_tmp=$(find /tmp -type f -size +100M -exec ls -lh {} \;)
log "Large Files Found in /tmp: $large_files_in_tmp"
log "Large Files Found in /tmp: $large_files_in_tmp" > ./large_files_in_tmp.log
# Monitor failed SSH attempts
log "Monitoring failed SSH attempts..."
grep "Failed password" /var/log/auth.log | grep -c "ssh2" | while read -r attempts; do
    if [ "$attempts" -gt 10 ]; then
        log "High number of failed SSH attempts: $attempts"
        log "High number of failed SSH attempts: $attempts" > ./high_failed_ssh_attempts.log
    fi
done
# Check for modified system binaries
log "Checking for modified system binaries..."
rm -f ./modified_system_binaries.log
# for file in /bin/* /sbin/* /usr/bin/* /usr/sbin/*; do
    # sha256_hash=$(sha256sum "$file" | awk '{print $1}')
    # md5_hash=$(md5sum "$file" | awk '{print $1}')
    #TODO: Add hash verification
    # if ! grep -q "$sha256_hash" /var/lib/binary-hashes.db; then
    #     echo "$file: $sha256_hash" >> ./modified_system_binaries.log
    # fi
# done
if [[ -x "$(command -v systemctl)" ]]; then
    # Automated Incident Response Script
    cat > /usr/local/bin/incident-response.sh << EOF
#!/bin/bash
# ####################################################################################
# Author: Tanav Malhotra
# License: GNU General Public License v3.0
# Copyright (c) 2024 Tanav Malhotra
#
# This script is licensed under the GNU General Public License v3.0.
# You may obtain a copy of the license at:
#   https://www.gnu.org/licenses/gpl-3.0.html
#
# The script is provided "as-is", without any warranty of any kind,
# express or implied, including but not limited to the implied warranties
# of merchantability and fitness for a particular purpose. See the GPL-3.0
# for full details.
# ####################################################################################

# Function to collect system state
collect_system_state() {
    mkdir -p /var/log/incidents/\$(date +%Y%m%d_%H%M%S)
    cd /var/log/incidents/\$(date +%Y%m%d_%H%M%S)
    
    # Collect process information
    ps auxf > processes.txt
    lsof > open_files.txt
    
    # Collect network information
    netstat -antup > network_connections.txt
    ss -tualpn > socket_statistics.txt
    
    # Collect system logs
    cp /var/log/syslog ./
    cp /var/log/auth.log ./
    
    # Memory dump
    grep -v "^0" /proc/[0-9]*/maps > memory_maps.txt
    
    # System information
    uname -a > system_info.txt
    df -h > disk_usage.txt
    free -m > memory_usage.txt
    
    # Package information
    dpkg -l > installed_packages.txt
}

# Function to respond to suspicious processes
handle_suspicious_process() {
    pid=\$1
    # Collect process information
    ps -fp \$pid > "/var/log/incidents/process_\${pid}.txt"
    
    # Get open files and connections
    lsof -p \$pid >> "/var/log/incidents/process_\${pid}.txt"
    
    # Optionally terminate process
    kill -9 \$pid
}

# Function to block suspicious IP
block_ip() {
    ip=\$1
    nft add rule inet filter input ip saddr \$ip drop
    echo "Blocked IP: \$ip at \$(date)" >> /var/log/incidents/blocked_ips.log
}

# Main monitoring loop
while true; do
    # Check for high CPU usage processes
    ps aux | awk '{if(\$3 > 90.0) print \$2}' | while read pid; do
        handle_suspicious_process \$pid
    done
    
    # Check for suspicious network connections
    netstat -ant | grep -E "^tcp.*ESTABLISHED" | awk '{print \$5}' | cut -d: -f1 | sort | uniq -c | sort -rn | while read count ip; do
        if [ \$count -gt 100 ]; then
            block_ip \$ip
        fi
    done
    
    sleep 60
done
EOF
    chmod +x /usr/local/bin/incident-response.sh
    # Create service for incident response
    cat > /etc/systemd/system/incident-response.service << EOF
[Unit]
Description=Automated Incident Response Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/incident-response.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable incident-response
    systemctl start incident-response
fi
# Network Segmentation with VLANs
# Make VLANs persistent
cat > /etc/network/interfaces.d/vlans << EOF
auto eth0.10
iface eth0.10 inet static
    address 192.168.10.1
    netmask 255.255.255.0
    vlan-raw-device eth0

auto eth0.20
iface eth0.20 inet static
    address 192.168.20.1
    netmask 255.255.255.0
    vlan-raw-device eth0

auto eth0.30
iface eth0.30 inet static
    address 192.168.30.1
    netmask 255.255.255.0
    vlan-raw-device eth0
EOF
# Load VLAN module
modprobe 8021q
# Create VLANs
vconfig add eth0 10  # Admin VLAN
vconfig add eth0 20  # User VLAN
vconfig add eth0 30  # Guest VLAN
# Configure VLAN interfaces
ip addr add 192.168.10.1/24 dev eth0.10
ip addr add 192.168.20.1/24 dev eth0.20
ip addr add 192.168.30.1/24 dev eth0.30
# Set up bridges for each VLAN
brctl addbr br10
brctl addbr br20
brctl addbr br30
brctl addif br10 eth0.10
brctl addif br20 eth0.20
brctl addif br30 eth0.30
# Configure routing between VLANs
ip route add 192.168.20.0/24 via 192.168.10.1
ip route add 192.168.30.0/24 via 192.168.10.1
# Set up VLAN-specific firewall rules
nft add table inet vlan_filter
nft add chain inet vlan_filter input '{ type filter hook input priority 0 ; }'
nft add chain inet vlan_filter forward '{ type filter hook forward priority 0 ; }'
# Allow established connections
nft add rule inet vlan_filter input ct state established,related accept
# VLAN-specific rules
nft add rule inet vlan_filter forward iifname "eth0.30" oifname "eth0.10" drop  # Prevent guest -> admin
nft add rule inet vlan_filter forward iifname "eth0.30" oifname "eth0.20" drop  # Prevent guest -> user
# Run VLAN setup
mkdir -p /etc/dpkg/dpkg.cfg.d/
echo "Show-Changed-Conffiles" > /etc/dpkg/dpkg.cfg.d/show-changed
echo "force-confold" > /etc/dpkg/dpkg.cfg.d/force-confold

##### Anti-Malware #####
freshclam
if [[ -x "$(command -v systemctl)" ]]; then
    systemctl enable clamav-freshclam
    systemctl start clamav-freshclam
elif [[ -x "$(command -v service)" ]]; then
    update-rc.d clamav-freshclam defaults
    service clamav-freshclam start
else
    log "error: Unable to start clamav-freshclam service."
fi

##### AUDITING #####
log "Setting up auditing..."
cat > /etc/audit/audit.rules << EOF
-D
-w / -p rwax -k filesystem_change
-a always,exit -S all
-e 2
EOF
cat > /etc/audit/auditd.conf << EOF
max_log_file = 10485760
space_left_action = email
action_mail_acct = root
admin_space_left_action = halt
max_log_file_action = keep_logs
EOF
auditctl -e 1
if [[ -x "$(command -v systemctl)" ]]; then
    systemctl enable auditd
    systemctl start auditd
    systemctl restart auditd
elif [[ -x "$(command -v service)" ]]; then
    update-rc.d auditd defaults
    service auditd start
    service auditd restart
else
    log "error: Unable to restart auditd service."
fi
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 # Auditing world writable files
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nouser # Auditing unowned files/directories
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup # Auditing ungrouped files/directories
df --local -P | awk '{if (NR!=1)print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000 # Audit SUID executable
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000 # Audit SGID executables

# Setting up rsyslog
log "Setting up rsyslog..."
sed -i 's/RSYSLOG_TraditionalFileFormat/RSYSLOG_FileFormat/' /etc/rsyslog.conf
if [[ -x "$(command -v systemctl)" ]]; then
    systemctl enable rsyslog
    systemctl start rsyslog
    systemctl restart rsyslog
elif [[ -x "$(command -v service)" ]]; then
    update-rc.d rsyslog defaults
    service rsyslog start
    service rsyslog restart
else
    log "error: Unable to restart rsyslog service."
fi

##### APPARMOR #####
log "Setting up AppArmor..."
aa-enforce /etc/apparmor.d/*
if [[ -x "$(command -v systemctl)" ]]; then
    systemctl enable apparmor
    systemctl start apparmor
    systemctl restart apparmor
elif [[ -x "$(command -v service)" ]]; then
    update-rc.d apparmor defaults
    service apparmor start
    service apparmor restart
else
    log "error: Unable to restart apparmor service."
fi

##### FINDING & SAVING INFO #####
log "Finding and saving open ports to \`./open_ports.log\`..."
ss -ln > ./open_ports.log
log "Finding and saving running services to \`./services.log\`..."
service --status-all > ./services.log
log "Finding & saving unused software to \`./unused_software.log\`..."
deborphan --guess-all > ./unused_software.log
# log "Removing unused software..."
# log "The following files will be removed:"
# cat ./unused_software.log
# # Prompt the user for confirmation
# ring_bell
# read -r -p "Do you want to proceed with the deletion? (Y/n): " choice
# if [[ $choice =~ ^[Nn].* ]]; then
#     log "No software was removed."
# else
#     # Proceed with removal
#     while IFS= read -r file; do
#         rm -rf "$file"
#     done < ./unused_software.log

#     log "Unused software has been removed."
# fi
log "Finding & saving installed software to \`./software_installed.log\`..."
apt list --installed > ./software_installed.log
log "Finding & saving enabled services to \`./enabled_services.log\`..."
service --status-all > ./enabled_services.log
log "Finding & saving media files to \`./media_files.log\`..."
find /home/ -type f \( -name "*.mp3" -o -name "*.mp4" -o -name "*.wav" -o -name "*.avi" -o -name "*.mkv" -o -name "*.flac" -o -name "*.mov" \) -print > ./media_files.log
log "Finding & saving possible hacking tools as packages to \`./packages.log\`..."
find /home/ -type f \( -name "*.tar.gz" -o -name "*.tgz" -o -name "*.zip" -o -name "*.deb" \) -print > ./packages.log
log "Finding & saving World Writable files to \`./world_writable.log\`..."
find /dir -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print > ./world_writable.log
log "Finding & saving No-User files to \`./no_user.log\`..."
find /dir -xdev \( -nouser -o -nogroup \) -print > ./no_user.log

##### REMOVING MEDIA FILES #####
log "Removing media files..."
log "The following files will be removed:"
cat ./media_files.log
ring_bell
read -r -p "Do you want to proceed with the deletion? (Y/n): " choice
if [[ $choice =~ ^[Nn].* ]]; then
    log "No files were removed."
else
    while IFS= read -r file; do
        rm -rf "$file"
    done < ./media_files.log

    log "Files have been removed."
fi
log "Removing packages..."
log "The following files will be removed:"
cat ./packages.log
ring_bell
read -r -p "Do you want to proceed with the deletion? (Y/n): " choice
if [[ $choice =~ ^[Nn].* ]]; then
    log "No files were removed."
else
    while IFS= read -r file; do
        rm -rf "$file"
    done < ./packages.log
    log "Files have been removed."
fi

##### USER/PASSWORD MANAGEMENT #####
log "User Management..."
# Lock Root
log "Locking root account..."
passwd -l root
usermod -s /bin/false root
usermod -L root
usermod -g 0 root
# log "Setting default shell for users..."
# chsh -s /bin/bash
cp /etc/sudoers /etc/sudoers.bak
cp -r /etc/sudoers.d /etc/sudoers.d.bak
cp /etc/passwd /etc/passwd.bak
touch /etc/lightdm/lightdm.conf
touch /etc/gdm/custom.conf
touch /etc/pam.d/gdm-password
cp /etc/lightdm/lightdm.conf /etc/lightdm/lightdm.conf.bak
cp /etc/lightdm/users.conf /etc/lightdm/users.conf.bak
cp /etc/gdm/custom.conf /etc/gdm/custom.conf.bak
cp /etc/pam.d/gdm-password /etc/pam.d/gdm-password.bak
sed -i '/NOPASSWD:/s/\(NOPASSWD:.*\)/NOPASSWD:/g' /etc/sudoers
sed -i 's/nopasswd//g' /etc/sudoers
sed -i 's/!authenticate//g' /etc/sudoers
sed -i 's/nopasswd//g' /etc/sudoers.d
sed -i 's/!authenticate//g' /etc/sudoers.d
log "Running \`visudo -c\`..."
if visudo -c; then
    log "Sudoers files validated successfully. No syntax errors found."
else
    log "error: Syntax errors detected in sudoers files, namely \`/etc/sudoers\`! It is CRITICAL to fix these errors to prevent losing \`sudo\` access."
    log "Press 'Enter' to continue..."
    read
    visudo
fi
log "Turning off guest login and auto login..."
groupdel autologin
sed -i 's/allow-guest=true/allow-guest=false/' /etc/lightdm/lightdm.conf
echo "allow-guest=false" >> /etc/lightdm/users.conf
cp /etc/lightdm/lightdm.conf /etc/lightdm/lightdm.conf.with_autologin.bak
sed -i '/^autologin-user/s/^/#/' /etc/lightdm/lightdm.conf
sed -i 's/AutomaticLoginEnable=True/AutomaticLoginEnable=False/' /etc/gdm/custom.conf
sed -i '/^\[security\]/,/^\[.*\]/s/^AllowGuest=true/AllowGuest=false/' /etc/gdm/custom.conf
sed -i 's/auth sufficient pam_succeed_if.so user ingroup nopasswdlogin//' /etc/pam.d/gdm-password
mawk -F: '$1 == "sudo"' /etc/group > ./admins.log
log "Admins (saved to \`./admins.log\`)..."
mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd > ./users.log
log "Users (saved to \`./users.log\`)..."
mawk -F: '$2 == ""' /etc/passwd > ./no_passwd.log
log "Empty Passwords (saved to \`./no_passwd.log\`)..."
mawk -F: '$3 == 0 && $1 != "root"' /etc/passwd > ./non-root_uid0.log
log "Non-root UID 0 users (saved to \`./non-root_uid0.log\`)..."
# Changing Passwords and user management
NEW_PASSWORD="CyberPatr!0t"
existing_users=$(cut -d: -f1 /etc/passwd | grep -Ev "^(root|nobody|nfsnobody)$")
declare -A admin_map
declare -A user_map
for admin in "${ADMINS[@]}"; do
    admin_map["$admin"]=1
done
for user in "${USERS[@]}"; do
    user_map["$user"]=1
done
ALL_USERS=$(printf "%s\n" "${USERS[@]}" "${ADMINS[@]}")
log "Changing Passwords of all users and admins to \`$NEW_PASSWORD\` (and making sure they belong on system and have the right permissions)..."
# Add any missing users from users.txt
for u in "${USERS[@]}"; do
    if ! grep -qw "$u" <<<"$existing_users"; then # TODO: try method used in line 827 & 829
        useradd "$u"
        log "User $u added to the system as user."
    fi
done
# Add any missing admins from admins.txt
for a in "${ADMINS[@]}"; do
    if ! grep -qw "$a" <<<"$existing_users"; then # TODO: try method used in line 827 & 829
        useradd "$a"
        log "User $a added to the system as admin."
    fi
done
cut -d: -f1,3 /etc/passwd | while IFS=: read -r user uid; do
    # UID (User ID) >= 1000 for human users
    if [[ "$uid" -ge 1000 && "$user" != "nobody" && "$user" != "nfsnobody" && "$user" != "root" ]]; then
        # if id -nG "$user" | grep -qwE 'sudo|wheel|admin'; then
        #     current_role="Admin"
        # else
        #     current_role="User"
        # fi
        # # Determine the intended role based on the files
        # if [[ -n "${admin_map[$user]}" ]]; then
        #     ROLE="admin"
        # elif [[ -n "${user_map[$user]}" ]]; then
        #     ROLE="user"
        # else
        #     userdel -r "$user"
        #     log "$current_role $user and their data have been removed from the system."
        #     continue
        # fi

        if id -nG "$user" | grep -qwE 'sudo|wheel|admin'; then
            ROLE="admin"
        else
            ROLE="user"
        fi

        echo "$user:$NEW_PASSWORD" | chpasswd
        log "Password for $ROLE $user changed."

        # Make sure they belong on the system
        if [[ "$ROLE" == "user" ]]; then
            # Ensure user is not in admin groups
            gpasswd -d "$user" sudo &>/dev/null
            gpasswd -d "$user" admin &>/dev/null # older ubuntu versions
            gpasswd -d "$user" wheel &>/dev/null
        elif [[ "$ROLE" == "admin" ]]; then
            # Ensure user is in admin groups
            gpasswd -a "$user" sudo &>/dev/null
            gpasswd -a "$user" admin &>/dev/null # older ubuntu versions
            gpasswd -a "$user" wheel &>/dev/null
        fi
    fi
done
echo "root:$NEW_PASSWORD" | chpasswd
log "Password for admin root changed."
# Secure GRUB
HASH=$(echo -e "$NEW_PASSWORD\n$NEW_PASSWORD" | grub-mkpasswd-pbkdf2 | grep -o "grub.*") # generate a password hash
cat > /etc/grub.d/40_custom << EOF
#!/bin/sh
exec tail -n +3 $0
# This file provides an easy way to add custom menu entries.  Simply type the
# menu entries you want to add after this comment.  Be careful not to change
# the 'exec tail' line above.

set superusers="root"
password_pbkdf2 root $HASH
set check_signatures=enforce
export check_signatures
export superusers
EOF
sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="kaslr /' /etc/default/grub # Enable KASLR by updating GRUB
update-grub
log "GRUB password set for admin root and GRUB signature checks enabled."

##### CHANGING POLICIES #####
# Setting max password days
log "Setting max password days..."
cp /etc/login.defs /etc/login.defs.bak
sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 30/;s/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/;s/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
# Change PAM (Pluggable Authentication Modules) settings
log "Changing PAM settings (setting max password attempts, minimum password langths, etc.)..."
cp /etc/pam.d/common-auth /etc/pam.d/common-auth.bak
sed -i 's/\w*nullok\w*//g' /etc/pam.d/common-auth
# Lockout Policy
#sed -i 's/\(pam_tally2\.so.*\)$/\1 deny=5 audit silent unlock_time=1/' /etc/pam.d/common-auth
#echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=1' >> /etc/pam.d/common-auth
#echo 'auth required pam_unix.so' >> /etc/pam.d/common-auth
echo "auth required pam_faillock.so preauth deny=5 unlock_time=1" >> /etc/pam.d/common-auth
echo "auth required pam_faillock.so authfail deny=5 unlock_time=1" >> /etc/pam.d/common-auth
# sed -i 's/deny=[0-9]\+/deny=5/' /etc/pam.d/common-auth
# sed -i 's/unlock_time=[0-9]\+/unlock_time=1/' /etc/pam.d/common-auth
cp /etc/pam.d/common-password /etc/pam.d/common-password.bak
sed -i 's/\(pam_unix\.so.*\)$/\1 remember=5 minlen=12/' /etc/pam.d/common-password
sed -i 's/\(pam_cracklib\.so.*\)$/\1 maxclassrepeat=5 maxsequence=5 minclass=4 dcredit=-1 ocredit=-1 lcredit=-1 ucredit=-1 minlen=12 difok=8 retry=5/' /etc/pam.d/common-password # try difok=5
cp /etc/default/useradd /etc/default/useradd.bak
sed -i 's/^EXPIRE=[0-9]\+/EXPIRE=30/' /etc/default/useradd
sed -i 's/^INACTIVE=[0-9]\+/INACTIVE=30/' /etc/default/useradd
# Change password encryption method to SHA512
log "Changing password encryption method to SHA512..."
cp /etc/login.defs /etc/login_with_max_pw_days.defs.bak
sed -i '/^ENCRYPT_METHOD/c\ENCRYPT_METHOD SHA512' /etc/login.defs
echo "SHA_CRYPT_MIN_ROUNDS 12000" >> /etc/login.defs
echo "SHA_CRYPT_MAX_ROUNDS 15000" >> /etc/login.defs
# Configure PAM for memory protection
cat >> /etc/security/limits.conf << EOF
* soft data 512000
* hard data 512000
* soft rss  512000
* hard rss  512000
* soft as   1024000
* hard as   1024000
EOF

##### LANGUAGE #####
LANG_TO_KEEP="en_US.UTF-8"
log "Setting language to $LANG_TO_KEEP..."
cat > /etc/locale.gen << EOF
$LANG_TO_KEEP UTF-8
C.UTF-8 UTF-8
C
EOF
locale-gen
update-locale LANG=$LANG_TO_KEEP LANGUAGE=$LANG_TO_KEEP

##### CLEANING UP #####
log "Cleaning up..."
apt autoremove --purge -y
apt clean

##### CALCULATING TIME #####
end_time=$(date +"%Y-%m-%d, %I:%M:%S %p")
end_secs=$(date +%s.%N)
duration=$(echo "$end_secs - $start_secs" | bc)
final_min=$(echo "$duration / 60" | bc)
final_sec=$(echo "$duration % 60" | bc)

##### FINAL NOTES FOR USER #####
log "Finished in $final_min minute(s) and $final_sec second(s)..."
log
log "Final Notes:"
log "Please manually check the world-writable files and the no-user files."
log "Please make sure only the required services are enabled."
log "Please check all the .log files in the current directory ($(pwd)) for any information saved by this script."
service --status-all
log "Make sure updates are installed daily."
ring_bell
read -r -p "Run \`software-properties-gtk &\`? (y/N): " check_auto_update
if [[ $check_auto_update =~ ^[Yy].* ]]; then
    software-properties-gtk &
fi
log
# log "Launching settings..."
# if [[ "$DESKTOP_SESSION" == "gnome" ]]; then
#     gnome-control-center > /dev/null 2>&1 &
# elif [[ "$DESKTOP_SESSION" == "cinnamon" ]]; then
#     cinnamon-settings > /dev/null 2>&1 &
# elif [[ "$DESKTOP_SESSION" == "kde" ]]; then
#     systemsettings5 > /dev/null 2>&1 &
# elif [[ "$DESKTOP_SESSION" == "xfce" ]]; then
#     xfce4-settings-manager > /dev/null 2>&1 &
# else
#     log "Unsupported desktop environment (standalone window managers are not supported). Please open settings manually if needed."
# fi

##### WISH GOOD LUCK #####
log;log;log;
log "Thank you for using this script. Good luck for the competition!"
log
log "==================================="
log "Copyright (c) 2024 Tanav Malhotra"
log "GNU General Public License v3.0"
log "==================================="
log
log_info "End time: $end_time" # log end time

##### REBOOT #####
ring_bell
read -r -p "Reboot the system? (y/N): " reboot_choice
if [[ $reboot_choice =~ ^[Yy].* ]]; then
    log "Rebooting..."
    reboot
else
    log "Remember to manually reboot the system when you're ready."
fi

##### EXIT #####
exit 0
