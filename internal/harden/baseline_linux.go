//go:build linux

package harden

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// runPlatformBaseline applies baseline hardening for the current platform (Linux).
func runPlatformBaseline(ctx context.Context, cfg BaselineConfig, result *BaselineResult) (*BaselineResult, error) {
	h := New()
	
	// Detect distro
	distro := detectDistro()
	result.OSVersion = distro
	fmt.Printf("Detected: %s\n\n", distro)
	
	// 1. Password Policy
	fmt.Println("━━━ Configuring Password Policy ━━━")
	applyLinuxPasswordPolicy(ctx, h, cfg, result)
	
	// 2. Kernel Hardening (sysctl)
	fmt.Println("\n━━━ Applying Kernel Hardening ━━━")
	applyKernelHardening(ctx, h, cfg, result)
	
	// 3. IPv6
	if cfg.DisableIPv6 {
		fmt.Println("\n━━━ Disabling IPv6 ━━━")
		disableIPv6(ctx, h, result)
	} else {
		addSkipped(result, "Network", "Disable IPv6", "user chose to keep enabled")
	}
	
	// 4. Firewall
	if cfg.EnableFirewall {
		fmt.Println("\n━━━ Enabling Firewall ━━━")
		enableLinuxFirewall(ctx, h, result)
	} else {
		addSkipped(result, "Firewall", "Enable UFW/firewalld", "user chose to skip")
	}
	
	// 5. Security Tools
	fmt.Println("\n━━━ Installing Security Tools ━━━")

	if cfg.InstallAuditd {
		installAuditd(ctx, h, result)
	} else {
		addSkipped(result, "Security Tools", "Install auditd", "user chose to skip")
	}

	if cfg.InstallApparmor {
		installApparmor(ctx, h, result)
	} else {
		addSkipped(result, "Security Tools", "Install AppArmor", "user chose to skip")
	}

	if cfg.InstallFail2ban && !isServiceRequired(cfg.RequiredServices, "ssh") {
		// Only install fail2ban if SSH is not a required service that might have specific config
		installFail2ban(ctx, h, result)
	} else if isServiceRequired(cfg.RequiredServices, "ssh") {
		addSkipped(result, "Security Tools", "Install fail2ban", "SSH is required - configure manually if needed")
	} else {
		addSkipped(result, "Security Tools", "Install fail2ban", "user chose to skip")
	}

	// 6. Service-specific hardening (only if NOT required)
	fmt.Println("\n━━━ Service Hardening ━━━")
	hardenLinuxServices(ctx, h, cfg, result)

	// 7. Disable Guest Account
	fmt.Println("\n━━━ Disabling Guest Account ━━━")
	disableLinuxGuest(ctx, h, result)
	
	// 8. Secure File Permissions
	fmt.Println("\n━━━ Securing File Permissions ━━━")
	secureFilePermissions(ctx, h, result)
	
	// 9. Disable Ctrl+Alt+Del
	fmt.Println("\n━━━ Disabling Ctrl+Alt+Del Reboot ━━━")
	disableCtrlAltDel(ctx, h, result)
	
	result.PrintResults()
	return result, nil
}

func detectDistro() string {
	content, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "Linux (unknown)"
	}
	
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			name := strings.TrimPrefix(line, "PRETTY_NAME=")
			name = strings.Trim(name, "\"")
			return name
		}
	}
	return "Linux"
}

func applyLinuxPasswordPolicy(ctx context.Context, h *Hardener, cfg BaselineConfig, result *BaselineResult) {
	// 1. Configure login.defs
	loginDefsContent := fmt.Sprintf(`# Configured by IronGuard baseline hardening
PASS_MAX_DAYS   %d
PASS_MIN_DAYS   %d
PASS_WARN_AGE   %d
FAILLOG_ENAB    YES
LOG_UNKFAIL_ENAB YES
SYSLOG_SU_ENAB  YES
SYSLOG_SG_ENAB  YES
`, cfg.MaxPasswordAge, cfg.MinPasswordAge, cfg.PasswordWarnAge)
	
	// Backup and update login.defs
	_, err := h.runBashSingle(ctx, "cp /etc/login.defs /etc/login.defs.bak 2>/dev/null")
	if err == nil {
		// Update specific values instead of overwriting
		script := fmt.Sprintf(`
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   %d/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   %d/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   %d/' /etc/login.defs
grep -q "^FAILLOG_ENAB" /etc/login.defs || echo "FAILLOG_ENAB YES" >> /etc/login.defs
grep -q "^LOG_UNKFAIL_ENAB" /etc/login.defs || echo "LOG_UNKFAIL_ENAB YES" >> /etc/login.defs
`, cfg.MaxPasswordAge, cfg.MinPasswordAge, cfg.PasswordWarnAge)
		_, err = h.runBashSingle(ctx, script)
	}
	
	if err != nil {
		addResult(result, "Password Policy", "Configure /etc/login.defs", false, "", err.Error())
	} else {
		addResult(result, "Password Policy", fmt.Sprintf("Set PASS_MAX_DAYS=%d, MIN=%d, WARN=%d", 
			cfg.MaxPasswordAge, cfg.MinPasswordAge, cfg.PasswordWarnAge), true, "", "")
		fmt.Printf("  ✓ login.defs configured\n")
	}
	
	// 2. Install and configure PAM pwquality
	_, err = h.runBashSingle(ctx, "apt-get install -y libpam-pwquality 2>/dev/null || dnf install -y libpwquality 2>/dev/null || yum install -y libpwquality 2>/dev/null")
	
	pwqualityContent := fmt.Sprintf(`# Configured by IronGuard baseline hardening
minlen = %d
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
difok = 3
reject_username
enforce_for_root
`, cfg.MinPasswordLen)
	
	err = os.WriteFile("/etc/security/pwquality.conf", []byte(pwqualityContent), 0644)
	if err != nil {
		addResult(result, "Password Policy", "Configure pwquality.conf", false, "", err.Error())
	} else {
		addResult(result, "Password Policy", fmt.Sprintf("Set minimum password length=%d with complexity", cfg.MinPasswordLen), true, "", "")
		fmt.Printf("  ✓ pwquality.conf configured (minlen=%d, complexity enabled)\n", cfg.MinPasswordLen)
	}
	
	// 3. Configure PAM to remember passwords
	pamScript := `
# Add password history to PAM
if [ -f /etc/pam.d/common-password ]; then
    grep -q "remember=" /etc/pam.d/common-password || \
    sed -i 's/pam_unix.so.*/& remember=24/' /etc/pam.d/common-password
fi

# Remove nullok from PAM (no empty passwords)
if [ -f /etc/pam.d/common-password ]; then
    sed -i 's/nullok//g' /etc/pam.d/common-password
fi
if [ -f /etc/pam.d/common-auth ]; then
    sed -i 's/nullok//g' /etc/pam.d/common-auth
fi
`
	_, err = h.runBashSingle(ctx, pamScript)
	if err != nil {
		addResult(result, "Password Policy", "Configure PAM password history", false, "", err.Error())
	} else {
		addResult(result, "Password Policy", "Set password history=24, removed nullok", true, "", "")
		fmt.Printf("  ✓ PAM configured (history=24, nullok removed)\n")
	}
	
	// 4. Configure account lockout
	lockoutScript := `
# Add account lockout to PAM
if [ -f /etc/pam.d/common-auth ]; then
    grep -q "pam_tally2\|pam_faillock" /etc/pam.d/common-auth || \
    sed -i '1a auth required pam_faillock.so preauth silent deny=5 unlock_time=1800 fail_interval=900' /etc/pam.d/common-auth
fi
`
	_, err = h.runBashSingle(ctx, lockoutScript)
	if err != nil {
		addResult(result, "Password Policy", "Configure account lockout", false, "", err.Error())
	} else {
		addResult(result, "Password Policy", "Set account lockout (5 attempts, 30 min)", true, "", "")
		fmt.Printf("  ✓ Account lockout configured (5 attempts, 30 min lockout)\n")
	}
	
	_ = loginDefsContent // Used for documentation
}

func applyKernelHardening(ctx context.Context, h *Hardener, cfg BaselineConfig, result *BaselineResult) {
	sysctlContent := `# IronGuard Kernel Hardening
# Network security
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0

# IPv6 (if not disabled separately)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Kernel security
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
`
	
	err := os.WriteFile("/etc/sysctl.d/99-ironguard-hardening.conf", []byte(sysctlContent), 0644)
	if err != nil {
		addResult(result, "Kernel", "Create sysctl hardening config", false, "", err.Error())
		return
	}
	addResult(result, "Kernel", "Created /etc/sysctl.d/99-ironguard-hardening.conf", true, "", "")
	fmt.Printf("  ✓ Created sysctl hardening config\n")
	
	// Apply sysctl settings
	_, err = h.runBashSingle(ctx, "sysctl --system")
	if err != nil {
		addResult(result, "Kernel", "Apply sysctl settings", false, "", err.Error())
	} else {
		addResult(result, "Kernel", "Applied kernel hardening (syncookies, rp_filter, ASLR, etc.)", true, "", "")
		fmt.Printf("  ✓ Applied sysctl settings\n")
	}
}

func disableIPv6(ctx context.Context, h *Hardener, result *BaselineResult) {
	ipv6Config := `# Disable IPv6 - IronGuard
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
`
	err := os.WriteFile("/etc/sysctl.d/99-disable-ipv6.conf", []byte(ipv6Config), 0644)
	if err != nil {
		addResult(result, "Network", "Disable IPv6", false, "", err.Error())
		return
	}
	
	_, err = h.runBashSingle(ctx, "sysctl --system")
	if err != nil {
		addResult(result, "Network", "Apply IPv6 disable", false, "", err.Error())
	} else {
		addResult(result, "Network", "Disabled IPv6", true, "", "")
		fmt.Printf("  ✓ IPv6 disabled\n")
	}
}

func enableLinuxFirewall(ctx context.Context, h *Hardener, result *BaselineResult) {
	// Try UFW first (Ubuntu/Debian), then firewalld (RHEL/Fedora)
	_, err := h.runBashSingle(ctx, `
		if command -v ufw &>/dev/null; then
			ufw --force enable
			ufw default deny incoming
			ufw default allow outgoing
			echo "UFW enabled"
		elif command -v firewall-cmd &>/dev/null; then
			systemctl enable --now firewalld
			firewall-cmd --set-default-zone=drop
			echo "firewalld enabled"
		else
			apt-get install -y ufw && ufw --force enable && ufw default deny incoming && ufw default allow outgoing
		fi
	`)
	
	if err != nil {
		addResult(result, "Firewall", "Enable firewall", false, "", err.Error())
	} else {
		addResult(result, "Firewall", "Enabled UFW/firewalld with default deny incoming", true, "", "")
		fmt.Printf("  ✓ Firewall enabled\n")
	}
}

func installAuditd(ctx context.Context, h *Hardener, result *BaselineResult) {
	script := `
		apt-get install -y auditd audispd-plugins 2>/dev/null || \
		dnf install -y audit 2>/dev/null || \
		yum install -y audit 2>/dev/null
		
		systemctl enable auditd
		systemctl start auditd
		
		# Add basic audit rules
		cat >> /etc/audit/rules.d/ironguard.rules << 'EOF'
# IronGuard audit rules
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/secure -p wa -k auth_log
EOF
		augenrules --load 2>/dev/null || service auditd restart
	`
	
	_, err := h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "Security Tools", "Install/configure auditd", false, "", err.Error())
	} else {
		addResult(result, "Security Tools", "Installed auditd with identity and sudoers monitoring", true, "", "")
		fmt.Printf("  ✓ auditd installed and configured\n")
	}
}

func installApparmor(ctx context.Context, h *Hardener, result *BaselineResult) {
	script := `
		apt-get install -y apparmor apparmor-utils 2>/dev/null || \
		dnf install -y apparmor 2>/dev/null
		
		systemctl enable apparmor 2>/dev/null
		systemctl start apparmor 2>/dev/null
		
		# Enforce all profiles
		aa-enforce /etc/apparmor.d/* 2>/dev/null || true
	`
	
	_, err := h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "Security Tools", "Install/configure AppArmor", false, "", err.Error())
	} else {
		addResult(result, "Security Tools", "Installed AppArmor and enforced profiles", true, "", "")
		fmt.Printf("  ✓ AppArmor installed and enforced\n")
	}
}

func installFail2ban(ctx context.Context, h *Hardener, result *BaselineResult) {
	script := `
		apt-get install -y fail2ban 2>/dev/null || \
		dnf install -y fail2ban 2>/dev/null || \
		yum install -y fail2ban 2>/dev/null
		
		# Create local config
		cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
		
		systemctl enable fail2ban
		systemctl restart fail2ban
	`
	
	_, err := h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "Security Tools", "Install/configure fail2ban", false, "", err.Error())
	} else {
		addResult(result, "Security Tools", "Installed fail2ban with SSH protection", true, "", "")
		fmt.Printf("  ✓ fail2ban installed and configured\n")
	}
}

func disableLinuxGuest(ctx context.Context, h *Hardener, result *BaselineResult) {
	script := `
		# Disable guest account in LightDM
		if [ -d /etc/lightdm ]; then
			mkdir -p /etc/lightdm/lightdm.conf.d
			cat > /etc/lightdm/lightdm.conf.d/50-no-guest.conf << 'EOF'
[Seat:*]
allow-guest=false
greeter-hide-users=true
greeter-show-manual-login=true
EOF
		fi
		
		# Disable guest account in GDM
		if [ -f /etc/gdm3/custom.conf ]; then
			sed -i 's/^#*AutomaticLoginEnable.*/AutomaticLoginEnable=false/' /etc/gdm3/custom.conf
		fi
		
		# Lock guest account if exists
		passwd -l guest 2>/dev/null || true
		usermod -L guest 2>/dev/null || true
	`
	
	_, err := h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "Guest Account", "Disable guest account", false, "", err.Error())
	} else {
		addResult(result, "Guest Account", "Disabled guest in LightDM/GDM, locked account", true, "", "")
		fmt.Printf("  ✓ Guest account disabled\n")
	}
}

func secureFilePermissions(ctx context.Context, h *Hardener, result *BaselineResult) {
	script := `
		# Secure critical files
		chmod 644 /etc/passwd
		chmod 600 /etc/shadow
		chmod 644 /etc/group
		chmod 600 /etc/gshadow
		chmod 700 /root
		chmod 600 /etc/ssh/sshd_config 2>/dev/null
		
		# Secure cron directories
		chmod 700 /etc/cron.d 2>/dev/null
		chmod 700 /etc/cron.daily 2>/dev/null
		chmod 700 /etc/cron.hourly 2>/dev/null
		chmod 700 /etc/cron.weekly 2>/dev/null
		chmod 700 /etc/cron.monthly 2>/dev/null
		chmod 600 /etc/crontab 2>/dev/null
	`
	
	_, err := h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "File Permissions", "Secure critical file permissions", false, "", err.Error())
	} else {
		addResult(result, "File Permissions", "Secured /etc/passwd, shadow, group, cron dirs", true, "", "")
		fmt.Printf("  ✓ File permissions secured\n")
	}
}

func disableCtrlAltDel(ctx context.Context, h *Hardener, result *BaselineResult) {
	_, err := h.runBashSingle(ctx, "systemctl mask ctrl-alt-del.target")
	if err != nil {
		addResult(result, "System", "Disable Ctrl+Alt+Del", false, "", err.Error())
	} else {
		addResult(result, "System", "Disabled Ctrl+Alt+Del reboot", true, "", "")
		fmt.Printf("  ✓ Ctrl+Alt+Del disabled\n")
	}
}

// hardenLinuxServices hardens services that are NOT required.
func hardenLinuxServices(ctx context.Context, h *Hardener, cfg BaselineConfig, result *BaselineResult) {
	// SSH hardening (if not required)
	if !isServiceRequired(cfg.RequiredServices, "ssh") {
		hardenOrDisableSSH(ctx, h, result)
	} else {
		addSkipped(result, "Services", "SSH hardening", "marked as required")
		fmt.Printf("  ⊘ SSH skipped (required)\n")
	}

	// SMB/Samba (if not required)
	if !isServiceRequired(cfg.RequiredServices, "samba") {
		disableServiceIfExists(ctx, h, result, "smbd", "Samba SMB")
		disableServiceIfExists(ctx, h, result, "nmbd", "Samba NetBIOS")
	} else {
		addSkipped(result, "Services", "Samba hardening", "marked as required")
	}

	// FTP (if not required)
	if !isServiceRequired(cfg.RequiredServices, "ftp") {
		disableServiceIfExists(ctx, h, result, "vsftpd", "FTP Server")
		disableServiceIfExists(ctx, h, result, "proftpd", "ProFTPD")
	} else {
		addSkipped(result, "Services", "FTP hardening", "marked as required")
	}

	// NFS (if not required)
	if !isServiceRequired(cfg.RequiredServices, "nfs") {
		disableServiceIfExists(ctx, h, result, "nfs-server", "NFS Server")
		disableServiceIfExists(ctx, h, result, "rpcbind", "RPC Bind")
	} else {
		addSkipped(result, "Services", "NFS hardening", "marked as required")
	}

	// VNC (if not required)
	if !isServiceRequired(cfg.RequiredServices, "vnc") {
		disableServiceIfExists(ctx, h, result, "vncserver", "VNC Server")
		disableServiceIfExists(ctx, h, result, "x11vnc", "X11 VNC")
	} else {
		addSkipped(result, "Services", "VNC hardening", "marked as required")
	}

	// Telnet (almost never required, but check anyway)
	disableServiceIfExists(ctx, h, result, "telnetd", "Telnet Server")
	disableServiceIfExists(ctx, h, result, "xinetd", "xinetd")
	
	// Avahi (mDNS - usually not needed)
	disableServiceIfExists(ctx, h, result, "avahi-daemon", "Avahi mDNS")
	
	// CUPS (if not required)
	if !isServiceRequired(cfg.RequiredServices, "cups") {
		disableServiceIfExists(ctx, h, result, "cups", "CUPS Printing")
	}
}

// hardenOrDisableSSH hardens SSH if installed, disables if not required.
func hardenOrDisableSSH(ctx context.Context, h *Hardener, result *BaselineResult) {
	// Check if SSH is installed
	_, err := exec.LookPath("sshd")
	if err != nil {
		addSkipped(result, "Services", "SSH", "not installed")
		return
	}

	// SSH is installed but not required - harden it restrictively
	script := `
		cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null
		
		sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
		sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
		sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
		sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
		sed -i 's/^#*Protocol.*/Protocol 2/' /etc/ssh/sshd_config
		sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config
		sed -i 's/^#*AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
		sed -i 's/^#*AllowAgentForwarding.*/AllowAgentForwarding no/' /etc/ssh/sshd_config
		
		grep -q "^PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
		grep -q "^PermitEmptyPasswords" /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
		
		systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
	`

	_, err = h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "Services", "Harden SSH (not required, securing)", false, "", err.Error())
	} else {
		addResult(result, "Services", "SSH hardened (PermitRootLogin=no, X11=no, etc.)", true, "", "")
		fmt.Printf("  ✓ SSH hardened\n")
	}
}

// disableServiceIfExists disables a service if it exists.
func disableServiceIfExists(ctx context.Context, h *Hardener, result *BaselineResult, service, description string) {
	// Check if service exists
	_, err := h.runBashSingle(ctx, fmt.Sprintf("systemctl list-unit-files | grep -q '^%s'", service))
	if err != nil {
		// Service doesn't exist
		return
	}

	// Service exists - disable it
	script := fmt.Sprintf("systemctl stop %s 2>/dev/null; systemctl disable %s 2>/dev/null", service, service)
	_, err = h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "Services", fmt.Sprintf("Disable %s", description), false, "", err.Error())
	} else {
		addResult(result, "Services", fmt.Sprintf("Disabled %s", description), true, "", "")
		fmt.Printf("  ✓ Disabled %s\n", description)
	}
}

