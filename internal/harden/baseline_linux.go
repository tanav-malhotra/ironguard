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
func runPlatformBaseline(ctx context.Context, cfg *BaselineConfig, result *BaselineResult) (*BaselineResult, error) {
	h := New()

	// Detect distro
	distro := detectDistro()
	result.OSVersion = distro
	cfg.progress("Detected: %s", distro)
	cfg.progress("")

	// 1. Password Policy
	cfg.progress("━━━ Configuring Password Policy ━━━")
	applyLinuxPasswordPolicy(ctx, h, cfg, result)

	// 2. Kernel Hardening (sysctl)
	cfg.progress("")
	cfg.progress("━━━ Applying Kernel Hardening ━━━")
	applyKernelHardening(ctx, h, cfg, result)

	// 3. IPv6
	if cfg.DisableIPv6 {
		cfg.progress("")
		cfg.progress("━━━ Disabling IPv6 ━━━")
		disableIPv6(ctx, h, cfg, result)
	} else {
		addSkipped(result, "Network", "Disable IPv6", "user chose to keep enabled")
	}

	// 4. Firewall
	if cfg.EnableFirewall {
		cfg.progress("")
		cfg.progress("━━━ Enabling Firewall ━━━")
		enableLinuxFirewall(ctx, h, cfg, result)
	} else {
		addSkipped(result, "Firewall", "Enable UFW/firewalld", "user chose to skip")
	}

	// 5. Security Tools
	cfg.progress("")
	cfg.progress("━━━ Installing Security Tools ━━━")

	if cfg.InstallAuditd {
		installAuditd(ctx, h, cfg, result)
	} else {
		addSkipped(result, "Security Tools", "Install auditd", "user chose to skip")
	}

	if cfg.InstallApparmor {
		installApparmor(ctx, h, cfg, result)
	} else {
		addSkipped(result, "Security Tools", "Install AppArmor", "user chose to skip")
	}

	if cfg.InstallFail2ban && !isServiceRequired(cfg.RequiredServices, "ssh") {
		// Only install fail2ban if SSH is not a required service that might have specific config
		installFail2ban(ctx, h, cfg, result)
	} else if isServiceRequired(cfg.RequiredServices, "ssh") {
		addSkipped(result, "Security Tools", "Install fail2ban", "SSH is required - configure manually if needed")
	} else {
		addSkipped(result, "Security Tools", "Install fail2ban", "user chose to skip")
	}

	// 6. Service-specific hardening (only if NOT required)
	cfg.progress("")
	cfg.progress("━━━ Service Hardening ━━━")
	hardenLinuxServices(ctx, h, cfg, result)

	// 7. Disable Guest Account
	cfg.progress("")
	cfg.progress("━━━ Disabling Guest Account ━━━")
	disableLinuxGuest(ctx, h, cfg, result)

	// 8. Secure File Permissions
	cfg.progress("")
	cfg.progress("━━━ Securing File Permissions ━━━")
	secureFilePermissions(ctx, h, cfg, result)

	// 9. Disable Ctrl+Alt+Del
	cfg.progress("")
	cfg.progress("━━━ Disabling Ctrl+Alt+Del Reboot ━━━")
	disableCtrlAltDel(ctx, h, cfg, result)

	// 10. Sudo Hardening
	cfg.progress("")
	cfg.progress("━━━ Hardening Sudo Configuration ━━━")
	hardenSudo(ctx, h, cfg, result)

	// 11. Lock Root Account (if blank password)
	cfg.progress("")
	cfg.progress("━━━ Securing Root Account ━━━")
	secureRootAccount(ctx, h, cfg, result)

	// 12. Install ClamAV (if requested)
	if cfg.InstallClamAV {
		cfg.progress("")
		cfg.progress("━━━ Installing ClamAV Antivirus ━━━")
		installClamAV(ctx, h, cfg, result)
	}

	// 13. Audit SUID Binaries
	cfg.progress("")
	cfg.progress("━━━ Auditing SUID Binaries ━━━")
	auditSUIDBinaries(ctx, h, cfg, result)

	// 14. Check for Malicious Cron Jobs
	cfg.progress("")
	cfg.progress("━━━ Checking Cron Jobs ━━━")
	auditCronJobs(ctx, h, cfg, result)

	// 15. Screen Lock and Timeout Settings
	cfg.progress("")
	cfg.progress("━━━ Configuring Screen Lock Settings ━━━")
	configureScreenLock(ctx, h, cfg, result)

	// 16. GDM/Display Manager Hardening
	cfg.progress("")
	cfg.progress("━━━ Hardening Display Manager ━━━")
	hardenDisplayManager(ctx, h, cfg, result)

	// 17. Process Limits
	cfg.progress("")
	cfg.progress("━━━ Setting Process Limits ━━━")
	setProcessLimits(ctx, h, cfg, result)

	// 18. GRUB Permissions
	cfg.progress("")
	cfg.progress("━━━ Securing GRUB Configuration ━━━")
	secureGrubPermissions(ctx, h, cfg, result)

	// 19. User Password Management (if requested)
	if cfg.SetUserPasswords {
		cfg.progress("")
		cfg.progress("━━━ Setting User Passwords ━━━")
		setAllUserPasswords(ctx, h, cfg, result)
	} else {
		addSkipped(result, "User Passwords", "Set standard password for all users", "user chose to skip")
	}

	// 20. System Updates (if requested)
	if cfg.RunUpdates {
		cfg.progress("")
		cfg.progress("━━━ Running System Updates (this may take a while...) ━━━")
		runLinuxUpdates(ctx, h, cfg, result)
	} else {
		addSkipped(result, "Updates", "System updates", "user chose to skip (run manually: sudo apt update && sudo apt upgrade -y)")
	}

	result.PrintResults(cfg.ProgressCallback)
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

func applyLinuxPasswordPolicy(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
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
		cfg.progress("  ✓ login.defs configured")
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
		cfg.progress("  ✓ pwquality.conf configured (minlen=%d, complexity enabled)", cfg.MinPasswordLen)
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
		cfg.progress("  ✓ PAM configured (history=24, nullok removed)")
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
		cfg.progress("  ✓ Account lockout configured (5 attempts, 30 min lockout)")
	}

	_ = loginDefsContent // Used for documentation
}

func applyKernelHardening(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
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
kernel.perf_event_paranoid = 3
kernel.kexec_load_disabled = 1
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
	cfg.progress("  ✓ Created sysctl hardening config")

	// Apply sysctl settings
	_, err = h.runBashSingle(ctx, "sysctl --system")
	if err != nil {
		addResult(result, "Kernel", "Apply sysctl settings", false, "", err.Error())
	} else {
		addResult(result, "Kernel", "Applied kernel hardening (syncookies, rp_filter, ASLR, etc.)", true, "", "")
		cfg.progress("  ✓ Applied sysctl settings")
	}
}

func disableIPv6(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
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
		cfg.progress("  ✓ IPv6 disabled")
	}
}

func enableLinuxFirewall(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
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
		cfg.progress("  ✓ Firewall enabled")
	}
}

func installAuditd(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
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
		cfg.progress("  ✓ auditd installed and configured")
	}
}

func installApparmor(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
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
		cfg.progress("  ✓ AppArmor installed and enforced")
	}
}

func installFail2ban(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
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
		cfg.progress("  ✓ fail2ban installed and configured")
	}
}

func disableLinuxGuest(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
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
		cfg.progress("  ✓ Guest account disabled")
	}
}

func secureFilePermissions(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
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
		cfg.progress("  ✓ File permissions secured")
	}
}

func disableCtrlAltDel(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
	_, err := h.runBashSingle(ctx, "systemctl mask ctrl-alt-del.target")
	if err != nil {
		addResult(result, "System", "Disable Ctrl+Alt+Del", false, "", err.Error())
	} else {
		addResult(result, "System", "Disabled Ctrl+Alt+Del reboot", true, "", "")
		cfg.progress("  ✓ Ctrl+Alt+Del disabled")
	}
}

// hardenLinuxServices hardens services that are NOT required.
func hardenLinuxServices(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
	// SSH hardening (if not required)
	if !isServiceRequired(cfg.RequiredServices, "ssh") {
		hardenOrDisableSSH(ctx, h, cfg, result)
	} else {
		addSkipped(result, "Services", "SSH hardening", "marked as required")
		cfg.progress("  ⊘ SSH skipped (required)")
	}

	// Apache/httpd (if not required) - handles both Debian and RHEL naming
	if !isServiceRequired(cfg.RequiredServices, "apache") {
		// Try both service names - apache2 (Debian/Ubuntu) and httpd (RHEL/CentOS)
		disableServiceIfExists(ctx, h, cfg, result, "apache2", "Apache2 Web Server")
		disableServiceIfExists(ctx, h, cfg, result, "httpd", "Apache httpd Web Server")
	} else {
		addSkipped(result, "Services", "Apache/httpd", "marked as required")
		cfg.progress("  ⊘ Apache skipped (required)")
	}

	// Nginx (if not required)
	if !isServiceRequired(cfg.RequiredServices, "nginx") {
		disableServiceIfExists(ctx, h, cfg, result, "nginx", "Nginx Web Server")
	} else {
		addSkipped(result, "Services", "Nginx", "marked as required")
	}

	// MySQL (if not required)
	if !isServiceRequired(cfg.RequiredServices, "mysql") {
		disableServiceIfExists(ctx, h, cfg, result, "mysql", "MySQL Server")
		disableServiceIfExists(ctx, h, cfg, result, "mysqld", "MySQL Server (mysqld)")
	} else {
		addSkipped(result, "Services", "MySQL", "marked as required")
	}

	// MariaDB (if not required)
	if !isServiceRequired(cfg.RequiredServices, "mariadb") {
		disableServiceIfExists(ctx, h, cfg, result, "mariadb", "MariaDB Server")
	} else {
		addSkipped(result, "Services", "MariaDB", "marked as required")
	}

	// PostgreSQL (if not required)
	if !isServiceRequired(cfg.RequiredServices, "postgresql") {
		disableServiceIfExists(ctx, h, cfg, result, "postgresql", "PostgreSQL Server")
	} else {
		addSkipped(result, "Services", "PostgreSQL", "marked as required")
	}

	// SMB/Samba (if not required)
	if !isServiceRequired(cfg.RequiredServices, "samba") {
		disableServiceIfExists(ctx, h, cfg, result, "smbd", "Samba SMB")
		disableServiceIfExists(ctx, h, cfg, result, "nmbd", "Samba NetBIOS")
	} else {
		addSkipped(result, "Services", "Samba hardening", "marked as required")
	}

	// FTP (if not required)
	if !isServiceRequired(cfg.RequiredServices, "ftp") {
		disableServiceIfExists(ctx, h, cfg, result, "vsftpd", "FTP Server (vsftpd)")
		disableServiceIfExists(ctx, h, cfg, result, "proftpd", "FTP Server (ProFTPD)")
		disableServiceIfExists(ctx, h, cfg, result, "pure-ftpd", "FTP Server (Pure-FTPd)")
	} else {
		addSkipped(result, "Services", "FTP hardening", "marked as required")
	}

	// NFS (if not required)
	if !isServiceRequired(cfg.RequiredServices, "nfs") {
		disableServiceIfExists(ctx, h, cfg, result, "nfs-server", "NFS Server")
		disableServiceIfExists(ctx, h, cfg, result, "nfs-kernel-server", "NFS Kernel Server")
		disableServiceIfExists(ctx, h, cfg, result, "rpcbind", "RPC Bind")
	} else {
		addSkipped(result, "Services", "NFS hardening", "marked as required")
	}

	// DNS/BIND (if not required)
	if !isServiceRequired(cfg.RequiredServices, "dns") {
		disableServiceIfExists(ctx, h, cfg, result, "named", "BIND DNS (named)")
		disableServiceIfExists(ctx, h, cfg, result, "bind9", "BIND9 DNS")
	} else {
		addSkipped(result, "Services", "DNS/BIND", "marked as required")
	}

	// Mail servers (if not required)
	if !isServiceRequired(cfg.RequiredServices, "mail") {
		disableServiceIfExists(ctx, h, cfg, result, "postfix", "Postfix Mail")
		disableServiceIfExists(ctx, h, cfg, result, "dovecot", "Dovecot IMAP/POP3")
		disableServiceIfExists(ctx, h, cfg, result, "sendmail", "Sendmail")
		disableServiceIfExists(ctx, h, cfg, result, "exim4", "Exim Mail")
	} else {
		addSkipped(result, "Services", "Mail servers", "marked as required")
	}

	// Docker (if not required)
	if !isServiceRequired(cfg.RequiredServices, "docker") {
		disableServiceIfExists(ctx, h, cfg, result, "docker", "Docker")
		disableServiceIfExists(ctx, h, cfg, result, "containerd", "containerd")
	} else {
		addSkipped(result, "Services", "Docker", "marked as required")
	}

	// MongoDB (if not required)
	if !isServiceRequired(cfg.RequiredServices, "mongodb") {
		disableServiceIfExists(ctx, h, cfg, result, "mongod", "MongoDB")
	} else {
		addSkipped(result, "Services", "MongoDB", "marked as required")
	}

	// Redis (if not required)
	if !isServiceRequired(cfg.RequiredServices, "redis") {
		disableServiceIfExists(ctx, h, cfg, result, "redis-server", "Redis Server")
		disableServiceIfExists(ctx, h, cfg, result, "redis", "Redis")
	} else {
		addSkipped(result, "Services", "Redis", "marked as required")
	}

	// VNC (if not required)
	if !isServiceRequired(cfg.RequiredServices, "vnc") {
		disableServiceIfExists(ctx, h, cfg, result, "vncserver", "VNC Server")
		disableServiceIfExists(ctx, h, cfg, result, "x11vnc", "X11 VNC")
		disableServiceIfExists(ctx, h, cfg, result, "tigervnc", "TigerVNC")
	} else {
		addSkipped(result, "Services", "VNC hardening", "marked as required")
	}

	// XRDP (if not required)
	if !isServiceRequired(cfg.RequiredServices, "xrdp") {
		disableServiceIfExists(ctx, h, cfg, result, "xrdp", "XRDP Remote Desktop")
	} else {
		addSkipped(result, "Services", "XRDP", "marked as required")
	}

	// Tomcat (if not required)
	if !isServiceRequired(cfg.RequiredServices, "tomcat") {
		disableServiceIfExists(ctx, h, cfg, result, "tomcat", "Apache Tomcat")
		disableServiceIfExists(ctx, h, cfg, result, "tomcat9", "Tomcat 9")
		disableServiceIfExists(ctx, h, cfg, result, "tomcat8", "Tomcat 8")
	} else {
		addSkipped(result, "Services", "Tomcat", "marked as required")
	}

	// Squid proxy (if not required)
	if !isServiceRequired(cfg.RequiredServices, "squid") {
		disableServiceIfExists(ctx, h, cfg, result, "squid", "Squid Proxy")
	} else {
		addSkipped(result, "Services", "Squid", "marked as required")
	}

	// OpenVPN (if not required)
	if !isServiceRequired(cfg.RequiredServices, "openvpn") {
		disableServiceIfExists(ctx, h, cfg, result, "openvpn", "OpenVPN")
	} else {
		addSkipped(result, "Services", "OpenVPN", "marked as required")
	}

	// LDAP (if not required)
	if !isServiceRequired(cfg.RequiredServices, "ldap") {
		disableServiceIfExists(ctx, h, cfg, result, "slapd", "OpenLDAP Server")
	} else {
		addSkipped(result, "Services", "LDAP", "marked as required")
	}

	// Telnet (almost never required in CyberPatriot)
	if !isServiceRequired(cfg.RequiredServices, "telnet") {
		disableServiceIfExists(ctx, h, cfg, result, "telnetd", "Telnet Server")
		disableServiceIfExists(ctx, h, cfg, result, "inetd", "inetd")
		disableServiceIfExists(ctx, h, cfg, result, "xinetd", "xinetd")
	}

	// CUPS (if not required)
	if !isServiceRequired(cfg.RequiredServices, "cups") {
		disableServiceIfExists(ctx, h, cfg, result, "cups", "CUPS Printing")
		disableServiceIfExists(ctx, h, cfg, result, "cups-browsed", "CUPS Browsed")
	} else {
		addSkipped(result, "Services", "CUPS", "marked as required")
	}

	// Always disable these (security risks, rarely needed)
	disableServiceIfExists(ctx, h, cfg, result, "avahi-daemon", "Avahi mDNS")
	disableServiceIfExists(ctx, h, cfg, result, "rsh-server", "RSH Server")
	disableServiceIfExists(ctx, h, cfg, result, "rlogin", "rlogin")
	disableServiceIfExists(ctx, h, cfg, result, "rexec", "rexec")
	disableServiceIfExists(ctx, h, cfg, result, "talk", "talk")
	disableServiceIfExists(ctx, h, cfg, result, "ntalk", "ntalk")
	disableServiceIfExists(ctx, h, cfg, result, "tftp", "TFTP Server")
}

// hardenOrDisableSSH hardens SSH if installed, disables if not required.
func hardenOrDisableSSH(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
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
		cfg.progress("  ✓ SSH hardened")
	}
}

// disableServiceIfExists disables a service if it exists.
func disableServiceIfExists(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult, service, description string) {
	// Check if service exists using multiple methods for reliability
	// Method 1: Check unit files (catches enabled/disabled services)
	// Method 2: Check if service is known to systemd at all
	checkScript := fmt.Sprintf(`
		systemctl list-unit-files '%s.service' 2>/dev/null | grep -q '%s.service' || \
		systemctl status '%s' 2>/dev/null | grep -q 'Loaded:' || \
		test -f /etc/init.d/%s
	`, service, service, service, service)

	_, err := h.runBashSingle(ctx, checkScript)
	if err != nil {
		// Service doesn't exist anywhere
		return
	}

	// Service exists - try to disable it using multiple methods
	script := fmt.Sprintf(`
		# Try systemctl first (most systems)
		systemctl stop '%s' 2>/dev/null
		systemctl disable '%s' 2>/dev/null
		# Also try with .service suffix
		systemctl stop '%s.service' 2>/dev/null
		systemctl disable '%s.service' 2>/dev/null
		# Try init.d for older systems
		if [ -f /etc/init.d/%s ]; then
			/etc/init.d/%s stop 2>/dev/null
			update-rc.d %s disable 2>/dev/null || chkconfig %s off 2>/dev/null
		fi
		exit 0
	`, service, service, service, service, service, service, service, service)

	_, err = h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "Services", fmt.Sprintf("Disable %s", description), false, "", err.Error())
	} else {
		addResult(result, "Services", fmt.Sprintf("Disabled %s", description), true, "", "")
		cfg.progress("  ✓ Disabled %s", description)
	}
}

// hardenSudo configures sudo securely.
func hardenSudo(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
	// First, remove NOPASSWD and !authenticate from all sudoers files
	removeInsecureScript := `
REMOVED=0

# Remove NOPASSWD from /etc/sudoers (backup first)
if grep -q 'NOPASSWD' /etc/sudoers 2>/dev/null; then
    cp /etc/sudoers /etc/sudoers.bak.ironguard
    sed -i 's/NOPASSWD://g' /etc/sudoers
    sed -i 's/NOPASSWD\s*//g' /etc/sudoers
    REMOVED=$((REMOVED + 1))
fi

# Remove !authenticate from /etc/sudoers
if grep -q '!authenticate' /etc/sudoers 2>/dev/null; then
    sed -i 's/!authenticate//g' /etc/sudoers
    REMOVED=$((REMOVED + 1))
fi

# Check sudoers.d directory
for f in /etc/sudoers.d/*; do
    if [ -f "$f" ] && [ "$f" != "/etc/sudoers.d/99-ironguard-hardening" ]; then
        if grep -q 'NOPASSWD' "$f" 2>/dev/null; then
            sed -i 's/NOPASSWD://g' "$f"
            sed -i 's/NOPASSWD\s*//g' "$f"
            echo "Removed NOPASSWD from $f"
            REMOVED=$((REMOVED + 1))
        fi
        if grep -q '!authenticate' "$f" 2>/dev/null; then
            sed -i 's/!authenticate//g' "$f"
            echo "Removed !authenticate from $f"
            REMOVED=$((REMOVED + 1))
        fi
    fi
done

# Validate sudoers after changes
visudo -c >/dev/null 2>&1
if [ $? -ne 0 ]; then
    # Restore from backup if syntax is broken
    if [ -f /etc/sudoers.bak.ironguard ]; then
        cp /etc/sudoers.bak.ironguard /etc/sudoers
        echo "RESTORED_BACKUP"
    fi
fi

echo "REMOVED_COUNT=$REMOVED"
`
	output, err := h.runBashSingle(ctx, removeInsecureScript)
	if err != nil {
		addResult(result, "Sudo", "Remove NOPASSWD/!authenticate", false, "", err.Error())
	} else if strings.Contains(output, "RESTORED_BACKUP") {
		addResult(result, "Sudo", "Remove NOPASSWD/!authenticate", false, "", "Had to restore backup - manual review needed")
		cfg.progress("  ⚠ Sudoers changes caused syntax error - restored backup")
	} else {
		addResult(result, "Sudo", "Removed NOPASSWD and !authenticate from sudoers", true, "", "")
		cfg.progress("  ✓ NOPASSWD and !authenticate removed (sudo will require password)")
	}

	// Now add our secure defaults
	script := `
# Create secure sudoers.d config
cat > /etc/sudoers.d/99-ironguard-hardening << 'EOF'
# IronGuard sudo hardening
Defaults env_reset
Defaults mail_badpass
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults !visiblepw
Defaults timestamp_timeout=5
Defaults passwd_tries=3

# Ensure authenticate is required (opposite of !authenticate)
Defaults authenticate
EOF
chmod 440 /etc/sudoers.d/99-ironguard-hardening

# Disable coredumps system-wide for setuid programs
grep -q '^\* hard core 0' /etc/security/limits.conf 2>/dev/null || echo '* hard core 0' >> /etc/security/limits.conf
grep -q 'fs.suid_dumpable' /etc/sysctl.conf || echo 'fs.suid_dumpable = 0' >> /etc/sysctl.conf

# Validate sudoers syntax
visudo -c -f /etc/sudoers.d/99-ironguard-hardening 2>/dev/null || rm /etc/sudoers.d/99-ironguard-hardening
`
	_, err = h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "Sudo", "Harden sudo configuration", false, "", err.Error())
	} else {
		addResult(result, "Sudo", "Enabled env_reset, authenticate, disabled coredumps, added logging", true, "", "")
		cfg.progress("  ✓ Sudo hardened (env_reset, authenticate required, no coredumps, logging)")
	}
}

// secureRootAccount ensures root account is properly secured.
func secureRootAccount(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
	script := `
# Check if root has blank password and lock it
ROOT_HASH=$(getent shadow root | cut -d: -f2)
if [ "$ROOT_HASH" = "" ] || [ "$ROOT_HASH" = "!" ] || [ "$ROOT_HASH" = "*" ] || [ "$ROOT_HASH" = "!!" ]; then
    # Root already locked or no password - ensure it's locked
    passwd -l root 2>/dev/null
    echo "locked"
else
    # Root has a password - good, but ensure it's not blank/simple
    if [ ${#ROOT_HASH} -lt 10 ]; then
        passwd -l root 2>/dev/null
        echo "locked_short"
    else
        echo "has_password"
    fi
fi

# Disable root login in GDM
if [ -f /etc/gdm3/custom.conf ]; then
    sed -i '/^\[security\]/a AllowRoot=false' /etc/gdm3/custom.conf 2>/dev/null || true
fi

# Disable root login in LightDM greeter
if [ -d /etc/lightdm ]; then
    mkdir -p /etc/lightdm/lightdm.conf.d
    echo '[Seat:*]' > /etc/lightdm/lightdm.conf.d/50-no-root.conf
    echo 'greeter-show-manual-login=true' >> /etc/lightdm/lightdm.conf.d/50-no-root.conf
    echo 'greeter-hide-users=true' >> /etc/lightdm/lightdm.conf.d/50-no-root.conf
fi
`
	output, err := h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "Root Account", "Secure root account", false, "", err.Error())
	} else {
		if strings.Contains(output, "locked") {
			addResult(result, "Root Account", "Locked root account (was blank/invalid)", true, "", "")
			cfg.progress("  ✓ Root account locked")
		} else {
			addResult(result, "Root Account", "Root account has password, disabled greeter login", true, "", "")
			cfg.progress("  ✓ Root greeter login disabled")
		}
	}
}

// installClamAV installs and configures ClamAV antivirus.
func installClamAV(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
	script := `
# Install ClamAV
apt-get install -y clamav clamav-daemon 2>/dev/null || \
dnf install -y clamav clamd clamav-update 2>/dev/null || \
yum install -y clamav clamd clamav-update 2>/dev/null

# Stop freshclam to update database
systemctl stop clamav-freshclam 2>/dev/null || true

# Update virus database (may take time, run in background)
freshclam 2>/dev/null &

# Enable and start services
systemctl enable clamav-daemon 2>/dev/null || systemctl enable clamd 2>/dev/null
systemctl start clamav-daemon 2>/dev/null || systemctl start clamd 2>/dev/null

# Restart freshclam
systemctl enable clamav-freshclam 2>/dev/null
systemctl start clamav-freshclam 2>/dev/null
`
	_, err := h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "Antivirus", "Install ClamAV", false, "", err.Error())
	} else {
		addResult(result, "Antivirus", "Installed ClamAV, updating virus definitions", true, "", "")
		cfg.progress("  ✓ ClamAV installed (definitions updating in background)")
	}
}

// auditSUIDBinaries checks for potentially dangerous SUID binaries.
func auditSUIDBinaries(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
	// These are commonly exploited SUID binaries that shouldn't have SUID in most cases
	script := `
# Check for dangerous SUID bits and remove them
DANGEROUS_SUIDS="date nano vi vim nmap find perl python python3 ruby lua"

for bin in $DANGEROUS_SUIDS; do
    PATHS=$(which $bin 2>/dev/null)
    for path in $PATHS; do
        if [ -f "$path" ]; then
            PERMS=$(stat -c '%a' "$path" 2>/dev/null)
            if [ -n "$PERMS" ] && [ $((PERMS & 4000)) -ne 0 ]; then
                chmod u-s "$path" 2>/dev/null
                echo "Removed SUID from $path"
            fi
        fi
    done
done

# Report remaining SUID binaries (informational)
echo "---REMAINING_SUID---"
find /usr -type f -perm -4000 2>/dev/null | head -20
`
	output, err := h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "SUID Audit", "Audit SUID binaries", false, "", err.Error())
	} else {
		if strings.Contains(output, "Removed SUID") {
			addResult(result, "SUID Audit", "Removed dangerous SUID bits (date, editors, scripting languages)", true, "", "")
			cfg.progress("  ✓ Removed dangerous SUID bits")
		} else {
			addResult(result, "SUID Audit", "No dangerous SUID binaries found", true, "", "")
			cfg.progress("  ✓ SUID binaries audited (none dangerous)")
		}
	}
}

// auditCronJobs checks for suspicious cron jobs.
func auditCronJobs(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
	script := `
SUSPICIOUS=0

# Check system crontabs for suspicious entries
for cronfile in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
    if [ -f "$cronfile" ]; then
        # Look for suspicious patterns
        if grep -qE '(wget|curl|nc |netcat|bash -i|/dev/tcp|python.*-c|perl.*-e|ruby.*-e)' "$cronfile" 2>/dev/null; then
            echo "SUSPICIOUS: $cronfile"
            SUSPICIOUS=$((SUSPICIOUS + 1))
        fi
    fi
done

# Check rc.local for backdoors
if [ -f /etc/rc.local ]; then
    if grep -qE '(wget|curl|nc |netcat|bash -i|/dev/tcp|python.*-c|perl.*-e)' /etc/rc.local 2>/dev/null; then
        echo "SUSPICIOUS: /etc/rc.local"
        SUSPICIOUS=$((SUSPICIOUS + 1))
    fi
fi

# Check init.d for non-standard scripts
for initscript in /etc/init.d/*; do
    if [ -f "$initscript" ]; then
        # Check if script contains suspicious network activity
        if grep -qE '(wget|curl|nc |netcat|bash -i|/dev/tcp)' "$initscript" 2>/dev/null; then
            echo "SUSPICIOUS: $initscript"
            SUSPICIOUS=$((SUSPICIOUS + 1))
        fi
    fi
done

echo "TOTAL_SUSPICIOUS=$SUSPICIOUS"
`
	output, err := h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "Cron Audit", "Audit cron jobs", false, "", err.Error())
	} else {
		if strings.Contains(output, "SUSPICIOUS:") {
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "SUSPICIOUS:") {
					cfg.progress("  ⚠ %s", line)
				}
			}
			addResult(result, "Cron Audit", "Found suspicious cron/startup scripts - MANUAL REVIEW NEEDED", false, "", "Review the files listed above for backdoors")
		} else {
			addResult(result, "Cron Audit", "No obviously suspicious cron jobs found", true, "", "")
			cfg.progress("  ✓ Cron jobs audited (no obvious backdoors)")
		}
	}
}

// verifyAndFixAptSources ensures apt sources are correctly configured before updates.
// thirdPartyAction: "keep" = allow and keep, "remove" = delete files, "disable" = comment out
func verifyAndFixAptSources(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult, thirdPartyAction string) {
	cfg.progress("  Verifying apt sources...")

	// Script to check and fix apt sources
	script := `
#!/bin/bash
CHANGES=0
SOURCES_FILE="/etc/apt/sources.list"
SOURCES_DIR="/etc/apt/sources.list.d"

# Backup original sources
if [ -f "$SOURCES_FILE" ]; then
    cp -n "$SOURCES_FILE" "${SOURCES_FILE}.ironguard.bak" 2>/dev/null
fi

# Get the OS codename
if [ -f /etc/os-release ]; then
    . /etc/os-release
    CODENAME="${VERSION_CODENAME:-$UBUNTU_CODENAME}"
fi

# Check for disabled repos (commented lines with main, restricted, universe, multiverse)
if [ -f "$SOURCES_FILE" ]; then
    # Uncomment main repos that are commented
    if grep -qE '^#.*\s(main|restricted|universe|multiverse)' "$SOURCES_FILE"; then
        sed -i 's/^#\s*\(deb.*\(main\|restricted\|universe\|multiverse\)\)/\1/' "$SOURCES_FILE"
        CHANGES=$((CHANGES + 1))
        echo "ENABLED_REPOS"
    fi
    
    # Ensure security repos are enabled
    if ! grep -qE '^deb.*security' "$SOURCES_FILE"; then
        if [ -n "$CODENAME" ]; then
            echo "deb http://security.ubuntu.com/ubuntu ${CODENAME}-security main restricted universe multiverse" >> "$SOURCES_FILE"
            CHANGES=$((CHANGES + 1))
            echo "ADDED_SECURITY"
        fi
    fi
    
    # Ensure updates repos are enabled
    if ! grep -qE '^deb.*-updates' "$SOURCES_FILE"; then
        if [ -n "$CODENAME" ]; then
            echo "deb http://archive.ubuntu.com/ubuntu ${CODENAME}-updates main restricted universe multiverse" >> "$SOURCES_FILE"
            CHANGES=$((CHANGES + 1))
            echo "ADDED_UPDATES"
        fi
    fi
fi
`
	// Handle 3rd party repos based on user choice
	switch thirdPartyAction {
	case "keep":
		// Do nothing - keep existing 3rd party repos
		script += `
echo "3RD_PARTY_KEPT"
`
	case "remove":
		// Remove (delete) 3rd party repo files
		script += `
# Remove 3rd party repo files
if [ -d "$SOURCES_DIR" ]; then
    for file in "$SOURCES_DIR"/*.list; do
        [ -f "$file" ] || continue
        filename=$(basename "$file")
        # Skip official Ubuntu sources
        case "$filename" in
            ubuntu*.list|official*.list) continue ;;
        esac
        rm -f "$file"
        CHANGES=$((CHANGES + 1))
        echo "REMOVED_3RD_PARTY: $filename"
    done
fi
`
	default: // "disable" or empty
		// Comment out 3rd party repos
		script += `
# Disable (comment out) 3rd party repos
if [ -d "$SOURCES_DIR" ]; then
    for file in "$SOURCES_DIR"/*.list; do
        [ -f "$file" ] || continue
        filename=$(basename "$file")
        # Skip official Ubuntu sources
        case "$filename" in
            ubuntu*.list|official*.list) continue ;;
        esac
        # Comment out 3rd party repos
        if grep -qE '^deb\s' "$file"; then
            sed -i 's/^deb/#deb/' "$file"
            CHANGES=$((CHANGES + 1))
            echo "DISABLED_3RD_PARTY: $filename"
        fi
    done
fi
`
	}

	script += `
if [ $CHANGES -gt 0 ]; then
    echo "SOURCES_FIXED: $CHANGES changes made"
else
    echo "SOURCES_OK"
fi
`

	output, err := h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "APT Sources", "Verify apt sources", false, "", err.Error())
		cfg.progress("  ✗ Failed to verify apt sources: %s", err.Error())
		return
	}

	if strings.Contains(output, "SOURCES_OK") && !strings.Contains(output, "SOURCES_FIXED") {
		addResult(result, "APT Sources", "Apt sources verified - no changes needed", true, "", "")
		cfg.progress("  ✓ Apt sources verified (no changes needed)")
	} else {
		changes := []string{}
		if strings.Contains(output, "ENABLED_REPOS") {
			changes = append(changes, "uncommented main repos")
		}
		if strings.Contains(output, "ADDED_SECURITY") {
			changes = append(changes, "added security repo")
		}
		if strings.Contains(output, "ADDED_UPDATES") {
			changes = append(changes, "added updates repo")
		}
		if strings.Contains(output, "DISABLED_3RD_PARTY") {
			changes = append(changes, "disabled 3rd party repos")
		}
		if strings.Contains(output, "REMOVED_3RD_PARTY") {
			changes = append(changes, "removed 3rd party repos")
		}
		if strings.Contains(output, "3RD_PARTY_KEPT") {
			changes = append(changes, "kept 3rd party repos")
		}

		if len(changes) > 0 {
			changeStr := strings.Join(changes, ", ")
			addResult(result, "APT Sources", "Fixed apt sources: "+changeStr, true, "", "")
			cfg.progress("  ✓ Apt sources fixed: %s", changeStr)
		} else {
			addResult(result, "APT Sources", "Apt sources verified", true, "", "")
			cfg.progress("  ✓ Apt sources verified")
		}
	}
}

// runLinuxUpdates runs system updates.
func runLinuxUpdates(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
	// First, verify and fix apt sources
	verifyAndFixAptSources(ctx, h, cfg, result, cfg.ThirdPartyRepoAction)

	cfg.progress("  Running updates... (this may take several minutes)")

	// Configure automatic updates first
	autoUpdateScript := `
# Enable automatic security updates
if command -v apt-get &>/dev/null; then
    apt-get install -y unattended-upgrades
    dpkg-reconfigure -plow unattended-upgrades 2>/dev/null || true
    # Configure to check daily
    echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
    echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
fi
`
	h.runBashSingle(ctx, autoUpdateScript)
	addResult(result, "Updates", "Configured automatic security updates", true, "", "")
	cfg.progress("  ✓ Automatic updates configured")

	// Run the actual update
	script := `
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get upgrade -y -qq --with-new-pkgs 2>&1 | tail -5
elif command -v dnf &>/dev/null; then
    dnf update -y -q 2>&1 | tail -5
elif command -v yum &>/dev/null; then
    yum update -y -q 2>&1 | tail -5
fi
echo "UPDATE_COMPLETE"
`
	output, err := h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "Updates", "Run system updates", false, "", err.Error())
		cfg.progress("  ✗ Updates failed: %s", err.Error())
	} else if strings.Contains(output, "UPDATE_COMPLETE") {
		addResult(result, "Updates", "System packages updated", true, "", "")
		cfg.progress("  ✓ System updates completed")
	} else {
		addResult(result, "Updates", "Updates may have partially completed", false, "", output)
		cfg.progress("  ⚠ Updates may have partially completed")
	}
}

// configureScreenLock sets screen timeout and lock for multiple desktop environments.
func configureScreenLock(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
	// This script handles GNOME, Cinnamon (Mint), MATE, XFCE, and KDE
	script := `
CONFIGURED=0
TIMEOUT_SECONDS=300  # 5 minutes

# Get list of real users (UID >= 1000)
USERS=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd)

for USER in $USERS; do
    USER_HOME=$(getent passwd "$USER" | cut -d: -f6)
    
    # GNOME (Ubuntu, Fedora GNOME, etc.)
    if sudo -u "$USER" gsettings list-schemas 2>/dev/null | grep -q "org.gnome.desktop.session"; then
        sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u $USER)/bus" \
            gsettings set org.gnome.desktop.session idle-delay $TIMEOUT_SECONDS 2>/dev/null && CONFIGURED=$((CONFIGURED+1))
        sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u $USER)/bus" \
            gsettings set org.gnome.desktop.screensaver lock-enabled true 2>/dev/null
        sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u $USER)/bus" \
            gsettings set org.gnome.desktop.screensaver lock-delay 0 2>/dev/null
        echo "GNOME configured for $USER"
    fi
    
    # Cinnamon (Linux Mint)
    if sudo -u "$USER" gsettings list-schemas 2>/dev/null | grep -q "org.cinnamon.desktop.session"; then
        sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u $USER)/bus" \
            gsettings set org.cinnamon.desktop.session idle-delay $TIMEOUT_SECONDS 2>/dev/null && CONFIGURED=$((CONFIGURED+1))
        sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u $USER)/bus" \
            gsettings set org.cinnamon.desktop.screensaver lock-enabled true 2>/dev/null
        sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u $USER)/bus" \
            gsettings set org.cinnamon.desktop.screensaver lock-delay 0 2>/dev/null
        echo "Cinnamon configured for $USER"
    fi
    
    # MATE
    if sudo -u "$USER" gsettings list-schemas 2>/dev/null | grep -q "org.mate.session"; then
        sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u $USER)/bus" \
            gsettings set org.mate.session idle-delay $TIMEOUT_SECONDS 2>/dev/null && CONFIGURED=$((CONFIGURED+1))
        sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u $USER)/bus" \
            gsettings set org.mate.screensaver lock-enabled true 2>/dev/null
        echo "MATE configured for $USER"
    fi
done

# XFCE (uses xfconf)
if command -v xfconf-query &>/dev/null; then
    for USER in $USERS; do
        sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u $USER)/bus" \
            xfconf-query -c xfce4-session -p /general/LockCommand -s "xflock4" 2>/dev/null
        sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u $USER)/bus" \
            xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/blank-on-ac -s 5 2>/dev/null && CONFIGURED=$((CONFIGURED+1))
        sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u $USER)/bus" \
            xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/lock-screen-suspend-hibernate -s true 2>/dev/null
    done
    echo "XFCE configured"
fi

# KDE Plasma (uses kwriteconfig5)
if command -v kwriteconfig5 &>/dev/null; then
    for USER in $USERS; do
        USER_HOME=$(getent passwd "$USER" | cut -d: -f6)
        sudo -u "$USER" kwriteconfig5 --file kscreenlockerrc --group Daemon --key Autolock true 2>/dev/null
        sudo -u "$USER" kwriteconfig5 --file kscreenlockerrc --group Daemon --key Timeout 5 2>/dev/null && CONFIGURED=$((CONFIGURED+1))
        sudo -u "$USER" kwriteconfig5 --file kscreenlockerrc --group Daemon --key LockOnResume true 2>/dev/null
    done
    echo "KDE configured"
fi

# Fallback: Create dconf profile for all users (works on GNOME/Cinnamon systems)
mkdir -p /etc/dconf/profile
cat > /etc/dconf/profile/user << 'DCONFEOF'
user-db:user
system-db:local
DCONFEOF

mkdir -p /etc/dconf/db/local.d
cat > /etc/dconf/db/local.d/00-screensaver << 'DCONFEOF'
[org/gnome/desktop/session]
idle-delay=uint32 300

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0

[org/cinnamon/desktop/session]
idle-delay=uint32 300

[org/cinnamon/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
DCONFEOF

# Update dconf database
dconf update 2>/dev/null && CONFIGURED=$((CONFIGURED+1))

echo "CONFIGURED=$CONFIGURED"
`
	output, err := h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "Screen Lock", "Configure screen timeout and lock", false, "", err.Error())
		cfg.progress("  ⚠ Screen lock configuration had errors")
	} else {
		addResult(result, "Screen Lock", "Set 5-minute idle timeout, auto-lock enabled (GNOME/Cinnamon/MATE/XFCE/KDE)", true, "", "")
		cfg.progress("  ✓ Screen lock configured (5 min timeout, lock on idle)")
		// Print which DEs were configured
		if strings.Contains(output, "GNOME configured") {
			cfg.progress("    → GNOME settings applied")
		}
		if strings.Contains(output, "Cinnamon configured") {
			cfg.progress("    → Cinnamon (Mint) settings applied")
		}
		if strings.Contains(output, "MATE configured") {
			cfg.progress("    → MATE settings applied")
		}
		if strings.Contains(output, "XFCE configured") {
			cfg.progress("    → XFCE settings applied")
		}
		if strings.Contains(output, "KDE configured") {
			cfg.progress("    → KDE Plasma settings applied")
		}
	}
}

// hardenDisplayManager configures GDM/LightDM/SDDM security settings and removes unselected DMs.
func hardenDisplayManager(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
	selectedDM := cfg.SelectedDisplayManager

	// First, remove unselected display managers if user selected one
	if selectedDM != "" {
		dmsToRemove := []string{}
		if selectedDM != "gdm3" {
			dmsToRemove = append(dmsToRemove, "gdm3", "gdm")
		}
		if selectedDM != "lightdm" {
			dmsToRemove = append(dmsToRemove, "lightdm")
		}
		if selectedDM != "sddm" {
			dmsToRemove = append(dmsToRemove, "sddm")
		}

		if len(dmsToRemove) > 0 {
			// Build removal script
			removeScript := fmt.Sprintf(`
SELECTED="%s"
REMOVED=""

# Stop and disable unselected DMs before removal
`, selectedDM)
			for _, dm := range dmsToRemove {
				removeScript += fmt.Sprintf(`
# Remove %s if installed
if dpkg -l "%s" 2>/dev/null | grep -q "^ii"; then
    systemctl stop %s 2>/dev/null || true
    systemctl disable %s 2>/dev/null || true
    apt-get purge -y %s 2>/dev/null
    REMOVED="$REMOVED %s"
fi
`, dm, dm, dm, dm, dm, dm)
			}

			removeScript += `
# Make sure selected DM is set as default and running
if [ -n "$SELECTED" ]; then
    # Set as default
    if command -v update-alternatives &>/dev/null; then
        case "$SELECTED" in
            gdm3|gdm)
                update-alternatives --set x-session-manager /usr/bin/gnome-session 2>/dev/null || true
                ;;
            lightdm)
                # LightDM doesn't need special alternatives
                ;;
            sddm)
                # SDDM doesn't need special alternatives
                ;;
        esac
    fi
    
    # Enable and start selected DM
    systemctl enable "$SELECTED" 2>/dev/null || true
    # Don't start now - might be in text mode
fi

echo "REMOVED:$REMOVED"
`
			output, err := h.runBashSingle(ctx, removeScript)
			if err != nil {
				addResult(result, "Display Manager", fmt.Sprintf("Remove unselected display managers"), false, "", err.Error())
			} else {
				if strings.Contains(output, "REMOVED:") && !strings.HasSuffix(strings.TrimSpace(output), "REMOVED:") {
					// Extract what was removed
					parts := strings.Split(output, "REMOVED:")
					if len(parts) > 1 {
						removed := strings.TrimSpace(parts[1])
						if removed != "" {
							addResult(result, "Display Manager", fmt.Sprintf("Removed: %s (keeping %s)", removed, selectedDM), true, "", "")
							cfg.progress("  ✓ Removed unused display managers: %s", removed)
						}
					}
				} else {
					cfg.progress("  ✓ Only %s was installed (nothing to remove)", selectedDM)
				}
			}
		}
	}

	// Now harden the selected/remaining display manager(s)
	script := `
HARDENED=0

# GDM3 hardening
if [ -f /etc/gdm3/custom.conf ] || [ -d /etc/gdm3 ]; then
    mkdir -p /etc/gdm3
    
    # Ensure custom.conf exists with security section
    if [ ! -f /etc/gdm3/custom.conf ]; then
        cat > /etc/gdm3/custom.conf << 'EOF'
[daemon]

[security]
DisallowTCP=true

[xdmcp]

[chooser]

[debug]
EOF
    else
        # Add DisallowTCP if not present
        if ! grep -q "DisallowTCP" /etc/gdm3/custom.conf; then
            if grep -q "\[security\]" /etc/gdm3/custom.conf; then
                sed -i '/\[security\]/a DisallowTCP=true' /etc/gdm3/custom.conf
            else
                echo -e "\n[security]\nDisallowTCP=true" >> /etc/gdm3/custom.conf
            fi
        else
            sed -i 's/DisallowTCP=.*/DisallowTCP=true/' /etc/gdm3/custom.conf
        fi
    fi
    
    # Disable automatic login if set
    sed -i 's/^AutomaticLoginEnable=.*/AutomaticLoginEnable=False/' /etc/gdm3/custom.conf 2>/dev/null
    sed -i 's/^AutomaticLogin=/#AutomaticLogin=/' /etc/gdm3/custom.conf 2>/dev/null
    
    HARDENED=$((HARDENED+1))
    echo "GDM3 hardened"
fi

# LightDM hardening (common on Mint, Ubuntu variants)
if [ -d /etc/lightdm ]; then
    mkdir -p /etc/lightdm/lightdm.conf.d
    
    cat > /etc/lightdm/lightdm.conf.d/50-security.conf << 'EOF'
[Seat:*]
allow-guest=false
greeter-hide-users=true
greeter-show-manual-login=true
autologin-user=
EOF
    
    # Also check main lightdm.conf for autologin
    if [ -f /etc/lightdm/lightdm.conf ]; then
        sed -i 's/^autologin-user=.*/autologin-user=/' /etc/lightdm/lightdm.conf 2>/dev/null
        sed -i 's/^allow-guest=.*/allow-guest=false/' /etc/lightdm/lightdm.conf 2>/dev/null
    fi
    
    HARDENED=$((HARDENED+1))
    echo "LightDM hardened"
fi

# SDDM hardening (KDE)
if [ -d /etc/sddm.conf.d ] || [ -f /etc/sddm.conf ]; then
    mkdir -p /etc/sddm.conf.d
    cat > /etc/sddm.conf.d/security.conf << 'EOF'
[Autologin]
User=
Session=

[Users]
HideUsers=
HideShells=/sbin/nologin,/bin/false
EOF
    HARDENED=$((HARDENED+1))
    echo "SDDM hardened"
fi

echo "HARDENED=$HARDENED"
`
	output, err := h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "Display Manager", "Harden display manager settings", false, "", err.Error())
	} else {
		addResult(result, "Display Manager", "Disabled TCP, guest login, autologin in display managers", true, "", "")
		cfg.progress("  ✓ Display manager hardened (TCP disabled, no guest/autologin)")
		if strings.Contains(output, "GDM3 hardened") {
			cfg.progress("    → GDM3 configured")
		}
		if strings.Contains(output, "LightDM hardened") {
			cfg.progress("    → LightDM configured")
		}
		if strings.Contains(output, "SDDM hardened") {
			cfg.progress("    → SDDM (KDE) configured")
		}
	}
}

// setProcessLimits configures secure process limits.
func setProcessLimits(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
	script := `
# Set hard process limit (prevents fork bombs)
if ! grep -q '^\* hard nproc' /etc/security/limits.conf; then
    echo '* hard nproc 2500' >> /etc/security/limits.conf
fi

# Ensure soft limit is also set
if ! grep -q '^\* soft nproc' /etc/security/limits.conf; then
    echo '* soft nproc 2000' >> /etc/security/limits.conf
fi

# Set max open files limit
if ! grep -q '^\* hard nofile' /etc/security/limits.conf; then
    echo '* hard nofile 65535' >> /etc/security/limits.conf
fi

# Ensure limits are enforced via PAM
if [ -f /etc/pam.d/common-session ]; then
    if ! grep -q 'pam_limits.so' /etc/pam.d/common-session; then
        echo 'session required pam_limits.so' >> /etc/pam.d/common-session
    fi
fi

if [ -f /etc/pam.d/common-session-noninteractive ]; then
    if ! grep -q 'pam_limits.so' /etc/pam.d/common-session-noninteractive; then
        echo 'session required pam_limits.so' >> /etc/pam.d/common-session-noninteractive
    fi
fi

echo "LIMITS_SET"
`
	output, err := h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "Process Limits", "Set secure process limits", false, "", err.Error())
	} else if strings.Contains(output, "LIMITS_SET") {
		addResult(result, "Process Limits", "Set nproc=2500, nofile=65535 hard limits", true, "", "")
		cfg.progress("  ✓ Process limits configured (nproc=2500, nofile=65535)")
	}
}

// secureGrubPermissions sets secure permissions on GRUB configuration.
func secureGrubPermissions(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
	script := `
SECURED=0

# Secure GRUB config files
for grubfile in /boot/grub/grub.cfg /boot/grub2/grub.cfg /boot/efi/EFI/*/grub.cfg; do
    if [ -f "$grubfile" ]; then
        chmod 600 "$grubfile"
        chown root:root "$grubfile"
        SECURED=$((SECURED+1))
        echo "Secured: $grubfile"
    fi
done

# Secure GRUB directory
if [ -d /boot/grub ]; then
    chmod 700 /boot/grub
fi
if [ -d /boot/grub2 ]; then
    chmod 700 /boot/grub2
fi

echo "SECURED=$SECURED"
`
	output, err := h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "GRUB", "Secure GRUB configuration permissions", false, "", err.Error())
	} else if strings.Contains(output, "Secured:") {
		addResult(result, "GRUB", "Set GRUB config to 600 (root only)", true, "", "")
		cfg.progress("  ✓ GRUB configuration secured (chmod 600)")
	} else {
		addResult(result, "GRUB", "No GRUB config files found", true, "", "May be using different bootloader")
		cfg.progress("  ✓ No GRUB config found (may use different bootloader)")
	}
}

// setAllUserPasswords sets a standard password for all human users.
func setAllUserPasswords(ctx context.Context, h *Hardener, cfg *BaselineConfig, result *BaselineResult) {
	password := cfg.StandardPassword
	if password == "" {
		password = "CyberPatr!0t"
	}

	script := fmt.Sprintf(`
PASSWORD='%s'
LOCK_ACCOUNTS=%t
EXPIRE_PASSWORDS=%t
CHANGED=0
FAILED=0

# Get all human users (UID >= 1000, excluding nobody and system accounts)
while IFS=: read -r username _ uid _ _ _ shell; do
    if [ "$uid" -ge 1000 ] && [ "$username" != "nobody" ] && [ "$username" != "nogroup" ]; then
        # Check if user has a valid login shell
        case "$shell" in
            */bash|*/sh|*/zsh|*/fish)
                # Set password
                echo "$username:$PASSWORD" | chpasswd 2>/dev/null
                if [ $? -eq 0 ]; then
                    echo "Password set for: $username"
                    CHANGED=$((CHANGED+1))
                    
                    # Lock account if requested
                    if [ "$LOCK_ACCOUNTS" = "true" ]; then
                        passwd -l "$username" 2>/dev/null
                        echo "Locked: $username"
                    fi
                    
                    # Expire password if requested (force change on next login)
                    if [ "$EXPIRE_PASSWORDS" = "true" ]; then
                        chage -d 0 "$username" 2>/dev/null
                        echo "Expired: $username"
                    fi
                else
                    echo "Failed: $username"
                    FAILED=$((FAILED+1))
                fi
                ;;
        esac
    fi
done < /etc/passwd

echo "CHANGED=$CHANGED"
echo "FAILED=$FAILED"
`, password, cfg.LockUserAccounts, cfg.ExpireUserPasswords)

	output, err := h.runBashSingle(ctx, script)
	if err != nil {
		addResult(result, "User Passwords", "Set standard password for all users", false, "", err.Error())
		cfg.progress("  ✗ Failed to set user passwords: %s", err.Error())
	} else {
		// Count successes
		var changed, failed int
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, "CHANGED=") {
				fmt.Sscanf(line, "CHANGED=%d", &changed)
			}
			if strings.HasPrefix(line, "FAILED=") {
				fmt.Sscanf(line, "FAILED=%d", &failed)
			}
		}

		desc := fmt.Sprintf("Set password for %d users", changed)
		if cfg.LockUserAccounts {
			desc += ", locked accounts"
		}
		if cfg.ExpireUserPasswords {
			desc += ", expired (must change on login)"
		}

		if failed > 0 {
			addResult(result, "User Passwords", desc, false, "", fmt.Sprintf("%d users failed", failed))
		} else {
			addResult(result, "User Passwords", desc, true, "", "")
		}

		cfg.progress("  ✓ Password set for %d users", changed)
		if cfg.LockUserAccounts {
			cfg.progress("    → Accounts locked")
		}
		if cfg.ExpireUserPasswords {
			cfg.progress("    → Passwords expired (must change on next login)")
		}
		if failed > 0 {
			cfg.progress("  ⚠ Failed for %d users", failed)
		}
	}
}

