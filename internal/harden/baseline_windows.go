//go:build windows

package harden

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// runPlatformBaseline applies baseline hardening for the current platform (Windows).
func runPlatformBaseline(ctx context.Context, cfg BaselineConfig, result *BaselineResult) (*BaselineResult, error) {
	h := New()
	
	// Detect Windows version
	version := detectWindowsVersion(ctx, h)
	result.OSVersion = version
	isServer := strings.Contains(strings.ToLower(version), "server")
	fmt.Printf("Detected: %s\n\n", version)
	
	// 1. Password and Account Policies
	fmt.Println("━━━ Configuring Password & Account Policies ━━━")
	applyWindowsPasswordPolicy(ctx, h, cfg, result)
	
	// 2. Local Security Policies
	fmt.Println("\n━━━ Applying Local Security Policies ━━━")
	applyLocalSecurityPolicies(ctx, h, result)
	
	// 3. Firewall
	if cfg.EnableFirewall {
		fmt.Println("\n━━━ Enabling Windows Firewall ━━━")
		enableWindowsFirewall(ctx, h, result)
	} else {
		addSkipped(result, "Firewall", "Enable Windows Firewall", "user chose to skip")
	}
	
	// 4. Disable Guest Account
	fmt.Println("\n━━━ Disabling Guest Account ━━━")
	disableWindowsGuest(ctx, h, result)
	
	// 5. Audit Policies
	fmt.Println("\n━━━ Configuring Audit Policies ━━━")
	configureAuditPolicies(ctx, h, result)
	
	// 6. Disable Unnecessary Services (respecting required services)
	fmt.Println("\n━━━ Disabling Unnecessary Services ━━━")
	disableUnnecessaryServices(ctx, h, cfg, result)
	
	// 7. Windows Defender
	fmt.Println("\n━━━ Configuring Windows Defender ━━━")
	configureWindowsDefender(ctx, h, result)
	
	// 8. Registry Hardening (respecting required services like RDP)
	fmt.Println("\n━━━ Applying Registry Hardening ━━━")
	applyRegistryHardening(ctx, h, cfg, result)
	
	// 9. Server-specific hardening
	if isServer {
		fmt.Println("\n━━━ Applying Server-Specific Hardening ━━━")
		applyServerHardening(ctx, h, result)
	}
	
	// 10. SMB Hardening (skip if SMB is required)
	if !isServiceRequired(cfg.RequiredServices, "smb") {
		fmt.Println("\n━━━ Hardening SMB ━━━")
		hardenSMB(ctx, h, result)
	} else {
		addSkipped(result, "SMB", "SMB hardening", "SMB marked as required")
		fmt.Println("\n━━━ Skipping SMB Hardening (required) ━━━")
	}
	
	result.PrintResults()
	return result, nil
}

func detectWindowsVersion(ctx context.Context, h *Hardener) string {
	output, err := h.runPowerShellSingle(ctx, "(Get-WmiObject Win32_OperatingSystem).Caption")
	if err != nil {
		return "Windows (unknown)"
	}
	return strings.TrimSpace(output)
}

func applyWindowsPasswordPolicy(ctx context.Context, h *Hardener, cfg BaselineConfig, result *BaselineResult) {
	// Create security policy configuration
	script := fmt.Sprintf(`
$cfg = @"
[System Access]
MinimumPasswordAge = %d
MaximumPasswordAge = %d
MinimumPasswordLength = %d
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
RequireLogonToChangePassword = 0
ClearTextPassword = 0
"@

$tempPath = "$env:TEMP\secpol_ironguard.cfg"
$cfg | Out-File -FilePath $tempPath -Encoding ASCII

# Import the policy
secedit /configure /db "$env:TEMP\secpol.sdb" /cfg $tempPath /areas SECURITYPOLICY /quiet

Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
`, cfg.MinPasswordAge, cfg.MaxPasswordAge, cfg.MinPasswordLen)

	_, err := h.runPowerShellSingle(ctx, script)
	if err != nil {
		addResult(result, "Password Policy", "Configure password policy via secedit", false, "", err.Error())
	} else {
		addResult(result, "Password Policy", fmt.Sprintf("Set: max_age=%d, min_age=%d, min_length=%d, complexity=on, history=24",
			cfg.MaxPasswordAge, cfg.MinPasswordAge, cfg.MinPasswordLen), true, "", "")
		addResult(result, "Password Policy", "Set: lockout=5 attempts, duration=30 min", true, "", "")
		fmt.Printf("  ✓ Password policy configured\n")
		fmt.Printf("  ✓ Account lockout policy configured\n")
	}
}

func applyLocalSecurityPolicies(ctx context.Context, h *Hardener, result *BaselineResult) {
	policies := []struct {
		name   string
		script string
	}{
		{
			"Require Ctrl+Alt+Del for login",
			`Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0 -Type DWord -Force`,
		},
		{
			"Don't display last username",
			`Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1 -Type DWord -Force`,
		},
		{
			"Enable UAC",
			`Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord -Force`,
		},
		{
			"UAC prompt for elevation on secure desktop",
			`Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force`,
		},
		{
			"UAC admin approval mode",
			`Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -Force`,
		},
		{
			"Limit blank password console only",
			`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Type DWord -Force`,
		},
		{
			"Disable anonymous enumeration of SAM",
			`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force`,
		},
		{
			"Disable anonymous enumeration of shares",
			`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord -Force`,
		},
		{
			"Do not store LAN Manager hash",
			`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Type DWord -Force`,
		},
		{
			"LAN Manager authentication level (NTLMv2 only)",
			`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force`,
		},
	}

	for _, policy := range policies {
		_, err := h.runPowerShellSingle(ctx, policy.script)
		if err != nil {
			addResult(result, "Security Policy", policy.name, false, "", err.Error())
		} else {
			addResult(result, "Security Policy", policy.name, true, "", "")
			fmt.Printf("  ✓ %s\n", policy.name)
		}
	}
}

func enableWindowsFirewall(ctx context.Context, h *Hardener, result *BaselineResult) {
	script := `
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
Set-NetFirewallProfile -Profile Domain,Public,Private -LogMaxSizeKilobytes 16384
Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True
`
	_, err := h.runPowerShellSingle(ctx, script)
	if err != nil {
		addResult(result, "Firewall", "Enable Windows Firewall (all profiles)", false, "", err.Error())
	} else {
		addResult(result, "Firewall", "Enabled for all profiles, default deny inbound, logging enabled", true, "", "")
		fmt.Printf("  ✓ Windows Firewall enabled (all profiles)\n")
	}
}

func disableWindowsGuest(ctx context.Context, h *Hardener, result *BaselineResult) {
	script := `
Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
# Also disable Administrator account if not the only admin
# Get-LocalUser -Name "Administrator" | Disable-LocalUser -ErrorAction SilentlyContinue
`
	_, err := h.runPowerShellSingle(ctx, script)
	if err != nil {
		addResult(result, "Guest Account", "Disable Guest account", false, "", err.Error())
	} else {
		addResult(result, "Guest Account", "Disabled Guest account", true, "", "")
		fmt.Printf("  ✓ Guest account disabled\n")
	}
}

func configureAuditPolicies(ctx context.Context, h *Hardener, result *BaselineResult) {
	script := `
# Enable comprehensive auditing
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
`
	_, err := h.runPowerShellSingle(ctx, script)
	if err != nil {
		addResult(result, "Audit Policy", "Configure audit policies", false, "", err.Error())
	} else {
		addResult(result, "Audit Policy", "Enabled auditing for all categories (success/failure)", true, "", "")
		fmt.Printf("  ✓ Audit policies configured\n")
	}
}

func disableUnnecessaryServices(ctx context.Context, h *Hardener, cfg BaselineConfig, result *BaselineResult) {
	// Map of service names to required service IDs they belong to
	serviceMapping := map[string]string{
		"RemoteRegistry": "",              // Always disable
		"TapiSrv":        "telnet",        // Telephony
		"RpcLocator":     "",              // Always disable
		"SNMPTRAP":       "snmp",          // SNMP
		"SNMP":           "snmp",          // SNMP
		"Fax":            "",              // Always disable (rarely needed)
		"XblAuthManager": "",              // Xbox services
		"XblGameSave":    "",              // Xbox services
		"XboxNetApiSvc":  "",              // Xbox services
		"WMPNetworkSvc":  "",              // Windows Media sharing
		"icssvc":         "",              // Windows Mobile Hotspot
		"TermService":    "rdp",           // Remote Desktop
		"SessionEnv":     "rdp",           // Remote Desktop
		"UmRdpService":   "rdp",           // Remote Desktop
		"W3SVC":          "iis",           // IIS Web Server
		"IISADMIN":       "iis",           // IIS Admin
		"ftpsvc":         "ftp",           // FTP Service
		"MSFTPSVC":       "ftp",           // FTP Service
		"LanmanServer":   "smb",           // File sharing (SMB)
		"sshd":           "ssh",           // OpenSSH Server
		"MSSQLSERVER":    "sql",           // SQL Server
		"MySQL":          "mysql",         // MySQL
		"MySQL80":        "mysql",         // MySQL 8.0
		"Spooler":        "print",         // Print Spooler
		"DNS":            "dns",           // DNS Server
		"DHCPServer":     "dhcp",          // DHCP Server
		"TelnetServer":   "telnet",        // Telnet
		"WinRM":          "winrm",         // WinRM
		"vmms":           "hyperv",        // Hyper-V
	}

	// Always disable these (no required service option)
	alwaysDisable := []string{
		"RemoteRegistry",
		"RpcLocator",
		"Fax",
		"XblAuthManager",
		"XblGameSave",
		"XboxNetApiSvc",
		"WMPNetworkSvc",
		"icssvc",
	}

	// Disable always-disable services
	for _, svc := range alwaysDisable {
		disableWindowsService(ctx, h, result, svc)
	}

	// Conditionally disable services based on required list
	conditionalServices := []struct {
		service  string
		requires string
		desc     string
	}{
		{"SNMPTRAP", "snmp", "SNMP Trap"},
		{"SNMP", "snmp", "SNMP Service"},
		{"TelnetServer", "telnet", "Telnet Server"},
		{"TapiSrv", "telnet", "Telephony"},
	}

	for _, cs := range conditionalServices {
		if !isServiceRequired(cfg.RequiredServices, cs.requires) {
			disableWindowsService(ctx, h, result, cs.service)
		} else {
			addSkipped(result, "Services", fmt.Sprintf("Disable %s", cs.desc), fmt.Sprintf("%s is required", cs.requires))
		}
	}

	// Note: We don't auto-disable RDP, SMB, FTP, IIS, SQL, etc. - those are handled
	// by the service selection. The user explicitly chose what's required.
	_ = serviceMapping // For documentation purposes
}

func disableWindowsService(ctx context.Context, h *Hardener, result *BaselineResult, svc string) {
	script := fmt.Sprintf(`
$svc = Get-Service -Name "%s" -ErrorAction SilentlyContinue
if ($svc) {
    Stop-Service -Name "%s" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "%s" -StartupType Disabled -ErrorAction SilentlyContinue
    "Disabled"
} else {
    "NotFound"
}
`, svc, svc, svc)

	output, err := h.runPowerShellSingle(ctx, script)
	output = strings.TrimSpace(output)

	if output == "NotFound" {
		// Don't report services that don't exist
		return
	}

	if err != nil {
		addResult(result, "Services", fmt.Sprintf("Disable %s", svc), false, "", err.Error())
	} else {
		addResult(result, "Services", fmt.Sprintf("Disabled %s", svc), true, "", "")
		fmt.Printf("  ✓ Disabled %s\n", svc)
	}
}

func configureWindowsDefender(ctx context.Context, h *Hardener, result *BaselineResult) {
	script := `
# Enable Windows Defender features
Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue
Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue

# Enable SmartScreen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
`
	_, err := h.runPowerShellSingle(ctx, script)
	if err != nil {
		addResult(result, "Windows Defender", "Configure Windows Defender", false, "", err.Error())
	} else {
		addResult(result, "Windows Defender", "Enabled real-time protection, behavior monitoring, SmartScreen", true, "", "")
		fmt.Printf("  ✓ Windows Defender configured\n")
	}
}

func applyRegistryHardening(ctx context.Context, h *Hardener, cfg BaselineConfig, result *BaselineResult) {
	// Always apply these policies
	alwaysPolicies := []struct {
		name   string
		script string
	}{
		{
			"Disable AutoPlay (all drives)",
			`Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force`,
		},
		{
			"Disable AutoRun",
			`Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Type DWord -Force`,
		},
		{
			"Clear page file at shutdown",
			`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1 -Type DWord -Force`,
		},
		{
			"Disable Windows Script Host",
			`Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue`,
		},
		{
			"Disable WDigest (prevent cleartext passwords in memory)",
			`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord -Force`,
		},
		{
			"Enable SEHOP",
			`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue`,
		},
	}

	for _, policy := range alwaysPolicies {
		_, err := h.runPowerShellSingle(ctx, policy.script)
		if err != nil {
			addResult(result, "Registry", policy.name, false, "", err.Error())
		} else {
			addResult(result, "Registry", policy.name, true, "", "")
			fmt.Printf("  ✓ %s\n", policy.name)
		}
	}

	// RDP-specific settings - only apply if RDP is NOT required
	if !isServiceRequired(cfg.RequiredServices, "rdp") {
		_, err := h.runPowerShellSingle(ctx, `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Type DWord -Force`)
		if err != nil {
			addResult(result, "Registry", "Disable Remote Desktop", false, "", err.Error())
		} else {
			addResult(result, "Registry", "Disabled Remote Desktop (not required)", true, "", "")
			fmt.Printf("  ✓ Disabled Remote Desktop\n")
		}
	} else {
		// RDP is required - enable NLA for security
		_, err := h.runPowerShellSingle(ctx, `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Type DWord -Force`)
		if err != nil {
			addResult(result, "Registry", "Enable NLA for Remote Desktop", false, "", err.Error())
		} else {
			addResult(result, "Registry", "Enabled NLA for Remote Desktop (required service)", true, "", "")
			fmt.Printf("  ✓ Enabled NLA for Remote Desktop\n")
		}
		addSkipped(result, "Registry", "Disable Remote Desktop", "RDP marked as required")
	}
}

func applyServerHardening(ctx context.Context, h *Hardener, result *BaselineResult) {
	// Server-specific hardening measures
	policies := []struct {
		name   string
		script string
	}{
		{
			"Disable Server Manager auto-start",
			`Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ServerManager" -Name "DoNotOpenServerManagerAtLogon" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue`,
		},
		{
			"Disable IE Enhanced Security for Admins",
			`Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue`,
		},
		{
			"Enable LDAP signing (if DC)",
			`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue`,
		},
	}

	for _, policy := range policies {
		_, err := h.runPowerShellSingle(ctx, policy.script)
		if err != nil {
			addResult(result, "Server Hardening", policy.name, false, "", err.Error())
		} else {
			addResult(result, "Server Hardening", policy.name, true, "", "")
			fmt.Printf("  ✓ %s\n", policy.name)
		}
	}
}

func hardenSMB(ctx context.Context, h *Hardener, result *BaselineResult) {
	script := `
# Disable SMB v1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue

# Enable SMB signing
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue

# Enable SMB encryption (Windows 8+/Server 2012+)
Set-SmbServerConfiguration -EncryptData $true -Force -ErrorAction SilentlyContinue
`
	_, err := h.runPowerShellSingle(ctx, script)
	if err != nil {
		addResult(result, "SMB", "Harden SMB (disable v1, enable signing/encryption)", false, "", err.Error())
	} else {
		addResult(result, "SMB", "Disabled SMBv1, enabled signing and encryption", true, "", "")
		fmt.Printf("  ✓ SMB hardened (v1 disabled, signing/encryption enabled)\n")
	}
}

// Ensure the package compiles on Windows even without exec
var _ = exec.Command

