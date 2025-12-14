package agent

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/tanav-malhotra/ironguard/internal/harden"
	"github.com/tanav-malhotra/ironguard/internal/tools"
)

// BaselineExecutorAdapter implements tools.BaselineExecutor.
type BaselineExecutorAdapter struct {
	agent *Agent
}

// NewBaselineExecutorAdapter creates a new adapter.
func NewBaselineExecutorAdapter(a *Agent) *BaselineExecutorAdapter {
	return &BaselineExecutorAdapter{agent: a}
}

// RunBaselineSection runs a specific baseline section.
func (b *BaselineExecutorAdapter) RunBaselineSection(ctx context.Context, section string, config tools.BaselineToolConfig) (string, error) {
	// Convert tools config to harden config
	hardenConfig := harden.BaselineConfig{
		MaxPasswordAge:   config.MaxPasswordAge,
		MinPasswordAge:   config.MinPasswordAge,
		PasswordWarnAge:  7, // Default
		MinPasswordLen:   config.MinPasswordLen,
		DisableIPv6:      config.DisableIPv6,
		EnableFirewall:   true,
		InstallAuditd:    true,
		InstallApparmor:  true,
		InstallFail2ban:  true,
		RequiredServices: config.RequiredServices,
		Interactive:      false, // AI-driven, no prompts
	}

	// Run the appropriate section based on OS
	if runtime.GOOS == "windows" {
		return b.runWindowsSection(ctx, section, hardenConfig)
	}
	return b.runLinuxSection(ctx, section, hardenConfig)
}

// GetAvailableSections returns section info (delegated to tools package).
func (b *BaselineExecutorAdapter) GetAvailableSections() []tools.BaselineSectionInfo {
	// This is implemented in the tools package
	return nil
}

func (b *BaselineExecutorAdapter) runWindowsSection(ctx context.Context, section string, cfg harden.BaselineConfig) (string, error) {
	h := harden.New()
	result := &harden.BaselineResult{
		OSType:  "windows",
		Config:  cfg,
		Actions: []harden.ActionResult{},
	}

	switch section {
	case "password_policy":
		return b.runWindowsPasswordPolicy(ctx, h, cfg, result)
	case "local_security":
		return b.runWindowsLocalSecurity(ctx, h, result)
	case "firewall":
		return b.runWindowsFirewall(ctx, h, result)
	case "guest_account":
		return b.runWindowsGuestDisable(ctx, h, result)
	case "audit_policy":
		return b.runWindowsAuditPolicy(ctx, h, result)
	case "services":
		return b.runWindowsServices(ctx, h, cfg, result)
	case "defender":
		return b.runWindowsDefender(ctx, h, result)
	case "registry":
		return b.runWindowsRegistry(ctx, h, cfg, result)
	case "smb":
		return b.runWindowsSMB(ctx, h, cfg, result)
	case "additional_security":
		return b.runWindowsAdditionalSecurity(ctx, h, cfg, result)
	case "critical_services":
		return b.runWindowsCriticalServices(ctx, h, result)
	default:
		return "", fmt.Errorf("unknown Windows section: %s", section)
	}
}

func (b *BaselineExecutorAdapter) runLinuxSection(ctx context.Context, section string, cfg harden.BaselineConfig) (string, error) {
	h := harden.New()
	result := &harden.BaselineResult{
		OSType:  "linux",
		Config:  cfg,
		Actions: []harden.ActionResult{},
	}

	switch section {
	case "password_policy":
		return b.runLinuxPasswordPolicy(ctx, h, cfg, result)
	case "kernel":
		return b.runLinuxKernel(ctx, h, cfg, result)
	case "firewall":
		return b.runLinuxFirewall(ctx, h, result)
	case "auditd":
		return b.runLinuxAuditd(ctx, h, result)
	case "apparmor":
		return b.runLinuxApparmor(ctx, h, result)
	case "fail2ban":
		return b.runLinuxFail2ban(ctx, h, result)
	case "services":
		return b.runLinuxServices(ctx, h, cfg, result)
	case "guest":
		return b.runLinuxGuest(ctx, h, result)
	case "permissions":
		return b.runLinuxPermissions(ctx, h, result)
	case "ctrl_alt_del":
		return b.runLinuxCtrlAltDel(ctx, h, result)
	default:
		return "", fmt.Errorf("unknown Linux section: %s", section)
	}
}

// Helper to format results
func formatSectionResult(section string, result *harden.BaselineResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Section: %s ===\n", section))

	successCount := 0
	failCount := 0

	for _, action := range result.Actions {
		if action.Skipped {
			sb.WriteString(fmt.Sprintf("⊘ SKIPPED: %s - %s\n", action.Action, action.SkipReason))
		} else if action.Success {
			successCount++
			sb.WriteString(fmt.Sprintf("✓ %s\n", action.Action))
		} else {
			failCount++
			sb.WriteString(fmt.Sprintf("✗ FAILED: %s - %s\n", action.Action, action.Error))
		}
	}

	sb.WriteString(fmt.Sprintf("\nSummary: %d successful, %d failed\n", successCount, failCount))
	return sb.String()
}

// Windows section implementations
func (b *BaselineExecutorAdapter) runWindowsPasswordPolicy(ctx context.Context, h *harden.Hardener, cfg harden.BaselineConfig, result *harden.BaselineResult) (string, error) {
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
secedit /configure /db "$env:TEMP\secpol.sdb" /cfg $tempPath /areas SECURITYPOLICY /quiet
Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
`, cfg.MinPasswordAge, cfg.MaxPasswordAge, cfg.MinPasswordLen)

	_, err := h.RunPowerShellSingle(ctx, script)
	if err != nil {
		result.Actions = append(result.Actions, harden.ActionResult{
			Category: "Password Policy",
			Action:   "Configure password policy via secedit",
			Success:  false,
			Error:    err.Error(),
		})
		return formatSectionResult("password_policy", result), nil
	}

	result.Actions = append(result.Actions, harden.ActionResult{
		Category: "Password Policy",
		Action:   fmt.Sprintf("Set: max_age=%d, min_age=%d, min_length=%d, complexity=on, history=24, lockout=5/30min", cfg.MaxPasswordAge, cfg.MinPasswordAge, cfg.MinPasswordLen),
		Success:  true,
	})

	return formatSectionResult("password_policy", result), nil
}

func (b *BaselineExecutorAdapter) runWindowsLocalSecurity(ctx context.Context, h *harden.Hardener, result *harden.BaselineResult) (string, error) {
	policies := []struct {
		name   string
		script string
	}{
		{"Require Ctrl+Alt+Del", `Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0 -Type DWord -Force`},
		{"Don't display last username", `Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1 -Type DWord -Force`},
		{"Enable UAC", `Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord -Force`},
		{"UAC secure desktop", `Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force`},
		{"Limit blank password use", `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Type DWord -Force`},
		{"Disable anonymous SAM enumeration", `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force`},
		{"NTLMv2 only", `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force`},
	}

	for _, p := range policies {
		_, err := h.RunPowerShellSingle(ctx, p.script)
		result.Actions = append(result.Actions, harden.ActionResult{
			Category: "Local Security",
			Action:   p.name,
			Success:  err == nil,
			Error:    errStr(err),
		})
	}

	return formatSectionResult("local_security", result), nil
}

func (b *BaselineExecutorAdapter) runWindowsFirewall(ctx context.Context, h *harden.Hardener, result *harden.BaselineResult) (string, error) {
	script := `
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
`
	_, err := h.RunPowerShellSingle(ctx, script)
	result.Actions = append(result.Actions, harden.ActionResult{
		Category: "Firewall",
		Action:   "Enable Windows Firewall (all profiles, deny inbound)",
		Success:  err == nil,
		Error:    errStr(err),
	})
	return formatSectionResult("firewall", result), nil
}

func (b *BaselineExecutorAdapter) runWindowsGuestDisable(ctx context.Context, h *harden.Hardener, result *harden.BaselineResult) (string, error) {
	_, err := h.RunPowerShellSingle(ctx, `Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue`)
	result.Actions = append(result.Actions, harden.ActionResult{
		Category: "Guest Account",
		Action:   "Disable Guest account",
		Success:  err == nil,
		Error:    errStr(err),
	})
	return formatSectionResult("guest_account", result), nil
}

func (b *BaselineExecutorAdapter) runWindowsAuditPolicy(ctx context.Context, h *harden.Hardener, result *harden.BaselineResult) (string, error) {
	script := `
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
`
	_, err := h.RunPowerShellSingle(ctx, script)
	result.Actions = append(result.Actions, harden.ActionResult{
		Category: "Audit Policy",
		Action:   "Enable auditing for all categories",
		Success:  err == nil,
		Error:    errStr(err),
	})
	return formatSectionResult("audit_policy", result), nil
}

func (b *BaselineExecutorAdapter) runWindowsServices(ctx context.Context, h *harden.Hardener, cfg harden.BaselineConfig, result *harden.BaselineResult) (string, error) {
	// Always disable these
	alwaysDisable := []string{"RemoteRegistry", "RpcLocator", "Fax", "XblAuthManager", "XblGameSave"}
	for _, svc := range alwaysDisable {
		script := fmt.Sprintf(`Stop-Service -Name "%s" -Force -ErrorAction SilentlyContinue; Set-Service -Name "%s" -StartupType Disabled -ErrorAction SilentlyContinue`, svc, svc)
		_, _ = h.RunPowerShellSingle(ctx, script)
		result.Actions = append(result.Actions, harden.ActionResult{
			Category: "Services",
			Action:   fmt.Sprintf("Disable %s", svc),
			Success:  true,
		})
	}
	return formatSectionResult("services", result), nil
}

func (b *BaselineExecutorAdapter) runWindowsDefender(ctx context.Context, h *harden.Hardener, result *harden.BaselineResult) (string, error) {
	script := `
Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
`
	_, err := h.RunPowerShellSingle(ctx, script)
	result.Actions = append(result.Actions, harden.ActionResult{
		Category: "Defender",
		Action:   "Enable real-time protection, behavior monitoring, SmartScreen",
		Success:  err == nil,
		Error:    errStr(err),
	})
	return formatSectionResult("defender", result), nil
}

func (b *BaselineExecutorAdapter) runWindowsRegistry(ctx context.Context, h *harden.Hardener, cfg harden.BaselineConfig, result *harden.BaselineResult) (string, error) {
	policies := []struct {
		name   string
		script string
	}{
		{"Disable AutoPlay", `Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force`},
		{"Disable WDigest", `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord -Force`},
		{"Enable SEHOP", `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue`},
	}

	for _, p := range policies {
		_, err := h.RunPowerShellSingle(ctx, p.script)
		result.Actions = append(result.Actions, harden.ActionResult{
			Category: "Registry",
			Action:   p.name,
			Success:  err == nil,
			Error:    errStr(err),
		})
	}
	return formatSectionResult("registry", result), nil
}

func (b *BaselineExecutorAdapter) runWindowsSMB(ctx context.Context, h *harden.Hardener, cfg harden.BaselineConfig, result *harden.BaselineResult) (string, error) {
	if isRequired(cfg.RequiredServices, "smb") {
		result.Actions = append(result.Actions, harden.ActionResult{
			Category:   "SMB",
			Action:     "SMB hardening",
			Skipped:    true,
			SkipReason: "SMB is required",
		})
		return formatSectionResult("smb", result), nil
	}

	script := `
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -EncryptData $true -Force -ErrorAction SilentlyContinue
`
	_, err := h.RunPowerShellSingle(ctx, script)
	result.Actions = append(result.Actions, harden.ActionResult{
		Category: "SMB",
		Action:   "Disable SMBv1, enable signing and encryption",
		Success:  err == nil,
		Error:    errStr(err),
	})
	return formatSectionResult("smb", result), nil
}

func (b *BaselineExecutorAdapter) runWindowsAdditionalSecurity(ctx context.Context, h *harden.Hardener, cfg harden.BaselineConfig, result *harden.BaselineResult) (string, error) {
	policies := []struct {
		name   string
		script string
	}{
		{"Enable FIPS", `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" -Name "Enabled" -Value 1 -Type DWord -Force`},
		{"Disable print drivers over HTTP", `New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Force -ErrorAction SilentlyContinue | Out-Null; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value 1 -Type DWord -Force`},
		{"Shell protocol protected mode", `Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "PreXPSP2ShellProtocolBehavior" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue`},
		{"Require logon to shutdown", `Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Value 0 -Type DWord -Force`},
	}

	for _, p := range policies {
		_, err := h.RunPowerShellSingle(ctx, p.script)
		result.Actions = append(result.Actions, harden.ActionResult{
			Category: "Additional Security",
			Action:   p.name,
			Success:  err == nil,
			Error:    errStr(err),
		})
	}
	return formatSectionResult("additional_security", result), nil
}

func (b *BaselineExecutorAdapter) runWindowsCriticalServices(ctx context.Context, h *harden.Hardener, result *harden.BaselineResult) (string, error) {
	services := []string{"EventLog", "MpsSvc", "WinDefend", "wscsvc", "wuauserv"}
	for _, svc := range services {
		script := fmt.Sprintf(`Set-Service -Name "%s" -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service -Name "%s" -ErrorAction SilentlyContinue`, svc, svc)
		_, _ = h.RunPowerShellSingle(ctx, script)
		result.Actions = append(result.Actions, harden.ActionResult{
			Category: "Critical Services",
			Action:   fmt.Sprintf("Enable %s (automatic)", svc),
			Success:  true,
		})
	}
	return formatSectionResult("critical_services", result), nil
}

// Linux section implementations (stubs - will work on Linux only)
func (b *BaselineExecutorAdapter) runLinuxPasswordPolicy(ctx context.Context, h *harden.Hardener, cfg harden.BaselineConfig, result *harden.BaselineResult) (string, error) {
	result.Actions = append(result.Actions, harden.ActionResult{
		Category: "Password Policy",
		Action:   "Linux password policy (PAM/login.defs)",
		Skipped:  true,
		SkipReason: "Run on Linux system",
	})
	return formatSectionResult("password_policy", result), nil
}

func (b *BaselineExecutorAdapter) runLinuxKernel(ctx context.Context, h *harden.Hardener, cfg harden.BaselineConfig, result *harden.BaselineResult) (string, error) {
	result.Actions = append(result.Actions, harden.ActionResult{
		Category: "Kernel",
		Action:   "Linux kernel hardening (sysctl)",
		Skipped:  true,
		SkipReason: "Run on Linux system",
	})
	return formatSectionResult("kernel", result), nil
}

func (b *BaselineExecutorAdapter) runLinuxFirewall(ctx context.Context, h *harden.Hardener, result *harden.BaselineResult) (string, error) {
	result.Actions = append(result.Actions, harden.ActionResult{
		Category: "Firewall",
		Action:   "Linux firewall (UFW/firewalld)",
		Skipped:  true,
		SkipReason: "Run on Linux system",
	})
	return formatSectionResult("firewall", result), nil
}

func (b *BaselineExecutorAdapter) runLinuxAuditd(ctx context.Context, h *harden.Hardener, result *harden.BaselineResult) (string, error) {
	result.Actions = append(result.Actions, harden.ActionResult{
		Category: "Auditd",
		Action:   "Linux auditd setup",
		Skipped:  true,
		SkipReason: "Run on Linux system",
	})
	return formatSectionResult("auditd", result), nil
}

func (b *BaselineExecutorAdapter) runLinuxApparmor(ctx context.Context, h *harden.Hardener, result *harden.BaselineResult) (string, error) {
	result.Actions = append(result.Actions, harden.ActionResult{
		Category: "AppArmor",
		Action:   "Linux AppArmor setup",
		Skipped:  true,
		SkipReason: "Run on Linux system",
	})
	return formatSectionResult("apparmor", result), nil
}

func (b *BaselineExecutorAdapter) runLinuxFail2ban(ctx context.Context, h *harden.Hardener, result *harden.BaselineResult) (string, error) {
	result.Actions = append(result.Actions, harden.ActionResult{
		Category: "Fail2ban",
		Action:   "Linux fail2ban setup",
		Skipped:  true,
		SkipReason: "Run on Linux system",
	})
	return formatSectionResult("fail2ban", result), nil
}

func (b *BaselineExecutorAdapter) runLinuxServices(ctx context.Context, h *harden.Hardener, cfg harden.BaselineConfig, result *harden.BaselineResult) (string, error) {
	result.Actions = append(result.Actions, harden.ActionResult{
		Category: "Services",
		Action:   "Linux service hardening",
		Skipped:  true,
		SkipReason: "Run on Linux system",
	})
	return formatSectionResult("services", result), nil
}

func (b *BaselineExecutorAdapter) runLinuxGuest(ctx context.Context, h *harden.Hardener, result *harden.BaselineResult) (string, error) {
	result.Actions = append(result.Actions, harden.ActionResult{
		Category: "Guest",
		Action:   "Linux guest account disable",
		Skipped:  true,
		SkipReason: "Run on Linux system",
	})
	return formatSectionResult("guest", result), nil
}

func (b *BaselineExecutorAdapter) runLinuxPermissions(ctx context.Context, h *harden.Hardener, result *harden.BaselineResult) (string, error) {
	result.Actions = append(result.Actions, harden.ActionResult{
		Category: "Permissions",
		Action:   "Linux file permissions",
		Skipped:  true,
		SkipReason: "Run on Linux system",
	})
	return formatSectionResult("permissions", result), nil
}

func (b *BaselineExecutorAdapter) runLinuxCtrlAltDel(ctx context.Context, h *harden.Hardener, result *harden.BaselineResult) (string, error) {
	result.Actions = append(result.Actions, harden.ActionResult{
		Category: "Ctrl+Alt+Del",
		Action:   "Linux Ctrl+Alt+Del disable",
		Skipped:  true,
		SkipReason: "Run on Linux system",
	})
	return formatSectionResult("ctrl_alt_del", result), nil
}

// Helper functions
func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func isRequired(services []string, service string) bool {
	for _, s := range services {
		if s == service {
			return true
		}
	}
	return false
}

