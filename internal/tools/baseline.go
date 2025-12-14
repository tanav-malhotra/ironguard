package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
)

// BaselineExecutor interface for running baseline hardening.
type BaselineExecutor interface {
	RunBaselineSection(ctx context.Context, section string, config BaselineToolConfig) (string, error)
	GetAvailableSections() []BaselineSectionInfo
}

// BaselineToolConfig holds configuration for AI-driven baseline execution.
type BaselineToolConfig struct {
	// Password Policy
	MaxPasswordAge  int `json:"max_password_age"`
	MinPasswordAge  int `json:"min_password_age"`
	PasswordWarnAge int `json:"password_warn_age"`
	MinPasswordLen  int `json:"min_password_len"`

	// Network
	DisableIPv6 bool `json:"disable_ipv6"`

	// Required Services - these will NOT be disabled
	RequiredServices []string `json:"required_services"`
}

// BaselineSectionInfo describes a baseline section for AI understanding.
type BaselineSectionInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Actions     []string `json:"actions"`
	Reversible  bool     `json:"reversible"`
	SafeForFQ   bool     `json:"safe_for_forensics"` // Won't affect forensic questions
}

var globalBaselineExecutor BaselineExecutor

// SetBaselineExecutor sets the global baseline executor.
func SetBaselineExecutor(e BaselineExecutor) {
	globalBaselineExecutor = e
}

// RegisterBaselineTools adds baseline-related tools to the registry.
func (r *Registry) RegisterBaselineTools() {
	// Tool to run specific baseline sections
	r.Register(&Tool{
		Name: "run_baseline_section",
		Description: `Execute a specific baseline hardening section. Use this to apply security configurations.

IMPORTANT: Before running ANY section, consider:
1. Have forensic questions been answered? Some sections modify system state.
2. Does the README require any services that this section might affect?
3. Are you sure this won't conflict with image requirements?

Sections are designed to be safe, but you should still verify against README first.
Use 'list_baseline_sections' to see all available sections and what they do.`,
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"section": map[string]interface{}{
					"type":        "string",
					"description": "The section ID to run (e.g., 'password_policy', 'firewall', 'audit_policy')",
				},
				"required_services": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Services that are REQUIRED by the README and should NOT be disabled (e.g., ['ssh', 'apache', 'mysql'])",
				},
				"max_password_age": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum password age in days (default: 30)",
					"default":     30,
				},
				"min_password_age": map[string]interface{}{
					"type":        "integer",
					"description": "Minimum password age in days (default: 1)",
					"default":     1,
				},
				"min_password_len": map[string]interface{}{
					"type":        "integer",
					"description": "Minimum password length (default: 12)",
					"default":     12,
				},
				"disable_ipv6": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether to disable IPv6 (default: false, only set true if README allows)",
					"default":     false,
				},
			},
			"required": []string{"section"},
		},
		Handler:  toolRunBaselineSection,
		Mutating: true,
	})

	// Tool to list available sections and what they do
	r.Register(&Tool{
		Name: "list_baseline_sections",
		Description: `List all available baseline hardening sections with detailed descriptions.
Each section shows:
- What actions it performs
- Whether it's reversible
- Whether it's safe for forensic questions (won't destroy evidence)

Use this to understand exactly what each section does before running it.`,
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler:  toolListBaselineSections,
		Mutating: false,
	})

	// Tool to run all safe baseline sections at once
	r.Register(&Tool{
		Name: "run_baseline_safe",
		Description: `Run all baseline sections that are SAFE for forensic questions.
This runs sections that won't modify files, logs, or other evidence needed for forensics.

Safe sections include: password policy, audit policy, firewall, security settings.
Skips: service disabling, file permission changes, anything that might affect evidence.

Use this after answering forensic questions, or if you're confident forensics don't
depend on system state.`,
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"required_services": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Services that are REQUIRED by the README",
				},
			},
		},
		Handler:  toolRunBaselineSafe,
		Mutating: true,
	})

	// Tool to run full baseline (all sections)
	r.Register(&Tool{
		Name: "run_baseline_full",
		Description: `Run the FULL baseline hardening script with all sections.
⚠️ WARNING: This modifies many system settings. Only use when:
1. All forensic questions have been answered
2. You have identified all required services from README
3. You are ready to apply comprehensive hardening

This is equivalent to the user running '/baseline' command.`,
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"required_services": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Services that are REQUIRED by the README - CRITICAL to specify correctly!",
				},
				"disable_ipv6": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether to disable IPv6 (default: false)",
					"default":     false,
				},
			},
			"required": []string{"required_services"},
		},
		Handler:  toolRunBaselineFull,
		Mutating: true,
	})
}

func toolRunBaselineSection(ctx context.Context, args json.RawMessage) (string, error) {
	if globalBaselineExecutor == nil {
		return "", fmt.Errorf("baseline executor not initialized")
	}

	var params struct {
		Section          string   `json:"section"`
		RequiredServices []string `json:"required_services"`
		MaxPasswordAge   int      `json:"max_password_age"`
		MinPasswordAge   int      `json:"min_password_age"`
		MinPasswordLen   int      `json:"min_password_len"`
		DisableIPv6      bool     `json:"disable_ipv6"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	// Set defaults
	if params.MaxPasswordAge == 0 {
		params.MaxPasswordAge = 30
	}
	if params.MinPasswordAge == 0 {
		params.MinPasswordAge = 1
	}
	if params.MinPasswordLen == 0 {
		params.MinPasswordLen = 12
	}

	config := BaselineToolConfig{
		MaxPasswordAge:   params.MaxPasswordAge,
		MinPasswordAge:   params.MinPasswordAge,
		MinPasswordLen:   params.MinPasswordLen,
		DisableIPv6:      params.DisableIPv6,
		RequiredServices: params.RequiredServices,
	}

	result, err := globalBaselineExecutor.RunBaselineSection(ctx, params.Section, config)
	if err != nil {
		return "", fmt.Errorf("failed to run section '%s': %w", params.Section, err)
	}

	return result, nil
}

func toolListBaselineSections(ctx context.Context, args json.RawMessage) (string, error) {
	sections := getBaselineSections()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Baseline Hardening Sections (%s) ===\n\n", runtime.GOOS))

	for _, section := range sections {
		sb.WriteString(fmt.Sprintf("📦 [%s] %s\n", section.ID, section.Name))
		sb.WriteString(fmt.Sprintf("   %s\n", section.Description))
		sb.WriteString("   Actions:\n")
		for _, action := range section.Actions {
			sb.WriteString(fmt.Sprintf("     • %s\n", action))
		}
		if section.Reversible {
			sb.WriteString("   ✅ Reversible: Yes\n")
		} else {
			sb.WriteString("   ⚠️ Reversible: No (or difficult)\n")
		}
		if section.SafeForFQ {
			sb.WriteString("   🔍 Safe for Forensics: Yes\n")
		} else {
			sb.WriteString("   ⚠️ Safe for Forensics: May affect evidence\n")
		}
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

func toolRunBaselineSafe(ctx context.Context, args json.RawMessage) (string, error) {
	if globalBaselineExecutor == nil {
		return "", fmt.Errorf("baseline executor not initialized")
	}

	var params struct {
		RequiredServices []string `json:"required_services"`
	}
	json.Unmarshal(args, &params)

	config := BaselineToolConfig{
		MaxPasswordAge:   30,
		MinPasswordAge:   1,
		MinPasswordLen:   12,
		RequiredServices: params.RequiredServices,
	}

	sections := getBaselineSections()
	var results []string

	for _, section := range sections {
		if section.SafeForFQ {
			result, err := globalBaselineExecutor.RunBaselineSection(ctx, section.ID, config)
			if err != nil {
				results = append(results, fmt.Sprintf("❌ [%s] Failed: %v", section.ID, err))
			} else {
				results = append(results, fmt.Sprintf("✅ [%s] %s", section.ID, result))
			}
		}
	}

	return fmt.Sprintf("=== Safe Baseline Sections Complete ===\n\n%s", strings.Join(results, "\n")), nil
}

func toolRunBaselineFull(ctx context.Context, args json.RawMessage) (string, error) {
	if globalBaselineExecutor == nil {
		return "", fmt.Errorf("baseline executor not initialized")
	}

	var params struct {
		RequiredServices []string `json:"required_services"`
		DisableIPv6      bool     `json:"disable_ipv6"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	config := BaselineToolConfig{
		MaxPasswordAge:   30,
		MinPasswordAge:   1,
		MinPasswordLen:   12,
		DisableIPv6:      params.DisableIPv6,
		RequiredServices: params.RequiredServices,
	}

	sections := getBaselineSections()
	var results []string

	for _, section := range sections {
		result, err := globalBaselineExecutor.RunBaselineSection(ctx, section.ID, config)
		if err != nil {
			results = append(results, fmt.Sprintf("❌ [%s] Failed: %v", section.ID, err))
		} else {
			results = append(results, fmt.Sprintf("✅ [%s] %s", section.ID, result))
		}
	}

	return fmt.Sprintf("=== Full Baseline Complete ===\n\nRequired Services (not touched): %v\nIPv6 Disabled: %v\n\nResults:\n%s",
		params.RequiredServices, params.DisableIPv6, strings.Join(results, "\n")), nil
}

// getBaselineSections returns section info based on OS.
func getBaselineSections() []BaselineSectionInfo {
	if runtime.GOOS == "windows" {
		return getWindowsBaselineSections()
	}
	return getLinuxBaselineSections()
}

func getWindowsBaselineSections() []BaselineSectionInfo {
	return []BaselineSectionInfo{
		{
			ID:          "password_policy",
			Name:        "Password & Account Policy",
			Description: "Configure password complexity, length, age, and lockout settings",
			Actions: []string{
				"Set minimum password length (default: 12)",
				"Set maximum password age (default: 30 days)",
				"Set minimum password age (default: 1 day)",
				"Enable password complexity requirements",
				"Set password history to 24",
				"Set account lockout: 5 attempts, 30 min duration",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
		{
			ID:          "local_security",
			Name:        "Local Security Policies",
			Description: "Apply local security settings via registry",
			Actions: []string{
				"Require Ctrl+Alt+Del for login",
				"Don't display last username",
				"Enable UAC",
				"UAC prompt on secure desktop",
				"Limit blank password use",
				"Disable anonymous enumeration of SAM/shares",
				"Don't store LAN Manager hash",
				"Set NTLMv2 only authentication",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
		{
			ID:          "firewall",
			Name:        "Windows Firewall",
			Description: "Enable and configure Windows Firewall",
			Actions: []string{
				"Enable firewall for all profiles (Domain, Public, Private)",
				"Set default inbound action to Block",
				"Set default outbound action to Allow",
				"Enable firewall logging",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
		{
			ID:          "guest_account",
			Name:        "Disable Guest Account",
			Description: "Disable the built-in Guest account",
			Actions: []string{
				"Disable Guest local account",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
		{
			ID:          "audit_policy",
			Name:        "Audit Policies",
			Description: "Enable comprehensive audit logging",
			Actions: []string{
				"Enable Account Logon auditing (success/failure)",
				"Enable Account Management auditing",
				"Enable Logon/Logoff auditing",
				"Enable Object Access auditing",
				"Enable Policy Change auditing",
				"Enable Privilege Use auditing",
				"Enable System auditing",
				"Enable Detailed Tracking auditing",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
		{
			ID:          "services",
			Name:        "Disable Unnecessary Services",
			Description: "Stop and disable services not required by README",
			Actions: []string{
				"Disable RemoteRegistry, RpcLocator, Fax",
				"Disable Xbox services, WMPNetworkSvc",
				"Disable SNMP/Telnet (if not required)",
				"Respects required_services parameter",
			},
			Reversible: true,
			SafeForFQ:  false, // Could affect running services
		},
		{
			ID:          "defender",
			Name:        "Windows Defender",
			Description: "Configure Windows Defender settings",
			Actions: []string{
				"Enable real-time protection",
				"Enable behavior monitoring",
				"Enable script scanning",
				"Enable PUA protection",
				"Enable SmartScreen",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
		{
			ID:          "registry",
			Name:        "Registry Hardening",
			Description: "Apply security settings via registry",
			Actions: []string{
				"Disable AutoPlay/AutoRun (all drives)",
				"Clear page file at shutdown",
				"Disable Windows Script Host",
				"Disable WDigest",
				"Enable SEHOP",
				"Disable/harden RDP (if not required)",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
		{
			ID:          "smb",
			Name:        "SMB Hardening",
			Description: "Harden SMB configuration (if SMB not required)",
			Actions: []string{
				"Disable SMBv1",
				"Enable SMB signing",
				"Enable SMB encryption",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
		{
			ID:          "additional_security",
			Name:        "Additional Security Settings",
			Description: "Commonly scored CyberPatriot settings",
			Actions: []string{
				"Enable FIPS compliant algorithms",
				"Disable downloading print drivers over HTTP",
				"Enable Shell protocol protected mode",
				"Prevent users from installing printer drivers",
				"Require logon to shutdown system",
				"Security prompt for web-based Windows installer",
				"Disable WinRM (if not required)",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
		{
			ID:          "critical_services",
			Name:        "Ensure Critical Services",
			Description: "Ensure security services are running",
			Actions: []string{
				"Enable Windows Event Log (automatic)",
				"Enable Windows Defender Firewall service",
				"Enable Windows Defender Antivirus",
				"Enable Security Center",
				"Enable Windows Update",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
	}
}

func getLinuxBaselineSections() []BaselineSectionInfo {
	return []BaselineSectionInfo{
		{
			ID:          "password_policy",
			Name:        "Password Policy",
			Description: "Configure PAM and login.defs for password requirements",
			Actions: []string{
				"Set PASS_MAX_DAYS (default: 30)",
				"Set PASS_MIN_DAYS (default: 1)",
				"Set PASS_WARN_AGE (default: 7)",
				"Configure PAM pwquality (minlen, complexity)",
				"Enable password history",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
		{
			ID:          "kernel",
			Name:        "Kernel Hardening (sysctl)",
			Description: "Apply sysctl security settings",
			Actions: []string{
				"Disable IP forwarding",
				"Disable ICMP redirects",
				"Enable TCP SYN cookies",
				"Enable reverse path filtering",
				"Enable ASLR (randomize_va_space=2)",
				"Log martian packets",
				"Optionally disable IPv6",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
		{
			ID:          "firewall",
			Name:        "Firewall (UFW/firewalld)",
			Description: "Enable and configure firewall",
			Actions: []string{
				"Install UFW or use firewalld",
				"Enable firewall",
				"Set default deny incoming",
				"Set default allow outgoing",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
		{
			ID:          "auditd",
			Name:        "Auditd (System Auditing)",
			Description: "Install and configure auditd",
			Actions: []string{
				"Install auditd package",
				"Enable auditd service",
				"Add rules for /etc/passwd, /etc/shadow, /etc/group",
				"Add rules for /etc/sudoers",
				"Add rules for command execution",
			},
			Reversible: true,
			SafeForFQ:  false, // Starts logging which could create evidence
		},
		{
			ID:          "apparmor",
			Name:        "AppArmor (MAC)",
			Description: "Install and enable AppArmor (Debian-based)",
			Actions: []string{
				"Install apparmor and apparmor-utils",
				"Enable apparmor service",
				"Enforce existing profiles",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
		{
			ID:          "fail2ban",
			Name:        "Fail2ban (Brute Force Protection)",
			Description: "Install and configure fail2ban",
			Actions: []string{
				"Install fail2ban package",
				"Enable fail2ban service",
				"Configure SSH jail",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
		{
			ID:          "services",
			Name:        "Disable Unnecessary Services",
			Description: "Stop and disable services not required by README",
			Actions: []string{
				"Disable Apache/httpd, Nginx (if not required)",
				"Disable MySQL/MariaDB/PostgreSQL (if not required)",
				"Disable Samba/NFS (if not required)",
				"Disable FTP servers (if not required)",
				"Disable SSH (if not required) or harden it",
				"Disable Avahi, rsh, telnet, tftp",
			},
			Reversible: true,
			SafeForFQ:  false, // Stopping services could affect evidence
		},
		{
			ID:          "guest",
			Name:        "Disable Guest Account",
			Description: "Disable guest login in display managers",
			Actions: []string{
				"Disable guest in LightDM",
				"Disable guest in GDM3",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
		{
			ID:          "permissions",
			Name:        "Secure File Permissions",
			Description: "Set secure permissions on critical files",
			Actions: []string{
				"chmod 644 /etc/passwd",
				"chmod 640 /etc/shadow",
				"chmod 644 /etc/group",
				"chmod 440 /etc/sudoers",
				"chmod 700 /root",
			},
			Reversible: true,
			SafeForFQ:  false, // Could affect file access evidence
		},
		{
			ID:          "ctrl_alt_del",
			Name:        "Disable Ctrl+Alt+Del",
			Description: "Prevent reboot via Ctrl+Alt+Del",
			Actions: []string{
				"Mask ctrl-alt-del.target",
			},
			Reversible: true,
			SafeForFQ:  true,
		},
	}
}

