package harden

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// BaselineConfig holds user choices for baseline hardening.
type BaselineConfig struct {
	// Password Policy
	MaxPasswordAge  int // Default: 30
	MinPasswordAge  int // Default: 1
	PasswordWarnAge int // Default: 7
	MinPasswordLen  int // Default: 12

	// Network
	DisableIPv6    bool // Ask user - default: false (some systems need it)
	EnableFirewall bool // Default: true

	// Security Tools (Linux)
	InstallAuditd   bool // Default: true
	InstallApparmor bool // Default: true
	InstallFail2ban bool // Default: true

	// Required Services - these will NOT be disabled/hardened restrictively
	RequiredServices []string // e.g., ["ssh", "apache", "mysql"]

	// Interactive mode
	Interactive bool // If false, use all defaults
}

// LinuxServices is the list of services users can mark as required on Linux.
var LinuxServices = []ServiceOption{
	{ID: "1", Name: "ssh", Description: "SSH Server (OpenSSH)"},
	{ID: "2", Name: "apache", Description: "Apache/Apache2 Web Server (httpd)"},
	{ID: "3", Name: "nginx", Description: "Nginx Web Server"},
	{ID: "4", Name: "mysql", Description: "MySQL Database"},
	{ID: "5", Name: "mariadb", Description: "MariaDB Database"},
	{ID: "6", Name: "postgresql", Description: "PostgreSQL Database"},
	{ID: "7", Name: "ftp", Description: "FTP Server (vsftpd/proftpd)"},
	{ID: "8", Name: "samba", Description: "Samba File Sharing (SMB)"},
	{ID: "9", Name: "nfs", Description: "NFS File Sharing"},
	{ID: "10", Name: "docker", Description: "Docker Containers"},
	{ID: "11", Name: "php", Description: "PHP (with web server)"},
	{ID: "12", Name: "wordpress", Description: "WordPress"},
	{ID: "13", Name: "dns", Description: "DNS Server (BIND)"},
	{ID: "14", Name: "mail", Description: "Mail Server (Postfix/Dovecot)"},
	{ID: "15", Name: "cups", Description: "CUPS Printing"},
	{ID: "16", Name: "vnc", Description: "VNC Remote Desktop"},
	{ID: "17", Name: "xrdp", Description: "XRDP Remote Desktop"},
	{ID: "18", Name: "mongodb", Description: "MongoDB Database"},
	{ID: "19", Name: "redis", Description: "Redis Cache"},
	{ID: "20", Name: "tomcat", Description: "Apache Tomcat"},
	{ID: "21", Name: "squid", Description: "Squid Proxy"},
	{ID: "22", Name: "openvpn", Description: "OpenVPN"},
	{ID: "23", Name: "wireguard", Description: "WireGuard VPN"},
	{ID: "24", Name: "ldap", Description: "LDAP Server (OpenLDAP)"},
	{ID: "25", Name: "jenkins", Description: "Jenkins CI/CD"},
}

// WindowsServices is the list of services users can mark as required on Windows.
var WindowsServices = []ServiceOption{
	{ID: "1", Name: "rdp", Description: "Remote Desktop (RDP)"},
	{ID: "2", Name: "ssh", Description: "OpenSSH Server"},
	{ID: "3", Name: "iis", Description: "IIS Web Server"},
	{ID: "4", Name: "ftp", Description: "FTP Server"},
	{ID: "5", Name: "smb", Description: "File Sharing (SMB)"},
	{ID: "6", Name: "dns", Description: "DNS Server"},
	{ID: "7", Name: "dhcp", Description: "DHCP Server"},
	{ID: "8", Name: "ad", Description: "Active Directory"},
	{ID: "9", Name: "sql", Description: "SQL Server"},
	{ID: "10", Name: "mysql", Description: "MySQL Database"},
	{ID: "11", Name: "print", Description: "Print Spooler"},
	{ID: "12", Name: "hyperv", Description: "Hyper-V"},
	{ID: "13", Name: "wsus", Description: "WSUS Updates"},
	{ID: "14", Name: "exchange", Description: "Exchange Server"},
	{ID: "15", Name: "sharepoint", Description: "SharePoint"},
	{ID: "16", Name: "telnet", Description: "Telnet Server"},
	{ID: "17", Name: "snmp", Description: "SNMP Service"},
	{ID: "18", Name: "winrm", Description: "Windows Remote Management"},
	{ID: "19", Name: "wds", Description: "Windows Deployment Services"},
	{ID: "20", Name: "nfs", Description: "NFS Client/Server"},
	{ID: "21", Name: "ca", Description: "Certificate Authority (AD CS)"},
	{ID: "22", Name: "rras", Description: "Routing and Remote Access"},
	{ID: "23", Name: "npas", Description: "Network Policy Server (RADIUS)"},
	{ID: "24", Name: "wms", Description: "Windows Media Services"},
	{ID: "25", Name: "tftp", Description: "TFTP Server"},
}

// ServiceOption represents a service that can be marked as required.
type ServiceOption struct {
	ID          string
	Name        string
	Description string
}

// isServiceRequired checks if a service is in the required list.
func isServiceRequired(required []string, service string) bool {
	for _, s := range required {
		if s == service {
			return true
		}
	}
	return false
}

// BaselineResult tracks what was changed during baseline hardening.
type BaselineResult struct {
	Actions   []ActionResult
	Config    BaselineConfig
	OSType    string
	OSVersion string
}

// ActionResult represents a single hardening action result.
type ActionResult struct {
	Category    string // e.g., "Password Policy", "Kernel", "Firewall"
	Action      string // What was done
	Success     bool
	Output      string
	Error       string
	Skipped     bool   // If user chose to skip
	SkipReason  string
}

// DefaultBaselineConfig returns secure defaults.
func DefaultBaselineConfig() BaselineConfig {
	return BaselineConfig{
		MaxPasswordAge:   30,
		MinPasswordAge:   1,
		PasswordWarnAge:  7,
		MinPasswordLen:   12,
		DisableIPv6:      false, // Don't disable by default - ask user
		EnableFirewall:   true,
		InstallAuditd:    true,
		InstallApparmor:  true,
		InstallFail2ban:  true,
		RequiredServices: []string{}, // None by default - user selects
		Interactive:      true,
	}
}

// RunBaseline executes baseline hardening based on the current OS.
func RunBaseline(ctx context.Context, cfg BaselineConfig) (*BaselineResult, error) {
	result := &BaselineResult{
		Config: cfg,
		OSType: runtime.GOOS,
	}
	
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║            IRONGUARD BASELINE HARDENING                      ║")
	fmt.Println("║   Applying standard security configurations                  ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	
	return runPlatformBaseline(ctx, cfg, result)
}

// RunBaselineInteractive runs baseline with interactive prompts.
func RunBaselineInteractive(ctx context.Context) (*BaselineResult, error) {
	cfg := DefaultBaselineConfig()
	cfg.Interactive = true

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║            IRONGUARD BASELINE HARDENING                      ║")
	fmt.Println("║   Interactive Setup - Press Enter for defaults              ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)

	// Password Policy
	fmt.Println("━━━ PASSWORD POLICY ━━━")
	cfg.MaxPasswordAge = askInt(reader, "Maximum password age (days)", 30)
	cfg.MinPasswordAge = askInt(reader, "Minimum password age (days)", 1)
	cfg.PasswordWarnAge = askInt(reader, "Password warning age (days)", 7)
	cfg.MinPasswordLen = askInt(reader, "Minimum password length", 12)
	fmt.Println()

	// Network
	fmt.Println("━━━ NETWORK ━━━")
	cfg.DisableIPv6 = askYesNo(reader, "Disable IPv6? (some systems need it, say N if unsure)", false)
	cfg.EnableFirewall = askYesNo(reader, "Enable firewall?", true)
	fmt.Println()

	// Required Services Selection
	fmt.Println("━━━ REQUIRED SERVICES ━━━")
	fmt.Println("Select services that ARE REQUIRED by the README.")
	fmt.Println("These will NOT be disabled or hardened restrictively.")
	fmt.Println("Enter numbers WITHOUT spaces (e.g., '135' for options 1,3,5)")
	fmt.Println("Press Enter for none.")
	fmt.Println()

	var services []ServiceOption
	if runtime.GOOS == "windows" {
		services = WindowsServices
	} else {
		services = LinuxServices
	}

	// Print service list in columns
	printServiceList(services)
	fmt.Println()

	cfg.RequiredServices = askServiceSelection(reader, services)
	if len(cfg.RequiredServices) > 0 {
		fmt.Printf("Selected: %v\n", cfg.RequiredServices)
	} else {
		fmt.Println("No required services selected - all will be secured/disabled if found.")
	}
	fmt.Println()

	if runtime.GOOS != "windows" {
		// Linux-specific security tools
		fmt.Println("━━━ SECURITY TOOLS ━━━")
		cfg.InstallAuditd = askYesNo(reader, "Install/configure auditd (system auditing)?", true)
		cfg.InstallApparmor = askYesNo(reader, "Install/configure AppArmor (mandatory access control)?", true)
		cfg.InstallFail2ban = askYesNo(reader, "Install/configure fail2ban (brute force protection)?", true)
		fmt.Println()
	}

	fmt.Println("━━━ CONFIRMATION ━━━")
	fmt.Println("The following will be configured:")
	fmt.Printf("  • Password policy: max=%d days, min=%d days, warn=%d days, length=%d\n",
		cfg.MaxPasswordAge, cfg.MinPasswordAge, cfg.PasswordWarnAge, cfg.MinPasswordLen)
	fmt.Printf("  • IPv6: %s\n", boolToAction(cfg.DisableIPv6, "DISABLE", "keep enabled"))
	fmt.Printf("  • Firewall: %s\n", boolToAction(cfg.EnableFirewall, "ENABLE", "skip"))
	if len(cfg.RequiredServices) > 0 {
		fmt.Printf("  • Required services (won't touch): %v\n", cfg.RequiredServices)
	}
	if runtime.GOOS != "windows" {
		fmt.Printf("  • auditd: %s\n", boolToAction(cfg.InstallAuditd, "install/configure", "skip"))
		fmt.Printf("  • AppArmor: %s\n", boolToAction(cfg.InstallApparmor, "install/configure", "skip"))
		fmt.Printf("  • fail2ban: %s\n", boolToAction(cfg.InstallFail2ban, "install/configure", "skip"))
	}
	fmt.Println()

	if !askYesNo(reader, "Proceed with baseline hardening?", true) {
		return nil, fmt.Errorf("baseline hardening cancelled by user")
	}

	fmt.Println()
	return RunBaseline(ctx, cfg)
}

// printServiceList prints services in a formatted list.
func printServiceList(services []ServiceOption) {
	for _, svc := range services {
		fmt.Printf("  [%2s] %s\n", svc.ID, svc.Description)
	}
}

// askServiceSelection prompts user to select services by number.
func askServiceSelection(reader *bufio.Reader, services []ServiceOption) []string {
	fmt.Print("Required services: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		return nil
	}

	// Build a map for quick lookup
	idToName := make(map[string]string)
	for _, svc := range services {
		idToName[svc.ID] = svc.Name
	}

	// Parse input - each character/number group is an ID
	var selected []string
	seen := make(map[string]bool)

	// Handle both single digits and multi-digit IDs
	// Input like "135" means 1, 3, 5
	// Input like "1 3 5" or "1,3,5" also works
	// For IDs >= 10, user must use spaces or commas
	
	// First, try splitting by common delimiters
	parts := strings.FieldsFunc(input, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';'
	})

	if len(parts) > 1 {
		// User used delimiters
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if name, ok := idToName[part]; ok && !seen[name] {
				selected = append(selected, name)
				seen[name] = true
			}
		}
	} else {
		// No delimiters - treat each character as an ID (only works for 1-9)
		// For 10+, they need to use the full number with delimiter
		for _, ch := range input {
			id := string(ch)
			if name, ok := idToName[id]; ok && !seen[name] {
				selected = append(selected, name)
				seen[name] = true
			}
		}
		
		// Also check if the whole input is a valid ID (for two-digit numbers)
		if len(selected) == 0 {
			if name, ok := idToName[input]; ok {
				selected = append(selected, name)
			}
		}
	}

	return selected
}

// FormatResultsForAI returns a summary suitable for AI context.
func (r *BaselineResult) FormatResultsForAI() string {
	var sb strings.Builder

	sb.WriteString("=== BASELINE HARDENING ALREADY APPLIED ===\n\n")
	sb.WriteString(fmt.Sprintf("OS: %s\n\n", r.OSType))

	sb.WriteString("Configuration Applied:\n")
	sb.WriteString(fmt.Sprintf("  • Password Policy: max_age=%d, min_age=%d, warn=%d, min_length=%d\n",
		r.Config.MaxPasswordAge, r.Config.MinPasswordAge, r.Config.PasswordWarnAge, r.Config.MinPasswordLen))
	sb.WriteString(fmt.Sprintf("  • IPv6: %s\n", boolToStatus(r.Config.DisableIPv6, "disabled", "kept enabled")))
	sb.WriteString(fmt.Sprintf("  • Firewall: %s\n", boolToStatus(r.Config.EnableFirewall, "enabled", "skipped")))

	if r.OSType == "linux" {
		sb.WriteString(fmt.Sprintf("  • auditd: %s\n", boolToStatus(r.Config.InstallAuditd, "installed/configured", "skipped")))
		sb.WriteString(fmt.Sprintf("  • AppArmor: %s\n", boolToStatus(r.Config.InstallApparmor, "installed/configured", "skipped")))
		sb.WriteString(fmt.Sprintf("  • fail2ban: %s\n", boolToStatus(r.Config.InstallFail2ban, "installed/configured", "skipped")))
	}

	// CRITICAL: Required services that should NOT be disabled
	if len(r.Config.RequiredServices) > 0 {
		sb.WriteString(fmt.Sprintf("\n⚠️ REQUIRED SERVICES (DO NOT DISABLE): %v\n", r.Config.RequiredServices))
		sb.WriteString("The user marked these as required by the README. Do NOT stop, disable, or remove them!\n")
	} else {
		sb.WriteString("\nNo services marked as required - disable unnecessary services as needed.\n")
	}

	sb.WriteString("\nActions Completed:\n")
	successCount := 0
	failCount := 0
	skipCount := 0

	for _, action := range r.Actions {
		if action.Skipped {
			skipCount++
			continue
		}
		if action.Success {
			successCount++
			sb.WriteString(fmt.Sprintf("  ✓ [%s] %s\n", action.Category, action.Action))
		} else {
			failCount++
			sb.WriteString(fmt.Sprintf("  ✗ [%s] %s - ERROR: %s\n", action.Category, action.Action, action.Error))
		}
	}

	sb.WriteString(fmt.Sprintf("\nSummary: %d successful, %d failed, %d skipped\n", successCount, failCount, skipCount))
	sb.WriteString("\nDO NOT repeat these actions - they are already done!\n")
	sb.WriteString("Focus on: user management, forensics questions, prohibited files, and image-specific services.\n")

	return sb.String()
}

// PrintResults prints results to console.
func (r *BaselineResult) PrintResults() {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║            BASELINE HARDENING COMPLETE                       ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	
	successCount := 0
	failCount := 0
	skipCount := 0
	
	currentCategory := ""
	for _, action := range r.Actions {
		if action.Category != currentCategory {
			currentCategory = action.Category
			fmt.Printf("\n━━━ %s ━━━\n", strings.ToUpper(currentCategory))
		}
		
		if action.Skipped {
			skipCount++
			fmt.Printf("  ⊘ %s (skipped: %s)\n", action.Action, action.SkipReason)
		} else if action.Success {
			successCount++
			fmt.Printf("  ✓ %s\n", action.Action)
		} else {
			failCount++
			fmt.Printf("  ✗ %s\n", action.Action)
			if action.Error != "" {
				fmt.Printf("    Error: %s\n", action.Error)
			}
		}
	}
	
	fmt.Println()
	fmt.Println("━━━ SUMMARY ━━━")
	fmt.Printf("  Successful: %d\n", successCount)
	fmt.Printf("  Failed:     %d\n", failCount)
	fmt.Printf("  Skipped:    %d\n", skipCount)
	fmt.Println()
}

// Helper functions

func askYesNo(reader *bufio.Reader, prompt string, defaultVal bool) bool {
	defaultStr := "Y/n"
	if !defaultVal {
		defaultStr = "y/N"
	}
	
	fmt.Printf("%s [%s]: ", prompt, defaultStr)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	
	if input == "" {
		return defaultVal
	}
	return input == "y" || input == "yes"
}

func askInt(reader *bufio.Reader, prompt string, defaultVal int) int {
	fmt.Printf("%s [%d]: ", prompt, defaultVal)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	
	if input == "" {
		return defaultVal
	}
	
	var val int
	if _, err := fmt.Sscanf(input, "%d", &val); err != nil {
		return defaultVal
	}
	return val
}

func boolToAction(val bool, trueStr, falseStr string) string {
	if val {
		return trueStr
	}
	return falseStr
}

func boolToStatus(val bool, trueStr, falseStr string) string {
	if val {
		return trueStr
	}
	return falseStr
}

func addResult(result *BaselineResult, category, action string, success bool, output, errStr string) {
	result.Actions = append(result.Actions, ActionResult{
		Category: category,
		Action:   action,
		Success:  success,
		Output:   output,
		Error:    errStr,
	})
}

func addSkipped(result *BaselineResult, category, action, reason string) {
	result.Actions = append(result.Actions, ActionResult{
		Category:   category,
		Action:     action,
		Skipped:    true,
		SkipReason: reason,
	})
}

