//go:build windows

package cracker

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// startWindowsInterception starts monitoring on Windows using PowerShell and Process Monitor techniques
func (c *Cracker) startWindowsInterception(ctx context.Context, pid int) error {
	// Check if we have admin access
	if !isWindowsAdmin() {
		return fmt.Errorf("administrator privileges required for Windows interception")
	}

	// Start multiple monitoring goroutines
	go c.monitorFileAccessWindows(ctx, pid)
	go c.monitorRegistryWindows(ctx, pid)
	go c.monitorProcessesWindows(ctx, pid)
	go c.periodicConfigCheck(ctx)

	return nil
}

// isWindowsAdmin checks if running with administrator privileges
func isWindowsAdmin() bool {
	// Try to open a privileged registry key
	cmd := exec.Command("powershell", "-Command", 
		"(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "True"
}

// monitorFileAccessWindows monitors file access using PowerShell and filesystem watcher
func (c *Cracker) monitorFileAccessWindows(ctx context.Context, pid int) {
	// Key directories to monitor
	watchDirs := []string{
		`C:\Windows\System32\config`,      // Security policy
		`C:\Windows\System32\GroupPolicy`, // Group policy
		`C:\Program Files\CyberPatriot`,   // CCS installation
		`C:\Users`,                         // User directories
	}

	// Common files the scoring engine checks
	commonChecks := []string{
		`C:\Windows\System32\config\SAM`,
		`C:\Windows\System32\secpol.msc`,
		`C:\Program Files\CyberPatriot\ScoringReport.html`,
	}

	// Check common files immediately
	for _, path := range commonChecks {
		if _, err := os.Stat(path); err == nil {
			c.analyzeWindowsFile(path)
		}
	}

	// Periodically check for new files being accessed
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check key security files
			c.checkSecurityPolicies()
			c.checkUserAccounts()
			c.checkServices()
			c.checkFirewall()
		}
	}

	// Note: For true file access monitoring, we would use:
	// 1. ETW (Event Tracing for Windows) with FileIO provider
	// 2. Minifilter driver (requires kernel driver)
	// 3. Process Monitor integration
	// These require more complex setup and are marked for future enhancement
	_ = watchDirs
}

// monitorRegistryWindows monitors registry access
func (c *Cracker) monitorRegistryWindows(ctx context.Context, pid int) {
	// Key registry paths the scoring engine typically checks
	registryChecks := []struct {
		path     string
		expected string
		hint     string
	}{
		// Password Policy
		{`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge`, "30", "Set maximum password age to 30 days"},
		{`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\MinimumPasswordLength`, "12", "Set minimum password length to 12"},
		
		// Account Lockout
		{`HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout\MaxDenials`, "5", "Set account lockout threshold to 5"},
		
		// Security Settings
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`, "1", "Enable UAC"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin`, "2", "Set UAC to prompt for credentials"},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`, "1", "Enable Admin Approval Mode"},
		
		// Remote Desktop
		{`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`, "1", "Disable Remote Desktop if not needed"},
		{`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication`, "1", "Enable NLA for RDP"},
		
		// Audit Policy
		{`HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security\MaxSize`, "20971520", "Increase Security log size"},
		
		// SMB
		{`HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1`, "0", "Disable SMB1"},
		{`HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature`, "1", "Enable SMB signing"},
		
		// Windows Defender
		{`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware`, "0", "Enable Windows Defender"},
		
		// Guest Account
		{`HKLM\SAM\SAM\Domains\Account\Users\000001F5\F`, "", "Disable Guest account"},
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, check := range registryChecks {
				c.checkRegistryValue(check.path, check.expected, check.hint)
			}
		}
	}
}

// checkRegistryValue checks a registry value and reports findings
func (c *Cracker) checkRegistryValue(path, expected, hint string) {
	// Split path into hive and subkey
	parts := strings.SplitN(path, `\`, 2)
	if len(parts) != 2 {
		return
	}

	// Extract value name (last part after \)
	keyPath := filepath.Dir(parts[1])
	valueName := filepath.Base(parts[1])

	// Query registry using PowerShell
	psScript := fmt.Sprintf(`
try {
    $val = Get-ItemProperty -Path "Registry::%s\%s" -Name "%s" -ErrorAction Stop
    $val."%s"
} catch {
    "NOT_FOUND"
}
`, parts[0], keyPath, valueName, valueName)

	cmd := exec.Command("powershell", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return
	}

	current := strings.TrimSpace(string(output))
	
	finding := Finding{
		Type:        FindingTypeRegistry,
		Path:        path,
		CurrentVal:  current,
		ExpectedVal: expected,
		FixHint:     hint,
	}

	c.addFinding(finding)
}

// monitorProcessesWindows monitors running processes
func (c *Cracker) monitorProcessesWindows(ctx context.Context, pid int) {
	// Suspicious process patterns
	suspiciousPatterns := []struct {
		pattern string
		reason  string
	}{
		{"nc.exe", "Netcat (potential backdoor)"},
		{"ncat.exe", "Ncat (potential backdoor)"},
		{"netcat", "Netcat (potential backdoor)"},
		{"mimikatz", "Mimikatz credential dumper"},
		{"pwdump", "Password dumper"},
		{"cain", "Cain & Abel hacking tool"},
		{"wireshark", "Network sniffer (check if authorized)"},
		{"nmap", "Network scanner (check if authorized)"},
		{"putty", "SSH client (check if authorized)"},
		{"teamviewer", "Remote access (check if authorized)"},
		{"anydesk", "Remote access (check if authorized)"},
		{"vnc", "VNC remote access"},
		{"rdp", "RDP wrapper (potential unauthorized)"},
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Get list of running processes
			cmd := exec.Command("powershell", "-Command", 
				`Get-Process | Select-Object ProcessName, Path | ConvertTo-Csv -NoTypeInformation`)
			output, err := cmd.Output()
			if err != nil {
				continue
			}

			scanner := bufio.NewScanner(strings.NewReader(string(output)))
			for scanner.Scan() {
				line := strings.ToLower(scanner.Text())
				
				for _, pattern := range suspiciousPatterns {
					if strings.Contains(line, pattern.pattern) {
						finding := Finding{
							Type:        FindingTypeProcess,
							Path:        line,
							CurrentVal:  "RUNNING",
							ExpectedVal: "STOPPED/REMOVED",
							FixHint:     pattern.reason,
						}
						c.addFinding(finding)
					}
				}
			}
		}
	}
}

// periodicConfigCheck periodically checks common security configurations
func (c *Cracker) periodicConfigCheck(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.checkPasswordPolicy()
			c.checkAuditPolicy()
			c.checkUserRights()
		}
	}
}

// checkSecurityPolicies checks local security policies
func (c *Cracker) checkSecurityPolicies() {
	// Export and analyze security policy
	psScript := `
$tempFile = [System.IO.Path]::GetTempFileName()
secedit /export /cfg $tempFile /quiet
Get-Content $tempFile
Remove-Item $tempFile -Force
`
	cmd := exec.Command("powershell", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return
	}

	content := string(output)

	// Check for key policy settings
	policyChecks := []struct {
		pattern  *regexp.Regexp
		expected string
		name     string
		hint     string
	}{
		{regexp.MustCompile(`MinimumPasswordLength\s*=\s*(\d+)`), "12", "Minimum Password Length", "Set to 12 or higher"},
		{regexp.MustCompile(`MaximumPasswordAge\s*=\s*(\d+)`), "30", "Maximum Password Age", "Set to 30 days or less"},
		{regexp.MustCompile(`PasswordComplexity\s*=\s*(\d+)`), "1", "Password Complexity", "Enable password complexity requirements"},
		{regexp.MustCompile(`LockoutBadCount\s*=\s*(\d+)`), "5", "Account Lockout Threshold", "Set to 5 or fewer attempts"},
		{regexp.MustCompile(`EnableGuestAccount\s*=\s*(\d+)`), "0", "Guest Account", "Disable guest account"},
	}

	for _, check := range policyChecks {
		if matches := check.pattern.FindStringSubmatch(content); len(matches) > 1 {
			current := matches[1]
			finding := Finding{
				Type:        FindingTypeFile,
				Path:        "Security Policy: " + check.name,
				CurrentVal:  current,
				ExpectedVal: check.expected,
				FixHint:     check.hint,
			}
			c.addFinding(finding)
		}
	}
}

// checkUserAccounts checks for unauthorized user accounts
func (c *Cracker) checkUserAccounts() {
	psScript := `Get-LocalUser | Select-Object Name, Enabled, Description | ConvertTo-Csv -NoTypeInformation`
	cmd := exec.Command("powershell", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return
	}

	// Report user accounts for the AI to analyze
	finding := Finding{
		Type:       FindingTypeFile,
		Path:       "Local User Accounts",
		CurrentVal: strings.TrimSpace(string(output)),
		FixHint:    "Review for unauthorized users",
	}
	c.addFinding(finding)
}

// checkServices checks for suspicious or misconfigured services
func (c *Cracker) checkServices() {
	// Services that should typically be disabled
	dangerousServices := []string{
		"RemoteRegistry",
		"Telnet",
		"SNMP",
		"SSDPSRV",      // SSDP Discovery
		"upnphost",     // UPnP Device Host
		"WMPNetworkSvc", // Windows Media Player Network Sharing
	}

	for _, svc := range dangerousServices {
		psScript := fmt.Sprintf(`
$svc = Get-Service -Name "%s" -ErrorAction SilentlyContinue
if ($svc) {
    "$($svc.Status)|$($svc.StartType)"
} else {
    "NOT_INSTALLED"
}
`, svc)
		cmd := exec.Command("powershell", "-Command", psScript)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		result := strings.TrimSpace(string(output))
		if result == "NOT_INSTALLED" {
			continue
		}

		parts := strings.Split(result, "|")
		if len(parts) != 2 {
			continue
		}

		status := parts[0]
		startType := parts[1]

		if status == "Running" || startType == "Automatic" {
			finding := Finding{
				Type:        FindingTypeProcess,
				Path:        "Service: " + svc,
				CurrentVal:  fmt.Sprintf("Status=%s, StartType=%s", status, startType),
				ExpectedVal: "Disabled/Stopped",
				FixHint:     fmt.Sprintf("Disable %s service: Set-Service -Name %s -StartupType Disabled", svc, svc),
			}
			c.addFinding(finding)
		}
	}
}

// checkFirewall checks Windows Firewall status
func (c *Cracker) checkFirewall() {
	profiles := []string{"Domain", "Private", "Public"}
	
	for _, profile := range profiles {
		psScript := fmt.Sprintf(`(Get-NetFirewallProfile -Name %s).Enabled`, profile)
		cmd := exec.Command("powershell", "-Command", psScript)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		enabled := strings.TrimSpace(string(output))
		finding := Finding{
			Type:        FindingTypeFile,
			Path:        fmt.Sprintf("Windows Firewall: %s Profile", profile),
			CurrentVal:  enabled,
			ExpectedVal: "True",
			FixHint:     fmt.Sprintf("Enable firewall: Set-NetFirewallProfile -Profile %s -Enabled True", profile),
		}
		c.addFinding(finding)
	}
}

// checkPasswordPolicy checks password policy settings
func (c *Cracker) checkPasswordPolicy() {
	psScript := `net accounts`
	cmd := exec.Command("cmd", "/c", psScript)
	output, err := cmd.Output()
	if err != nil {
		return
	}

	content := string(output)

	// Parse key values
	checks := []struct {
		pattern  *regexp.Regexp
		expected string
		name     string
		hint     string
	}{
		{regexp.MustCompile(`Minimum password length:\s*(\d+)`), "12", "Minimum password length", "Set to 12: net accounts /minpwlen:12"},
		{regexp.MustCompile(`Maximum password age \(days\):\s*(\d+)`), "30", "Maximum password age", "Set to 30: net accounts /maxpwage:30"},
		{regexp.MustCompile(`Minimum password age \(days\):\s*(\d+)`), "1", "Minimum password age", "Set to 1: net accounts /minpwage:1"},
		{regexp.MustCompile(`Lockout threshold:\s*(\d+)`), "5", "Lockout threshold", "Set to 5: net accounts /lockoutthreshold:5"},
	}

	for _, check := range checks {
		if matches := check.pattern.FindStringSubmatch(content); len(matches) > 1 {
			current := matches[1]
			finding := Finding{
				Type:        FindingTypeFile,
				Path:        "Password Policy: " + check.name,
				CurrentVal:  current,
				ExpectedVal: check.expected,
				FixHint:     check.hint,
			}
			c.addFinding(finding)
		}
	}
}

// checkAuditPolicy checks audit policy settings
func (c *Cracker) checkAuditPolicy() {
	psScript := `auditpol /get /category:*`
	cmd := exec.Command("cmd", "/c", psScript)
	output, err := cmd.Output()
	if err != nil {
		return
	}

	content := string(output)

	// Check for important audit settings
	auditChecks := []string{
		"Logon",
		"Account Logon",
		"Account Management",
		"Policy Change",
		"Privilege Use",
	}

	for _, category := range auditChecks {
		pattern := regexp.MustCompile(fmt.Sprintf(`(?m)^\s*%s\s+(Success and Failure|Success|Failure|No Auditing)`, regexp.QuoteMeta(category)))
		if matches := pattern.FindStringSubmatch(content); len(matches) > 1 {
			current := matches[1]
			expected := "Success and Failure"
			
			finding := Finding{
				Type:        FindingTypeFile,
				Path:        "Audit Policy: " + category,
				CurrentVal:  current,
				ExpectedVal: expected,
				FixHint:     fmt.Sprintf("Enable auditing: auditpol /set /category:\"%s\" /success:enable /failure:enable", category),
			}
			c.addFinding(finding)
		}
	}
}

// checkUserRights checks user rights assignments
func (c *Cracker) checkUserRights() {
	// Key user rights that are often misconfigured
	psScript := `
$rights = @{
    "SeDenyNetworkLogonRight" = "Deny access from network"
    "SeDenyBatchLogonRight" = "Deny batch logon"
    "SeDenyServiceLogonRight" = "Deny service logon"
    "SeDenyRemoteInteractiveLogonRight" = "Deny RDP logon"
}

foreach ($right in $rights.Keys) {
    $users = (secedit /export /cfg "$env:TEMP\rights.inf" /areas USER_RIGHTS | Out-Null; Select-String -Path "$env:TEMP\rights.inf" -Pattern $right)
    if ($users) {
        "$right = $($users.Line)"
    }
}
`
	cmd := exec.Command("powershell", "-Command", psScript)
	output, _ := cmd.Output()
	
	if len(output) > 0 {
		finding := Finding{
			Type:       FindingTypeFile,
			Path:       "User Rights Assignments",
			CurrentVal: strings.TrimSpace(string(output)),
			FixHint:    "Review user rights for proper restrictions",
		}
		c.addFinding(finding)
	}
}

// analyzeWindowsFile analyzes a Windows file and generates findings
func (c *Cracker) analyzeWindowsFile(path string) {
	// Check if file exists and is readable
	info, err := os.Stat(path)
	if err != nil {
		return
	}

	finding := Finding{
		Type:       FindingTypeFile,
		Path:       path,
		CurrentVal: fmt.Sprintf("Size: %d bytes, Modified: %s", info.Size(), info.ModTime().Format("2006-01-02 15:04:05")),
		FixHint:    "File is being monitored by scoring engine",
	}
	c.addFinding(finding)
}
