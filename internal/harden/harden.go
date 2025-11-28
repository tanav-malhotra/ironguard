package harden

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// HardenResult represents the result of a hardening action.
type HardenResult struct {
	Action      string
	Success     bool
	Output      string
	Error       string
	PointsGained int
}

// Hardener provides system hardening functionality.
type Hardener struct {
	os string
}

// New creates a new Hardener for the current OS.
func New() *Hardener {
	return &Hardener{os: runtime.GOOS}
}

// IsWindows returns true if running on Windows.
func (h *Hardener) IsWindows() bool {
	return h.os == "windows"
}

// IsLinux returns true if running on Linux.
func (h *Hardener) IsLinux() bool {
	return h.os == "linux"
}

// ===== USER MANAGEMENT =====

// ListUsers returns all local users on the system.
func (h *Hardener) ListUsers(ctx context.Context) ([]string, error) {
	if h.IsWindows() {
		return h.runPowerShell(ctx, "Get-LocalUser | Select-Object -ExpandProperty Name")
	}
	return h.runBash(ctx, "cut -d: -f1 /etc/passwd")
}

// ListAdmins returns users with administrative privileges.
func (h *Hardener) ListAdmins(ctx context.Context) ([]string, error) {
	if h.IsWindows() {
		return h.runPowerShell(ctx, "Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name")
	}
	return h.runBash(ctx, "getent group sudo wheel admin 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sort -u")
}

// DisableUser disables a user account.
func (h *Hardener) DisableUser(ctx context.Context, username string) *HardenResult {
	result := &HardenResult{Action: fmt.Sprintf("Disable user: %s", username)}

	var cmd string
	if h.IsWindows() {
		cmd = fmt.Sprintf("Disable-LocalUser -Name '%s'", username)
		output, err := h.runPowerShellSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Output = output
	} else {
		cmd = fmt.Sprintf("usermod -L '%s'", username)
		output, err := h.runBashSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Output = output
	}

	result.Success = true
	return result
}

// DeleteUser removes a user account.
func (h *Hardener) DeleteUser(ctx context.Context, username string) *HardenResult {
	result := &HardenResult{Action: fmt.Sprintf("Delete user: %s", username)}

	if h.IsWindows() {
		cmd := fmt.Sprintf("Remove-LocalUser -Name '%s'", username)
		output, err := h.runPowerShellSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Output = output
	} else {
		cmd := fmt.Sprintf("userdel -r '%s' 2>/dev/null || userdel '%s'", username, username)
		output, err := h.runBashSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Output = output
	}

	result.Success = true
	return result
}

// SetPassword sets a user's password.
func (h *Hardener) SetPassword(ctx context.Context, username, password string) *HardenResult {
	result := &HardenResult{Action: fmt.Sprintf("Set password for: %s", username)}

	if h.IsWindows() {
		cmd := fmt.Sprintf("Set-LocalUser -Name '%s' -Password (ConvertTo-SecureString '%s' -AsPlainText -Force)", username, password)
		_, err := h.runPowerShellSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Output = "Password set successfully"
	} else {
		cmd := fmt.Sprintf("echo '%s:%s' | chpasswd", username, password)
		_, err := h.runBashSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Output = "Password set successfully"
	}

	result.Success = true
	return result
}

// RemoveFromAdmins removes a user from the administrators group.
func (h *Hardener) RemoveFromAdmins(ctx context.Context, username string) *HardenResult {
	result := &HardenResult{Action: fmt.Sprintf("Remove from admins: %s", username)}

	if h.IsWindows() {
		cmd := fmt.Sprintf("Remove-LocalGroupMember -Group 'Administrators' -Member '%s'", username)
		_, err := h.runPowerShellSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Output = "Removed from Administrators group"
	} else {
		// Try multiple admin groups
		for _, group := range []string{"sudo", "wheel", "admin"} {
			h.runBashSingle(ctx, fmt.Sprintf("gpasswd -d '%s' '%s' 2>/dev/null", username, group))
		}
		result.Output = "Removed from admin groups"
	}

	result.Success = true
	return result
}

// ===== SERVICE MANAGEMENT =====

// ListServices returns all services on the system.
func (h *Hardener) ListServices(ctx context.Context) ([]string, error) {
	if h.IsWindows() {
		return h.runPowerShell(ctx, "Get-Service | Select-Object -ExpandProperty Name")
	}
	return h.runBash(ctx, "systemctl list-units --type=service --all --no-pager --no-legend | awk '{print $1}'")
}

// ListRunningServices returns running services.
func (h *Hardener) ListRunningServices(ctx context.Context) ([]string, error) {
	if h.IsWindows() {
		return h.runPowerShell(ctx, "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -ExpandProperty Name")
	}
	return h.runBash(ctx, "systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'")
}

// StopService stops a service.
func (h *Hardener) StopService(ctx context.Context, service string) *HardenResult {
	result := &HardenResult{Action: fmt.Sprintf("Stop service: %s", service)}

	if h.IsWindows() {
		cmd := fmt.Sprintf("Stop-Service -Name '%s' -Force", service)
		_, err := h.runPowerShellSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
	} else {
		cmd := fmt.Sprintf("systemctl stop '%s'", service)
		_, err := h.runBashSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
	}

	result.Success = true
	result.Output = "Service stopped"
	return result
}

// DisableService disables a service from starting at boot.
func (h *Hardener) DisableService(ctx context.Context, service string) *HardenResult {
	result := &HardenResult{Action: fmt.Sprintf("Disable service: %s", service)}

	if h.IsWindows() {
		cmd := fmt.Sprintf("Set-Service -Name '%s' -StartupType Disabled", service)
		_, err := h.runPowerShellSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
	} else {
		cmd := fmt.Sprintf("systemctl disable '%s'", service)
		_, err := h.runBashSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
	}

	result.Success = true
	result.Output = "Service disabled"
	return result
}

// ===== FIREWALL =====

// EnableFirewall enables the system firewall.
func (h *Hardener) EnableFirewall(ctx context.Context) *HardenResult {
	result := &HardenResult{Action: "Enable firewall"}

	if h.IsWindows() {
		cmd := "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
		_, err := h.runPowerShellSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Output = "Windows Firewall enabled for all profiles"
	} else {
		// Try ufw first, then firewalld
		_, err := h.runBashSingle(ctx, "ufw --force enable 2>/dev/null || systemctl enable --now firewalld 2>/dev/null")
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Output = "Firewall enabled"
	}

	result.Success = true
	return result
}

// ===== UPDATES =====

// CheckUpdates checks for available system updates.
func (h *Hardener) CheckUpdates(ctx context.Context) (string, error) {
	if h.IsWindows() {
		output, err := h.runPowerShellSingle(ctx, `
			$UpdateSession = New-Object -ComObject Microsoft.Update.Session
			$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
			$Updates = $UpdateSearcher.Search("IsInstalled=0").Updates
			$Updates | Select-Object Title | Format-Table -AutoSize
		`)
		return output, err
	}
	return h.runBashSingle(ctx, "apt list --upgradable 2>/dev/null || dnf check-update 2>/dev/null || yum check-update 2>/dev/null")
}

// InstallUpdates installs available system updates.
func (h *Hardener) InstallUpdates(ctx context.Context) *HardenResult {
	result := &HardenResult{Action: "Install system updates"}

	if h.IsWindows() {
		cmd := `
			Install-Module PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction SilentlyContinue
			Import-Module PSWindowsUpdate
			Get-WindowsUpdate -Install -AcceptAll -AutoReboot:$false
		`
		output, err := h.runPowerShellSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Output = output
	} else {
		output, err := h.runBashSingle(ctx, "apt update && apt upgrade -y 2>/dev/null || dnf upgrade -y 2>/dev/null || yum update -y 2>/dev/null")
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Output = output
	}

	result.Success = true
	return result
}

// ===== SECURITY POLICIES =====

// SetPasswordPolicy configures password complexity requirements.
func (h *Hardener) SetPasswordPolicy(ctx context.Context) *HardenResult {
	result := &HardenResult{Action: "Set password policy"}

	if h.IsWindows() {
		cmd := `
			# Set password policy via secedit
			$cfg = @"
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 12
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
"@
			$cfg | Out-File -FilePath "$env:TEMP\secpol.cfg" -Encoding ASCII
			secedit /configure /db "$env:TEMP\secpol.sdb" /cfg "$env:TEMP\secpol.cfg" /areas SECURITYPOLICY
		`
		output, err := h.runPowerShellSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Output = output
	} else {
		// Configure PAM password requirements
		cmd := `
			# Install libpam-pwquality if not present
			apt install -y libpam-pwquality 2>/dev/null || dnf install -y libpwquality 2>/dev/null

			# Configure password requirements
			cat > /etc/security/pwquality.conf << 'EOF'
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
EOF
		`
		output, err := h.runBashSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Output = output
	}

	result.Success = true
	result.Output = "Password policy configured"
	return result
}

// DisableGuestAccount disables the guest account.
func (h *Hardener) DisableGuestAccount(ctx context.Context) *HardenResult {
	result := &HardenResult{Action: "Disable guest account"}

	if h.IsWindows() {
		cmd := "Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue"
		h.runPowerShellSingle(ctx, cmd)
		result.Output = "Guest account disabled"
	} else {
		cmd := "usermod -L guest 2>/dev/null; passwd -l guest 2>/dev/null"
		h.runBashSingle(ctx, cmd)
		result.Output = "Guest account locked"
	}

	result.Success = true
	return result
}

// ===== PROHIBITED FILES =====

// FindProhibitedFiles searches for common prohibited file types.
func (h *Hardener) FindProhibitedFiles(ctx context.Context) (string, error) {
	if h.IsWindows() {
		cmd := `
			$extensions = @("*.mp3", "*.mp4", "*.avi", "*.mkv", "*.flac", "*.wav", "*.mov", "*.wmv")
			$results = @()
			foreach ($ext in $extensions) {
				$files = Get-ChildItem -Path "C:\Users" -Recurse -Filter $ext -ErrorAction SilentlyContinue
				$results += $files.FullName
			}
			$results | Select-Object -First 100
		`
		return h.runPowerShellSingle(ctx, cmd)
	}
	return h.runBashSingle(ctx, `find /home -type f \( -name "*.mp3" -o -name "*.mp4" -o -name "*.avi" -o -name "*.mkv" -o -name "*.flac" -o -name "*.wav" -o -name "*.mov" -o -name "*.wmv" \) 2>/dev/null | head -100`)
}

// DeleteFile deletes a file.
func (h *Hardener) DeleteFile(ctx context.Context, path string) *HardenResult {
	result := &HardenResult{Action: fmt.Sprintf("Delete file: %s", path)}

	if h.IsWindows() {
		cmd := fmt.Sprintf("Remove-Item -Path '%s' -Force", path)
		_, err := h.runPowerShellSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
	} else {
		cmd := fmt.Sprintf("rm -f '%s'", path)
		_, err := h.runBashSingle(ctx, cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
	}

	result.Success = true
	result.Output = "File deleted"
	return result
}

// ===== AUDIT =====

// AuditSystem performs a basic security audit.
func (h *Hardener) AuditSystem(ctx context.Context) (string, error) {
	var sb strings.Builder

	sb.WriteString("=== SECURITY AUDIT ===\n\n")

	// Users
	sb.WriteString("--- USERS ---\n")
	users, err := h.ListUsers(ctx)
	if err == nil {
		sb.WriteString(fmt.Sprintf("Total users: %d\n", len(users)))
		sb.WriteString(strings.Join(users, "\n") + "\n")
	}

	sb.WriteString("\n--- ADMINISTRATORS ---\n")
	admins, err := h.ListAdmins(ctx)
	if err == nil {
		sb.WriteString(strings.Join(admins, "\n") + "\n")
	}

	// Services
	sb.WriteString("\n--- RUNNING SERVICES ---\n")
	services, err := h.ListRunningServices(ctx)
	if err == nil {
		sb.WriteString(fmt.Sprintf("Running services: %d\n", len(services)))
	}

	// Prohibited files
	sb.WriteString("\n--- PROHIBITED FILES ---\n")
	files, err := h.FindProhibitedFiles(ctx)
	if err == nil && files != "" {
		sb.WriteString(files + "\n")
	} else {
		sb.WriteString("No prohibited files found\n")
	}

	return sb.String(), nil
}

// Helper functions

func (h *Hardener) runPowerShell(ctx context.Context, script string) ([]string, error) {
	output, err := h.runPowerShellSingle(ctx, script)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result, nil
}

func (h *Hardener) runPowerShellSingle(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (h *Hardener) runBash(ctx context.Context, script string) ([]string, error) {
	output, err := h.runBashSingle(ctx, script)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result, nil
}

func (h *Hardener) runBashSingle(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "bash", "-c", script)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

