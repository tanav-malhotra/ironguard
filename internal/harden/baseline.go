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
	MaxPasswordAge int  // Default: 30
	MinPasswordAge int  // Default: 1
	PasswordWarnAge int // Default: 7
	MinPasswordLen int  // Default: 12
	
	// Network
	DisableIPv6 bool // Ask user - default: false (some systems need it)
	
	// Services
	EnableFirewall bool // Default: true
	
	// Security Tools (Linux)
	InstallAuditd   bool // Default: true
	InstallApparmor bool // Default: true
	InstallFail2ban bool // Default: true
	
	// SSH Hardening (Linux)
	HardenSSH bool // Default: true
	
	// Interactive mode
	Interactive bool // If false, use all defaults
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
		MaxPasswordAge:  30,
		MinPasswordAge:  1,
		PasswordWarnAge: 7,
		MinPasswordLen:  12,
		DisableIPv6:     false, // Don't disable by default - ask user
		EnableFirewall:  true,
		InstallAuditd:   true,
		InstallApparmor: true,
		InstallFail2ban: true,
		HardenSSH:       true,
		Interactive:     true,
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
	
	if runtime.GOOS != "windows" {
		// Linux-specific
		fmt.Println("━━━ SECURITY TOOLS ━━━")
		cfg.InstallAuditd = askYesNo(reader, "Install/configure auditd (system auditing)?", true)
		cfg.InstallApparmor = askYesNo(reader, "Install/configure AppArmor (mandatory access control)?", true)
		cfg.InstallFail2ban = askYesNo(reader, "Install/configure fail2ban (brute force protection)?", true)
		cfg.HardenSSH = askYesNo(reader, "Harden SSH configuration?", true)
		fmt.Println()
	}
	
	fmt.Println("━━━ CONFIRMATION ━━━")
	fmt.Println("The following will be configured:")
	fmt.Printf("  • Password policy: max=%d days, min=%d days, warn=%d days, length=%d\n", 
		cfg.MaxPasswordAge, cfg.MinPasswordAge, cfg.PasswordWarnAge, cfg.MinPasswordLen)
	fmt.Printf("  • IPv6: %s\n", boolToAction(cfg.DisableIPv6, "DISABLE", "keep enabled"))
	fmt.Printf("  • Firewall: %s\n", boolToAction(cfg.EnableFirewall, "ENABLE", "skip"))
	if runtime.GOOS != "windows" {
		fmt.Printf("  • auditd: %s\n", boolToAction(cfg.InstallAuditd, "install/configure", "skip"))
		fmt.Printf("  • AppArmor: %s\n", boolToAction(cfg.InstallApparmor, "install/configure", "skip"))
		fmt.Printf("  • fail2ban: %s\n", boolToAction(cfg.InstallFail2ban, "install/configure", "skip"))
		fmt.Printf("  • SSH hardening: %s\n", boolToAction(cfg.HardenSSH, "apply", "skip"))
	}
	fmt.Println()
	
	if !askYesNo(reader, "Proceed with baseline hardening?", true) {
		return nil, fmt.Errorf("baseline hardening cancelled by user")
	}
	
	fmt.Println()
	return RunBaseline(ctx, cfg)
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
		sb.WriteString(fmt.Sprintf("  • SSH: %s\n", boolToStatus(r.Config.HardenSSH, "hardened", "skipped")))
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
	sb.WriteString("Focus on: user management, forensics questions, prohibited files, and services.\n")
	
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

