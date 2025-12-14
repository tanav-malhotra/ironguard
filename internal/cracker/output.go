package cracker

import (
	"fmt"
	"strings"
)

// PrintFinding prints a finding to console in a formatted way
func PrintFinding(f Finding) {
	// Color codes (ANSI)
	red := "\033[31m"
	green := "\033[32m"
	yellow := "\033[33m"
	cyan := "\033[36m"
	reset := "\033[0m"
	bold := "\033[1m"

	// Type indicator with color
	var typeStr string
	switch f.Type {
	case FindingTypeFile:
		typeStr = fmt.Sprintf("%s[FILE]%s", cyan, reset)
	case FindingTypeRegistry:
		typeStr = fmt.Sprintf("%s[REG]%s", cyan, reset)
	case FindingTypeProcess:
		typeStr = fmt.Sprintf("%s[PROC]%s", yellow, reset)
	case FindingTypeKernelParam:
		typeStr = fmt.Sprintf("%s[KERN]%s", cyan, reset)
	case FindingTypeForensics:
		typeStr = fmt.Sprintf("%s[FORENSICS]%s", green, reset)
	}

	// Status indicator
	var statusStr string
	if f.ExpectedVal != "" && f.CurrentVal != f.ExpectedVal {
		statusStr = fmt.Sprintf("%s✗%s", red, reset)
	} else {
		statusStr = fmt.Sprintf("%s✓%s", green, reset)
	}

	// Print the finding
	fmt.Printf("%s %s %s%s%s\n", statusStr, typeStr, bold, f.Path, reset)
	
	if f.CurrentVal != "" {
		fmt.Printf("   Current: %s%s%s\n", yellow, f.CurrentVal, reset)
	}
	if f.ExpectedVal != "" && f.CurrentVal != f.ExpectedVal {
		fmt.Printf("   Expected: %s%s%s\n", green, f.ExpectedVal, reset)
	}
	if f.FixHint != "" {
		fmt.Printf("   Hint: %s\n", f.FixHint)
	}
	fmt.Println()
}

// FormatFindingForAI formats a finding as a system message for the AI
func FormatFindingForAI(f Finding) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("[SCORING ENGINE] %s check detected\n", f.Type.String()))
	sb.WriteString(fmt.Sprintf("Path: %s\n", f.Path))
	
	if f.CurrentVal != "" {
		sb.WriteString(fmt.Sprintf("Current: %s\n", f.CurrentVal))
	}
	if f.ExpectedVal != "" && f.CurrentVal != f.ExpectedVal {
		sb.WriteString(fmt.Sprintf("Expected: %s\n", f.ExpectedVal))
		sb.WriteString("ACTION NEEDED: Fix this to earn points!\n")
	}
	if f.FixHint != "" {
		sb.WriteString(fmt.Sprintf("Hint: %s\n", f.FixHint))
	}

	return sb.String()
}

// FormatAllFindings formats all findings for display
func FormatAllFindings(findings []Finding) string {
	if len(findings) == 0 {
		return "No findings yet. Waiting for scoring engine checks..."
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("═══ SCORING ENGINE FINDINGS (%d unique checks) ═══\n\n", len(findings)))

	// Group by type
	files := []Finding{}
	processes := []Finding{}
	kernel := []Finding{}
	forensics := []Finding{}

	for _, f := range findings {
		switch f.Type {
		case FindingTypeFile:
			files = append(files, f)
		case FindingTypeProcess:
			processes = append(processes, f)
		case FindingTypeKernelParam:
			kernel = append(kernel, f)
		case FindingTypeForensics:
			forensics = append(forensics, f)
		}
	}

	if len(forensics) > 0 {
		sb.WriteString("─── FORENSICS QUESTIONS ───\n")
		for _, f := range forensics {
			status := "✗ UNANSWERED"
			if f.CurrentVal == "ANSWERED" {
				status = "✓ ANSWERED"
			}
			sb.WriteString(fmt.Sprintf("  %s: %s\n", status, f.Path))
		}
		sb.WriteString("\n")
	}

	if len(processes) > 0 {
		sb.WriteString("─── PROCESSES BEING CHECKED ───\n")
		for _, f := range processes {
			if f.ExpectedVal == "STOPPED/REMOVED" {
				sb.WriteString(fmt.Sprintf("  ⚠ SUSPICIOUS: %s\n", f.Path))
				sb.WriteString(fmt.Sprintf("    → %s\n", f.FixHint))
			} else {
				sb.WriteString(fmt.Sprintf("  • %s\n", f.Path))
			}
		}
		sb.WriteString("\n")
	}

	if len(kernel) > 0 {
		sb.WriteString("─── KERNEL PARAMETERS ───\n")
		for _, f := range kernel {
			status := "✓"
			if f.ExpectedVal != "" && f.CurrentVal != f.ExpectedVal {
				status = "✗"
			}
			sb.WriteString(fmt.Sprintf("  %s %s = %s", status, f.Path, f.CurrentVal))
			if f.ExpectedVal != "" && f.CurrentVal != f.ExpectedVal {
				sb.WriteString(fmt.Sprintf(" (expected: %s)", f.ExpectedVal))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	if len(files) > 0 {
		sb.WriteString("─── FILES BEING CHECKED ───\n")
		for _, f := range files {
			status := "✓"
			if f.ExpectedVal != "" && f.CurrentVal != f.ExpectedVal {
				status = "✗"
			}
			sb.WriteString(fmt.Sprintf("  %s %s\n", status, f.Path))
			if f.CurrentVal != "" {
				sb.WriteString(fmt.Sprintf("    Current: %s\n", f.CurrentVal))
			}
			if f.FixHint != "" && (f.ExpectedVal == "" || f.CurrentVal != f.ExpectedVal) {
				sb.WriteString(fmt.Sprintf("    Hint: %s\n", f.FixHint))
			}
		}
	}

	return sb.String()
}

