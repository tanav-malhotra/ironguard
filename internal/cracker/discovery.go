package cracker

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// ScoringEnginePatterns are process names to look for
var ScoringEnginePatterns = []string{
	"CCSClient",
	"ccs",
	"css",
	"CyberPatriot",
	"ScoringEngine",
	"scoring",
}

// DiscoverScoringEngine finds the scoring engine process
// Returns PID, process name, and error
func DiscoverScoringEngine() (int, string, error) {
	if runtime.GOOS == "windows" {
		return discoverWindows()
	}
	return discoverLinux()
}

// discoverLinux finds the scoring engine on Linux by scanning /proc
func discoverLinux() (int, string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, "", fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a PID
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		// Read the command line
		cmdlinePath := filepath.Join("/proc", entry.Name(), "cmdline")
		cmdlineBytes, err := os.ReadFile(cmdlinePath)
		if err != nil {
			continue
		}

		cmdline := string(cmdlineBytes)
		// Replace null bytes with spaces
		cmdline = strings.ReplaceAll(cmdline, "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)

		// Also check comm (short process name)
		commPath := filepath.Join("/proc", entry.Name(), "comm")
		commBytes, err := os.ReadFile(commPath)
		comm := ""
		if err == nil {
			comm = strings.TrimSpace(string(commBytes))
		}

		// Check against patterns
		for _, pattern := range ScoringEnginePatterns {
			patternLower := strings.ToLower(pattern)
			if strings.Contains(strings.ToLower(cmdline), patternLower) ||
				strings.Contains(strings.ToLower(comm), patternLower) {
				// Extract the actual binary name
				parts := strings.Fields(cmdline)
				processName := comm
				if len(parts) > 0 {
					processName = filepath.Base(parts[0])
				}
				return pid, processName, nil
			}
		}
	}

	return 0, "", fmt.Errorf("scoring engine not found (tried: %v)", ScoringEnginePatterns)
}

// discoverWindows finds the scoring engine on Windows using PowerShell
func discoverWindows() (int, string, error) {
	// Use PowerShell to find CCS processes
	psScript := `
Get-Process | Where-Object { 
    $_.ProcessName -match 'ccs|css|scoring|cyberpatriot' 
} | Select-Object -First 1 Id, ProcessName | ForEach-Object {
    "$($_.Id)|$($_.ProcessName)"
}
`
	cmd := exec.Command("powershell", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return 0, "", fmt.Errorf("failed to query processes: %w", err)
	}

	result := strings.TrimSpace(string(output))
	if result == "" {
		return 0, "", fmt.Errorf("scoring engine process not found")
	}

	parts := strings.Split(result, "|")
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("unexpected output format: %s", result)
	}

	var pid int
	fmt.Sscanf(parts[0], "%d", &pid)
	return pid, parts[1], nil
}

