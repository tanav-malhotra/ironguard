package tools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// PersistentShell maintains shell state (working directory, environment variables)
// across multiple command executions. Each command runs in a new process but
// inherits the accumulated state from previous commands.
type PersistentShell struct {
	mu  sync.Mutex
	cwd string
	env map[string]string // Custom environment variables set during session
}

var defaultShellSession = newPersistentShell()

// newPersistentShell creates a new persistent shell instance.
func newPersistentShell() *PersistentShell {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	return &PersistentShell{
		cwd: cwd,
		env: make(map[string]string),
	}
}

// Run executes a command in the persistent shell context.
// If newSession is true, the state is reset before running.
func (p *PersistentShell) Run(ctx context.Context, command string, newSession bool) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("command cannot be empty")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if newSession {
		p.resetLocked()
	}

	return p.executeCommandLocked(ctx, command)
}

// GetCwd returns the current working directory.
func (p *PersistentShell) GetCwd() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cwd
}

// Reset clears all session state.
func (p *PersistentShell) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resetLocked()
}

func (p *PersistentShell) resetLocked() {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	p.cwd = cwd
	p.env = make(map[string]string)
}

func (p *PersistentShell) executeCommandLocked(ctx context.Context, command string) (string, error) {
	// Build the command with state tracking
	var cmd *exec.Cmd
	var wrappedCommand string

	if runtime.GOOS == "windows" {
		// PowerShell: Execute command, then output the new working directory
		// We use a marker to separate command output from state info
		wrappedCommand = fmt.Sprintf(`
$ErrorActionPreference = 'Continue'
try {
    %s
} finally {
    Write-Host "___IRONGUARD_STATE___"
    Write-Host "CWD:$((Get-Location).Path)"
}
`, command)
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", wrappedCommand)
	} else {
		// Bash: Execute command, then output the new working directory
		wrappedCommand = fmt.Sprintf(`
%s
__exit_code=$?
echo "___IRONGUARD_STATE___"
echo "CWD:$(pwd)"
exit $__exit_code
`, command)
		cmd = exec.CommandContext(ctx, "bash", "-c", wrappedCommand)
	}

	// Set working directory
	cmd.Dir = p.cwd

	// Build environment
	cmd.Env = os.Environ()
	for k, v := range p.env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	output, err := cmd.CombinedOutput()
	result := string(output)

	// Parse state from output
	if idx := strings.Index(result, "___IRONGUARD_STATE___"); idx != -1 {
		stateSection := result[idx:]
		result = strings.TrimSpace(result[:idx])

		// Extract CWD
		lines := strings.Split(stateSection, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "CWD:") {
				newCwd := strings.TrimPrefix(line, "CWD:")
				if newCwd != "" && dirExists(newCwd) {
					p.cwd = filepath.Clean(newCwd)
				}
			}
		}
	}

	// Handle exit code
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result += fmt.Sprintf("\n[Exit code: %d]", exitErr.ExitCode())
		} else {
			return result, fmt.Errorf("command failed: %w", err)
		}
	}

	return result, nil
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// RunCommand is the tool handler for run_command.
func RunCommand(ctx context.Context, command string, newSession bool) (string, error) {
	return defaultShellSession.Run(ctx, command, newSession)
}

// ResetShellSession resets the global shell session.
func ResetShellSession() {
	defaultShellSession.Reset()
}

// GetShellCwd returns the current working directory of the shell.
func GetShellCwd(ctx context.Context) (string, error) {
	return defaultShellSession.GetCwd(), nil
}
