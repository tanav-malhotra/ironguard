package tools

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// normalizePath resolves symlinks and short paths to get canonical path
func normalizePath(path string) string {
	// First clean the path
	path = filepath.Clean(path)
	
	// Try to get the real/canonical path (resolves symlinks and short names on Windows)
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	if eval, err := filepath.EvalSymlinks(path); err == nil {
		path = eval
	}
	
	return path
}

func TestPersistentShellBasicCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	shell := newPersistentShell()
	defer shell.Reset()

	var output string
	var err error

	if runtime.GOOS == "windows" {
		output, err = shell.Run(ctx, "Write-Output 'hello world'", false)
	} else {
		output, err = shell.Run(ctx, "echo 'hello world'", false)
	}

	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if !strings.Contains(output, "hello world") {
		t.Fatalf("expected output to contain 'hello world', got: %s", output)
	}
}

func TestPersistentShellCdPersists(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	shell := newPersistentShell()
	defer shell.Reset()

	// Create a temp directory
	tmpDir := t.TempDir()

	// Change to temp directory
	var cdCmd string
	if runtime.GOOS == "windows" {
		cdCmd = "Set-Location '" + tmpDir + "'"
	} else {
		cdCmd = "cd '" + tmpDir + "'"
	}

	_, err := shell.Run(ctx, cdCmd, false)
	if err != nil {
		t.Fatalf("cd failed: %v", err)
	}

	// Verify the shell's cwd was updated
	// Use normalizePath to handle Windows short paths (8.3) vs long paths
	expectedPath := normalizePath(tmpDir)
	actualPath := normalizePath(shell.GetCwd())

	if actualPath != expectedPath {
		t.Fatalf("shell cwd %q does not match expected %q", actualPath, expectedPath)
	}

	// Verify subsequent commands run in the new directory
	var pwdCmd string
	if runtime.GOOS == "windows" {
		pwdCmd = "(Get-Location).Path"
	} else {
		pwdCmd = "pwd"
	}

	output, err := shell.Run(ctx, pwdCmd, false)
	if err != nil {
		t.Fatalf("pwd failed: %v", err)
	}

	if !strings.Contains(output, filepath.Base(tmpDir)) {
		t.Fatalf("pwd output %q does not contain expected directory name", output)
	}
}

func TestPersistentShellNewSessionResetsCwd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	shell := newPersistentShell()
	defer shell.Reset()

	originalCwd := shell.GetCwd()

	// Create and change to a temp directory
	tmpDir := t.TempDir()

	var cdCmd string
	if runtime.GOOS == "windows" {
		cdCmd = "Set-Location '" + tmpDir + "'"
	} else {
		cdCmd = "cd '" + tmpDir + "'"
	}

	_, err := shell.Run(ctx, cdCmd, false)
	if err != nil {
		t.Fatalf("cd failed: %v", err)
	}

	// Verify cwd changed
	if shell.GetCwd() == originalCwd {
		t.Fatal("expected cwd to change after cd")
	}

	// Run with new session - should reset to original cwd
	var echoCmd string
	if runtime.GOOS == "windows" {
		echoCmd = "Write-Output 'test'"
	} else {
		echoCmd = "echo 'test'"
	}

	_, err = shell.Run(ctx, echoCmd, true)
	if err != nil {
		t.Fatalf("command with new session failed: %v", err)
	}

	// The cwd should be reset (to the process's original cwd)
	resetCwd := shell.GetCwd()
	if resetCwd == filepath.Clean(tmpDir) {
		t.Fatalf("expected cwd to be reset, but still at %s", tmpDir)
	}
}

func TestPersistentShellChainedCommands(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	shell := newPersistentShell()
	defer shell.Reset()

	// Create a temp directory with a subdirectory
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	// First cd to tmpDir
	var cdCmd1 string
	if runtime.GOOS == "windows" {
		cdCmd1 = "Set-Location '" + tmpDir + "'"
	} else {
		cdCmd1 = "cd '" + tmpDir + "'"
	}

	_, err := shell.Run(ctx, cdCmd1, false)
	if err != nil {
		t.Fatalf("first cd failed: %v", err)
	}

	// Then cd to subdir (relative path should work now)
	var cdCmd2 string
	if runtime.GOOS == "windows" {
		cdCmd2 = "Set-Location 'subdir'"
	} else {
		cdCmd2 = "cd subdir"
	}

	_, err = shell.Run(ctx, cdCmd2, false)
	if err != nil {
		t.Fatalf("second cd failed: %v", err)
	}

	// Verify we're in the subdirectory
	// Use normalizePath to handle Windows short paths (8.3) vs long paths
	expectedPath := normalizePath(subDir)
	actualPath := normalizePath(shell.GetCwd())

	if actualPath != expectedPath {
		t.Fatalf("shell cwd %q does not match expected %q", actualPath, expectedPath)
	}
}

func TestPersistentShellExitCodeReported(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	shell := newPersistentShell()
	defer shell.Reset()

	// Run a command that fails
	var failCmd string
	if runtime.GOOS == "windows" {
		failCmd = "exit 42"
	} else {
		failCmd = "exit 42"
	}

	output, _ := shell.Run(ctx, failCmd, false)

	// Check that exit code is reported
	if !strings.Contains(output, "42") {
		t.Fatalf("expected output to contain exit code 42, got: %s", output)
	}
}

func TestPersistentShellGetCwd(t *testing.T) {
	shell := newPersistentShell()
	defer shell.Reset()

	cwd := shell.GetCwd()

	if cwd == "" {
		t.Fatal("GetCwd returned empty string")
	}

	// Should be an absolute path
	if !filepath.IsAbs(cwd) {
		t.Fatalf("GetCwd returned non-absolute path: %s", cwd)
	}
}

func TestPersistentShellReset(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	shell := newPersistentShell()

	// Change to a temp directory
	tmpDir := t.TempDir()

	var cdCmd string
	if runtime.GOOS == "windows" {
		cdCmd = "Set-Location '" + tmpDir + "'"
	} else {
		cdCmd = "cd '" + tmpDir + "'"
	}

	_, err := shell.Run(ctx, cdCmd, false)
	if err != nil {
		t.Fatalf("cd failed: %v", err)
	}

	// Reset
	shell.Reset()

	// Cwd should be back to original
	cwd := shell.GetCwd()
	if cwd == filepath.Clean(tmpDir) {
		t.Fatal("expected cwd to be reset after Reset()")
	}
}

func TestRunCommandToolFunction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use the exported function with new session to isolate
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "Write-Output 'tool test'"
	} else {
		cmd = "echo 'tool test'"
	}

	output, err := RunCommand(ctx, cmd, true)
	if err != nil {
		t.Fatalf("RunCommand failed: %v", err)
	}

	if !strings.Contains(output, "tool test") {
		t.Fatalf("expected output to contain 'tool test', got: %s", output)
	}

	// Clean up
	ResetShellSession()
}

func TestGetShellCwdFunction(t *testing.T) {
	ctx := context.Background()

	// Reset to known state
	ResetShellSession()

	cwd, err := GetShellCwd(ctx)
	if err != nil {
		t.Fatalf("GetShellCwd failed: %v", err)
	}

	if cwd == "" {
		t.Fatal("GetShellCwd returned empty string")
	}

	if !filepath.IsAbs(cwd) {
		t.Fatalf("GetShellCwd returned non-absolute path: %s", cwd)
	}
}
