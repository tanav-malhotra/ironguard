package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()

	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}

	// Check that default tools are registered
	expectedTools := []string{
		"read_file",
		"write_file",
		"list_dir",
		"run_command",
		"read_readme",
		"read_forensics",
		"write_answer",
		"get_system_info",
		"search_files",
	}

	for _, name := range expectedTools {
		tool, ok := r.Get(name)
		if !ok {
			t.Errorf("expected tool %s to be registered", name)
			continue
		}
		if tool.Name != name {
			t.Errorf("tool name mismatch: got %s, want %s", tool.Name, name)
		}
	}
}

func TestToolReadFile(t *testing.T) {
	r := NewRegistry()
	ctx := context.Background()

	// Create a temp file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	testContent := "Hello, ironguard!"

	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Test reading the file
	args, _ := json.Marshal(map[string]string{"path": testFile})
	result, err := r.Execute(ctx, "read_file", args)

	if err != nil {
		t.Errorf("read_file failed: %v", err)
	}

	if result != testContent {
		t.Errorf("read_file returned %q, want %q", result, testContent)
	}
}

func TestToolWriteFile(t *testing.T) {
	r := NewRegistry()
	ctx := context.Background()

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "output.txt")
	testContent := "Written by ironguard"

	// Test writing the file
	args, _ := json.Marshal(map[string]string{
		"path":    testFile,
		"content": testContent,
	})
	_, err := r.Execute(ctx, "write_file", args)

	if err != nil {
		t.Errorf("write_file failed: %v", err)
	}

	// Verify the file was written
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Errorf("failed to read written file: %v", err)
	}

	if string(content) != testContent {
		t.Errorf("file content = %q, want %q", string(content), testContent)
	}
}

func TestToolListDir(t *testing.T) {
	r := NewRegistry()
	ctx := context.Background()

	tmpDir := t.TempDir()

	// Create some test files
	os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("test"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("test"), 0644)
	os.Mkdir(filepath.Join(tmpDir, "subdir"), 0755)

	args, _ := json.Marshal(map[string]string{"path": tmpDir})
	result, err := r.Execute(ctx, "list_dir", args)

	if err != nil {
		t.Errorf("list_dir failed: %v", err)
	}

	// Check that all items are listed
	if result == "" {
		t.Error("list_dir returned empty result")
	}
}

func TestToolIsMutating(t *testing.T) {
	r := NewRegistry()

	// Non-mutating tools
	nonMutating := []string{"read_file", "list_dir", "get_system_info", "search_files"}
	for _, name := range nonMutating {
		if r.IsMutating(name) {
			t.Errorf("tool %s should not be mutating", name)
		}
	}

	// Mutating tools
	mutating := []string{"write_file", "run_command", "write_answer"}
	for _, name := range mutating {
		if !r.IsMutating(name) {
			t.Errorf("tool %s should be mutating", name)
		}
	}
}

func TestToolGetSystemInfo(t *testing.T) {
	r := NewRegistry()
	ctx := context.Background()

	args, _ := json.Marshal(map[string]interface{}{})
	result, err := r.Execute(ctx, "get_system_info", args)

	if err != nil {
		t.Errorf("get_system_info failed: %v", err)
	}

	// Should contain OS info
	if result == "" {
		t.Error("get_system_info returned empty result")
	}
}

