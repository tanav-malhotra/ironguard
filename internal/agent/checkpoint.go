package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CheckpointType represents the type of action that was checkpointed.
type CheckpointType string

const (
	CheckpointFileEdit    CheckpointType = "file_edit"
	CheckpointFileCreate  CheckpointType = "file_create"
	CheckpointFileDelete  CheckpointType = "file_delete"
	CheckpointCommand     CheckpointType = "command"
	CheckpointUserCreate  CheckpointType = "user_create"
	CheckpointUserDelete  CheckpointType = "user_delete"
	CheckpointUserModify  CheckpointType = "user_modify"
	CheckpointService     CheckpointType = "service"
	CheckpointFirewall    CheckpointType = "firewall"
	CheckpointRegistry    CheckpointType = "registry"
	CheckpointOther       CheckpointType = "other"
)

// Checkpoint represents a single undoable action.
type Checkpoint struct {
	ID          string         `json:"id"`
	Type        CheckpointType `json:"type"`
	Description string         `json:"description"`
	Timestamp   time.Time      `json:"timestamp"`
	
	// For file operations
	FilePath        string `json:"file_path,omitempty"`
	OriginalContent []byte `json:"original_content,omitempty"` // Content before change
	NewContent      []byte `json:"new_content,omitempty"`      // Content after change (for redo)
	FileExisted     bool   `json:"file_existed,omitempty"`     // Whether file existed before
	
	// For commands
	Command       string `json:"command,omitempty"`
	UndoCommand   string `json:"undo_command,omitempty"` // Command to reverse the action
	CommandOutput string `json:"command_output,omitempty"`
	
	// State
	Undone bool `json:"undone"`
}

// CheckpointManager manages the checkpoint/undo system.
type CheckpointManager struct {
	checkpoints []Checkpoint
	mu          sync.RWMutex
	maxHistory  int // Maximum number of checkpoints to keep
}

// NewCheckpointManager creates a new checkpoint manager.
func NewCheckpointManager() *CheckpointManager {
	return &CheckpointManager{
		checkpoints: make([]Checkpoint, 0),
		maxHistory:  100, // Keep last 100 checkpoints
	}
}

// CreateFileCheckpoint creates a checkpoint before modifying a file.
func (cm *CheckpointManager) CreateFileCheckpoint(filePath, description string) (*Checkpoint, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	// Read current file content
	var originalContent []byte
	fileExisted := false
	
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath
	}
	
	if content, err := os.ReadFile(absPath); err == nil {
		originalContent = content
		fileExisted = true
	}
	
	cp := Checkpoint{
		ID:              fmt.Sprintf("cp_%d", time.Now().UnixNano()),
		Type:            CheckpointFileEdit,
		Description:     description,
		Timestamp:       time.Now(),
		FilePath:        absPath,
		OriginalContent: originalContent,
		FileExisted:     fileExisted,
		Undone:          false,
	}
	
	cm.addCheckpoint(cp)
	return &cp, nil
}

// CreateFileDeleteCheckpoint creates a checkpoint before deleting a file.
func (cm *CheckpointManager) CreateFileDeleteCheckpoint(filePath string) (*Checkpoint, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath
	}
	
	// Read current file content before deletion
	content, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("cannot checkpoint file that doesn't exist: %w", err)
	}
	
	cp := Checkpoint{
		ID:              fmt.Sprintf("cp_%d", time.Now().UnixNano()),
		Type:            CheckpointFileDelete,
		Description:     fmt.Sprintf("Delete file: %s", filePath),
		Timestamp:       time.Now(),
		FilePath:        absPath,
		OriginalContent: content,
		FileExisted:     true,
		Undone:          false,
	}
	
	cm.addCheckpoint(cp)
	return &cp, nil
}

// CreateCommandCheckpoint creates a checkpoint for a command execution.
func (cm *CheckpointManager) CreateCommandCheckpoint(command, undoCommand, description string) *Checkpoint {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	cp := Checkpoint{
		ID:          fmt.Sprintf("cp_%d", time.Now().UnixNano()),
		Type:        CheckpointCommand,
		Description: description,
		Timestamp:   time.Now(),
		Command:     command,
		UndoCommand: undoCommand,
		Undone:      false,
	}
	
	cm.addCheckpoint(cp)
	return &cp
}

// UpdateCheckpointNewContent updates a checkpoint with the new content after a file edit.
func (cm *CheckpointManager) UpdateCheckpointNewContent(id string, newContent []byte) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	for i := range cm.checkpoints {
		if cm.checkpoints[i].ID == id {
			cm.checkpoints[i].NewContent = newContent
			return
		}
	}
}

// addCheckpoint adds a checkpoint to the history, pruning old ones if needed.
func (cm *CheckpointManager) addCheckpoint(cp Checkpoint) {
	cm.checkpoints = append(cm.checkpoints, cp)
	
	// Prune old checkpoints if over limit
	if len(cm.checkpoints) > cm.maxHistory {
		cm.checkpoints = cm.checkpoints[len(cm.checkpoints)-cm.maxHistory:]
	}
}

// Undo reverts the most recent non-undone checkpoint.
func (cm *CheckpointManager) Undo() (*Checkpoint, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	// Find the most recent non-undone checkpoint
	for i := len(cm.checkpoints) - 1; i >= 0; i-- {
		cp := &cm.checkpoints[i]
		if !cp.Undone {
			if err := cm.undoCheckpoint(cp); err != nil {
				return nil, err
			}
			cp.Undone = true
			return cp, nil
		}
	}
	
	return nil, fmt.Errorf("no checkpoints to undo")
}

// UndoByID reverts a specific checkpoint by ID.
func (cm *CheckpointManager) UndoByID(id string) (*Checkpoint, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	for i := range cm.checkpoints {
		if cm.checkpoints[i].ID == id && !cm.checkpoints[i].Undone {
			if err := cm.undoCheckpoint(&cm.checkpoints[i]); err != nil {
				return nil, err
			}
			cm.checkpoints[i].Undone = true
			return &cm.checkpoints[i], nil
		}
	}
	
	return nil, fmt.Errorf("checkpoint not found or already undone: %s", id)
}

// undoCheckpoint performs the actual undo operation.
func (cm *CheckpointManager) undoCheckpoint(cp *Checkpoint) error {
	switch cp.Type {
	case CheckpointFileEdit, CheckpointFileCreate:
		if cp.FileExisted {
			// Restore original content
			return os.WriteFile(cp.FilePath, cp.OriginalContent, 0644)
		} else {
			// File was created, delete it
			return os.Remove(cp.FilePath)
		}
		
	case CheckpointFileDelete:
		// Restore deleted file
		return os.WriteFile(cp.FilePath, cp.OriginalContent, 0644)
		
	case CheckpointCommand:
		// Commands with undo commands would need to be executed
		// This is informational - actual undo would need shell execution
		if cp.UndoCommand == "" {
			return fmt.Errorf("no undo command available for: %s", cp.Description)
		}
		// Return nil - the caller should execute the undo command
		return nil
		
	default:
		return fmt.Errorf("cannot undo checkpoint type: %s", cp.Type)
	}
}

// ListCheckpoints returns all checkpoints (most recent first).
func (cm *CheckpointManager) ListCheckpoints() []Checkpoint {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	// Return in reverse order (most recent first)
	result := make([]Checkpoint, len(cm.checkpoints))
	for i, cp := range cm.checkpoints {
		result[len(cm.checkpoints)-1-i] = cp
	}
	return result
}

// ListUndoable returns only checkpoints that can still be undone.
func (cm *CheckpointManager) ListUndoable() []Checkpoint {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	var result []Checkpoint
	for i := len(cm.checkpoints) - 1; i >= 0; i-- {
		if !cm.checkpoints[i].Undone {
			result = append(result, cm.checkpoints[i])
		}
	}
	return result
}

// GetCheckpoint returns a checkpoint by ID.
func (cm *CheckpointManager) GetCheckpoint(id string) (*Checkpoint, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	for i := range cm.checkpoints {
		if cm.checkpoints[i].ID == id {
			return &cm.checkpoints[i], true
		}
	}
	return nil, false
}

// Clear removes all checkpoints.
func (cm *CheckpointManager) Clear() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.checkpoints = make([]Checkpoint, 0)
}

// Count returns the number of checkpoints.
func (cm *CheckpointManager) Count() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.checkpoints)
}

// UndoableCount returns the number of checkpoints that can be undone.
func (cm *CheckpointManager) UndoableCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	count := 0
	for _, cp := range cm.checkpoints {
		if !cp.Undone {
			count++
		}
	}
	return count
}

