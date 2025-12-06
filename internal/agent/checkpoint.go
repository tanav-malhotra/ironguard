package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	CheckpointManual      CheckpointType = "manual"
	CheckpointSession     CheckpointType = "session"
	CheckpointOther       CheckpointType = "other"
)

// CheckpointNode represents a single checkpoint in the tree.
type CheckpointNode struct {
	ID          int            `json:"id"`           // Sequential numbered ID
	TimeLabel   string         `json:"time_label"`   // "14:32:05 - Description"
	Timestamp   time.Time      `json:"timestamp"`
	Description string         `json:"description"`
	Type        CheckpointType `json:"type"`
	BranchName  string         `json:"branch_name"`  // e.g., "main", "branch-1"
	ParentID    *int           `json:"parent_id"`    // nil for root
	ChildIDs    []int          `json:"child_ids"`    // IDs of child nodes

	// For file operations
	FilePath        string `json:"file_path,omitempty"`
	OriginalContent []byte `json:"original_content,omitempty"`
	NewContent      []byte `json:"new_content,omitempty"`
	FileExisted     bool   `json:"file_existed,omitempty"`

	// For commands
	Command       string `json:"command,omitempty"`
	UndoCommand   string `json:"undo_command,omitempty"`
	CommandOutput string `json:"command_output,omitempty"`

	// State
	Restored bool `json:"restored"` // True if this checkpoint was restored from
}

// CheckpointTree represents the full checkpoint history as a tree.
type CheckpointTree struct {
	Nodes         map[int]*CheckpointNode `json:"nodes"`
	RootID        int                     `json:"root_id"`
	CurrentID     int                     `json:"current_id"`     // Current position in tree
	CurrentBranch string                  `json:"current_branch"`
	NextID        int                     `json:"next_id"`
	NextBranchNum int                     `json:"next_branch_num"`
}

// CheckpointManager manages the checkpoint tree system.
type CheckpointManager struct {
	tree        *CheckpointTree
	mu          sync.RWMutex
	storagePath string
	backupDir   string
	maxBackups  int
}

// NewCheckpointManager creates a new checkpoint manager.
func NewCheckpointManager() *CheckpointManager {
	homeDir, _ := os.UserHomeDir()
	storageDir := filepath.Join(homeDir, ".ironguard")
	
	cm := &CheckpointManager{
		storagePath: filepath.Join(storageDir, "checkpoints.json"),
		backupDir:   filepath.Join(storageDir, "backups"),
		maxBackups:  10,
	}
	
	// Initialize empty tree
	cm.tree = &CheckpointTree{
		Nodes:         make(map[int]*CheckpointNode),
		RootID:        0,
		CurrentID:     0,
		CurrentBranch: "main",
		NextID:        1,
		NextBranchNum: 1,
	}
	
	return cm
}

// Initialize creates the initial "Session Start" checkpoint.
func (cm *CheckpointManager) Initialize() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	// Only initialize if tree is empty
	if len(cm.tree.Nodes) > 0 {
		return
	}
	
	now := time.Now()
	timeLabel := now.Format("15:04:05") + " - Session Start"
	
	root := &CheckpointNode{
		ID:          1,
		TimeLabel:   timeLabel,
		Timestamp:   now,
		Description: "Session Start",
		Type:        CheckpointSession,
		BranchName:  "main",
		ParentID:    nil,
		ChildIDs:    []int{},
	}
	
	cm.tree.Nodes[1] = root
	cm.tree.RootID = 1
	cm.tree.CurrentID = 1
	cm.tree.NextID = 2
	
	cm.saveToBackup()
}

// Load attempts to load checkpoints from disk.
func (cm *CheckpointManager) Load() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	data, err := os.ReadFile(cm.storagePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No saved state, start fresh
		}
		return fmt.Errorf("failed to read checkpoint file: %w", err)
	}
	
	var tree CheckpointTree
	if err := json.Unmarshal(data, &tree); err != nil {
		return fmt.Errorf("failed to parse checkpoint file: %w", err)
	}
	
	cm.tree = &tree
	return nil
}

// Save persists the checkpoint tree to disk.
func (cm *CheckpointManager) Save() error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	return cm.saveInternal()
}

func (cm *CheckpointManager) saveInternal() error {
	// Ensure directory exists
	dir := filepath.Dir(cm.storagePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}
	
	data, err := json.MarshalIndent(cm.tree, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint tree: %w", err)
	}
	
	if err := os.WriteFile(cm.storagePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write checkpoint file: %w", err)
	}
	
	return nil
}

func (cm *CheckpointManager) saveToBackup() {
	// Ensure backup directory exists
	if err := os.MkdirAll(cm.backupDir, 0755); err != nil {
		return
	}
	
	// Create backup filename with timestamp
	backupName := fmt.Sprintf("checkpoints_%s.json", time.Now().Format("20060102_150405"))
	backupPath := filepath.Join(cm.backupDir, backupName)
	
	data, err := json.MarshalIndent(cm.tree, "", "  ")
	if err != nil {
		return
	}
	
	os.WriteFile(backupPath, data, 0644)
	
	// Prune old backups
	cm.pruneBackups()
}

func (cm *CheckpointManager) pruneBackups() {
	entries, err := os.ReadDir(cm.backupDir)
	if err != nil {
		return
	}
	
	// Sort by name (which includes timestamp)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	
	// Remove oldest if over limit
	for len(entries) > cm.maxBackups {
		oldest := entries[0]
		os.Remove(filepath.Join(cm.backupDir, oldest.Name()))
		entries = entries[1:]
	}
}

// CreateCheckpoint creates a new checkpoint at the current position.
func (cm *CheckpointManager) CreateCheckpoint(cpType CheckpointType, description string) *CheckpointNode {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	now := time.Now()
	timeLabel := now.Format("15:04:05") + " - " + description
	
	node := &CheckpointNode{
		ID:          cm.tree.NextID,
		TimeLabel:   timeLabel,
		Timestamp:   now,
		Description: description,
		Type:        cpType,
		BranchName:  cm.tree.CurrentBranch,
		ParentID:    &cm.tree.CurrentID,
		ChildIDs:    []int{},
	}
	
	cm.tree.NextID++
	
	// Add to parent's children
	if parent, exists := cm.tree.Nodes[cm.tree.CurrentID]; exists {
		parent.ChildIDs = append(parent.ChildIDs, node.ID)
	}
	
	cm.tree.Nodes[node.ID] = node
	cm.tree.CurrentID = node.ID
	
	cm.saveInternal()
	cm.saveToBackup()
	
	return node
}

// CreateFileCheckpoint creates a checkpoint before modifying a file.
func (cm *CheckpointManager) CreateFileCheckpoint(filePath, description string) (*CheckpointNode, error) {
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
	
	node := cm.CreateCheckpoint(CheckpointFileEdit, description)
	
	cm.mu.Lock()
	node.FilePath = absPath
	node.OriginalContent = originalContent
	node.FileExisted = fileExisted
	cm.mu.Unlock()
	
	cm.Save()
	
	return node, nil
}

// CreateFileDeleteCheckpoint creates a checkpoint before deleting a file.
func (cm *CheckpointManager) CreateFileDeleteCheckpoint(filePath string) (*CheckpointNode, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath
	}
	
	content, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("cannot checkpoint file that doesn't exist: %w", err)
	}
	
	node := cm.CreateCheckpoint(CheckpointFileDelete, fmt.Sprintf("Delete file: %s", filepath.Base(filePath)))
	
	cm.mu.Lock()
	node.FilePath = absPath
	node.OriginalContent = content
	node.FileExisted = true
	cm.mu.Unlock()
	
	cm.Save()
	
	return node, nil
}

// CreateCommandCheckpoint creates a checkpoint for a command execution.
func (cm *CheckpointManager) CreateCommandCheckpoint(command, undoCommand, description string) *CheckpointNode {
	node := cm.CreateCheckpoint(CheckpointCommand, description)
	
	cm.mu.Lock()
	node.Command = command
	node.UndoCommand = undoCommand
	cm.mu.Unlock()
	
	cm.Save()
	
	return node
}

// CreateManualCheckpoint creates a user-initiated checkpoint.
func (cm *CheckpointManager) CreateManualCheckpoint(description string) *CheckpointNode {
	if description == "" {
		description = "Manual checkpoint"
	}
	return cm.CreateCheckpoint(CheckpointManual, description)
}

// UpdateCheckpointNewContent updates a checkpoint with the new content after a file edit.
func (cm *CheckpointManager) UpdateCheckpointNewContent(id int, newContent []byte) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	if node, exists := cm.tree.Nodes[id]; exists {
		node.NewContent = newContent
		cm.saveInternal()
	}
}

// RestoreToCheckpoint restores to a specific checkpoint, creating a new branch if needed.
func (cm *CheckpointManager) RestoreToCheckpoint(id int) (*CheckpointNode, string, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	node, exists := cm.tree.Nodes[id]
	if !exists {
		return nil, "", fmt.Errorf("checkpoint not found: %d", id)
	}
	
	// If restoring to a point that already has children, create a new branch
	var newBranch string
	if len(node.ChildIDs) > 0 {
		newBranch = fmt.Sprintf("branch-%d", cm.tree.NextBranchNum)
		cm.tree.NextBranchNum++
		cm.tree.CurrentBranch = newBranch
	}
	
	// Perform the actual restore based on checkpoint type
	if err := cm.performRestore(node); err != nil {
		return nil, "", err
	}
	
	node.Restored = true
	cm.tree.CurrentID = id
	
	// Create a "Restored" checkpoint on the new branch
	now := time.Now()
	restoredNode := &CheckpointNode{
		ID:          cm.tree.NextID,
		TimeLabel:   now.Format("15:04:05") + " - Restored from #" + fmt.Sprintf("%d", id),
		Timestamp:   now,
		Description: "Restored from #" + fmt.Sprintf("%d", id),
		Type:        CheckpointManual,
		BranchName:  cm.tree.CurrentBranch,
		ParentID:    &id,
		ChildIDs:    []int{},
	}
	cm.tree.NextID++
	
	node.ChildIDs = append(node.ChildIDs, restoredNode.ID)
	cm.tree.Nodes[restoredNode.ID] = restoredNode
	cm.tree.CurrentID = restoredNode.ID
	
	cm.saveInternal()
	cm.saveToBackup()
	
	return node, newBranch, nil
}

func (cm *CheckpointManager) performRestore(node *CheckpointNode) error {
	switch node.Type {
	case CheckpointFileEdit, CheckpointFileCreate:
		if node.FileExisted {
			return os.WriteFile(node.FilePath, node.OriginalContent, 0644)
		} else {
			return os.Remove(node.FilePath)
		}
		
	case CheckpointFileDelete:
		return os.WriteFile(node.FilePath, node.OriginalContent, 0644)
		
	case CheckpointCommand:
		// Commands require manual intervention or undo command execution
		return nil
		
	case CheckpointManual, CheckpointSession:
		// No action needed for manual/session checkpoints
		return nil
		
	default:
		return nil
	}
}

// EditCheckpoint updates the description of a checkpoint.
func (cm *CheckpointManager) EditCheckpoint(id int, newDescription string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	node, exists := cm.tree.Nodes[id]
	if !exists {
		return fmt.Errorf("checkpoint not found: %d", id)
	}
	
	node.Description = newDescription
	node.TimeLabel = node.Timestamp.Format("15:04:05") + " - " + newDescription
	
	cm.saveInternal()
	return nil
}

// DeleteCheckpoint removes a checkpoint and renumbers remaining ones.
func (cm *CheckpointManager) DeleteCheckpoint(id int) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	node, exists := cm.tree.Nodes[id]
	if !exists {
		return fmt.Errorf("checkpoint not found: %d", id)
	}
	
	// Can't delete root
	if node.ParentID == nil {
		return fmt.Errorf("cannot delete root checkpoint")
	}
	
	// Can't delete if it has children (would break the tree)
	if len(node.ChildIDs) > 0 {
		return fmt.Errorf("cannot delete checkpoint with children")
	}
	
	// Remove from parent's children
	if parent, exists := cm.tree.Nodes[*node.ParentID]; exists {
		newChildren := []int{}
		for _, cid := range parent.ChildIDs {
			if cid != id {
				newChildren = append(newChildren, cid)
			}
		}
		parent.ChildIDs = newChildren
	}
	
	// If this is the current checkpoint, move to parent
	if cm.tree.CurrentID == id {
		cm.tree.CurrentID = *node.ParentID
	}
	
	delete(cm.tree.Nodes, id)
	
	// Renumber all nodes
	cm.renumberNodes()
	
	cm.saveInternal()
	cm.saveToBackup()
	
	return nil
}

func (cm *CheckpointManager) renumberNodes() {
	// Get all nodes sorted by timestamp
	var nodes []*CheckpointNode
	for _, node := range cm.tree.Nodes {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Timestamp.Before(nodes[j].Timestamp)
	})
	
	// Create ID mapping
	oldToNew := make(map[int]int)
	for i, node := range nodes {
		oldToNew[node.ID] = i + 1
	}
	
	// Update all references
	newNodes := make(map[int]*CheckpointNode)
	for _, node := range nodes {
		newID := oldToNew[node.ID]
		node.ID = newID
		
		if node.ParentID != nil {
			newParentID := oldToNew[*node.ParentID]
			node.ParentID = &newParentID
		}
		
		newChildren := []int{}
		for _, cid := range node.ChildIDs {
			newChildren = append(newChildren, oldToNew[cid])
		}
		node.ChildIDs = newChildren
		
		newNodes[newID] = node
	}
	
	cm.tree.Nodes = newNodes
	cm.tree.RootID = oldToNew[cm.tree.RootID]
	cm.tree.CurrentID = oldToNew[cm.tree.CurrentID]
	cm.tree.NextID = len(nodes) + 1
}

// Clear removes all checkpoints and starts fresh.
func (cm *CheckpointManager) Clear() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	cm.tree = &CheckpointTree{
		Nodes:         make(map[int]*CheckpointNode),
		RootID:        0,
		CurrentID:     0,
		CurrentBranch: "main",
		NextID:        1,
		NextBranchNum: 1,
	}
	
	// Remove saved file
	os.Remove(cm.storagePath)
}

// GetCheckpoint returns a checkpoint by ID.
func (cm *CheckpointManager) GetCheckpoint(id int) (*CheckpointNode, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	node, exists := cm.tree.Nodes[id]
	return node, exists
}

// GetCurrentCheckpoint returns the current checkpoint.
func (cm *CheckpointManager) GetCurrentCheckpoint() *CheckpointNode {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	return cm.tree.Nodes[cm.tree.CurrentID]
}

// GetCurrentBranch returns the current branch name.
func (cm *CheckpointManager) GetCurrentBranch() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	return cm.tree.CurrentBranch
}

// ListBranches returns all branch names.
func (cm *CheckpointManager) ListBranches() []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	branches := make(map[string]bool)
	for _, node := range cm.tree.Nodes {
		branches[node.BranchName] = true
	}
	
	result := []string{}
	for branch := range branches {
		result = append(result, branch)
	}
	sort.Strings(result)
	return result
}

// ListCheckpoints returns all checkpoints sorted by ID.
func (cm *CheckpointManager) ListCheckpoints() []*CheckpointNode {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	var nodes []*CheckpointNode
	for _, node := range cm.tree.Nodes {
		nodes = append(nodes, node)
	}
	
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})
	
	return nodes
}

// GetTree returns the full checkpoint tree for visualization.
func (cm *CheckpointManager) GetTree() *CheckpointTree {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	return cm.tree
}

// Count returns the number of checkpoints.
func (cm *CheckpointManager) Count() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.tree.Nodes)
}

// HasSavedState returns true if there's a saved checkpoint file.
func (cm *CheckpointManager) HasSavedState() bool {
	_, err := os.Stat(cm.storagePath)
	return err == nil
}

// Legacy compatibility methods

// Undo reverts to the parent checkpoint of the current one.
func (cm *CheckpointManager) Undo() (*CheckpointNode, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	current := cm.tree.Nodes[cm.tree.CurrentID]
	if current == nil || current.ParentID == nil {
		return nil, fmt.Errorf("no checkpoint to undo")
	}
	
	parent := cm.tree.Nodes[*current.ParentID]
	if parent == nil {
		return nil, fmt.Errorf("parent checkpoint not found")
	}
	
	if err := cm.performRestore(current); err != nil {
		return nil, err
	}
	
	cm.tree.CurrentID = parent.ID
	cm.saveInternal()
	
	return current, nil
}

// UndoByID is now an alias for RestoreToCheckpoint.
func (cm *CheckpointManager) UndoByID(id string) (*CheckpointNode, error) {
	var intID int
	fmt.Sscanf(id, "%d", &intID)
	node, _, err := cm.RestoreToCheckpoint(intID)
	return node, err
}

// ListUndoable returns checkpoints that can be restored to.
func (cm *CheckpointManager) ListUndoable() []*CheckpointNode {
	return cm.ListCheckpoints()
}

// UndoableCount returns the number of checkpoints.
func (cm *CheckpointManager) UndoableCount() int {
	return cm.Count()
}
