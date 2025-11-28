package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// ManualTaskCallback is called when a manual task is added.
type ManualTaskCallback func(description, reason, priority string) string

// ManualTaskStore stores tasks that require user action.
type ManualTaskStore struct {
	tasks      []ManualTaskEntry
	mu         sync.RWMutex
	onAdd      ManualTaskCallback
}

// ManualTaskEntry represents a single manual task.
type ManualTaskEntry struct {
	ID          int
	Description string
	Reason      string
	Priority    string
	Done        bool
}

var globalManualTaskStore = &ManualTaskStore{
	tasks: make([]ManualTaskEntry, 0),
}

// SetManualTaskCallback sets the callback for when tasks are added.
func SetManualTaskCallback(cb ManualTaskCallback) {
	globalManualTaskStore.onAdd = cb
}

// GetManualTasks returns all manual tasks.
func GetManualTasks() []ManualTaskEntry {
	globalManualTaskStore.mu.RLock()
	defer globalManualTaskStore.mu.RUnlock()
	return append([]ManualTaskEntry{}, globalManualTaskStore.tasks...)
}

// RegisterManualTaskTools adds tools for managing manual tasks.
func (r *Registry) RegisterManualTaskTools() {
	// Add manual task tool
	r.Register(&Tool{
		Name:        "add_manual_task",
		Description: "Add a task for the user to complete manually. Use this when something requires GUI interaction, browser settings, or actions you cannot perform via terminal. The task will appear in the sidebar.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"description": map[string]interface{}{
					"type":        "string",
					"description": "What the user needs to do (be specific)",
				},
				"reason": map[string]interface{}{
					"type":        "string",
					"description": "Why you can't do this yourself (e.g., 'requires GUI', 'needs browser')",
				},
				"priority": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"high", "medium", "low"},
					"description": "How important this task is",
				},
			},
			"required": []string{"description"},
		},
		Handler:  toolAddManualTask,
		Mutating: false,
	})

	// List manual tasks tool
	r.Register(&Tool{
		Name:        "list_manual_tasks",
		Description: "List all manual tasks that have been added for the user.",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler:  toolListManualTasks,
		Mutating: false,
	})
}

func toolAddManualTask(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Description string `json:"description"`
		Reason      string `json:"reason"`
		Priority    string `json:"priority"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	if params.Priority == "" {
		params.Priority = "medium"
	}

	globalManualTaskStore.mu.Lock()
	id := len(globalManualTaskStore.tasks) + 1
	entry := ManualTaskEntry{
		ID:          id,
		Description: params.Description,
		Reason:      params.Reason,
		Priority:    params.Priority,
		Done:        false,
	}
	globalManualTaskStore.tasks = append(globalManualTaskStore.tasks, entry)
	globalManualTaskStore.mu.Unlock()

	// Call callback if set
	if globalManualTaskStore.onAdd != nil {
		globalManualTaskStore.onAdd(params.Description, params.Reason, params.Priority)
	}

	result := fmt.Sprintf("Added manual task #%d: %s", id, params.Description)
	if params.Reason != "" {
		result += fmt.Sprintf(" (Reason: %s)", params.Reason)
	}
	return result, nil
}

func toolListManualTasks(ctx context.Context, args json.RawMessage) (string, error) {
	globalManualTaskStore.mu.RLock()
	defer globalManualTaskStore.mu.RUnlock()

	if len(globalManualTaskStore.tasks) == 0 {
		return "No manual tasks have been added.", nil
	}

	var result string
	result = "Manual tasks for user:\n"
	for _, t := range globalManualTaskStore.tasks {
		status := "[ ]"
		if t.Done {
			status = "[✓]"
		}
		result += fmt.Sprintf("%d. %s %s", t.ID, status, t.Description)
		if t.Reason != "" {
			result += fmt.Sprintf(" (Reason: %s)", t.Reason)
		}
		result += "\n"
	}

	return result, nil
}

// MarkManualTaskDone marks a task as completed.
func MarkManualTaskDone(id int) bool {
	globalManualTaskStore.mu.Lock()
	defer globalManualTaskStore.mu.Unlock()

	for i := range globalManualTaskStore.tasks {
		if globalManualTaskStore.tasks[i].ID == id {
			globalManualTaskStore.tasks[i].Done = true
			return true
		}
	}
	return false
}

// ClearManualTasks removes all tasks.
func ClearManualTasks() {
	globalManualTaskStore.mu.Lock()
	defer globalManualTaskStore.mu.Unlock()
	globalManualTaskStore.tasks = make([]ManualTaskEntry, 0)
}

