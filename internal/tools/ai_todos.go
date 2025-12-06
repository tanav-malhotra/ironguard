package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AITodoEntry represents a task the AI created for itself.
type AITodoEntry struct {
	ID          int       `json:"id"`
	Description string    `json:"description"`
	Status      string    `json:"status"` // "pending", "in_progress", "completed", "cancelled"
	Priority    string    `json:"priority"` // "high", "medium", "low"
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AITodoStore stores the AI's task list.
type AITodoStore struct {
	todos  []AITodoEntry
	nextID int
	mu     sync.RWMutex
}

var globalAITodoStore = &AITodoStore{
	todos:  make([]AITodoEntry, 0),
	nextID: 1,
}

// GetAITodoStore returns the global AI todo store for direct manipulation.
func GetAITodoStore() *AITodoStore {
	return globalAITodoStore
}

// GetAITodos returns all AI todos.
func GetAITodos() []AITodoEntry {
	globalAITodoStore.mu.RLock()
	defer globalAITodoStore.mu.RUnlock()
	return append([]AITodoEntry{}, globalAITodoStore.todos...)
}

// UpdateStatus updates the status of a todo by ID.
func (s *AITodoStore) UpdateStatus(id int, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.todos {
		if s.todos[i].ID == id {
			s.todos[i].Status = status
			s.todos[i].UpdatedAt = time.Now()
			return nil
		}
	}
	return fmt.Errorf("task #%d not found", id)
}

// Delete removes a todo by ID.
func (s *AITodoStore) Delete(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.todos {
		if s.todos[i].ID == id {
			s.todos = append(s.todos[:i], s.todos[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("task #%d not found", id)
}

// ClearAITodos removes all AI todos.
func ClearAITodos() {
	globalAITodoStore.mu.Lock()
	defer globalAITodoStore.mu.Unlock()
	globalAITodoStore.todos = make([]AITodoEntry, 0)
	globalAITodoStore.nextID = 1
}

// RegisterAITodoTools adds tools for AI to manage its own task list.
func (r *Registry) RegisterAITodoTools() {
	// Create todo
	r.Register(&Tool{
		Name:        "create_todo",
		Description: "Create a new task for yourself to track. Use this to plan your work and keep track of what needs to be done. Tasks appear in the sidebar.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"description": map[string]interface{}{
					"type":        "string",
					"description": "What needs to be done",
				},
				"priority": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"high", "medium", "low"},
					"description": "Task priority (default: medium)",
				},
			},
			"required": []string{"description"},
		},
		Handler:  toolCreateTodo,
		Mutating: false,
	})

	// List todos
	r.Register(&Tool{
		Name:        "list_todos",
		Description: "List all your current tasks and their status.",
		Parameters: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
		Handler:  toolListTodos,
		Mutating: false,
	})

	// Update todo status
	r.Register(&Tool{
		Name:        "update_todo",
		Description: "Update the status of a task. Use 'in_progress' when starting, 'completed' when done, 'cancelled' if no longer needed.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "integer",
					"description": "Task ID to update",
				},
				"status": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"pending", "in_progress", "completed", "cancelled"},
					"description": "New status",
				},
			},
			"required": []string{"id", "status"},
		},
		Handler:  toolUpdateTodo,
		Mutating: false,
	})

	// Delete todo
	r.Register(&Tool{
		Name:        "delete_todo",
		Description: "Delete a task from your list.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "integer",
					"description": "Task ID to delete",
				},
			},
			"required": []string{"id"},
		},
		Handler:  toolDeleteTodo,
		Mutating: false,
	})

	// Bulk create todos (for planning)
	r.Register(&Tool{
		Name:        "plan_tasks",
		Description: "Create multiple tasks at once for planning. Use this when you want to break down a complex goal into steps.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tasks": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"description": map[string]interface{}{
								"type": "string",
							},
							"priority": map[string]interface{}{
								"type": "string",
								"enum": []string{"high", "medium", "low"},
							},
						},
						"required": []string{"description"},
					},
					"description": "Array of tasks to create",
				},
			},
			"required": []string{"tasks"},
		},
		Handler:  toolPlanTasks,
		Mutating: false,
	})
}

func toolCreateTodo(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Description string `json:"description"`
		Priority    string `json:"priority"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	if params.Priority == "" {
		params.Priority = "medium"
	}

	globalAITodoStore.mu.Lock()
	todo := AITodoEntry{
		ID:          globalAITodoStore.nextID,
		Description: params.Description,
		Status:      "pending",
		Priority:    params.Priority,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	globalAITodoStore.todos = append(globalAITodoStore.todos, todo)
	globalAITodoStore.nextID++
	globalAITodoStore.mu.Unlock()

	return fmt.Sprintf("Created task #%d: %s [%s priority]", todo.ID, todo.Description, todo.Priority), nil
}

func toolListTodos(ctx context.Context, args json.RawMessage) (string, error) {
	globalAITodoStore.mu.RLock()
	defer globalAITodoStore.mu.RUnlock()

	if len(globalAITodoStore.todos) == 0 {
		return "No tasks in your todo list.", nil
	}

	var result string
	result = "📋 YOUR TASK LIST:\n"

	statusIcons := map[string]string{
		"pending":     "○",
		"in_progress": "◐",
		"completed":   "●",
		"cancelled":   "✗",
	}

	priorityIcons := map[string]string{
		"high":   "🔴",
		"medium": "🟡",
		"low":    "🟢",
	}

	for _, t := range globalAITodoStore.todos {
		icon := statusIcons[t.Status]
		pIcon := priorityIcons[t.Priority]
		result += fmt.Sprintf("  %s %s #%d: %s [%s]\n", icon, pIcon, t.ID, t.Description, t.Status)
	}

	// Summary
	pending, inProgress, completed := 0, 0, 0
	for _, t := range globalAITodoStore.todos {
		switch t.Status {
		case "pending":
			pending++
		case "in_progress":
			inProgress++
		case "completed":
			completed++
		}
	}
	result += fmt.Sprintf("\nSummary: %d pending, %d in progress, %d completed", pending, inProgress, completed)

	return result, nil
}

func toolUpdateTodo(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		ID     int    `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	globalAITodoStore.mu.Lock()
	defer globalAITodoStore.mu.Unlock()

	for i := range globalAITodoStore.todos {
		if globalAITodoStore.todos[i].ID == params.ID {
			oldStatus := globalAITodoStore.todos[i].Status
			globalAITodoStore.todos[i].Status = params.Status
			globalAITodoStore.todos[i].UpdatedAt = time.Now()
			return fmt.Sprintf("Task #%d: %s → %s", params.ID, oldStatus, params.Status), nil
		}
	}

	return "", fmt.Errorf("task #%d not found", params.ID)
}

func toolDeleteTodo(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	globalAITodoStore.mu.Lock()
	defer globalAITodoStore.mu.Unlock()

	for i := range globalAITodoStore.todos {
		if globalAITodoStore.todos[i].ID == params.ID {
			desc := globalAITodoStore.todos[i].Description
			globalAITodoStore.todos = append(globalAITodoStore.todos[:i], globalAITodoStore.todos[i+1:]...)
			return fmt.Sprintf("Deleted task #%d: %s", params.ID, desc), nil
		}
	}

	return "", fmt.Errorf("task #%d not found", params.ID)
}

func toolPlanTasks(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Tasks []struct {
			Description string `json:"description"`
			Priority    string `json:"priority"`
		} `json:"tasks"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	if len(params.Tasks) == 0 {
		return "", fmt.Errorf("no tasks provided")
	}

	globalAITodoStore.mu.Lock()
	var created []int
	for _, task := range params.Tasks {
		priority := task.Priority
		if priority == "" {
			priority = "medium"
		}
		todo := AITodoEntry{
			ID:          globalAITodoStore.nextID,
			Description: task.Description,
			Status:      "pending",
			Priority:    priority,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		globalAITodoStore.todos = append(globalAITodoStore.todos, todo)
		created = append(created, todo.ID)
		globalAITodoStore.nextID++
	}
	globalAITodoStore.mu.Unlock()

	result := fmt.Sprintf("📋 Created %d tasks:\n", len(created))
	for i, task := range params.Tasks {
		result += fmt.Sprintf("  #%d: %s\n", created[i], task.Description)
	}
	return result, nil
}

