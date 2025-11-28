package tui

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ManualTask represents a task the AI suggests for the user to do manually.
type ManualTask struct {
	ID          string
	Description string
	Reason      string    // Why AI can't do this (e.g., "requires GUI", "needs browser")
	Priority    string    // "high", "medium", "low"
	Done        bool
	CreatedAt   time.Time
	DoneAt      *time.Time
}

// ManualTaskManager manages the list of manual tasks.
type ManualTaskManager struct {
	tasks   []ManualTask
	nextID  int
	mu      sync.RWMutex
}

// NewManualTaskManager creates a new task manager.
func NewManualTaskManager() *ManualTaskManager {
	return &ManualTaskManager{
		tasks:  make([]ManualTask, 0),
		nextID: 1,
	}
}

// Add creates a new manual task.
func (m *ManualTaskManager) Add(description, reason, priority string) *ManualTask {
	m.mu.Lock()
	defer m.mu.Unlock()

	if priority == "" {
		priority = "medium"
	}

	task := ManualTask{
		ID:          fmt.Sprintf("task-%d", m.nextID),
		Description: description,
		Reason:      reason,
		Priority:    priority,
		Done:        false,
		CreatedAt:   time.Now(),
	}
	m.nextID++
	m.tasks = append(m.tasks, task)
	return &task
}

// Complete marks a task as done.
func (m *ManualTaskManager) Complete(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.tasks {
		if m.tasks[i].ID == id || fmt.Sprintf("%d", i+1) == id {
			if !m.tasks[i].Done {
				now := time.Now()
				m.tasks[i].Done = true
				m.tasks[i].DoneAt = &now
				return true
			}
		}
	}
	return false
}

// Uncomplete marks a task as not done.
func (m *ManualTaskManager) Uncomplete(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.tasks {
		if m.tasks[i].ID == id || fmt.Sprintf("%d", i+1) == id {
			if m.tasks[i].Done {
				m.tasks[i].Done = false
				m.tasks[i].DoneAt = nil
				return true
			}
		}
	}
	return false
}

// Remove deletes a task.
func (m *ManualTaskManager) Remove(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.tasks {
		if m.tasks[i].ID == id || fmt.Sprintf("%d", i+1) == id {
			m.tasks = append(m.tasks[:i], m.tasks[i+1:]...)
			return true
		}
	}
	return false
}

// All returns all tasks.
func (m *ManualTaskManager) All() []ManualTask {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]ManualTask{}, m.tasks...)
}

// Pending returns all incomplete tasks.
func (m *ManualTaskManager) Pending() []ManualTask {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var pending []ManualTask
	for _, t := range m.tasks {
		if !t.Done {
			pending = append(pending, t)
		}
	}
	return pending
}

// Completed returns all completed tasks.
func (m *ManualTaskManager) Completed() []ManualTask {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var completed []ManualTask
	for _, t := range m.tasks {
		if t.Done {
			completed = append(completed, t)
		}
	}
	return completed
}

// Count returns total and pending counts.
func (m *ManualTaskManager) Count() (total, pending, completed int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total = len(m.tasks)
	for _, t := range m.tasks {
		if t.Done {
			completed++
		} else {
			pending++
		}
	}
	return
}

// Clear removes all tasks.
func (m *ManualTaskManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tasks = make([]ManualTask, 0)
	m.nextID = 1
}

// FormatForSidebar returns a formatted string for the TUI sidebar.
func (m *ManualTaskManager) FormatForSidebar(maxWidth int) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.tasks) == 0 {
		return "  No tasks"
	}

	var sb strings.Builder
	for i, t := range m.tasks {
		// Checkbox
		checkbox := "☐"
		if t.Done {
			checkbox = "☑"
		}

		// Priority indicator
		priority := ""
		switch t.Priority {
		case "high":
			priority = "!"
		case "low":
			priority = "·"
		}

		// Truncate description if too long
		desc := t.Description
		maxDesc := maxWidth - 6 // Account for checkbox, number, priority
		if len(desc) > maxDesc {
			desc = desc[:maxDesc-3] + "..."
		}

		sb.WriteString(fmt.Sprintf("%s %d%s %s\n", checkbox, i+1, priority, desc))
	}

	return sb.String()
}

// FormatDetailed returns a detailed list of all tasks.
func (m *ManualTaskManager) FormatDetailed() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.tasks) == 0 {
		return "No manual tasks."
	}

	var sb strings.Builder
	sb.WriteString("Manual Tasks:\n")
	sb.WriteString(strings.Repeat("─", 50) + "\n")

	for i, t := range m.tasks {
		status := "[ ]"
		if t.Done {
			status = "[✓]"
		}

		priority := ""
		switch t.Priority {
		case "high":
			priority = " [HIGH]"
		case "low":
			priority = " [low]"
		}

		sb.WriteString(fmt.Sprintf("%d. %s%s %s\n", i+1, status, priority, t.Description))
		if t.Reason != "" {
			sb.WriteString(fmt.Sprintf("   Reason: %s\n", t.Reason))
		}
		if t.Done && t.DoneAt != nil {
			sb.WriteString(fmt.Sprintf("   Completed: %s\n", t.DoneAt.Format("15:04:05")))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

