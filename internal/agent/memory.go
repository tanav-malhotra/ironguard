package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MemoryEntry represents a single piece of learned information.
type MemoryEntry struct {
	ID        string    `json:"id"`
	Category  string    `json:"category"`  // e.g., "vulnerability", "config", "command", "finding"
	Content   string    `json:"content"`   // The actual information
	Source    string    `json:"source"`    // Where this was learned (e.g., "web_search", "file_read")
	OS        string    `json:"os"`        // Which OS this applies to (or "all")
	CreatedAt time.Time `json:"created_at"`
	UsedCount int       `json:"used_count"` // How many times this was referenced
}

// Memory manages persistent learnings across sessions.
type Memory struct {
	Entries []MemoryEntry `json:"entries"`
	mu      sync.RWMutex
	path    string // Path to memory file
}

// NewMemory creates a new memory manager.
func NewMemory() *Memory {
	m := &Memory{
		Entries: make([]MemoryEntry, 0),
	}
	
	// Determine memory file path
	homeDir, err := os.UserHomeDir()
	if err == nil {
		m.path = filepath.Join(homeDir, ".ironguard", "memory.json")
	}
	
	return m
}

// Load loads memory from disk.
func (m *Memory) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.path == "" {
		return fmt.Errorf("no memory path configured")
	}
	
	data, err := os.ReadFile(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			// No memory file yet, that's fine
			return nil
		}
		return fmt.Errorf("failed to read memory: %w", err)
	}
	
	return json.Unmarshal(data, &m.Entries)
}

// Save saves memory to disk.
func (m *Memory) Save() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.path == "" {
		return fmt.Errorf("no memory path configured")
	}
	
	// Ensure directory exists
	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create memory directory: %w", err)
	}
	
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal memory: %w", err)
	}
	
	return os.WriteFile(m.path, data, 0600)
}

// Add adds a new memory entry.
func (m *Memory) Add(category, content, source, os string) *MemoryEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	entry := MemoryEntry{
		ID:        fmt.Sprintf("mem_%d", time.Now().UnixNano()),
		Category:  category,
		Content:   content,
		Source:    source,
		OS:        os,
		CreatedAt: time.Now(),
		UsedCount: 0,
	}
	
	m.Entries = append(m.Entries, entry)
	return &entry
}

// Search searches memory for relevant entries.
func (m *Memory) Search(query string, category string, os string) []MemoryEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	var results []MemoryEntry
	
	for _, entry := range m.Entries {
		// Filter by category if specified
		if category != "" && entry.Category != category {
			continue
		}
		
		// Filter by OS if specified
		if os != "" && entry.OS != "all" && entry.OS != os {
			continue
		}
		
		// Simple substring match for now
		// Could be enhanced with fuzzy matching or embeddings
		if query == "" || containsIgnoreCase(entry.Content, query) || containsIgnoreCase(entry.Category, query) {
			results = append(results, entry)
		}
	}
	
	return results
}

// GetByCategory returns all entries in a category.
func (m *Memory) GetByCategory(category string) []MemoryEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	var results []MemoryEntry
	for _, entry := range m.Entries {
		if entry.Category == category {
			results = append(results, entry)
		}
	}
	return results
}

// GetForOS returns entries applicable to a specific OS.
func (m *Memory) GetForOS(os string) []MemoryEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	var results []MemoryEntry
	for _, entry := range m.Entries {
		if entry.OS == "all" || entry.OS == os {
			results = append(results, entry)
		}
	}
	return results
}

// IncrementUsage increments the usage count for an entry.
func (m *Memory) IncrementUsage(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	for i := range m.Entries {
		if m.Entries[i].ID == id {
			m.Entries[i].UsedCount++
			return
		}
	}
}

// Delete removes a memory entry.
func (m *Memory) Delete(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	for i := range m.Entries {
		if m.Entries[i].ID == id {
			m.Entries = append(m.Entries[:i], m.Entries[i+1:]...)
			return true
		}
	}
	return false
}

// Clear removes all memory entries.
func (m *Memory) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Entries = make([]MemoryEntry, 0)
}

// Count returns the number of memory entries.
func (m *Memory) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.Entries)
}

// GetSummary returns a summary of memory contents for the AI.
func (m *Memory) GetSummary() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if len(m.Entries) == 0 {
		return ""
	}
	
	// Group by category
	categories := make(map[string][]MemoryEntry)
	for _, entry := range m.Entries {
		categories[entry.Category] = append(categories[entry.Category], entry)
	}
	
	summary := "=== REMEMBERED FROM PREVIOUS SESSIONS ===\n\n"
	
	// Show progress first (most important for restart recovery)
	if progress, ok := categories["progress"]; ok && len(progress) > 0 {
		summary += "[PROGRESS - RESTART RECOVERY]\n"
		// Show most recent progress entries (last 3)
		start := 0
		if len(progress) > 3 {
			start = len(progress) - 3
		}
		for i := start; i < len(progress); i++ {
			summary += fmt.Sprintf("  → %s\n", truncateString(progress[i].Content, 150))
		}
		summary += "\n"
	}
	
	// Show other categories
	for cat, entries := range categories {
		if cat == "progress" {
			continue // Already shown
		}
		summary += fmt.Sprintf("[%s] (%d entries)\n", cat, len(entries))
		// Show up to 3 most used entries per category
		shown := 0
		for _, e := range entries {
			if shown >= 3 {
				break
			}
			summary += fmt.Sprintf("  • %s\n", truncateString(e.Content, 100))
			shown++
		}
	}
	
	return summary
}

// GetProgress returns the most recent progress entry for restart recovery.
func (m *Memory) GetProgress() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	var latest *MemoryEntry
	for i := range m.Entries {
		if m.Entries[i].Category == "progress" {
			if latest == nil || m.Entries[i].CreatedAt.After(latest.CreatedAt) {
				latest = &m.Entries[i]
			}
		}
	}
	
	if latest != nil {
		return latest.Content
	}
	return ""
}

// ClearProgress removes all progress entries (call when starting fresh).
func (m *Memory) ClearProgress() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	filtered := make([]MemoryEntry, 0)
	for _, e := range m.Entries {
		if e.Category != "progress" {
			filtered = append(filtered, e)
		}
	}
	m.Entries = filtered
}

// containsIgnoreCase checks if s contains substr (case insensitive).
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

