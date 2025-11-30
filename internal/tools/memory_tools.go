package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// MemoryEntry represents a single piece of learned information.
type MemoryEntry struct {
	ID        string `json:"id"`
	Category  string `json:"category"`
	Content   string `json:"content"`
	Source    string `json:"source"`
	OS        string `json:"os"`
	UsedCount int    `json:"used_count"`
}

// MemoryManager interface for the AI to interact with persistent memory.
type MemoryManager interface {
	Add(category, content, source, os string) *MemoryEntry
	Search(query, category, os string) []MemoryEntry
	Delete(id string) bool
	GetAll() []MemoryEntry
	Count() int
	Save() error
}

var (
	memoryManager   MemoryManager
	memoryManagerMu sync.RWMutex
)

// SetMemoryManager sets the global memory manager for tools to use.
func SetMemoryManager(m MemoryManager) {
	memoryManagerMu.Lock()
	defer memoryManagerMu.Unlock()
	memoryManager = m
}

// GetMemoryManager returns the current memory manager.
func GetMemoryManager() MemoryManager {
	memoryManagerMu.RLock()
	defer memoryManagerMu.RUnlock()
	return memoryManager
}

// registerMemoryTools registers memory-related tools.
func registerMemoryTools(r *Registry) {
	// Remember tool - save to persistent memory
	r.Register(&Tool{
		Name:        "remember",
		Description: "Save information to persistent memory for future sessions. Use this to remember important findings, configurations, or patterns that might be useful later.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"category": map[string]interface{}{
					"type":        "string",
					"description": "Category of information: vulnerability, config, command, finding, tip, pattern",
					"enum":        []string{"vulnerability", "config", "command", "finding", "tip", "pattern"},
				},
				"content": map[string]interface{}{
					"type":        "string",
					"description": "The information to remember",
				},
				"os": map[string]interface{}{
					"type":        "string",
					"description": "Which OS this applies to: windows, linux, ubuntu, debian, or 'all' for universal",
					"default":     "all",
				},
			},
			"required": []string{"category", "content"},
		},
		Handler:  toolRemember,
		Mutating: false,
	})

	// Recall tool - search persistent memory
	r.Register(&Tool{
		Name:        "recall",
		Description: "Search persistent memory for previously saved information. Use this to find remembered vulnerabilities, configurations, commands, or patterns.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type":        "string",
					"description": "Search query (searches content and category)",
				},
				"category": map[string]interface{}{
					"type":        "string",
					"description": "Filter by category (optional)",
				},
				"os": map[string]interface{}{
					"type":        "string",
					"description": "Filter by OS (optional)",
				},
			},
			"required": []string{},
		},
		Handler:  toolRecall,
		Mutating: false,
	})

	// Forget tool - delete from memory
	r.Register(&Tool{
		Name:        "forget",
		Description: "Delete a specific memory entry by ID. Use recall first to find the ID.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{
					"type":        "string",
					"description": "The ID of the memory entry to delete",
				},
			},
			"required": []string{"id"},
		},
		Handler:  toolForget,
		Mutating: false,
	})

	// List memories tool
	r.Register(&Tool{
		Name:        "list_memories",
		Description: "List all entries in persistent memory, optionally filtered by category.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"category": map[string]interface{}{
					"type":        "string",
					"description": "Filter by category (optional)",
				},
			},
			"required": []string{},
		},
		Handler:  toolListMemories,
		Mutating: false,
	})
}

func toolRemember(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Category string `json:"category"`
		Content  string `json:"content"`
		OS       string `json:"os"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	mm := GetMemoryManager()
	if mm == nil {
		return "", fmt.Errorf("memory system not available")
	}

	if params.OS == "" {
		params.OS = "all"
	}

	entry := mm.Add(params.Category, params.Content, "ai", params.OS)
	if err := mm.Save(); err != nil {
		return fmt.Sprintf("Remembered but failed to persist: %s", err), nil
	}

	return fmt.Sprintf("✅ Remembered [%s] (ID: %s):\n%s\n\nThis will be available in future sessions.", 
		params.Category, entry.ID, params.Content), nil
}

func toolRecall(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Query    string `json:"query"`
		Category string `json:"category"`
		OS       string `json:"os"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	mm := GetMemoryManager()
	if mm == nil {
		return "", fmt.Errorf("memory system not available")
	}

	entries := mm.Search(params.Query, params.Category, params.OS)
	
	if len(entries) == 0 {
		if params.Query != "" {
			return fmt.Sprintf("No memories found matching '%s'", params.Query), nil
		}
		return "No memories saved yet. Use 'remember' to save information for future sessions.", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🧠 Found %d memories:\n\n", len(entries)))
	
	for i, entry := range entries {
		if i >= 20 {
			sb.WriteString(fmt.Sprintf("\n... and %d more", len(entries)-20))
			break
		}
		sb.WriteString(fmt.Sprintf("[%s] ID: %s\n", entry.Category, entry.ID))
		sb.WriteString(fmt.Sprintf("  OS: %s | Used: %d times\n", entry.OS, entry.UsedCount))
		sb.WriteString(fmt.Sprintf("  Content: %s\n\n", entry.Content))
	}

	return sb.String(), nil
}

func toolForget(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	mm := GetMemoryManager()
	if mm == nil {
		return "", fmt.Errorf("memory system not available")
	}

	if mm.Delete(params.ID) {
		if err := mm.Save(); err != nil {
			return fmt.Sprintf("Deleted but failed to persist: %s", err), nil
		}
		return fmt.Sprintf("✅ Deleted memory: %s", params.ID), nil
	}

	return fmt.Sprintf("Memory not found: %s", params.ID), nil
}

func toolListMemories(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Category string `json:"category"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	mm := GetMemoryManager()
	if mm == nil {
		return "", fmt.Errorf("memory system not available")
	}

	entries := mm.GetAll()
	
	// Filter by category if specified
	if params.Category != "" {
		var filtered []MemoryEntry
		for _, e := range entries {
			if e.Category == params.Category {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	if len(entries) == 0 {
		if params.Category != "" {
			return fmt.Sprintf("No memories in category '%s'", params.Category), nil
		}
		return "No memories saved yet.", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🧠 Persistent Memory (%d entries):\n\n", len(entries)))
	
	// Group by category
	categories := make(map[string][]MemoryEntry)
	for _, e := range entries {
		categories[e.Category] = append(categories[e.Category], e)
	}
	
	for cat, catEntries := range categories {
		sb.WriteString(fmt.Sprintf("=== %s (%d) ===\n", strings.ToUpper(cat), len(catEntries)))
		for _, entry := range catEntries {
			content := entry.Content
			if len(content) > 80 {
				content = content[:77] + "..."
			}
			sb.WriteString(fmt.Sprintf("  • [%s] %s\n", entry.ID, content))
		}
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

