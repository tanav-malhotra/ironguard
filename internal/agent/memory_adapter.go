package agent

import "github.com/tanav-malhotra/ironguard/internal/tools"

// MemoryManagerAdapter adapts the agent's Memory to the tools.MemoryManager interface.
type MemoryManagerAdapter struct {
	memory *Memory
}

// NewMemoryManagerAdapter creates a new adapter.
func NewMemoryManagerAdapter(m *Memory) *MemoryManagerAdapter {
	return &MemoryManagerAdapter{memory: m}
}

// Add adds a new memory entry.
func (a *MemoryManagerAdapter) Add(category, content, source, os string) *tools.MemoryEntry {
	entry := a.memory.Add(category, content, source, os)
	return &tools.MemoryEntry{
		ID:        entry.ID,
		Category:  entry.Category,
		Content:   entry.Content,
		Source:    entry.Source,
		OS:        entry.OS,
		UsedCount: entry.UsedCount,
	}
}

// Search searches memory for relevant entries.
func (a *MemoryManagerAdapter) Search(query, category, os string) []tools.MemoryEntry {
	entries := a.memory.Search(query, category, os)
	result := make([]tools.MemoryEntry, len(entries))
	for i, e := range entries {
		result[i] = tools.MemoryEntry{
			ID:        e.ID,
			Category:  e.Category,
			Content:   e.Content,
			Source:    e.Source,
			OS:        e.OS,
			UsedCount: e.UsedCount,
		}
	}
	return result
}

// Delete removes a memory entry.
func (a *MemoryManagerAdapter) Delete(id string) bool {
	return a.memory.Delete(id)
}

// GetAll returns all memory entries.
func (a *MemoryManagerAdapter) GetAll() []tools.MemoryEntry {
	entries := a.memory.Entries
	result := make([]tools.MemoryEntry, len(entries))
	for i, e := range entries {
		result[i] = tools.MemoryEntry{
			ID:        e.ID,
			Category:  e.Category,
			Content:   e.Content,
			Source:    e.Source,
			OS:        e.OS,
			UsedCount: e.UsedCount,
		}
	}
	return result
}

// Count returns the number of memory entries.
func (a *MemoryManagerAdapter) Count() int {
	return a.memory.Count()
}

// Save saves memory to disk.
func (a *MemoryManagerAdapter) Save() error {
	return a.memory.Save()
}

