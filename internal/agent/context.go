package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/tanav-malhotra/ironguard/internal/llm"
)

// ContextManager handles conversation context and auto-summarization.
type ContextManager struct {
	messages       []llm.Message
	maxTokens      int           // Approximate max context tokens
	summaryModel   string        // Model to use for summarization
	summaryClient  llm.Client    // Client for summarization
	mu             sync.RWMutex
}

// NewContextManager creates a new context manager.
func NewContextManager(maxTokens int) *ContextManager {
	return &ContextManager{
		messages:  make([]llm.Message, 0),
		maxTokens: maxTokens,
	}
}

// SetSummaryClient sets the client to use for context summarization.
func (cm *ContextManager) SetSummaryClient(client llm.Client, model string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.summaryClient = client
	cm.summaryModel = model
}

// AddMessage adds a message to the context.
func (cm *ContextManager) AddMessage(msg llm.Message) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.messages = append(cm.messages, msg)
}

// GetMessages returns all messages in context.
func (cm *ContextManager) GetMessages() []llm.Message {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return append([]llm.Message{}, cm.messages...)
}

// Clear removes all messages.
func (cm *ContextManager) Clear() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.messages = make([]llm.Message, 0)
}

// EstimateTokens roughly estimates token count (4 chars ≈ 1 token).
func (cm *ContextManager) EstimateTokens() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	totalChars := 0
	for _, msg := range cm.messages {
		totalChars += len(msg.Content)
		for _, tc := range msg.ToolCalls {
			totalChars += len(tc.Name) + len(tc.Arguments)
		}
	}
	return totalChars / 4
}

// NeedsSummarization returns true if context is getting too large.
func (cm *ContextManager) NeedsSummarization() bool {
	estimated := cm.EstimateTokens()
	// Summarize when we hit 80% of max tokens
	return estimated > (cm.maxTokens * 80 / 100)
}

// Summarize compresses the context by summarizing older messages.
func (cm *ContextManager) Summarize(ctx context.Context) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.summaryClient == nil {
		return fmt.Errorf("no summary client configured")
	}

	if len(cm.messages) < 10 {
		return nil // Not enough to summarize
	}

	// Keep the last 5 messages, summarize the rest
	keepCount := 5
	toSummarize := cm.messages[:len(cm.messages)-keepCount]
	toKeep := cm.messages[len(cm.messages)-keepCount:]

	// Build summary request
	var summaryContent strings.Builder
	summaryContent.WriteString("Summarize this conversation history concisely, preserving key information:\n\n")
	for _, msg := range toSummarize {
		summaryContent.WriteString(fmt.Sprintf("[%s]: %s\n", msg.Role, msg.Content))
		if len(msg.ToolCalls) > 0 {
			for _, tc := range msg.ToolCalls {
				summaryContent.WriteString(fmt.Sprintf("  [Tool: %s]\n", tc.Name))
			}
		}
	}

	req := llm.ChatRequest{
		Messages: []llm.Message{
			{Role: "user", Content: summaryContent.String()},
		},
		MaxTokens: 2000,
		SystemPrompt: `You are a conversation summarizer. Create a concise summary that preserves:
1. Key decisions made
2. Important findings (vulnerabilities found, scores achieved)
3. Actions taken and their results
4. Current state/progress
5. Any pending tasks or issues

Format as a brief narrative, not a list. Be concise but complete.`,
	}

	resp, err := cm.summaryClient.Chat(ctx, req)
	if err != nil {
		return fmt.Errorf("summarization failed: %w", err)
	}

	// Replace old messages with summary + recent messages
	summaryMsg := llm.Message{
		Role:    "system",
		Content: fmt.Sprintf("[CONTEXT SUMMARY]\n%s\n[END SUMMARY - Recent messages follow]", resp.Content),
	}

	cm.messages = append([]llm.Message{summaryMsg}, toKeep...)
	return nil
}

// GetContextSummary returns a summary of current context state.
func (cm *ContextManager) GetContextSummary() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	estimated := cm.EstimateTokens()
	percentage := (estimated * 100) / cm.maxTokens
	if percentage > 100 {
		percentage = 100
	}

	return fmt.Sprintf("Context: ~%d tokens (%d%% of %d max)", estimated, percentage, cm.maxTokens)
}

