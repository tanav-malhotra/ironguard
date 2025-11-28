package agent

import (
	"testing"

	"github.com/tanav-malhotra/ironguard/internal/config"
	"github.com/tanav-malhotra/ironguard/internal/llm"
)

func TestNewAgent(t *testing.T) {
	cfg := config.DefaultConfig()
	a := New(&cfg)

	if a == nil {
		t.Fatal("New returned nil")
	}

	if a.cfg == nil {
		t.Error("agent config is nil")
	}

	if a.llmRegistry == nil {
		t.Error("agent llmRegistry is nil")
	}

	if a.toolRegistry == nil {
		t.Error("agent toolRegistry is nil")
	}

	if a.events == nil {
		t.Error("agent events channel is nil")
	}
}

func TestAgentIsBusy(t *testing.T) {
	cfg := config.DefaultConfig()
	a := New(&cfg)

	// Initially not busy
	if a.IsBusy() {
		t.Error("agent should not be busy initially")
	}
}

func TestAgentSetProvider(t *testing.T) {
	cfg := config.DefaultConfig()
	a := New(&cfg)

	// Set to OpenAI
	if err := a.SetProvider("openai"); err != nil {
		t.Errorf("SetProvider failed: %v", err)
	}

	// Set to Gemini
	if err := a.SetProvider("gemini"); err != nil {
		t.Errorf("SetProvider failed: %v", err)
	}

	// Invalid provider should error
	if err := a.SetProvider("invalid"); err == nil {
		t.Error("SetProvider should fail for invalid provider")
	}
}

func TestAgentClearHistory(t *testing.T) {
	cfg := config.DefaultConfig()
	a := New(&cfg)

	// Add some messages
	a.messages = append(a.messages, llm.Message{
		Role:    "user",
		Content: "test message",
	})

	if len(a.messages) == 0 {
		t.Error("messages should not be empty")
	}

	a.ClearHistory()

	if len(a.messages) != 0 {
		t.Error("messages should be empty after ClearHistory")
	}
}

func TestAgentGetHistory(t *testing.T) {
	cfg := config.DefaultConfig()
	a := New(&cfg)

	history := a.GetHistory()

	// Should return empty slice, not nil
	if history == nil {
		t.Error("GetHistory should return empty slice, not nil")
	}
}
