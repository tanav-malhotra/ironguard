package llm

import (
	"testing"
)

func TestModelPresets(t *testing.T) {
	providers := []Provider{ProviderClaude, ProviderOpenAI, ProviderGemini}

	for _, p := range providers {
		models, ok := ModelPresets[p]
		if !ok {
			t.Errorf("no model presets for provider %s", p)
			continue
		}
		if len(models) == 0 {
			t.Errorf("empty model presets for provider %s", p)
		}
	}
}

func TestDefaultModel(t *testing.T) {
	tests := []struct {
		provider Provider
		expected string
	}{
		{ProviderClaude, "claude-opus-4-5"},
		{ProviderOpenAI, "gpt-5.1"}, // gpt-5.1 is first in ModelPresets, so it's the default
		{ProviderGemini, "gemini-3-pro"},
	}

	for _, tt := range tests {
		t.Run(string(tt.provider), func(t *testing.T) {
			result := DefaultModel(tt.provider)
			if result != tt.expected {
				t.Errorf("DefaultModel(%s) = %s, want %s", tt.provider, result, tt.expected)
			}
		})
	}
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()

	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}

	// Check all providers are registered
	for _, p := range []Provider{ProviderClaude, ProviderOpenAI, ProviderGemini} {
		client, err := r.Get(p)
		if err != nil {
			t.Errorf("failed to get client for provider %s: %v", p, err)
		}
		if client == nil {
			t.Errorf("client for provider %s is nil", p)
		}
	}
}

func TestRegistrySetCurrent(t *testing.T) {
	r := NewRegistry()

	// Default should be Claude
	if r.CurrentProvider() != ProviderClaude {
		t.Errorf("expected default provider to be Claude, got %s", r.CurrentProvider())
	}

	// Switch to OpenAI
	if err := r.SetCurrent(ProviderOpenAI); err != nil {
		t.Errorf("failed to set current provider: %v", err)
	}

	if r.CurrentProvider() != ProviderOpenAI {
		t.Errorf("expected provider to be OpenAI, got %s", r.CurrentProvider())
	}

	// Try invalid provider
	if err := r.SetCurrent("invalid"); err == nil {
		t.Error("expected error for invalid provider")
	}
}

