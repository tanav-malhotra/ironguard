package config

import (
	"runtime"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Provider != ProviderAnthropic {
		t.Errorf("expected provider %s, got %s", ProviderAnthropic, cfg.Provider)
	}

	if cfg.Model != "claude-opus-4-5" {
		t.Errorf("expected model claude-opus-4-5, got %s", cfg.Model)
	}

	if cfg.Mode != ModeAutopilot {
		t.Errorf("expected mode %s, got %s", ModeAutopilot, cfg.Mode)
	}

	if cfg.OS != runtime.GOOS {
		t.Errorf("expected OS %s, got %s", runtime.GOOS, cfg.OS)
	}

	if cfg.Architecture != runtime.GOARCH {
		t.Errorf("expected arch %s, got %s", runtime.GOARCH, cfg.Architecture)
	}
}

func TestProviderFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected Provider
	}{
		{"claude", ProviderAnthropic},
		{"anthropic", ProviderAnthropic},
		{"openai", ProviderOpenAI},
		{"gpt", ProviderOpenAI},
		{"gemini", ProviderGemini},
		{"google", ProviderGemini},
		{"unknown", ProviderAnthropic}, // defaults to anthropic
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ProviderFromString(tt.input)
			if result != tt.expected {
				t.Errorf("ProviderFromString(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

