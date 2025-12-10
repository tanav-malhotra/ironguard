package llm

import (
	"context"
	"encoding/json"
)

// Provider represents an LLM provider type.
type Provider string

const (
	ProviderClaude Provider = "claude"
	ProviderOpenAI Provider = "openai"
	ProviderGemini Provider = "gemini"
	ProviderLocal  Provider = "local"
)

// Message represents a chat message.
type Message struct {
	Role    string `json:"role"` // "user", "assistant", "system", "tool"
	Content string `json:"content"`

	// For tool calls (assistant requesting tool use)
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`

	// For tool results
	ToolCallID string `json:"tool_call_id,omitempty"`
	Name       string `json:"name,omitempty"` // tool name for tool results

	// Multi-modal content (images)
	Images []ImageContent `json:"images,omitempty"`
}

// ImageContent represents an image attachment.
type ImageContent struct {
	Data      []byte `json:"-"`          // Raw image data (not serialized)
	MediaType string `json:"media_type"` // "image/jpeg", "image/png", "image/gif", "image/webp"
	Path      string `json:"path"`       // Original file path (for reference)
}

// ToolCall represents a tool/function call requested by the model.
type ToolCall struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// Tool defines a tool/function that the model can call.
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"` // JSON Schema
}

// ReasoningLevel controls how hard the model thinks.
type ReasoningLevel string

const (
	ReasoningLow    ReasoningLevel = "low"
	ReasoningMedium ReasoningLevel = "medium"
	ReasoningHigh   ReasoningLevel = "high" // Default for competition - maximum accuracy
)

// ChatRequest represents a request to the LLM.
type ChatRequest struct {
	Messages       []Message
	Tools          []Tool
	MaxTokens      int
	Temperature    float64
	SystemPrompt   string
	ReasoningLevel ReasoningLevel // Controls thinking depth - default "high" for competition
	Model          string         // Optional: override the default model (used for summarization)
}

// ChatResponse represents a response from the LLM.
type ChatResponse struct {
	Content    string
	ToolCalls  []ToolCall
	FinishReason string // "stop", "tool_calls", "length", etc.
	Usage      Usage
}

// Usage tracks token usage.
type Usage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
}

// StreamDelta represents a streaming chunk from the LLM.
type StreamDelta struct {
	Content   string
	ToolCalls []ToolCall
	Done      bool
	Error     error
	Thinking  string // Extended thinking/reasoning content
}

// Client is the interface for LLM providers.
type Client interface {
	// Chat sends a chat request and returns the complete response.
	Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error)

	// ChatStream sends a chat request and streams the response.
	ChatStream(ctx context.Context, req ChatRequest, callback func(StreamDelta)) error

	// Provider returns the provider type.
	Provider() Provider

	// Models returns available models for this provider.
	Models() []string

	// SetAPIKey sets the API key for this client.
	SetAPIKey(key string)

	// HasAPIKey returns true if an API key is configured.
	HasAPIKey() bool

	// ValidateAPIKey tests if the API key is valid by making a minimal API call.
	// Returns nil if valid, error with details if invalid.
	ValidateAPIKey(ctx context.Context) error
}

// ModelPresets contains recommended models per provider.
// Only the most powerful models - we need maximum capability to win CyberPatriot.
var ModelPresets = map[Provider][]string{
	ProviderClaude: {
		"claude-opus-4-5", // Most powerful - DEFAULT
	},
	ProviderOpenAI: {
		"gpt-5.1",           // Latest flagship - DEFAULT
		"gpt-5.1-codex-max", // Maximum capability codex (same price as regular codex)
	},
	ProviderGemini: {
		"gemini-3-pro-preview", // Latest flagship (preview)
	},
}

// DefaultModel returns the default model for a provider.
func DefaultModel(p Provider) string {
	models := ModelPresets[p]
	if len(models) > 0 {
		return models[0]
	}
	return ""
}

