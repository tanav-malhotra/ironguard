package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const claudeAPIURL = "https://api.anthropic.com/v1/messages"

// ClaudeClient implements the Client interface for Anthropic's Claude API.
type ClaudeClient struct {
	apiKey     string
	httpClient *http.Client
}

// NewClaudeClient creates a new Claude client.
func NewClaudeClient() *ClaudeClient {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	return &ClaudeClient{
		apiKey:     apiKey,
		httpClient: &http.Client{},
	}
}

func (c *ClaudeClient) Provider() Provider {
	return ProviderClaude
}

func (c *ClaudeClient) Models() []string {
	return ModelPresets[ProviderClaude]
}

func (c *ClaudeClient) SetAPIKey(key string) {
	c.apiKey = key
}

// claudeRequest is the request format for Claude API.
type claudeRequest struct {
	Model     string         `json:"model"`
	MaxTokens int            `json:"max_tokens"`
	System    string         `json:"system,omitempty"`
	Messages  []claudeMsg    `json:"messages"`
	Tools     []claudeTool   `json:"tools,omitempty"`
	Stream    bool           `json:"stream,omitempty"`
	// Extended thinking for maximum reasoning capability
	Thinking  *claudeThinking `json:"thinking,omitempty"`
}

// claudeThinking enables extended thinking mode for deeper reasoning.
type claudeThinking struct {
	Type         string `json:"type"`           // "enabled"
	BudgetTokens int    `json:"budget_tokens"`  // Max tokens for thinking
}

type claudeMsg struct {
	Role    string        `json:"role"`
	Content []claudeBlock `json:"content"`
}

type claudeBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   string          `json:"content,omitempty"`
}

type claudeTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"input_schema"`
}

type claudeResponse struct {
	ID           string        `json:"id"`
	Type         string        `json:"type"`
	Role         string        `json:"role"`
	Content      []claudeBlock `json:"content"`
	Model        string        `json:"model"`
	StopReason   string        `json:"stop_reason"`
	StopSequence string        `json:"stop_sequence"`
	Usage        claudeUsage   `json:"usage"`
}

type claudeUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type claudeStreamEvent struct {
	Type         string         `json:"type"`
	Index        int            `json:"index,omitempty"`
	ContentBlock *claudeBlock   `json:"content_block,omitempty"`
	Delta        *claudeDelta   `json:"delta,omitempty"`
	Message      *claudeResponse `json:"message,omitempty"`
}

type claudeDelta struct {
	Type        string `json:"type"`
	Text        string `json:"text,omitempty"`
	PartialJSON string `json:"partial_json,omitempty"`
	Thinking    string `json:"thinking,omitempty"` // For thinking blocks
}

func (c *ClaudeClient) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	claudeReq := c.buildRequest(req, false)
	body, err := json.Marshal(claudeReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", claudeAPIURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var claudeResp claudeResponse
	if err := json.NewDecoder(resp.Body).Decode(&claudeResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return c.parseResponse(&claudeResp), nil
}

func (c *ClaudeClient) ChatStream(ctx context.Context, req ChatRequest, callback func(StreamDelta)) error {
	if c.apiKey == "" {
		return fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	claudeReq := c.buildRequest(req, true)
	body, err := json.Marshal(claudeReq)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", claudeAPIURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	scanner := bufio.NewScanner(resp.Body)
	var currentToolCalls []ToolCall
	var toolInputBuffer strings.Builder
	var currentToolIndex int = -1
	var isThinkingBlock bool = false

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			callback(StreamDelta{Done: true, ToolCalls: currentToolCalls})
			return nil
		}

		var event claudeStreamEvent
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}

		switch event.Type {
		case "content_block_start":
			if event.ContentBlock != nil {
				switch event.ContentBlock.Type {
				case "tool_use":
					currentToolIndex = event.Index
					currentToolCalls = append(currentToolCalls, ToolCall{
						ID:   event.ContentBlock.ID,
						Name: event.ContentBlock.Name,
					})
					toolInputBuffer.Reset()
					isThinkingBlock = false
				case "thinking":
					isThinkingBlock = true
				default:
					isThinkingBlock = false
				}
			}

		case "content_block_delta":
			if event.Delta != nil {
				switch event.Delta.Type {
				case "text_delta":
					callback(StreamDelta{Content: event.Delta.Text})
				case "thinking_delta":
					// Stream thinking content
					callback(StreamDelta{Thinking: event.Delta.Thinking})
				case "input_json_delta":
					toolInputBuffer.WriteString(event.Delta.PartialJSON)
				}
			}

		case "content_block_stop":
			if currentToolIndex >= 0 && currentToolIndex < len(currentToolCalls) {
				currentToolCalls[currentToolIndex].Arguments = json.RawMessage(toolInputBuffer.String())
				currentToolIndex = -1
			}
			isThinkingBlock = false

		case "message_stop":
			callback(StreamDelta{Done: true, ToolCalls: currentToolCalls})
			return nil
		}
	}
	_ = isThinkingBlock // Suppress unused warning

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("stream error: %w", err)
	}

	return nil
}

func (c *ClaudeClient) buildRequest(req ChatRequest, stream bool) claudeRequest {
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 128000 // Maximum output for extended thinking responses
	}

	// Use provided model or default to opus-4-5
	model := req.Model
	if model == "" {
		model = "claude-opus-4-5" // Most powerful model for competition
	}

	claudeReq := claudeRequest{
		Model:     model,
		MaxTokens: maxTokens,
		System:    req.SystemPrompt,
		Stream:    stream,
		// Enable extended thinking for maximum reasoning capability
		// This makes Claude think harder and produce more accurate responses
		Thinking: &claudeThinking{
			Type:         "enabled",
			BudgetTokens: 128000, // Maximum tokens for internal reasoning
		},
	}

	// Convert messages
	for _, msg := range req.Messages {
		claudeMsg := claudeMsg{Role: msg.Role}

		if msg.Role == "tool" {
			// Tool result message
			claudeMsg.Role = "user"
			claudeMsg.Content = []claudeBlock{{
				Type:      "tool_result",
				ToolUseID: msg.ToolCallID,
				Content:   msg.Content,
			}}
		} else if len(msg.ToolCalls) > 0 {
			// Assistant message with tool calls
			for _, tc := range msg.ToolCalls {
				claudeMsg.Content = append(claudeMsg.Content, claudeBlock{
					Type:  "tool_use",
					ID:    tc.ID,
					Name:  tc.Name,
					Input: tc.Arguments,
				})
			}
		} else {
			// Regular text message
			claudeMsg.Content = []claudeBlock{{
				Type: "text",
				Text: msg.Content,
			}}
		}

		claudeReq.Messages = append(claudeReq.Messages, claudeMsg)
	}

	// Convert tools
	for _, tool := range req.Tools {
		claudeReq.Tools = append(claudeReq.Tools, claudeTool{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: tool.Parameters,
		})
	}

	return claudeReq
}

func (c *ClaudeClient) parseResponse(resp *claudeResponse) *ChatResponse {
	chatResp := &ChatResponse{
		FinishReason: resp.StopReason,
		Usage: Usage{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.InputTokens + resp.Usage.OutputTokens,
		},
	}

	for _, block := range resp.Content {
		switch block.Type {
		case "text":
			chatResp.Content += block.Text
		case "tool_use":
			chatResp.ToolCalls = append(chatResp.ToolCalls, ToolCall{
				ID:        block.ID,
				Name:      block.Name,
				Arguments: block.Input,
			})
		}
	}

	return chatResp
}

