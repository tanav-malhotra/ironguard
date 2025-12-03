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

const openaiAPIURL = "https://api.openai.com/v1/chat/completions"

// OpenAIClient implements the Client interface for OpenAI's API.
type OpenAIClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// NewOpenAIClient creates a new OpenAI client.
func NewOpenAIClient() *OpenAIClient {
	apiKey := os.Getenv("OPENAI_API_KEY")
	baseURL := os.Getenv("OPENAI_API_BASE")
	if baseURL == "" {
		baseURL = openaiAPIURL
	}
	return &OpenAIClient{
		apiKey:     apiKey,
		baseURL:    baseURL,
		httpClient: &http.Client{},
	}
}

func (c *OpenAIClient) Provider() Provider {
	return ProviderOpenAI
}

func (c *OpenAIClient) Models() []string {
	return ModelPresets[ProviderOpenAI]
}

func (c *OpenAIClient) SetAPIKey(key string) {
	c.apiKey = key
}

func (c *OpenAIClient) HasAPIKey() bool {
	return c.apiKey != ""
}

// OpenAI API types
type openaiRequest struct {
	Model       string        `json:"model"`
	Messages    []openaiMsg   `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature,omitempty"`
	Tools       []openaiTool  `json:"tools,omitempty"`
	Stream      bool          `json:"stream,omitempty"`
	// Reasoning effort for o1/o3/codex models - set to "high" for maximum accuracy
	ReasoningEffort string `json:"reasoning_effort,omitempty"`
}

type openaiMsg struct {
	Role       string           `json:"role"`
	Content    string           `json:"content,omitempty"`
	ToolCalls  []openaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
	Name       string           `json:"name,omitempty"`
}

type openaiToolCall struct {
	ID       string             `json:"id"`
	Type     string             `json:"type"`
	Function openaiToolFunction `json:"function"`
}

type openaiToolFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type openaiTool struct {
	Type     string             `json:"type"`
	Function openaiToolDef      `json:"function"`
}

type openaiToolDef struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

type openaiResponse struct {
	ID      string         `json:"id"`
	Object  string         `json:"object"`
	Created int64          `json:"created"`
	Model   string         `json:"model"`
	Choices []openaiChoice `json:"choices"`
	Usage   openaiUsage    `json:"usage"`
}

type openaiChoice struct {
	Index        int       `json:"index"`
	Message      openaiMsg `json:"message"`
	Delta        openaiMsg `json:"delta"`
	FinishReason string    `json:"finish_reason"`
}

type openaiUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

func (c *OpenAIClient) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("OPENAI_API_KEY not set")
	}

	openaiReq := c.buildRequest(req, false)
	body, err := json.Marshal(openaiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var openaiResp openaiResponse
	if err := json.NewDecoder(resp.Body).Decode(&openaiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return c.parseResponse(&openaiResp), nil
}

func (c *OpenAIClient) ChatStream(ctx context.Context, req ChatRequest, callback func(StreamDelta)) error {
	if c.apiKey == "" {
		return fmt.Errorf("OPENAI_API_KEY not set")
	}

	openaiReq := c.buildRequest(req, true)
	body, err := json.Marshal(openaiReq)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

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
	var toolCalls []ToolCall
	toolCallArgs := make(map[int]*strings.Builder)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			// Finalize tool call arguments
			for i, tc := range toolCalls {
				if builder, ok := toolCallArgs[i]; ok {
					toolCalls[i].Arguments = json.RawMessage(builder.String())
				} else if tc.Arguments == nil {
					toolCalls[i].Arguments = json.RawMessage("{}")
				}
			}
			callback(StreamDelta{Done: true, ToolCalls: toolCalls})
			return nil
		}

		var streamResp openaiResponse
		if err := json.Unmarshal([]byte(data), &streamResp); err != nil {
			continue
		}

		if len(streamResp.Choices) == 0 {
			continue
		}

		delta := streamResp.Choices[0].Delta

		// Handle content
		if delta.Content != "" {
			callback(StreamDelta{Content: delta.Content})
		}

		// Handle tool calls
		for _, tc := range delta.ToolCalls {
			// Find or create tool call entry
			idx := -1
			for i, existing := range toolCalls {
				if existing.ID == tc.ID || (tc.ID != "" && i == len(toolCalls)-1) {
					idx = i
					break
				}
			}

			if tc.ID != "" && idx == -1 {
				// New tool call
				toolCalls = append(toolCalls, ToolCall{
					ID:   tc.ID,
					Name: tc.Function.Name,
				})
				idx = len(toolCalls) - 1
				toolCallArgs[idx] = &strings.Builder{}
			}

			if idx >= 0 {
				if tc.Function.Name != "" {
					toolCalls[idx].Name = tc.Function.Name
				}
				if tc.Function.Arguments != "" {
					if _, ok := toolCallArgs[idx]; !ok {
						toolCallArgs[idx] = &strings.Builder{}
					}
					toolCallArgs[idx].WriteString(tc.Function.Arguments)
				}
			}
		}

		// Check for finish
		if streamResp.Choices[0].FinishReason != "" {
			// Finalize tool call arguments
			for i := range toolCalls {
				if builder, ok := toolCallArgs[i]; ok {
					toolCalls[i].Arguments = json.RawMessage(builder.String())
				}
			}
			callback(StreamDelta{Done: true, ToolCalls: toolCalls})
			return nil
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("stream error: %w", err)
	}

	return nil
}

func (c *OpenAIClient) buildRequest(req ChatRequest, stream bool) openaiRequest {
	// Use provided model or default to gpt-5.1
	model := req.Model
	if model == "" {
		model = "gpt-5.1" // Latest flagship model (272K context)
	}
	
	openaiReq := openaiRequest{
		Model:           model,
		MaxTokens:       req.MaxTokens,
		Temperature:     req.Temperature,
		Stream:          stream,
		ReasoningEffort: "high", // Maximum reasoning for accurate responses
	}

	if openaiReq.MaxTokens == 0 {
		openaiReq.MaxTokens = 100000 // Maximum output for complex tasks
	}

	// Add system message if present
	if req.SystemPrompt != "" {
		openaiReq.Messages = append(openaiReq.Messages, openaiMsg{
			Role:    "system",
			Content: req.SystemPrompt,
		})
	}

	// Convert messages
	for _, msg := range req.Messages {
		openaiMsg := openaiMsg{Role: msg.Role}

		if msg.Role == "tool" {
			openaiMsg.ToolCallID = msg.ToolCallID
			openaiMsg.Content = msg.Content
			openaiMsg.Name = msg.Name
		} else if len(msg.ToolCalls) > 0 {
			for _, tc := range msg.ToolCalls {
				openaiMsg.ToolCalls = append(openaiMsg.ToolCalls, openaiToolCall{
					ID:   tc.ID,
					Type: "function",
					Function: openaiToolFunction{
						Name:      tc.Name,
						Arguments: string(tc.Arguments),
					},
				})
			}
		} else {
			openaiMsg.Content = msg.Content
		}

		openaiReq.Messages = append(openaiReq.Messages, openaiMsg)
	}

	// Convert tools
	for _, tool := range req.Tools {
		openaiReq.Tools = append(openaiReq.Tools, openaiTool{
			Type: "function",
			Function: openaiToolDef{
				Name:        tool.Name,
				Description: tool.Description,
				Parameters:  tool.Parameters,
			},
		})
	}

	return openaiReq
}

func (c *OpenAIClient) parseResponse(resp *openaiResponse) *ChatResponse {
	chatResp := &ChatResponse{
		Usage: Usage{
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		},
	}

	if len(resp.Choices) > 0 {
		choice := resp.Choices[0]
		chatResp.Content = choice.Message.Content
		chatResp.FinishReason = choice.FinishReason

		for _, tc := range choice.Message.ToolCalls {
			chatResp.ToolCalls = append(chatResp.ToolCalls, ToolCall{
				ID:        tc.ID,
				Name:      tc.Function.Name,
				Arguments: json.RawMessage(tc.Function.Arguments),
			})
		}
	}

	return chatResp
}

