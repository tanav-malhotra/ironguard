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

const geminiAPIURL = "https://generativelanguage.googleapis.com/v1beta/models"

// GeminiClient implements the Client interface for Google's Gemini API.
type GeminiClient struct {
	apiKey     string
	httpClient *http.Client
}

// NewGeminiClient creates a new Gemini client.
func NewGeminiClient() *GeminiClient {
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("GOOGLE_API_KEY")
	}
	return &GeminiClient{
		apiKey:     apiKey,
		httpClient: &http.Client{},
	}
}

func (c *GeminiClient) Provider() Provider {
	return ProviderGemini
}

func (c *GeminiClient) Models() []string {
	return ModelPresets[ProviderGemini]
}

func (c *GeminiClient) SetAPIKey(key string) {
	c.apiKey = key
}

// Gemini API types
type geminiRequest struct {
	Contents         []geminiContent       `json:"contents"`
	SystemInstruction *geminiContent       `json:"systemInstruction,omitempty"`
	Tools            []geminiToolDef       `json:"tools,omitempty"`
	GenerationConfig *geminiGenConfig      `json:"generationConfig,omitempty"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text             string                 `json:"text,omitempty"`
	FunctionCall     *geminiFunctionCall    `json:"functionCall,omitempty"`
	FunctionResponse *geminiFunctionResp    `json:"functionResponse,omitempty"`
}

type geminiFunctionCall struct {
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args"`
}

type geminiFunctionResp struct {
	Name     string                 `json:"name"`
	Response map[string]interface{} `json:"response"`
}

type geminiToolDef struct {
	FunctionDeclarations []geminiFunctionDecl `json:"functionDeclarations"`
}

type geminiFunctionDecl struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

type geminiGenConfig struct {
	MaxOutputTokens int     `json:"maxOutputTokens,omitempty"`
	Temperature     float64 `json:"temperature,omitempty"`
	// Enable thinking mode for deeper reasoning
	ThinkingConfig *geminiThinkingConfig `json:"thinkingConfig,omitempty"`
}

type geminiThinkingConfig struct {
	ThinkingBudget int `json:"thinkingBudget,omitempty"` // Max tokens for thinking
}

type geminiResponse struct {
	Candidates     []geminiCandidate `json:"candidates"`
	UsageMetadata  geminiUsage       `json:"usageMetadata"`
}

type geminiCandidate struct {
	Content       geminiContent `json:"content"`
	FinishReason  string        `json:"finishReason"`
}

type geminiUsage struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

func (c *GeminiClient) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("GEMINI_API_KEY not set")
	}

	model := "gemini-3-pro" // Latest Gemini 3 Pro
	url := fmt.Sprintf("%s/%s:generateContent?key=%s", geminiAPIURL, model, c.apiKey)

	geminiReq := c.buildRequest(req)
	body, err := json.Marshal(geminiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var geminiResp geminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return c.parseResponse(&geminiResp), nil
}

func (c *GeminiClient) ChatStream(ctx context.Context, req ChatRequest, callback func(StreamDelta)) error {
	if c.apiKey == "" {
		return fmt.Errorf("GEMINI_API_KEY not set")
	}

	model := "gemini-3-pro" // Latest Gemini 3 Pro
	url := fmt.Sprintf("%s/%s:streamGenerateContent?key=%s&alt=sse", geminiAPIURL, model, c.apiKey)

	geminiReq := c.buildRequest(req)
	body, err := json.Marshal(geminiReq)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

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

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "" {
			continue
		}

		var streamResp geminiResponse
		if err := json.Unmarshal([]byte(data), &streamResp); err != nil {
			continue
		}

		if len(streamResp.Candidates) == 0 {
			continue
		}

		candidate := streamResp.Candidates[0]
		for _, part := range candidate.Content.Parts {
			if part.Text != "" {
				callback(StreamDelta{Content: part.Text})
			}
			if part.FunctionCall != nil {
				argsJSON, _ := json.Marshal(part.FunctionCall.Args)
				toolCalls = append(toolCalls, ToolCall{
					ID:        fmt.Sprintf("call_%d", len(toolCalls)),
					Name:      part.FunctionCall.Name,
					Arguments: argsJSON,
				})
			}
		}

		if candidate.FinishReason != "" && candidate.FinishReason != "STOP" {
			callback(StreamDelta{Done: true, ToolCalls: toolCalls})
			return nil
		}
	}

	callback(StreamDelta{Done: true, ToolCalls: toolCalls})

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("stream error: %w", err)
	}

	return nil
}

func (c *GeminiClient) buildRequest(req ChatRequest) geminiRequest {
	geminiReq := geminiRequest{
		GenerationConfig: &geminiGenConfig{
			MaxOutputTokens: req.MaxTokens,
			Temperature:     req.Temperature,
			// Enable thinking mode for deeper reasoning
			ThinkingConfig: &geminiThinkingConfig{
				ThinkingBudget: 32768, // Maximum thinking budget
			},
		},
	}

	if geminiReq.GenerationConfig.MaxOutputTokens == 0 {
		geminiReq.GenerationConfig.MaxOutputTokens = 65536 // Maximum output for thinking responses
	}

	// System instruction
	if req.SystemPrompt != "" {
		geminiReq.SystemInstruction = &geminiContent{
			Parts: []geminiPart{{Text: req.SystemPrompt}},
		}
	}

	// Convert messages
	for _, msg := range req.Messages {
		content := geminiContent{}

		switch msg.Role {
		case "user":
			content.Role = "user"
		case "assistant":
			content.Role = "model"
		case "tool":
			// Tool result - add as user message with function response
			content.Role = "user"
			content.Parts = []geminiPart{{
				FunctionResponse: &geminiFunctionResp{
					Name: msg.Name,
					Response: map[string]interface{}{
						"result": msg.Content,
					},
				},
			}}
			geminiReq.Contents = append(geminiReq.Contents, content)
			continue
		default:
			content.Role = "user"
		}

		if len(msg.ToolCalls) > 0 {
			// Model message with function calls
			content.Role = "model"
			for _, tc := range msg.ToolCalls {
				var args map[string]interface{}
				json.Unmarshal(tc.Arguments, &args)
				content.Parts = append(content.Parts, geminiPart{
					FunctionCall: &geminiFunctionCall{
						Name: tc.Name,
						Args: args,
					},
				})
			}
		} else {
			content.Parts = []geminiPart{{Text: msg.Content}}
		}

		geminiReq.Contents = append(geminiReq.Contents, content)
	}

	// Convert tools
	if len(req.Tools) > 0 {
		toolDef := geminiToolDef{}
		for _, tool := range req.Tools {
			toolDef.FunctionDeclarations = append(toolDef.FunctionDeclarations, geminiFunctionDecl{
				Name:        tool.Name,
				Description: tool.Description,
				Parameters:  tool.Parameters,
			})
		}
		geminiReq.Tools = []geminiToolDef{toolDef}
	}

	return geminiReq
}

func (c *GeminiClient) parseResponse(resp *geminiResponse) *ChatResponse {
	chatResp := &ChatResponse{
		Usage: Usage{
			PromptTokens:     resp.UsageMetadata.PromptTokenCount,
			CompletionTokens: resp.UsageMetadata.CandidatesTokenCount,
			TotalTokens:      resp.UsageMetadata.TotalTokenCount,
		},
	}

	if len(resp.Candidates) > 0 {
		candidate := resp.Candidates[0]
		chatResp.FinishReason = candidate.FinishReason

		for _, part := range candidate.Content.Parts {
			if part.Text != "" {
				chatResp.Content += part.Text
			}
			if part.FunctionCall != nil {
				argsJSON, _ := json.Marshal(part.FunctionCall.Args)
				chatResp.ToolCalls = append(chatResp.ToolCalls, ToolCall{
					ID:        fmt.Sprintf("call_%d", len(chatResp.ToolCalls)),
					Name:      part.FunctionCall.Name,
					Arguments: argsJSON,
				})
			}
		}
	}

	return chatResp
}

