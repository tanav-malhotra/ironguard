package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// LocalProvider implements the Client interface for local LLM servers.
// Supports Ollama, LM Studio, text-generation-webui, and other OpenAI-compatible servers.
type LocalProvider struct {
	baseURL     string
	models      []string
	serverType  string // "ollama", "lmstudio", "openai-compatible"
	httpClient  *http.Client
}

// LocalServerInfo contains information about a detected local LLM server.
type LocalServerInfo struct {
	Type    string   // "ollama", "lmstudio", "text-gen-webui", "openai-compatible"
	URL     string   // Base URL of the server
	Models  []string // Available models
	Version string   // Server version if available
}

// Common local server endpoints to check
var localEndpoints = []struct {
	port       int
	path       string
	serverType string
	modelPath  string
}{
	{11434, "/api/tags", "ollama", "/api/tags"},                    // Ollama default
	{1234, "/v1/models", "lmstudio", "/v1/models"},                 // LM Studio default
	{5000, "/v1/models", "text-gen-webui", "/v1/models"},           // text-generation-webui
	{8080, "/v1/models", "openai-compatible", "/v1/models"},        // Generic OpenAI-compatible
	{3000, "/v1/models", "openai-compatible", "/v1/models"},        // Alternative port
}

// NewLocalProvider creates a new local LLM provider.
func NewLocalProvider() *LocalProvider {
	return &LocalProvider{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		models: []string{},
	}
}

// DetectLocalServers scans for running local LLM servers.
// It checks localhost, Docker bridge, and WSL host addresses.
func DetectLocalServers() []LocalServerInfo {
	var servers []LocalServerInfo
	
	// Addresses to check
	addresses := getAddressesToCheck()
	
	// Check each address and endpoint combination
	for _, addr := range addresses {
		for _, endpoint := range localEndpoints {
			url := fmt.Sprintf("http://%s:%d", addr, endpoint.port)
			server := checkServer(url, endpoint.path, endpoint.serverType, endpoint.modelPath)
			if server != nil {
				servers = append(servers, *server)
			}
		}
	}
	
	return servers
}

// getAddressesToCheck returns a list of addresses where local LLM servers might be running.
func getAddressesToCheck() []string {
	addresses := []string{"localhost", "127.0.0.1"}
	
	// Add Docker bridge network gateway (common: 172.17.0.1)
	addresses = append(addresses, "172.17.0.1")
	
	// On Windows/WSL, check the host from WSL
	if runtime.GOOS == "linux" {
		// Try to get WSL host IP (usually ends in .1)
		if wslHost := getWSLHostIP(); wslHost != "" {
			addresses = append(addresses, wslHost)
		}
	}
	
	// On Windows, check Docker Desktop host
	if runtime.GOOS == "windows" {
		addresses = append(addresses, "host.docker.internal")
	}
	
	return addresses
}

// getWSLHostIP tries to determine the Windows host IP from within WSL.
func getWSLHostIP() string {
	// In WSL2, the host IP is usually in /etc/resolv.conf as the nameserver
	// This is a common pattern but not guaranteed
	// Return empty if we can't determine it
	return ""
}

// checkServer attempts to connect to a potential LLM server.
func checkServer(baseURL, checkPath, serverType, modelPath string) *LocalServerInfo {
	client := &http.Client{
		Timeout: 2 * time.Second,
	}
	
	// Try to connect
	resp, err := client.Get(baseURL + checkPath)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	
	// Parse response to get models
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	
	var models []string
	
	switch serverType {
	case "ollama":
		models = parseOllamaModels(body)
	default:
		models = parseOpenAIModels(body)
	}
	
	if len(models) == 0 {
		return nil
	}
	
	return &LocalServerInfo{
		Type:   serverType,
		URL:    baseURL,
		Models: models,
	}
}

// parseOllamaModels parses the Ollama API response for available models.
func parseOllamaModels(body []byte) []string {
	var resp struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil
	}
	
	var models []string
	for _, m := range resp.Models {
		models = append(models, m.Name)
	}
	return models
}

// parseOpenAIModels parses OpenAI-compatible API response for available models.
func parseOpenAIModels(body []byte) []string {
	var resp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil
	}
	
	var models []string
	for _, m := range resp.Data {
		models = append(models, m.ID)
	}
	return models
}

// Connect connects to a local LLM server.
func (p *LocalProvider) Connect(server LocalServerInfo) error {
	p.baseURL = server.URL
	p.models = server.Models
	p.serverType = server.Type
	return nil
}

// ConnectToURL connects to a specific URL.
func (p *LocalProvider) ConnectToURL(url string) error {
	// Try to detect server type
	servers := []struct {
		path       string
		serverType string
	}{
		{"/api/tags", "ollama"},
		{"/v1/models", "openai-compatible"},
	}
	
	for _, s := range servers {
		server := checkServer(url, s.path, s.serverType, s.path)
		if server != nil {
			p.baseURL = server.URL
			p.models = server.Models
			p.serverType = server.Type
			return nil
		}
	}
	
	return fmt.Errorf("could not connect to local server at %s", url)
}

// Chat implements the Client interface.
func (p *LocalProvider) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	switch p.serverType {
	case "ollama":
		return p.chatOllama(ctx, req)
	default:
		return p.chatOpenAI(ctx, req)
	}
}

// ChatStream implements the Client interface.
func (p *LocalProvider) ChatStream(ctx context.Context, req ChatRequest, callback func(StreamDelta)) error {
	switch p.serverType {
	case "ollama":
		return p.chatStreamOllama(ctx, req, callback)
	default:
		return p.chatStreamOpenAI(ctx, req, callback)
	}
}

// chatOllama sends a chat request to an Ollama server.
func (p *LocalProvider) chatOllama(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	// Build Ollama request
	ollamaReq := map[string]interface{}{
		"model":  p.models[0], // Use first available model or specified
		"stream": false,
	}
	
	// Convert messages
	var messages []map[string]string
	if req.SystemPrompt != "" {
		messages = append(messages, map[string]string{
			"role":    "system",
			"content": req.SystemPrompt,
		})
	}
	for _, msg := range req.Messages {
		messages = append(messages, map[string]string{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}
	ollamaReq["messages"] = messages
	
	body, _ := json.Marshal(ollamaReq)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	
	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var result struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	return &ChatResponse{
		Content:      result.Message.Content,
		FinishReason: "stop",
	}, nil
}

// chatStreamOllama streams chat from an Ollama server.
func (p *LocalProvider) chatStreamOllama(ctx context.Context, req ChatRequest, callback func(StreamDelta)) error {
	// Build Ollama request
	ollamaReq := map[string]interface{}{
		"model":  p.models[0],
		"stream": true,
	}
	
	// Convert messages
	var messages []map[string]string
	if req.SystemPrompt != "" {
		messages = append(messages, map[string]string{
			"role":    "system",
			"content": req.SystemPrompt,
		})
	}
	for _, msg := range req.Messages {
		messages = append(messages, map[string]string{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}
	ollamaReq["messages"] = messages
	
	body, _ := json.Marshal(ollamaReq)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	
	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	decoder := json.NewDecoder(resp.Body)
	for {
		var chunk struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Done bool `json:"done"`
		}
		
		if err := decoder.Decode(&chunk); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		
		callback(StreamDelta{
			Content: chunk.Message.Content,
			Done:    chunk.Done,
		})
		
		if chunk.Done {
			break
		}
	}
	
	return nil
}

// chatOpenAI sends a chat request to an OpenAI-compatible server.
func (p *LocalProvider) chatOpenAI(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	model := p.models[0]
	if req.Model != "" {
		model = req.Model
	}
	
	openaiReq := map[string]interface{}{
		"model":  model,
		"stream": false,
	}
	
	// Convert messages
	var messages []map[string]string
	if req.SystemPrompt != "" {
		messages = append(messages, map[string]string{
			"role":    "system",
			"content": req.SystemPrompt,
		})
	}
	for _, msg := range req.Messages {
		messages = append(messages, map[string]string{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}
	openaiReq["messages"] = messages
	
	if req.MaxTokens > 0 {
		openaiReq["max_tokens"] = req.MaxTokens
	}
	if req.Temperature > 0 {
		openaiReq["temperature"] = req.Temperature
	}
	
	body, _ := json.Marshal(openaiReq)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	
	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no response from local model")
	}
	
	return &ChatResponse{
		Content:      result.Choices[0].Message.Content,
		FinishReason: result.Choices[0].FinishReason,
	}, nil
}

// chatStreamOpenAI streams chat from an OpenAI-compatible server.
func (p *LocalProvider) chatStreamOpenAI(ctx context.Context, req ChatRequest, callback func(StreamDelta)) error {
	model := p.models[0]
	if req.Model != "" {
		model = req.Model
	}
	
	openaiReq := map[string]interface{}{
		"model":  model,
		"stream": true,
	}
	
	// Convert messages
	var messages []map[string]string
	if req.SystemPrompt != "" {
		messages = append(messages, map[string]string{
			"role":    "system",
			"content": req.SystemPrompt,
		})
	}
	for _, msg := range req.Messages {
		messages = append(messages, map[string]string{
			"role":    msg.Role,
			"content": msg.Content,
		})
	}
	openaiReq["messages"] = messages
	
	if req.MaxTokens > 0 {
		openaiReq["max_tokens"] = req.MaxTokens
	}
	
	body, _ := json.Marshal(openaiReq)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	
	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	// Read SSE stream
	reader := resp.Body
	buf := make([]byte, 4096)
	
	for {
		n, err := reader.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		
		lines := strings.Split(string(buf[:n]), "\n")
		for _, line := range lines {
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			
			data := strings.TrimPrefix(line, "data: ")
			if data == "[DONE]" {
				callback(StreamDelta{Done: true})
				return nil
			}
			
			var chunk struct {
				Choices []struct {
					Delta struct {
						Content string `json:"content"`
					} `json:"delta"`
					FinishReason *string `json:"finish_reason"`
				} `json:"choices"`
			}
			
			if err := json.Unmarshal([]byte(data), &chunk); err != nil {
				continue
			}
			
			if len(chunk.Choices) > 0 {
				callback(StreamDelta{
					Content: chunk.Choices[0].Delta.Content,
					Done:    chunk.Choices[0].FinishReason != nil,
				})
			}
		}
	}
	
	return nil
}

// Provider implements the Client interface.
func (p *LocalProvider) Provider() Provider {
	return ProviderLocal
}

// Models implements the Client interface.
func (p *LocalProvider) Models() []string {
	return p.models
}

// SetAPIKey implements the Client interface (no-op for local).
func (p *LocalProvider) SetAPIKey(key string) {
	// Local providers don't need API keys
}

// HasAPIKey implements the Client interface.
func (p *LocalProvider) HasAPIKey() bool {
	// Local providers don't need API keys, return true if connected
	return p.baseURL != ""
}

// ValidateAPIKey implements the Client interface.
func (p *LocalProvider) ValidateAPIKey(ctx context.Context) error {
	if p.baseURL == "" {
		return fmt.Errorf("not connected to any local server")
	}
	
	// Try to list models to validate connection
	resp, err := p.httpClient.Get(p.baseURL + "/api/tags")
	if err != nil {
		// Try OpenAI-compatible endpoint
		resp, err = p.httpClient.Get(p.baseURL + "/v1/models")
		if err != nil {
			return fmt.Errorf("cannot connect to local server: %w", err)
		}
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("local server returned status %d", resp.StatusCode)
	}
	
	return nil
}

// RefreshModels refreshes the list of available models from the server.
func (p *LocalProvider) RefreshModels() error {
	if p.baseURL == "" {
		return fmt.Errorf("not connected to any server")
	}
	
	switch p.serverType {
	case "ollama":
		resp, err := p.httpClient.Get(p.baseURL + "/api/tags")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		
		body, _ := io.ReadAll(resp.Body)
		p.models = parseOllamaModels(body)
	default:
		resp, err := p.httpClient.Get(p.baseURL + "/v1/models")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		
		body, _ := io.ReadAll(resp.Body)
		p.models = parseOpenAIModels(body)
	}
	
	return nil
}

// GetServerType returns the type of the connected server.
func (p *LocalProvider) GetServerType() string {
	return p.serverType
}

// GetBaseURL returns the base URL of the connected server.
func (p *LocalProvider) GetBaseURL() string {
	return p.baseURL
}

// IsPortOpen checks if a port is open on a given host.
func IsPortOpen(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
