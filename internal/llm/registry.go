package llm

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Registry manages LLM client instances.
type Registry struct {
	clients      map[Provider]Client
	current      Provider
	localProvider *LocalProvider
}

// NewRegistry creates a new client registry with all providers initialized.
func NewRegistry() *Registry {
	r := &Registry{
		clients: make(map[Provider]Client),
		current: ProviderClaude,
	}

	// Initialize all clients
	r.clients[ProviderClaude] = NewClaudeClient()
	r.clients[ProviderOpenAI] = NewOpenAIClient()
	r.clients[ProviderGemini] = NewGeminiClient()

	return r
}

// SetLocalProvider sets the local LLM provider.
func (r *Registry) SetLocalProvider(p *LocalProvider) {
	r.localProvider = p
	r.clients[ProviderLocal] = p
}

// Get returns the client for a specific provider.
func (r *Registry) Get(p Provider) (Client, error) {
	client, ok := r.clients[p]
	if !ok {
		return nil, fmt.Errorf("unknown provider: %s", p)
	}
	return client, nil
}

// Current returns the currently selected client.
func (r *Registry) Current() Client {
	return r.clients[r.current]
}

// SetCurrent sets the current provider.
func (r *Registry) SetCurrent(p Provider) error {
	if _, ok := r.clients[p]; !ok {
		return fmt.Errorf("unknown provider: %s", p)
	}
	r.current = p
	return nil
}

// CurrentProvider returns the current provider type.
func (r *Registry) CurrentProvider() Provider {
	return r.current
}

// SetAPIKey sets the API key for a specific provider.
func (r *Registry) SetAPIKey(p Provider, key string) error {
	client, ok := r.clients[p]
	if !ok {
		return fmt.Errorf("unknown provider: %s", p)
	}
	client.SetAPIKey(key)
	return nil
}

// Providers returns all available providers.
func (r *Registry) Providers() []Provider {
	providers := []Provider{ProviderClaude, ProviderOpenAI, ProviderGemini}
	if r.localProvider != nil && r.localProvider.HasAPIKey() {
		providers = append(providers, ProviderLocal)
	}
	return providers
}

// GetLocalProvider returns the local provider if available.
func (r *Registry) GetLocalProvider() *LocalProvider {
	return r.localProvider
}

// HasAPIKey returns true if the current provider has an API key configured.
func (r *Registry) HasAPIKey() bool {
	return r.clients[r.current].HasAPIKey()
}

// ValidateAPIKey validates the API key for the current provider.
func (r *Registry) ValidateAPIKey(ctx context.Context) error {
	return r.clients[r.current].ValidateAPIKey(ctx)
}

// CheckInternet tests basic internet connectivity.
// Returns nil if connected, error otherwise.
func CheckInternet() error {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Try multiple reliable endpoints
	endpoints := []string{
		"https://www.google.com",
		"https://api.anthropic.com",
		"https://api.openai.com",
	}

	var lastErr error
	for _, url := range endpoints {
		resp, err := client.Head(url)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		lastErr = err
	}

	return fmt.Errorf("no internet connection: %v", lastErr)
}

// ConnectionStatus represents the result of connectivity checks.
type ConnectionStatus struct {
	Internet    bool
	InternetErr error
	APIKey      bool
	APIKeyErr   error
	Provider    Provider
}

// CheckConnection performs all connectivity checks.
func (r *Registry) CheckConnection(ctx context.Context) ConnectionStatus {
	status := ConnectionStatus{
		Provider: r.current,
	}

	// Check internet
	if err := CheckInternet(); err != nil {
		status.InternetErr = err
	} else {
		status.Internet = true
	}

	// Only check API key if we have internet and a key is configured
	if status.Internet && r.HasAPIKey() {
		if err := r.ValidateAPIKey(ctx); err != nil {
			status.APIKeyErr = err
		} else {
			status.APIKey = true
		}
	} else if !r.HasAPIKey() {
		status.APIKeyErr = fmt.Errorf("no API key configured")
	}

	return status
}

