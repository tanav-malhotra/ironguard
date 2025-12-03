package llm

import "fmt"

// Registry manages LLM client instances.
type Registry struct {
	clients map[Provider]Client
	current Provider
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
	return []Provider{ProviderClaude, ProviderOpenAI, ProviderGemini}
}

// HasAPIKey returns true if the current provider has an API key configured.
func (r *Registry) HasAPIKey() bool {
	return r.clients[r.current].HasAPIKey()
}

