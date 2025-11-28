package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// RegisterWebTools adds web search and URL fetching tools.
func (r *Registry) RegisterWebTools() {
	// Web search tool
	r.Register(&Tool{
		Name:        "web_search",
		Description: "Search the web for information. Use this when you need to look up how to fix a specific vulnerability, find documentation, or research an unknown issue.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type":        "string",
					"description": "The search query",
				},
			},
			"required": []string{"query"},
		},
		Handler:  toolWebSearch,
		Mutating: false,
	})

	// Fetch URL tool
	r.Register(&Tool{
		Name:        "fetch_url",
		Description: "Fetch and parse content from a URL. Useful for reading documentation pages.",
		Parameters: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"url": map[string]interface{}{
					"type":        "string",
					"description": "The URL to fetch",
				},
			},
			"required": []string{"url"},
		},
		Handler:  toolFetchURL,
		Mutating: false,
	})
}

func toolWebSearch(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	// Use DuckDuckGo HTML search (no API key needed)
	searchURL := fmt.Sprintf("https://html.duckduckgo.com/html/?q=%s", url.QueryEscape(params.Query))

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set user agent to get better results
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("search request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Parse the HTML to extract search results
	results := parseDuckDuckGoResults(string(body))

	if len(results) == 0 {
		return "No search results found for: " + params.Query, nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Search results for: %s\n\n", params.Query))
	for i, r := range results {
		if i >= 5 {
			break // Limit to top 5 results
		}
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, r.Title))
		sb.WriteString(fmt.Sprintf("   URL: %s\n", r.URL))
		sb.WriteString(fmt.Sprintf("   %s\n\n", r.Snippet))
	}

	return sb.String(), nil
}

type searchResult struct {
	Title   string
	URL     string
	Snippet string
}

func parseDuckDuckGoResults(html string) []searchResult {
	var results []searchResult

	// Extract result blocks
	resultRegex := regexp.MustCompile(`(?s)<a class="result__a"[^>]*href="([^"]*)"[^>]*>([^<]*)</a>.*?<a class="result__snippet"[^>]*>([^<]*)</a>`)
	matches := resultRegex.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) >= 4 {
			// DuckDuckGo uses redirect URLs, try to extract the actual URL
			actualURL := match[1]
			if strings.Contains(actualURL, "uddg=") {
				// Parse the redirect URL
				if u, err := url.Parse(actualURL); err == nil {
					if uddg := u.Query().Get("uddg"); uddg != "" {
						actualURL = uddg
					}
				}
			}

			results = append(results, searchResult{
				Title:   strings.TrimSpace(match[2]),
				URL:     actualURL,
				Snippet: strings.TrimSpace(match[3]),
			})
		}
	}

	// Fallback: try simpler extraction
	if len(results) == 0 {
		// Try to extract any links with result class
		linkRegex := regexp.MustCompile(`<a[^>]*class="[^"]*result[^"]*"[^>]*href="([^"]*)"[^>]*>([^<]+)</a>`)
		linkMatches := linkRegex.FindAllStringSubmatch(html, -1)
		for _, match := range linkMatches {
			if len(match) >= 3 {
				results = append(results, searchResult{
					Title:   strings.TrimSpace(match[2]),
					URL:     match[1],
					Snippet: "",
				})
			}
		}
	}

	return results
}

func toolFetchURL(ctx context.Context, args json.RawMessage) (string, error) {
	var params struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}

	// Validate URL
	parsedURL, err := url.Parse(params.URL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", fmt.Errorf("only http and https URLs are supported")
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", params.URL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP error: %d %s", resp.StatusCode, resp.Status)
	}

	// Limit response size to 100KB
	body, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		// Strip HTML for easier reading
		return stripHTML(string(body)), nil
	}

	return string(body), nil
}

