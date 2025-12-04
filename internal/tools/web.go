package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// isPrivateIP checks if an IP address is in a private/internal range.
// This prevents SSRF attacks by blocking requests to internal networks.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check for loopback (127.0.0.0/8, ::1)
	if ip.IsLoopback() {
		return true
	}

	// Check for private networks
	if ip.IsPrivate() {
		return true
	}

	// Check for link-local addresses (169.254.0.0/16, fe80::/10)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check for unspecified/any address (0.0.0.0, ::)
	if ip.IsUnspecified() {
		return true
	}

	// Additional check for IPv4 mapped IPv6 addresses
	if ip4 := ip.To4(); ip4 != nil {
		// 0.0.0.0/8 - "This" network
		if ip4[0] == 0 {
			return true
		}
		// 100.64.0.0/10 - Carrier-grade NAT
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		// 192.0.0.0/24 - IETF Protocol Assignments
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0 {
			return true
		}
		// 192.0.2.0/24 - TEST-NET-1
		if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2 {
			return true
		}
		// 198.51.100.0/24 - TEST-NET-2
		if ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100 {
			return true
		}
		// 203.0.113.0/24 - TEST-NET-3
		if ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113 {
			return true
		}
		// 224.0.0.0/4 - Multicast
		if ip4[0] >= 224 && ip4[0] <= 239 {
			return true
		}
		// 240.0.0.0/4 - Reserved for future use
		if ip4[0] >= 240 {
			return true
		}
	}

	return false
}

// validateURLNotInternal checks that a URL does not point to internal/private resources.
func validateURLNotInternal(urlStr string) error {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	host := parsedURL.Hostname()

	// Block localhost variations
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".localhost") {
		return fmt.Errorf("requests to localhost are not allowed")
	}

	// Resolve the hostname to IP addresses
	ips, err := net.LookupIP(host)
	if err != nil {
		// If we can't resolve, allow it (might be external DNS)
		// The HTTP client will fail anyway if it can't connect
		return nil
	}

	// Check all resolved IPs
	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("requests to private/internal IP addresses are not allowed (resolved to %s)", ip.String())
		}
	}

	return nil
}

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

	// SSRF protection: block requests to internal/private IP ranges
	if err := validateURLNotInternal(params.URL); err != nil {
		return "", err
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

