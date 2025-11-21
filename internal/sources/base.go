package sources

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// sharedClient is reused across all source fetches
var sharedClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	},
}

// regexFetch performs a fetch and extracts subdomains using regex
// This reduces code duplication across many sources
func regexFetch(url string, domain string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return []string{}, nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")

	resp, err := sharedClient.Do(req)
	if err != nil {
		return []string{}, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []string{}, nil
	}

	return extractSubdomains(string(body), domain), nil
}

// extractSubdomains extracts subdomains from text using regex
func extractSubdomains(text, domain string) []string {
	// Compile regex once per call (could cache but domain changes)
	pattern := fmt.Sprintf(`(?i)([a-z0-9][a-z0-9._-]*\.%s)`, regexp.QuoteMeta(domain))
	re := regexp.MustCompile(pattern)
	matches := re.FindAllStringSubmatch(text, -1)

	seen := make(map[string]bool)
	var subs []string
	for _, match := range matches {
		if len(match) > 1 {
			name := strings.ToLower(match[1])
			// Filter out invalid patterns
			if !seen[name] && !strings.HasPrefix(name, ".") && strings.HasSuffix(name, domain) {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}

	return subs
}

// dedupeAndFilter filters subdomains and ensures they belong to the target domain
func dedupeAndFilter(subs []string, domain string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, sub := range subs {
		sub = strings.ToLower(strings.TrimSpace(sub))
		sub = strings.TrimPrefix(sub, "*.")
		if sub != "" && !seen[sub] && strings.HasSuffix(sub, domain) {
			seen[sub] = true
			result = append(result, sub)
		}
	}
	return result
}
