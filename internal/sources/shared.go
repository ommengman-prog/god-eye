package sources

import (
	"crypto/tls"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Shared HTTP clients - singleton pattern
var (
	clientOnce sync.Once

	// Fast client for quick API calls (10s timeout)
	FastClient *http.Client

	// Standard client for most sources (15s timeout)
	StandardClient *http.Client

	// Slow client for heavy sources like crt.sh (120s timeout)
	SlowClient *http.Client

	// Shared transport for connection pooling
	sharedTransport *http.Transport
)

// Pre-compiled regex patterns - compiled once at init
var (
	// Generic subdomain pattern
	SubdomainRegex *regexp.Regexp

	// Email pattern (for extracting domains from emails)
	EmailDomainRegex *regexp.Regexp

	// URL pattern
	URLDomainRegex *regexp.Regexp

	// Common patterns used by multiple sources
	JSONSubdomainRegex *regexp.Regexp

	// Pattern for cleaning wildcard prefixes
	WildcardPrefixRegex *regexp.Regexp
)

func init() {
	initClients()
	initRegex()
}

func initClients() {
	clientOnce.Do(func() {
		// Shared transport with connection pooling
		sharedTransport = &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			MaxConnsPerHost:     20,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			ForceAttemptHTTP2:     true,
			ExpectContinueTimeout: 1 * time.Second,
		}

		FastClient = &http.Client{
			Transport: sharedTransport,
			Timeout:   10 * time.Second,
		}

		StandardClient = &http.Client{
			Transport: sharedTransport,
			Timeout:   15 * time.Second,
		}

		SlowClient = &http.Client{
			Transport: sharedTransport,
			Timeout:   120 * time.Second,
		}
	})
}

func initRegex() {
	// Generic subdomain extraction pattern
	SubdomainRegex = regexp.MustCompile(`(?i)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}`)

	// Email domain extraction
	EmailDomainRegex = regexp.MustCompile(`@([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}`)

	// URL domain extraction
	URLDomainRegex = regexp.MustCompile(`(?i)https?://([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}`)

	// JSON response subdomain pattern
	JSONSubdomainRegex = regexp.MustCompile(`"([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"`)

	// Wildcard prefix cleaner
	WildcardPrefixRegex = regexp.MustCompile(`^\*\.`)
}

// GetClientForTimeout returns appropriate shared client based on timeout needs
func GetClientForTimeout(timeout time.Duration) *http.Client {
	switch {
	case timeout <= 10*time.Second:
		return FastClient
	case timeout <= 30*time.Second:
		return StandardClient
	default:
		return SlowClient
	}
}

// ExtractSubdomains extracts subdomains from text using pre-compiled regex
func ExtractSubdomains(text, targetDomain string) []string {
	matches := SubdomainRegex.FindAllString(text, -1)
	seen := make(map[string]bool)
	var result []string

	targetSuffix := "." + targetDomain
	for _, match := range matches {
		match = WildcardPrefixRegex.ReplaceAllString(match, "")
		match = strings.ToLower(strings.TrimSpace(match))

		// Must end with target domain
		if !strings.HasSuffix(match, targetSuffix) && match != targetDomain {
			continue
		}

		if match != "" && !seen[match] {
			seen[match] = true
			result = append(result, match)
		}
	}

	return result
}

// CloseIdleConnections closes idle connections in the shared transport
func CloseIdleConnections() {
	if sharedTransport != nil {
		sharedTransport.CloseIdleConnections()
	}
}
