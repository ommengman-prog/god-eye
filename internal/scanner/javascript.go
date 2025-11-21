package scanner

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

// SecretPattern defines a pattern for finding secrets
type SecretPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// Secret patterns to search for in JS files
var secretPatterns = []SecretPattern{
	// API Keys
	{Name: "AWS Access Key", Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{Name: "AWS Secret Key", Pattern: regexp.MustCompile(`(?i)aws[_\-]?secret[_\-]?access[_\-]?key['"\s:=]+['"]?([A-Za-z0-9/+=]{40})['"]?`)},
	{Name: "Google API Key", Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{Name: "Google OAuth", Pattern: regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`)},
	{Name: "Firebase API Key", Pattern: regexp.MustCompile(`(?i)firebase[_\-]?api[_\-]?key['"\s:=]+['"]?([A-Za-z0-9_\-]{39})['"]?`)},
	{Name: "Stripe Key", Pattern: regexp.MustCompile(`(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}`)},
	{Name: "Stripe Restricted", Pattern: regexp.MustCompile(`rk_(?:test|live)_[0-9a-zA-Z]{24,}`)},
	{Name: "GitHub Token", Pattern: regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`)},
	{Name: "GitHub OAuth", Pattern: regexp.MustCompile(`github[_\-]?oauth[_\-]?token['"\s:=]+['"]?([a-f0-9]{40})['"]?`)},
	{Name: "Slack Token", Pattern: regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`)},
	{Name: "Slack Webhook", Pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}`)},
	{Name: "Discord Webhook", Pattern: regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,}`)},
	{Name: "Twilio API Key", Pattern: regexp.MustCompile(`SK[a-f0-9]{32}`)},
	{Name: "Twilio Account SID", Pattern: regexp.MustCompile(`AC[a-f0-9]{32}`)},
	{Name: "SendGrid API Key", Pattern: regexp.MustCompile(`SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}`)},
	{Name: "Mailgun API Key", Pattern: regexp.MustCompile(`key-[0-9a-zA-Z]{32}`)},
	{Name: "Mailchimp API Key", Pattern: regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`)},
	{Name: "Heroku API Key", Pattern: regexp.MustCompile(`(?i)heroku[_\-]?api[_\-]?key['"\s:=]+['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?`)},
	{Name: "DigitalOcean Token", Pattern: regexp.MustCompile(`dop_v1_[a-f0-9]{64}`)},
	{Name: "NPM Token", Pattern: regexp.MustCompile(`npm_[A-Za-z0-9]{36}`)},
	{Name: "PyPI Token", Pattern: regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}`)},
	{Name: "Square Access Token", Pattern: regexp.MustCompile(`sq0atp-[0-9A-Za-z\-_]{22}`)},
	{Name: "Square OAuth", Pattern: regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}`)},
	{Name: "Shopify Access Token", Pattern: regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`)},
	{Name: "Shopify Shared Secret", Pattern: regexp.MustCompile(`shpss_[a-fA-F0-9]{32}`)},
	{Name: "Algolia API Key", Pattern: regexp.MustCompile(`(?i)algolia[_\-]?api[_\-]?key['"\s:=]+['"]?([a-zA-Z0-9]{32})['"]?`)},
	{Name: "Auth0 Client Secret", Pattern: regexp.MustCompile(`(?i)auth0[_\-]?client[_\-]?secret['"\s:=]+['"]?([a-zA-Z0-9_\-]{32,})['"]?`)},

	// Generic secrets
	{Name: "Generic API Key", Pattern: regexp.MustCompile(`(?i)['"]?api[_\-]?key['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,64})['"]`)},
	{Name: "Generic Secret", Pattern: regexp.MustCompile(`(?i)['"]?(?:client[_\-]?)?secret['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,64})['"]`)},
	{Name: "Generic Token", Pattern: regexp.MustCompile(`(?i)['"]?(?:access[_\-]?)?token['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{20,500})['"]`)},
	{Name: "Generic Password", Pattern: regexp.MustCompile(`(?i)['"]?password['"]?\s*[:=]\s*['"]([^'"]{8,64})['"]`)},
	{Name: "Private Key", Pattern: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	{Name: "Bearer Token", Pattern: regexp.MustCompile(`(?i)['"]?authorization['"]?\s*[:=]\s*['"]Bearer\s+([a-zA-Z0-9_\-\.]+)['"]`)},
	{Name: "Basic Auth", Pattern: regexp.MustCompile(`(?i)['"]?authorization['"]?\s*[:=]\s*['"]Basic\s+([a-zA-Z0-9+/=]+)['"]`)},
	{Name: "JWT Token", Pattern: regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]*\.eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*`)},

	// Database connection strings
	{Name: "MongoDB URI", Pattern: regexp.MustCompile(`mongodb(?:\+srv)?://[^\s'"]+`)},
	{Name: "PostgreSQL URI", Pattern: regexp.MustCompile(`postgres(?:ql)?://[^\s'"]+`)},
	{Name: "MySQL URI", Pattern: regexp.MustCompile(`mysql://[^\s'"]+`)},
	{Name: "Redis URI", Pattern: regexp.MustCompile(`redis://[^\s'"]+`)},
}

// Endpoint patterns for API discovery - only external/interesting URLs
// Note: We exclude relative paths like /api/... as they're not secrets
var endpointPatterns = []*regexp.Regexp{
	regexp.MustCompile(`['"]https?://api\.[a-zA-Z0-9\-\.]+[a-zA-Z0-9/\-_]*['"]`),     // External API domains
	regexp.MustCompile(`['"]https?://[a-zA-Z0-9\-\.]+\.amazonaws\.com[^'"]*['"]`),    // AWS endpoints
	regexp.MustCompile(`['"]https?://[a-zA-Z0-9\-\.]+\.azure\.com[^'"]*['"]`),        // Azure endpoints
	regexp.MustCompile(`['"]https?://[a-zA-Z0-9\-\.]+\.googleapis\.com[^'"]*['"]`),   // Google API
	regexp.MustCompile(`['"]https?://[a-zA-Z0-9\-\.]+\.firebaseio\.com[^'"]*['"]`),   // Firebase
}

// AnalyzeJSFiles finds JavaScript files and extracts potential secrets
func AnalyzeJSFiles(subdomain string, client *http.Client) ([]string, []string) {
	var jsFiles []string
	var secrets []string
	var mu sync.Mutex

	baseURLs := []string{
		fmt.Sprintf("https://%s", subdomain),
		fmt.Sprintf("http://%s", subdomain),
	}

	// First, get the main page and extract JS file references
	var foundJSURLs []string
	for _, baseURL := range baseURLs {
		resp, err := client.Get(baseURL)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 500000))
		resp.Body.Close()
		if err != nil {
			continue
		}

		// Find JS files referenced in HTML
		jsRe := regexp.MustCompile(`(?:src|href)=["']([^"']*\.js(?:\?[^"']*)?)["']`)
		matches := jsRe.FindAllStringSubmatch(string(body), -1)
		for _, match := range matches {
			if len(match) > 1 {
				jsURL := normalizeURL(match[1], baseURL)
				if jsURL != "" && !contains(foundJSURLs, jsURL) {
					foundJSURLs = append(foundJSURLs, jsURL)
				}
			}
		}

		// Also look for dynamic imports and webpack chunks
		dynamicRe := regexp.MustCompile(`["']([^"']*(?:chunk|bundle|vendor|main|app)[^"']*\.js(?:\?[^"']*)?)["']`)
		dynamicMatches := dynamicRe.FindAllStringSubmatch(string(body), -1)
		for _, match := range dynamicMatches {
			if len(match) > 1 {
				jsURL := normalizeURL(match[1], baseURL)
				if jsURL != "" && !contains(foundJSURLs, jsURL) {
					foundJSURLs = append(foundJSURLs, jsURL)
				}
			}
		}

		if len(foundJSURLs) > 0 {
			break
		}
	}

	// Limit to first 15 JS files to avoid too many requests
	if len(foundJSURLs) > 15 {
		foundJSURLs = foundJSURLs[:15]
	}

	// Download and analyze each JS file concurrently
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit concurrent downloads

	for _, jsURL := range foundJSURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fileSecrets := analyzeJSContent(url, client)

			mu.Lock()
			jsFiles = append(jsFiles, url)
			secrets = append(secrets, fileSecrets...)
			mu.Unlock()
		}(jsURL)
	}

	wg.Wait()

	// Deduplicate and limit results
	jsFiles = UniqueStrings(jsFiles)
	secrets = UniqueStrings(secrets)

	if len(jsFiles) > 10 {
		jsFiles = jsFiles[:10]
	}
	if len(secrets) > 20 {
		secrets = secrets[:20]
	}

	return jsFiles, secrets
}

// analyzeJSContent downloads and analyzes a JS file for secrets
func analyzeJSContent(jsURL string, client *http.Client) []string {
	var secrets []string

	resp, err := client.Get(jsURL)
	if err != nil {
		return secrets
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return secrets
	}

	// Read JS content (limit to 2MB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return secrets
	}

	content := string(body)

	// Skip minified files that are too large without meaningful content
	if len(content) > 500000 && !containsInterestingPatterns(content) {
		return secrets
	}

	// Search for secrets
	for _, sp := range secretPatterns {
		matches := sp.Pattern.FindAllStringSubmatch(content, 3)
		for _, m := range matches {
			var secret string
			if len(m) > 1 && m[1] != "" {
				secret = m[1]
			} else {
				secret = m[0]
			}

			// Skip common false positives
			if isLikelyFalsePositive(secret) {
				continue
			}

			// Truncate long secrets
			if len(secret) > 80 {
				secret = secret[:77] + "..."
			}

			finding := fmt.Sprintf("[%s] %s", sp.Name, secret)
			secrets = append(secrets, finding)
		}
	}

	// Search for API endpoints
	for _, pattern := range endpointPatterns {
		matches := pattern.FindAllString(content, 5)
		for _, m := range matches {
			// Clean up the match
			m = strings.Trim(m, `'"`)
			if len(m) > 80 {
				m = m[:77] + "..."
			}
			secrets = append(secrets, fmt.Sprintf("[API Endpoint] %s", m))
		}
	}

	return secrets
}

// normalizeURL converts relative URLs to absolute URLs
func normalizeURL(jsURL, baseURL string) string {
	if jsURL == "" {
		return ""
	}

	// Skip data URIs and blob URLs
	if strings.HasPrefix(jsURL, "data:") || strings.HasPrefix(jsURL, "blob:") {
		return ""
	}

	// Already absolute URL
	if strings.HasPrefix(jsURL, "http://") || strings.HasPrefix(jsURL, "https://") {
		return jsURL
	}

	// Protocol-relative URL
	if strings.HasPrefix(jsURL, "//") {
		if strings.HasPrefix(baseURL, "https") {
			return "https:" + jsURL
		}
		return "http:" + jsURL
	}

	// Absolute path
	if strings.HasPrefix(jsURL, "/") {
		// Extract base (scheme + host)
		parts := strings.SplitN(baseURL, "/", 4)
		if len(parts) >= 3 {
			return parts[0] + "//" + parts[2] + jsURL
		}
		return baseURL + jsURL
	}

	// Relative path
	return strings.TrimSuffix(baseURL, "/") + "/" + jsURL
}

// containsInterestingPatterns checks if content might contain secrets
func containsInterestingPatterns(content string) bool {
	interestingKeywords := []string{
		"api_key", "apikey", "api-key",
		"secret", "password", "token",
		"authorization", "bearer",
		"aws_", "firebase", "stripe",
		"mongodb://", "postgres://", "mysql://",
		"private_key", "privatekey",
	}

	contentLower := strings.ToLower(content)
	for _, kw := range interestingKeywords {
		if strings.Contains(contentLower, kw) {
			return true
		}
	}
	return false
}

// isLikelyFalsePositive performs basic pre-filtering before AI analysis
// Only filters obvious patterns - AI will handle context-aware filtering
func isLikelyFalsePositive(secret string) bool {
	// Only filter obvious placeholder patterns
	// AI will handle context-aware filtering (UI text, etc.)
	obviousPlaceholders := []string{
		"YOUR_API_KEY", "API_KEY_HERE", "REPLACE_ME",
		"xxxxxxxx", "XXXXXXXX", "00000000",
	}

	secretLower := strings.ToLower(secret)
	for _, fp := range obviousPlaceholders {
		if strings.Contains(secretLower, strings.ToLower(fp)) {
			return true
		}
	}

	// Too short
	if len(secret) < 8 {
		return true
	}

	// Check for repeated characters (garbage data)
	if isRepeatedChars(secret) {
		return true
	}

	return false
}

// isRepeatedChars checks if string is mostly repeated characters
func isRepeatedChars(s string) bool {
	if len(s) < 10 {
		return false
	}
	charCount := make(map[rune]int)
	for _, c := range s {
		charCount[c]++
	}
	// If any single character is more than 60% of the string, it's likely garbage
	for _, count := range charCount {
		if float64(count)/float64(len(s)) > 0.6 {
			return true
		}
	}
	return false
}

// contains checks if a string slice contains a value
func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// UniqueStrings returns unique strings from a slice
func UniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
