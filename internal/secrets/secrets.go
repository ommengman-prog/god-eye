package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SecretFinding represents a discovered secret or credential
type SecretFinding struct {
	Type        string `json:"type"`         // api_key, password, token, etc.
	Source      string `json:"source"`       // github, gitlab, pastebin, etc.
	URL         string `json:"url"`          // source URL
	Match       string `json:"match"`        // the matched pattern (sanitized)
	Context     string `json:"context"`      // surrounding code/text
	Severity    string `json:"severity"`     // critical, high, medium, low
	Description string `json:"description"`
	Filename    string `json:"filename,omitempty"`
	Repository  string `json:"repository,omitempty"`
}

// SecretScanner searches for exposed secrets
type SecretScanner struct {
	client      *http.Client
	domain      string
	concurrency int
	patterns    []*SecretPattern
}

// SecretPattern defines a pattern to match secrets
type SecretPattern struct {
	Name           string
	Type           string
	Regex          *regexp.Regexp
	Severity       string
	Description    string
	MinEntropy     float64 // Minimum entropy for this pattern (0 = no check)
	RequireContext bool    // Require specific context (not in comments/docs)
}

// NewSecretScanner creates a new secret scanner
func NewSecretScanner(domain string, timeout int) *SecretScanner {
	return &SecretScanner{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
		domain:      domain,
		concurrency: 5, // Conservative to avoid rate limits
		patterns:    getSecretPatterns(),
	}
}

// getSecretPatterns returns compiled regex patterns for secrets with entropy requirements
func getSecretPatterns() []*SecretPattern {
	patterns := []struct {
		name           string
		patternType    string
		regex          string
		severity       string
		description    string
		minEntropy     float64 // Minimum Shannon entropy (bits/char) - 0 means no check
		requireContext bool    // Must not be in comments/docs
	}{
		// AWS - Highly structured, don't need entropy check
		{"AWS Access Key", "aws_key", `AKIA[0-9A-Z]{16}`, "critical", "AWS Access Key ID", 0, false},
		{"AWS Secret Key", "aws_secret", `(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]`, "critical", "AWS Secret Access Key", 4.0, true},

		// Google - Structured prefixes
		{"Google API Key", "google_api", `AIza[0-9A-Za-z-_]{35}`, "high", "Google API Key", 3.5, false},
		{"Google OAuth", "google_oauth", `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`, "high", "Google OAuth Client ID", 0, false},
		{"GCP Service Account", "gcp_service", `"type":\s*"service_account"`, "critical", "GCP Service Account JSON", 0, false},

		// GitHub - Highly structured prefixes
		{"GitHub Token", "github_token", `ghp_[0-9a-zA-Z]{36}`, "critical", "GitHub Personal Access Token", 0, false},
		{"GitHub OAuth", "github_oauth", `gho_[0-9a-zA-Z]{36}`, "critical", "GitHub OAuth Token", 0, false},
		{"GitHub App Token", "github_app", `(ghu|ghs)_[0-9a-zA-Z]{36}`, "critical", "GitHub App Token", 0, false},

		// Slack - Structured prefixes
		{"Slack Token", "slack_token", `xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`, "critical", "Slack API Token", 0, false},
		{"Slack Webhook", "slack_webhook", `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`, "high", "Slack Webhook URL", 0, false},

		// Stripe - Structured prefixes
		{"Stripe API Key", "stripe_key", `sk_live_[0-9a-zA-Z]{24,}`, "critical", "Stripe Live API Key", 0, false},
		{"Stripe Test Key", "stripe_test", `sk_test_[0-9a-zA-Z]{24,}`, "low", "Stripe Test API Key", 0, false}, // Lowered severity for test keys

		// Database - Need entropy check as passwords could be simple
		{"MySQL Connection", "mysql_conn", `mysql://[^:]+:[^@]+@[^/]+/[^\s]+`, "critical", "MySQL Connection String", 2.5, true},
		{"PostgreSQL Connection", "postgres_conn", `postgres(ql)?://[^:]+:[^@]+@[^/]+/[^\s]+`, "critical", "PostgreSQL Connection String", 2.5, true},
		{"MongoDB Connection", "mongodb_conn", `mongodb(\+srv)?://[^:]+:[^@]+@[^/]+`, "critical", "MongoDB Connection String", 2.5, true},
		{"Redis URL", "redis_url", `redis://[^:]*:[^@]+@[^/]+`, "high", "Redis Connection String", 2.5, true},

		// Private Keys - No entropy needed, structural match is definitive
		{"RSA Private Key", "rsa_key", `-----BEGIN RSA PRIVATE KEY-----`, "critical", "RSA Private Key", 0, false},
		{"SSH Private Key", "ssh_key", `-----BEGIN (OPENSSH|EC|DSA) PRIVATE KEY-----`, "critical", "SSH Private Key", 0, false},
		{"PGP Private Key", "pgp_key", `-----BEGIN PGP PRIVATE KEY BLOCK-----`, "critical", "PGP Private Key", 0, false},

		// JWT - Has structure, but need to verify it's not example token
		{"JWT Token", "jwt", `eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`, "high", "JSON Web Token", 3.5, true},

		// Generic - HIGH FALSE POSITIVE RISK - require entropy + context
		{"API Key", "api_key", `(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][0-9a-zA-Z]{20,}['"]`, "medium", "Generic API Key", 4.0, true},
		{"Password in URL", "password_url", `(?i)://[^:]+:([^@]+)@`, "high", "Password in URL", 3.0, true},
		{"Bearer Token", "bearer", `(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}`, "medium", "Bearer Token", 3.5, true}, // Increased min length

		// Cloud Services - Structured
		{"Heroku API Key", "heroku_key", `(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`, "high", "Heroku API Key", 0, true},
		{"SendGrid API Key", "sendgrid_key", `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`, "high", "SendGrid API Key", 0, false},
		{"Twilio", "twilio", `SK[0-9a-fA-F]{32}`, "high", "Twilio API Key", 0, false},
		{"MailChimp", "mailchimp", `[0-9a-f]{32}-us[0-9]{1,2}`, "medium", "MailChimp API Key", 4.0, true}, // Needs entropy to avoid false positives

		// Internal IP - Removed from critical findings (too noisy, rarely actionable)
		// Keeping it but with very low priority
	}

	compiled := make([]*SecretPattern, 0, len(patterns))
	for _, p := range patterns {
		if r, err := regexp.Compile(p.regex); err == nil {
			compiled = append(compiled, &SecretPattern{
				Name:           p.name,
				Type:           p.patternType,
				Regex:          r,
				Severity:       p.severity,
				Description:    p.description,
				MinEntropy:     p.minEntropy,
				RequireContext: p.requireContext,
			})
		}
	}

	return compiled
}

// calculateEntropy calculates Shannon entropy of a string (bits per character)
// Higher entropy = more random = more likely to be a real secret
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * log2(p)
		}
	}

	return entropy
}

// log2 calculates log base 2
func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// log2(x) = ln(x) / ln(2)
	ln2 := 0.693147180559945
	// Simple ln approximation for small values
	return ln(x) / ln2
}

// ln calculates natural logarithm using Taylor series
func ln(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Normalize to [0.5, 1.5) range
	n := 0
	for x > 1.5 {
		x /= 2
		n++
	}
	for x < 0.5 {
		x *= 2
		n--
	}

	// Taylor series for ln(1+y) where y = x-1
	y := x - 1
	result := 0.0
	term := y
	for i := 1; i <= 20; i++ {
		if i%2 == 1 {
			result += term / float64(i)
		} else {
			result -= term / float64(i)
		}
		term *= y
	}

	return result + float64(n)*0.693147180559945
}

// isInCommentOrDoc checks if the match appears to be in a comment or documentation
func isInCommentOrDoc(context string, match string) bool {
	lowerCtx := strings.ToLower(context)

	// Common comment patterns
	commentPatterns := []string{
		"//", "/*", "*/", "#", "<!--", "-->",
		"example", "sample", "test", "demo", "dummy",
		"placeholder", "your_", "your-", "<your",
		"xxx", "todo", "fixme", "replace",
		"documentation", "readme", "docs",
	}

	for _, pattern := range commentPatterns {
		if strings.Contains(lowerCtx, pattern) {
			return true
		}
	}

	// Check if it looks like documentation/example
	if strings.Contains(lowerCtx, "```") { // Markdown code block
		return true
	}

	// Check for example API keys
	lowerMatch := strings.ToLower(match)
	examplePatterns := []string{
		"example", "test", "demo", "sample", "fake",
		"xxxx", "0000", "1234", "abcd",
	}
	for _, pattern := range examplePatterns {
		if strings.Contains(lowerMatch, pattern) {
			return true
		}
	}

	return false
}

// validateSecret checks if a potential secret passes entropy and context validation
func (ss *SecretScanner) validateSecret(pattern *SecretPattern, match string, context string) bool {
	// Check entropy requirement
	if pattern.MinEntropy > 0 {
		entropy := calculateEntropy(match)
		if entropy < pattern.MinEntropy {
			return false // Too low entropy - likely placeholder or example
		}
	}

	// Check context requirement
	if pattern.RequireContext {
		if isInCommentOrDoc(context, match) {
			return false // Appears to be in documentation/comment
		}
	}

	return true
}

// ScanAll performs comprehensive secret scanning
func (ss *SecretScanner) ScanAll(ctx context.Context) []SecretFinding {
	var findings []SecretFinding
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Search GitHub
	wg.Add(1)
	go func() {
		defer wg.Done()
		ghFindings := ss.searchGitHub(ctx)
		mu.Lock()
		findings = append(findings, ghFindings...)
		mu.Unlock()
	}()

	// Search GitLab
	wg.Add(1)
	go func() {
		defer wg.Done()
		glFindings := ss.searchGitLab(ctx)
		mu.Lock()
		findings = append(findings, glFindings...)
		mu.Unlock()
	}()

	// Check for common exposed files
	wg.Add(1)
	go func() {
		defer wg.Done()
		fileFindings := ss.checkExposedFiles(ctx)
		mu.Lock()
		findings = append(findings, fileFindings...)
		mu.Unlock()
	}()

	wg.Wait()
	return findings
}

// GitHubSearchResult represents GitHub search API response
type GitHubSearchResult struct {
	TotalCount int `json:"total_count"`
	Items      []struct {
		Name       string `json:"name"`
		Path       string `json:"path"`
		HTMLURL    string `json:"html_url"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		TextMatches []struct {
			Fragment string `json:"fragment"`
		} `json:"text_matches"`
	} `json:"items"`
}

// searchGitHub searches GitHub for exposed secrets
func (ss *SecretScanner) searchGitHub(ctx context.Context) []SecretFinding {
	var findings []SecretFinding

	// Search queries
	queries := []string{
		fmt.Sprintf(`"%s" password`, ss.domain),
		fmt.Sprintf(`"%s" api_key`, ss.domain),
		fmt.Sprintf(`"%s" apikey`, ss.domain),
		fmt.Sprintf(`"%s" secret`, ss.domain),
		fmt.Sprintf(`"%s" token`, ss.domain),
		fmt.Sprintf(`"%s" AWS_SECRET`, ss.domain),
		fmt.Sprintf(`"%s" credentials`, ss.domain),
		fmt.Sprintf(`"%s" .env`, ss.domain),
		fmt.Sprintf(`"%s" config.json`, ss.domain),
	}

	for _, query := range queries {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		searchURL := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=10",
			url.QueryEscape(query))

		req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/vnd.github.v3.text-match+json")
		req.Header.Set("User-Agent", "GodEye-Security-Scanner/1.0")

		resp, err := ss.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
			resp.Body.Close()

			var result GitHubSearchResult
			if json.Unmarshal(body, &result) == nil && result.TotalCount > 0 {
				for _, item := range result.Items {
					// Check text matches for actual secrets
					for _, match := range item.TextMatches {
						for _, pattern := range ss.patterns {
							if pattern.Regex.MatchString(match.Fragment) {
								secretMatch := pattern.Regex.FindString(match.Fragment)

								// IMPROVED: Apply entropy and context validation
								if !ss.validateSecret(pattern, secretMatch, match.Fragment) {
									continue // Skip false positives
								}

								findings = append(findings, SecretFinding{
									Type:        pattern.Type,
									Source:      "github",
									URL:         item.HTMLURL,
									Match:       sanitizeSecret(secretMatch),
									Context:     truncateString(match.Fragment, 200),
									Severity:    pattern.Severity,
									Description: pattern.Description,
									Filename:    item.Path,
									Repository:  item.Repository.FullName,
								})
							}
						}
					}

					// Removed: "potential_exposure" findings - too noisy, rarely actionable
					// Only report actual secrets found
				}
			}
		} else {
			resp.Body.Close()
		}

		// Rate limiting - be conservative
		time.Sleep(2 * time.Second)
	}

	return findings
}

// searchGitLab searches GitLab for exposed secrets
func (ss *SecretScanner) searchGitLab(ctx context.Context) []SecretFinding {
	var findings []SecretFinding

	// GitLab API search
	searchURL := fmt.Sprintf("https://gitlab.com/api/v4/search?scope=blobs&search=%s",
		url.QueryEscape(ss.domain))

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return findings
	}
	req.Header.Set("User-Agent", "GodEye-Security-Scanner/1.0")

	resp, err := ss.client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))

		var results []struct {
			Basename   string `json:"basename"`
			Data       string `json:"data"`
			Path       string `json:"path"`
			Filename   string `json:"filename"`
			ProjectID  int    `json:"project_id"`
		}

		if json.Unmarshal(body, &results) == nil {
			for _, item := range results {
				for _, pattern := range ss.patterns {
					if pattern.Regex.MatchString(item.Data) {
						secretMatch := pattern.Regex.FindString(item.Data)

						// IMPROVED: Apply entropy and context validation
						if !ss.validateSecret(pattern, secretMatch, item.Data) {
							continue // Skip false positives
						}

						// FIXED: Correct GitLab URL format
						findings = append(findings, SecretFinding{
							Type:        pattern.Type,
							Source:      "gitlab",
							URL:         fmt.Sprintf("https://gitlab.com/projects/%d", item.ProjectID),
							Match:       sanitizeSecret(secretMatch),
							Context:     truncateString(item.Data, 200),
							Severity:    pattern.Severity,
							Description: pattern.Description,
							Filename:    item.Filename,
						})
					}
				}
			}
		}
	}

	return findings
}

// checkExposedFiles checks for commonly exposed sensitive files
func (ss *SecretScanner) checkExposedFiles(ctx context.Context) []SecretFinding {
	var findings []SecretFinding

	// Sensitive files to check
	sensitiveFiles := []struct {
		path        string
		description string
		severity    string
	}{
		{"/.env", "Environment file with credentials", "critical"},
		{"/.env.local", "Local environment file", "critical"},
		{"/.env.production", "Production environment file", "critical"},
		{"/.env.backup", "Backup environment file", "critical"},
		{"/config.json", "JSON configuration file", "high"},
		{"/config.yaml", "YAML configuration file", "high"},
		{"/config.yml", "YAML configuration file", "high"},
		{"/settings.json", "Settings file", "high"},
		{"/secrets.json", "Secrets file", "critical"},
		{"/credentials.json", "Credentials file", "critical"},
		{"/database.yml", "Database configuration", "critical"},
		{"/application.properties", "Java application properties", "high"},
		{"/application.yml", "Spring application config", "high"},
		{"/wp-config.php.bak", "WordPress config backup", "critical"},
		{"/phpinfo.php", "PHP info page", "medium"},
		{"/.git/config", "Git configuration", "high"},
		{"/.svn/entries", "SVN entries", "high"},
		{"/.DS_Store", "Mac directory file", "low"},
		{"/server-status", "Apache server status", "medium"},
		{"/elmah.axd", ".NET error log", "high"},
		{"/trace.axd", ".NET trace log", "high"},
		{"/debug.log", "Debug log file", "medium"},
		{"/error.log", "Error log file", "medium"},
		{"/access.log", "Access log file", "medium"},
		{"/id_rsa", "SSH private key", "critical"},
		{"/id_rsa.pub", "SSH public key", "low"},
		{"/.htpasswd", "Apache password file", "critical"},
		{"/web.config", "IIS configuration", "high"},
		{"/crossdomain.xml", "Flash cross-domain policy", "low"},
		{"/clientaccesspolicy.xml", "Silverlight access policy", "low"},
	}

	for _, file := range sensitiveFiles {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		url := fmt.Sprintf("https://%s%s", ss.domain, file.path)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

		resp, err := ss.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 50*1024))
			resp.Body.Close()

			bodyStr := string(body)
			contentType := resp.Header.Get("Content-Type")

			// Skip if it's an HTML error page
			if strings.Contains(contentType, "text/html") &&
				(strings.Contains(bodyStr, "<html") || strings.Contains(bodyStr, "<!DOCTYPE")) {
				continue
			}

			finding := SecretFinding{
				Type:        "exposed_file",
				Source:      "direct",
				URL:         url,
				Severity:    file.severity,
				Description: file.description,
				Filename:    file.path,
			}

			// Check for actual secrets in the content
			foundSecret := false
			for _, pattern := range ss.patterns {
				if pattern.Regex.MatchString(bodyStr) {
					secretMatch := pattern.Regex.FindString(bodyStr)

					// IMPROVED: Apply entropy and context validation
					if !ss.validateSecret(pattern, secretMatch, bodyStr) {
						continue // Skip false positives
					}

					finding.Type = pattern.Type
					finding.Match = sanitizeSecret(secretMatch)
					finding.Severity = pattern.Severity
					finding.Description = fmt.Sprintf("%s - %s", file.description, pattern.Description)
					foundSecret = true
					break
				}
			}

			// Only report if we found actual secrets, or if the file itself is sensitive
			if foundSecret || file.severity == "critical" {
				findings = append(findings, finding)
			}
		} else {
			resp.Body.Close()
		}
	}

	return findings
}

// ScanContent scans arbitrary content for secrets
func (ss *SecretScanner) ScanContent(content string) []SecretFinding {
	var findings []SecretFinding

	for _, pattern := range ss.patterns {
		matches := pattern.Regex.FindAllString(content, 10)
		for _, match := range matches {
			findings = append(findings, SecretFinding{
				Type:        pattern.Type,
				Source:      "content_scan",
				Match:       sanitizeSecret(match),
				Severity:    pattern.Severity,
				Description: pattern.Description,
			})
		}
	}

	return findings
}

// sanitizeSecret masks the middle portion of a secret
func sanitizeSecret(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}
	return secret[:4] + "****" + secret[len(secret)-4:]
}

// truncateString truncates a string to maxLen
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
