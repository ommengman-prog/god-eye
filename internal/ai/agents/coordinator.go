package agents

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CoordinatorAgent routes findings to specialized agents
type CoordinatorAgent struct {
	OllamaURL string
	Model     string
	timeout   time.Duration
	// Fast keyword-based pre-classification
	classifierRules map[string]AgentType
}

// NewCoordinatorAgent creates a new coordinator agent
func NewCoordinatorAgent(ollamaURL, fastModel string) *CoordinatorAgent {
	ca := &CoordinatorAgent{
		OllamaURL:       ollamaURL,
		Model:           fastModel,
		timeout:         30 * time.Second, // Increased for local LLM
		classifierRules: make(map[string]AgentType),
	}

	// Initialize fast classification rules (keyword -> agent type)
	ca.initClassifierRules()

	return ca
}

// initClassifierRules sets up keyword-based fast classification
func (ca *CoordinatorAgent) initClassifierRules() {
	// XSS indicators
	xssKeywords := []string{
		"script", "onerror", "onclick", "onload", "onmouseover", "onfocus",
		"innerHTML", "document.write", "document.cookie", "eval(", "alert(",
		"<img", "<svg", "<iframe", "javascript:", "vbscript:", "data:text/html",
		"xss", "cross-site", "reflected", "dom-based",
	}
	for _, kw := range xssKeywords {
		ca.classifierRules[kw] = AgentTypeXSS
	}

	// SQLi indicators
	sqliKeywords := []string{
		"sql", "mysql", "postgres", "sqlite", "oracle", "mssql",
		"union", "select", "insert", "update", "delete", "drop",
		"where", "from", "order by", "group by", "having",
		"'--", "\"--", "';", "\";", "/*", "*/",
		"sqlstate", "syntax error", "odbc", "jdbc",
		"injection", "sqli", "blind sql",
	}
	for _, kw := range sqliKeywords {
		ca.classifierRules[kw] = AgentTypeSQLi
	}

	// Auth indicators
	authKeywords := []string{
		"login", "logout", "signin", "signout", "auth", "session",
		"jwt", "token", "bearer", "oauth", "saml", "sso",
		"password", "credential", "2fa", "mfa", "totp", "otp",
		"cookie", "csrf", "xsrf", "idor", "bola",
		"privilege", "escalation", "bypass", "unauthorized",
		"admin", "superuser", "root",
	}
	for _, kw := range authKeywords {
		ca.classifierRules[kw] = AgentTypeAuth
	}

	// API indicators
	apiKeywords := []string{
		"graphql", "query", "mutation", "subscription", "introspection",
		"rest", "restful", "api/", "/api", "swagger", "openapi",
		"grpc", "protobuf", "websocket", "wss://",
		"rate limit", "ratelimit", "throttle",
		"cors", "access-control", "preflight",
		"json", "xml", "application/json",
	}
	for _, kw := range apiKeywords {
		ca.classifierRules[kw] = AgentTypeAPI
	}

	// Crypto indicators
	cryptoKeywords := []string{
		"ssl", "tls", "https", "certificate", "cert",
		"encrypt", "decrypt", "cipher", "aes", "rsa", "des", "3des",
		"sha1", "sha256", "md5", "hash", "hmac",
		"private key", "public key", "-----begin", "-----end",
		"pem", "pkcs", "x509",
		"weak cipher", "insecure", "deprecated",
	}
	for _, kw := range cryptoKeywords {
		ca.classifierRules[kw] = AgentTypeCrypto
	}

	// Secrets indicators
	secretsKeywords := []string{
		"api_key", "apikey", "api-key", "access_key", "secret_key",
		"aws_", "akia", "azure", "gcp",
		"ghp_", "gho_", "github", "gitlab",
		"sk_live", "pk_live", "stripe",
		"slack", "xox", "discord",
		"database_url", "db_password", "connection_string",
		"firebase", "twilio", "sendgrid", "mailchimp",
	}
	for _, kw := range secretsKeywords {
		ca.classifierRules[kw] = AgentTypeSecrets
	}

	// Headers indicators
	headersKeywords := []string{
		"content-security-policy", "csp", "x-frame-options", "x-xss-protection",
		"strict-transport-security", "hsts", "x-content-type-options",
		"access-control-allow", "referrer-policy", "permissions-policy",
		"server:", "x-powered-by", "x-aspnet",
		"cache-control", "pragma", "expires",
		"set-cookie", "secure;", "httponly",
	}
	for _, kw := range headersKeywords {
		ca.classifierRules[kw] = AgentTypeHeaders
	}
}

// ClassifyContext determines which agent should handle the finding
// Returns: agentType, confidence (0-1), reasoning
func (ca *CoordinatorAgent) ClassifyContext(ctx context.Context, finding Finding) (AgentType, float64, string) {
	// Step 1: Fast keyword-based classification
	agentType, score := ca.fastClassify(finding)

	if score >= 0.7 {
		// High confidence keyword match - skip LLM
		return agentType, score, fmt.Sprintf("Fast classification: found %s indicators", agentType)
	}

	// Step 2: LLM-based classification for ambiguous cases
	if score < 0.5 {
		llmType, llmConf, reason := ca.llmClassify(ctx, finding)
		if llmConf > score {
			return llmType, llmConf, reason
		}
	}

	// Return best fast match or general
	if score >= 0.3 {
		return agentType, score, "Partial keyword match"
	}

	return AgentTypeGeneral, 0.5, "No specific classification - using general agent"
}

// fastClassify performs keyword-based classification
func (ca *CoordinatorAgent) fastClassify(finding Finding) (AgentType, float64) {
	// Step 1: Type-based fast routing (highest priority)
	switch strings.ToLower(finding.Type) {
	case "javascript":
		// JS findings go to secrets first (API keys, tokens), then XSS
		if containsAny(finding.Context, []string{"api_key", "apikey", "secret", "token", "password", "akia", "sk_live", "pk_live", "ghp_"}) {
			return AgentTypeSecrets, 0.9
		}
		return AgentTypeXSS, 0.8
	case "http":
		// HTTP responses go to headers agent
		return AgentTypeHeaders, 0.8
	case "technology":
		// Technology findings go to crypto (for version/vuln analysis)
		return AgentTypeCrypto, 0.8
	case "api":
		return AgentTypeAPI, 0.9
	case "security_issue":
		// Security issues need general analysis
		return AgentTypeGeneral, 0.8
	case "takeover":
		// Takeover is auth-related
		return AgentTypeAuth, 0.9
	}

	// Step 2: Keyword-based classification for untyped findings
	content := strings.ToLower(finding.Context + " " + finding.URL + " " + finding.Type + " " + finding.Technology)
	for k, v := range finding.Headers {
		content += " " + strings.ToLower(k) + ":" + strings.ToLower(v)
	}

	// Count matches per agent type
	scores := make(map[AgentType]int)
	totalMatches := 0

	for keyword, agentType := range ca.classifierRules {
		if strings.Contains(content, strings.ToLower(keyword)) {
			scores[agentType]++
			totalMatches++
		}
	}

	if totalMatches == 0 {
		return AgentTypeGeneral, 0.5 // Default with moderate confidence
	}

	// Find agent with highest score
	var bestAgent AgentType
	var bestScore int
	for agent, score := range scores {
		if score > bestScore {
			bestScore = score
			bestAgent = agent
		}
	}

	// Calculate confidence (more matches = higher confidence)
	confidence := 0.5
	if bestScore >= 5 {
		confidence = 0.9
	} else if bestScore >= 3 {
		confidence = 0.75
	} else if bestScore >= 2 {
		confidence = 0.65
	} else if bestScore >= 1 {
		confidence = 0.55
	}

	return bestAgent, confidence
}

// llmClassify uses the LLM for complex classification
func (ca *CoordinatorAgent) llmClassify(ctx context.Context, finding Finding) (AgentType, float64, string) {
	prompt := fmt.Sprintf(`Classify this security finding into exactly ONE category. Respond with ONLY the category name and confidence.

Finding Type: %s
URL: %s
Technology: %s
Content Sample: %s

Categories:
- xss (Cross-Site Scripting, DOM manipulation, script injection)
- sqli (SQL Injection, database queries, SQL errors)
- auth (Authentication, sessions, tokens, authorization, IDOR)
- api (REST/GraphQL APIs, CORS, rate limiting)
- crypto (TLS/SSL, encryption, certificates, hashing)
- secrets (API keys, credentials, passwords, tokens in code)
- headers (HTTP security headers, CSP, HSTS, cookies)
- general (none of the above)

Response format: CATEGORY:confidence
Example: sqli:85`,
		finding.Type,
		finding.URL,
		finding.Technology,
		truncateStr(finding.Context, 500))

	response, err := ca.queryOllama(ctx, prompt)
	if err != nil {
		return AgentTypeGeneral, 0.5, "LLM classification failed"
	}

	// Parse response
	response = strings.TrimSpace(strings.ToLower(response))
	parts := strings.Split(response, ":")

	if len(parts) >= 1 {
		category := strings.TrimSpace(parts[0])
		confidence := 0.6 // Default confidence

		if len(parts) >= 2 {
			var conf float64
			fmt.Sscanf(parts[1], "%f", &conf)
			if conf > 1 {
				conf = conf / 100
			}
			if conf > 0 && conf <= 1 {
				confidence = conf
			}
		}

		agentType := parseAgentType(category)
		return agentType, confidence, fmt.Sprintf("LLM classified as %s", agentType)
	}

	return AgentTypeGeneral, 0.5, "Could not parse LLM response"
}

// DetermineHandoffs checks if additional agents should analyze the finding
func (ca *CoordinatorAgent) DetermineHandoffs(finding Finding, primaryResult *AgentResult) []AgentType {
	var handoffs []AgentType

	// Define handoff rules
	switch primaryResult.AgentType {
	case AgentTypeAPI:
		// API findings often have auth issues
		if containsAny(finding.Context, []string{"401", "403", "unauthorized", "forbidden"}) {
			handoffs = append(handoffs, AgentTypeAuth)
		}
		// CORS issues often relate to XSS
		if containsAny(finding.Context, []string{"cors", "access-control"}) {
			handoffs = append(handoffs, AgentTypeXSS)
		}

	case AgentTypeAuth:
		// Auth pages may have XSS
		if containsAny(finding.Context, []string{"<form", "input", "password"}) {
			handoffs = append(handoffs, AgentTypeXSS)
		}

	case AgentTypeXSS:
		// Stored XSS often involves SQLi vectors
		if containsAny(finding.Context, []string{"stored", "persistent", "database"}) {
			handoffs = append(handoffs, AgentTypeSQLi)
		}

	case AgentTypeSecrets:
		// Secrets in JS may indicate other JS vulns
		if finding.Type == "javascript" {
			handoffs = append(handoffs, AgentTypeXSS)
		}

	case AgentTypeHeaders:
		// Missing security headers may indicate broader issues
		if containsAny(strings.ToLower(fmt.Sprintf("%v", primaryResult)), []string{"csp", "cors"}) {
			handoffs = append(handoffs, AgentTypeXSS)
		}
	}

	// Only handoff if primary found something significant
	hasCritical := false
	for _, f := range primaryResult.Findings {
		if f.Severity == "critical" || f.Severity == "high" {
			hasCritical = true
			break
		}
	}

	if !hasCritical {
		return nil // No handoff for low-severity findings
	}

	return handoffs
}

// queryOllama sends a quick query to Ollama
func (ca *CoordinatorAgent) queryOllama(ctx context.Context, prompt string) (string, error) {
	type ollamaRequest struct {
		Model   string                 `json:"model"`
		Prompt  string                 `json:"prompt"`
		Stream  bool                   `json:"stream"`
		Options map[string]interface{} `json:"options,omitempty"`
	}

	type ollamaResponse struct {
		Response string `json:"response"`
	}

	reqBody := ollamaRequest{
		Model:  ca.Model,
		Prompt: prompt,
		Stream: false,
		Options: map[string]interface{}{
			"temperature": 0.1, // Very low for classification
			"num_predict": 50,  // Short response
		},
	}

	jsonData, _ := json.Marshal(reqBody)

	client := &http.Client{Timeout: ca.timeout}
	req, err := http.NewRequestWithContext(ctx, "POST", ca.OllamaURL+"/api/generate", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var ollamaResp ollamaResponse
	json.NewDecoder(resp.Body).Decode(&ollamaResp)

	return ollamaResp.Response, nil
}

// parseAgentType converts string to AgentType
func parseAgentType(s string) AgentType {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(s, "xss"):
		return AgentTypeXSS
	case strings.Contains(s, "sql"):
		return AgentTypeSQLi
	case strings.Contains(s, "auth"):
		return AgentTypeAuth
	case strings.Contains(s, "api"):
		return AgentTypeAPI
	case strings.Contains(s, "crypto"):
		return AgentTypeCrypto
	case strings.Contains(s, "secret"):
		return AgentTypeSecrets
	case strings.Contains(s, "header"):
		return AgentTypeHeaders
	default:
		return AgentTypeGeneral
	}
}

// containsAny checks if string contains any of the substrings
func containsAny(s string, substrings []string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrings {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
