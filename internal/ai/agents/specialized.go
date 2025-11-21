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

// SpecializedAgent represents an AI agent specialized for a specific vulnerability type
type SpecializedAgent struct {
	Type        AgentType
	OllamaURL   string
	Model       string
	SystemPrompt string
	Knowledge   *AgentKnowledge
	timeout     time.Duration
}

// AgentKnowledge contains domain-specific knowledge for the agent
type AgentKnowledge struct {
	Patterns      []string          // Regex/string patterns to look for
	Indicators    []string          // Indicators of vulnerability
	CommonCVEs    []string          // Common CVEs for this vuln type
	OWASP         string            // OWASP category
	PayloadHints  []string          // Example payloads (for detection, not attack)
	Remediation   map[string]string // severity -> remediation advice
}

// NewSpecializedAgent creates a new specialized agent
func NewSpecializedAgent(agentType AgentType, ollamaURL, model string) *SpecializedAgent {
	agent := &SpecializedAgent{
		Type:      agentType,
		OllamaURL: ollamaURL,
		Model:     model,
		timeout:   90 * time.Second, // Increased for local LLM
	}

	// Load agent-specific configuration
	agent.SystemPrompt = getAgentSystemPrompt(agentType)
	agent.Knowledge = getAgentKnowledge(agentType)

	return agent
}

// Analyze performs specialized analysis on the finding
func (sa *SpecializedAgent) Analyze(ctx context.Context, finding Finding) (*AgentResult, error) {
	start := time.Now()

	// Build the analysis prompt
	prompt := sa.buildPrompt(finding)

	// Query the model
	response, err := sa.queryOllama(ctx, prompt)
	if err != nil {
		return nil, err
	}

	// Parse the response into findings
	result := sa.parseResponse(response)
	result.AgentType = sa.Type
	result.Model = sa.Model
	result.Duration = time.Since(start)

	return result, nil
}

// buildPrompt constructs the analysis prompt with agent-specific context
func (sa *SpecializedAgent) buildPrompt(finding Finding) string {
	var sb strings.Builder

	// Add context about the finding
	sb.WriteString(fmt.Sprintf("Analyze this %s for %s vulnerabilities:\n\n", finding.Type, sa.Type))

	if finding.URL != "" {
		sb.WriteString(fmt.Sprintf("URL: %s\n", finding.URL))
	}

	if finding.StatusCode != 0 {
		sb.WriteString(fmt.Sprintf("Status Code: %d\n", finding.StatusCode))
	}

	if finding.ContentType != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: %s\n", finding.ContentType))
	}

	if finding.Technology != "" {
		sb.WriteString(fmt.Sprintf("Technology: %s", finding.Technology))
		if finding.Version != "" {
			sb.WriteString(fmt.Sprintf(" v%s", finding.Version))
		}
		sb.WriteString("\n")
	}

	if len(finding.Headers) > 0 {
		sb.WriteString("\nHeaders:\n")
		for k, v := range finding.Headers {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", k, truncateStr(v, 200)))
		}
	}

	if finding.Context != "" {
		content := truncateStr(finding.Context, 3000)
		sb.WriteString(fmt.Sprintf("\nContent:\n%s\n", content))
	}

	// Add knowledge hints
	if sa.Knowledge != nil && len(sa.Knowledge.Indicators) > 0 {
		sb.WriteString(fmt.Sprintf("\nLook specifically for: %s\n", strings.Join(sa.Knowledge.Indicators[:min(5, len(sa.Knowledge.Indicators))], ", ")))
	}

	sb.WriteString("\nRespond in this exact format:\n")
	sb.WriteString("SEVERITY: critical|high|medium|low|info\n")
	sb.WriteString("CONFIDENCE: 0-100\n")
	sb.WriteString("FINDING: <title>\n")
	sb.WriteString("DESCRIPTION: <detailed description>\n")
	sb.WriteString("EVIDENCE: <proof from the content>\n")
	sb.WriteString("REMEDIATION: <how to fix>\n")
	sb.WriteString("\nIf multiple issues found, repeat the format. If no issues, respond: FINDING: NONE")

	return sb.String()
}

// queryOllama sends the prompt to Ollama and gets the response
func (sa *SpecializedAgent) queryOllama(ctx context.Context, prompt string) (string, error) {
	type ollamaRequest struct {
		Model   string                 `json:"model"`
		System  string                 `json:"system,omitempty"`
		Prompt  string                 `json:"prompt"`
		Stream  bool                   `json:"stream"`
		Options map[string]interface{} `json:"options,omitempty"`
	}

	type ollamaResponse struct {
		Response string `json:"response"`
		Done     bool   `json:"done"`
	}

	reqBody := ollamaRequest{
		Model:  sa.Model,
		System: sa.SystemPrompt,
		Prompt: prompt,
		Stream: false,
		Options: map[string]interface{}{
			"temperature": 0.2, // Low for focused analysis
			"top_p":       0.9,
			"num_predict": 1000, // Limit response length
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %v", err)
	}

	client := &http.Client{Timeout: sa.timeout}
	req, err := http.NewRequestWithContext(ctx, "POST", sa.OllamaURL+"/api/generate", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	var ollamaResp ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %v", err)
	}

	return strings.TrimSpace(ollamaResp.Response), nil
}

// parseResponse extracts findings from the AI response
func (sa *SpecializedAgent) parseResponse(response string) *AgentResult {
	result := &AgentResult{
		Findings:   []AgentFinding{},
		Confidence: 0.5, // Default confidence
	}

	// Check for no findings
	if strings.Contains(strings.ToUpper(response), "FINDING: NONE") ||
		strings.Contains(strings.ToUpper(response), "NO ISSUES") ||
		strings.Contains(strings.ToUpper(response), "NO VULNERABILITIES") {
		return result
	}

	lines := strings.Split(response, "\n")
	var currentFinding *AgentFinding
	var currentField string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		upper := strings.ToUpper(line)

		// Parse fields
		if strings.HasPrefix(upper, "SEVERITY:") {
			// Save previous finding if exists
			if currentFinding != nil && currentFinding.Title != "" {
				result.Findings = append(result.Findings, *currentFinding)
			}
			currentFinding = &AgentFinding{
				OWASP: sa.Knowledge.OWASP,
			}
			severity := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "SEVERITY:")))
			severity = strings.TrimPrefix(severity, "severity:")
			// Clean up severity
			if strings.Contains(severity, "critical") {
				severity = "critical"
			} else if strings.Contains(severity, "high") {
				severity = "high"
			} else if strings.Contains(severity, "medium") {
				severity = "medium"
			} else if strings.Contains(severity, "low") {
				severity = "low"
			} else {
				severity = "info"
			}
			currentFinding.Severity = severity
			currentField = "severity"

		} else if strings.HasPrefix(upper, "CONFIDENCE:") {
			confStr := strings.TrimSpace(strings.TrimPrefix(line, "CONFIDENCE:"))
			confStr = strings.TrimPrefix(confStr, "confidence:")
			confStr = strings.TrimSuffix(confStr, "%")
			var conf float64
			fmt.Sscanf(confStr, "%f", &conf)
			if conf > 1 {
				conf = conf / 100 // Convert percentage to decimal
			}
			if conf > 0 && conf <= 1 {
				result.Confidence = conf
			}
			// Keep default 0.5 if parsing failed
			currentField = "confidence"

		} else if strings.HasPrefix(upper, "FINDING:") {
			if currentFinding == nil {
				currentFinding = &AgentFinding{OWASP: sa.Knowledge.OWASP}
			}
			currentFinding.Title = strings.TrimSpace(strings.TrimPrefix(line, "FINDING:"))
			currentFinding.Title = strings.TrimPrefix(currentFinding.Title, "finding:")
			currentField = "finding"

		} else if strings.HasPrefix(upper, "DESCRIPTION:") {
			if currentFinding != nil {
				currentFinding.Description = strings.TrimSpace(strings.TrimPrefix(line, "DESCRIPTION:"))
				currentFinding.Description = strings.TrimPrefix(currentFinding.Description, "description:")
			}
			currentField = "description"

		} else if strings.HasPrefix(upper, "EVIDENCE:") {
			if currentFinding != nil {
				currentFinding.Evidence = strings.TrimSpace(strings.TrimPrefix(line, "EVIDENCE:"))
				currentFinding.Evidence = strings.TrimPrefix(currentFinding.Evidence, "evidence:")
			}
			currentField = "evidence"

		} else if strings.HasPrefix(upper, "REMEDIATION:") {
			if currentFinding != nil {
				currentFinding.Remediation = strings.TrimSpace(strings.TrimPrefix(line, "REMEDIATION:"))
				currentFinding.Remediation = strings.TrimPrefix(currentFinding.Remediation, "remediation:")
			}
			currentField = "remediation"

		} else if strings.HasPrefix(upper, "CVE:") || strings.HasPrefix(upper, "CVES:") {
			if currentFinding != nil {
				cves := strings.TrimSpace(strings.TrimPrefix(line, "CVE:"))
				cves = strings.TrimPrefix(cves, "CVES:")
				currentFinding.CVEs = strings.Split(cves, ",")
			}

		} else if currentFinding != nil {
			// Continuation of previous field
			switch currentField {
			case "description":
				currentFinding.Description += " " + line
			case "evidence":
				currentFinding.Evidence += " " + line
			case "remediation":
				currentFinding.Remediation += " " + line
			}
		}
	}

	// Add last finding
	if currentFinding != nil && currentFinding.Title != "" {
		result.Findings = append(result.Findings, *currentFinding)
	}

	// Use highest severity finding's severity as overall
	for _, f := range result.Findings {
		if severityToInt(f.Severity) > severityToInt(result.AgentType.String()) {
			// Already tracked at finding level
		}
	}

	return result
}

// String returns the string representation of AgentType
func (at AgentType) String() string {
	return string(at)
}

// severityToInt converts severity to integer for comparison
func severityToInt(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// truncateStr truncates a string to max length
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...(truncated)"
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
