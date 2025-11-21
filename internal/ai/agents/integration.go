package agents

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"god-eye/internal/config"
)

// ScannerIntegration bridges the orchestrator with god-eye scanner
type ScannerIntegration struct {
	orchestrator *AgentOrchestrator
	verbose      bool
}

// NewScannerIntegration creates a new scanner integration
func NewScannerIntegration(ollamaURL, fastModel, deepModel string, verbose bool) *ScannerIntegration {
	return &ScannerIntegration{
		orchestrator: NewAgentOrchestrator(ollamaURL, fastModel, deepModel),
		verbose:      verbose,
	}
}

// AnalyzeSubdomainResult analyzes a subdomain result using multi-agent orchestration
func (si *ScannerIntegration) AnalyzeSubdomainResult(ctx context.Context, subdomain string, result *config.SubdomainResult) (*MultiAgentAnalysis, error) {
	findings := si.buildFindings(subdomain, result)

	if len(findings) == 0 {
		return &MultiAgentAnalysis{}, nil
	}

	// Analyze all findings sequentially to avoid Ollama overload
	agentResults := si.orchestrator.AnalyzeParallel(ctx, findings, 1)

	// Convert to analysis result
	analysis := si.convertResults(agentResults)

	return analysis, nil
}

// buildFindings converts subdomain result into findings for agent analysis
func (si *ScannerIntegration) buildFindings(subdomain string, result *config.SubdomainResult) []Finding {
	var findings []Finding

	// 1. JavaScript Analysis Finding
	if len(result.JSFiles) > 0 || len(result.JSSecrets) > 0 {
		jsContent := ""
		if len(result.JSSecrets) > 0 {
			jsContent = strings.Join(result.JSSecrets, "\n")
		}
		findings = append(findings, Finding{
			Type:    "javascript",
			URL:     subdomain,
			Context: jsContent,
			Metadata: map[string]string{
				"js_files": strings.Join(result.JSFiles, ", "),
			},
		})
	}

	// 2. HTTP Response Analysis Finding
	if result.StatusCode > 0 {
		headers := make(map[string]string)
		contentType := ""
		for _, h := range result.Headers {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				headers[key] = val
				if strings.EqualFold(key, "Content-Type") {
					contentType = val
				}
			}
		}

		findings = append(findings, Finding{
			Type:        "http",
			URL:         subdomain,
			StatusCode:  result.StatusCode,
			ContentType: contentType,
			Headers:     headers,
			Context:     result.Title,
			Metadata: map[string]string{
				"server": result.Server,
			},
		})
	}

	// 3. Technology-based Finding for CVE analysis
	for _, tech := range result.Tech {
		findings = append(findings, Finding{
			Type:       "technology",
			URL:        subdomain,
			Technology: tech,
			Context:    fmt.Sprintf("Detected technology: %s", tech),
		})
	}

	// 4. Security Issues Finding
	if result.OpenRedirect || result.CORSMisconfig != "" ||
		len(result.DangerousMethods) > 0 || result.GitExposed ||
		result.SvnExposed || len(result.BackupFiles) > 0 {

		issueContext := buildSecurityIssuesContext(result)
		findings = append(findings, Finding{
			Type:    "security_issue",
			URL:     subdomain,
			Context: issueContext,
		})
	}

	// 5. Takeover Finding
	if result.Takeover != "" {
		findings = append(findings, Finding{
			Type:    "takeover",
			URL:     subdomain,
			Context: result.Takeover,
		})
	}

	// 6. API Endpoint Finding
	if len(result.APIEndpoints) > 0 {
		findings = append(findings, Finding{
			Type:    "api",
			URL:     subdomain,
			Context: strings.Join(result.APIEndpoints, "\n"),
		})
	}

	return findings
}

// buildSecurityIssuesContext creates context string from security issues
func buildSecurityIssuesContext(result *config.SubdomainResult) string {
	var issues []string

	if result.OpenRedirect {
		issues = append(issues, "Open Redirect vulnerability detected")
	}
	if result.CORSMisconfig != "" {
		issues = append(issues, fmt.Sprintf("CORS Misconfiguration: %s", result.CORSMisconfig))
	}
	if len(result.DangerousMethods) > 0 {
		issues = append(issues, fmt.Sprintf("Dangerous HTTP methods: %s", strings.Join(result.DangerousMethods, ", ")))
	}
	if result.GitExposed {
		issues = append(issues, "Git repository exposed (.git)")
	}
	if result.SvnExposed {
		issues = append(issues, "SVN repository exposed (.svn)")
	}
	if len(result.BackupFiles) > 0 {
		issues = append(issues, fmt.Sprintf("Backup files found: %s", strings.Join(result.BackupFiles, ", ")))
	}

	return strings.Join(issues, "\n")
}

// convertResults converts agent results to MultiAgentAnalysis
func (si *ScannerIntegration) convertResults(results []*AgentResult) *MultiAgentAnalysis {
	analysis := &MultiAgentAnalysis{
		Findings:    make([]AnalyzedFinding, 0),
		AgentStats:  make(map[string]AgentStat),
		TotalIssues: 0,
	}

	for _, result := range results {
		if result == nil {
			continue
		}

		// Track agent stats
		stat := analysis.AgentStats[string(result.AgentType)]
		stat.CallCount++
		stat.AvgConfidence = (stat.AvgConfidence*float64(stat.CallCount-1) + result.Confidence) / float64(stat.CallCount)
		stat.TotalDuration += result.Duration.Nanoseconds()
		analysis.AgentStats[string(result.AgentType)] = stat

		// Convert findings
		for _, f := range result.Findings {
			analysis.Findings = append(analysis.Findings, AnalyzedFinding{
				Agent:       string(result.AgentType),
				Severity:    f.Severity,
				Title:       f.Title,
				Description: f.Description,
				Evidence:    f.Evidence,
				Remediation: f.Remediation,
				CVEs:        f.CVEs,
				OWASP:       f.OWASP,
				Confidence:  result.Confidence,
			})
			analysis.TotalIssues++

			// Track severity counts
			switch f.Severity {
			case "critical":
				analysis.CriticalCount++
			case "high":
				analysis.HighCount++
			case "medium":
				analysis.MediumCount++
			case "low":
				analysis.LowCount++
			}
		}
	}

	return analysis
}

// MultiAgentAnalysis contains the aggregated analysis from all agents
type MultiAgentAnalysis struct {
	Findings      []AnalyzedFinding
	AgentStats    map[string]AgentStat
	TotalIssues   int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
}

// AnalyzedFinding represents a finding analyzed by an agent
type AnalyzedFinding struct {
	Agent       string   `json:"agent"`
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	CVEs        []string `json:"cves,omitempty"`
	OWASP       string   `json:"owasp,omitempty"`
	Confidence  float64  `json:"confidence"`
}

// AgentStat tracks statistics for each agent
type AgentStat struct {
	CallCount     int
	AvgConfidence float64
	TotalDuration int64 // nanoseconds
}

// AnalyzeAllResults analyzes all subdomain results concurrently
func (si *ScannerIntegration) AnalyzeAllResults(ctx context.Context, results map[string]*config.SubdomainResult, resultsMu *sync.Mutex, maxConcurrent int) *MultiAgentAnalysis {
	aggregated := &MultiAgentAnalysis{
		Findings:   make([]AnalyzedFinding, 0),
		AgentStats: make(map[string]AgentStat),
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrent)

	resultsMu.Lock()
	subdomains := make([]string, 0, len(results))
	for sub := range results {
		subdomains = append(subdomains, sub)
	}
	resultsMu.Unlock()

	for _, subdomain := range subdomains {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			resultsMu.Lock()
			result := results[sub]
			resultsMu.Unlock()

			if result == nil {
				return
			}

			analysis, err := si.AnalyzeSubdomainResult(ctx, sub, result)
			if err != nil {
				return
			}

			// Aggregate
			mu.Lock()
			aggregated.Findings = append(aggregated.Findings, analysis.Findings...)
			aggregated.TotalIssues += analysis.TotalIssues
			aggregated.CriticalCount += analysis.CriticalCount
			aggregated.HighCount += analysis.HighCount
			aggregated.MediumCount += analysis.MediumCount
			aggregated.LowCount += analysis.LowCount

			for agent, stat := range analysis.AgentStats {
				existing := aggregated.AgentStats[agent]
				existing.CallCount += stat.CallCount
				aggregated.AgentStats[agent] = existing
			}
			mu.Unlock()

		}(subdomain)
	}

	wg.Wait()
	return aggregated
}

// FormatAnalysis formats the analysis for display
func (si *ScannerIntegration) FormatAnalysis(analysis *MultiAgentAnalysis) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Multi-Agent Analysis Summary:\n"))
	sb.WriteString(fmt.Sprintf("  Total Issues: %d (Critical: %d, High: %d, Medium: %d, Low: %d)\n\n",
		analysis.TotalIssues, analysis.CriticalCount, analysis.HighCount, analysis.MediumCount, analysis.LowCount))

	// Group by severity
	severityOrder := []string{"critical", "high", "medium", "low", "info"}
	for _, sev := range severityOrder {
		for _, f := range analysis.Findings {
			if f.Severity != sev {
				continue
			}

			icon := "i"
			switch sev {
			case "critical":
				icon = "!!"
			case "high":
				icon = "!"
			case "medium":
				icon = "M"
			case "low":
				icon = "L"
			}

			sb.WriteString(fmt.Sprintf("[%s] %s: %s\n", icon, strings.ToUpper(sev), f.Title))
			sb.WriteString(fmt.Sprintf("    Agent: %s (confidence: %.0f%%)\n", f.Agent, f.Confidence*100))
			if f.Description != "" {
				sb.WriteString(fmt.Sprintf("    %s\n", f.Description))
			}
			if f.OWASP != "" {
				sb.WriteString(fmt.Sprintf("    OWASP: %s\n", f.OWASP))
			}
			if f.Remediation != "" {
				sb.WriteString(fmt.Sprintf("    Fix: %s\n", f.Remediation))
			}
			sb.WriteString("\n")
		}
	}

	// Agent stats
	sb.WriteString("Agent Usage:\n")
	for agent, stat := range analysis.AgentStats {
		sb.WriteString(fmt.Sprintf("  %s: %d calls\n", agent, stat.CallCount))
	}

	return sb.String()
}

// GetOrchestrator returns the underlying orchestrator for direct access
func (si *ScannerIntegration) GetOrchestrator() *AgentOrchestrator {
	return si.orchestrator
}
