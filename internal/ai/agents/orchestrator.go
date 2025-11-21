package agents

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// AgentType represents the type of specialized agent
type AgentType string

const (
	AgentTypeXSS      AgentType = "xss"
	AgentTypeSQLi     AgentType = "sqli"
	AgentTypeAuth     AgentType = "auth"
	AgentTypeAPI      AgentType = "api"
	AgentTypeCrypto   AgentType = "crypto"
	AgentTypeSecrets  AgentType = "secrets"
	AgentTypeHeaders  AgentType = "headers"
	AgentTypeGeneral  AgentType = "general"
)

// Finding represents a security finding to be analyzed
type Finding struct {
	Type        string            // "http", "javascript", "api", "config", etc.
	URL         string            // Target URL
	Context     string            // Raw data to analyze
	Headers     map[string]string // HTTP headers if applicable
	StatusCode  int               // HTTP status code if applicable
	ContentType string            // Content-Type if applicable
	Technology  string            // Detected technology
	Version     string            // Version if known
	Metadata    map[string]string // Additional context
}

// AgentResult represents the analysis result from a specialized agent
type AgentResult struct {
	AgentType   AgentType
	Findings    []AgentFinding
	Confidence  float64       // 0.0 - 1.0
	Model       string        // Which model was used
	Duration    time.Duration // Time taken
	Reasoning   string        // Chain of thought (for debugging)
	HandoffFrom AgentType     // Which agent handed off to this one (if any)
}

// AgentFinding represents a single finding from an agent
type AgentFinding struct {
	Severity    string   // critical, high, medium, low, info
	Title       string   // Short title
	Description string   // Detailed description
	Evidence    string   // Proof/evidence
	Remediation string   // How to fix
	CVEs        []string // Related CVEs if any
	OWASP       string   // OWASP category (e.g., "A03:2021-Injection")
}

// AgentOrchestrator coordinates specialized AI agents
type AgentOrchestrator struct {
	mu            sync.RWMutex
	agents        map[AgentType]*SpecializedAgent
	coordinator   *CoordinatorAgent
	ollamaBaseURL string
	fastModel     string
	deepModel     string
	stats         *OrchestratorStats
}

// OrchestratorStats tracks agent usage statistics
type OrchestratorStats struct {
	mu              sync.Mutex
	TotalAnalyses   int
	AgentCalls      map[AgentType]int
	AvgConfidence   map[AgentType]float64
	TotalDuration   time.Duration
	HandoffCount    int
	CacheHits       int
}

// NewAgentOrchestrator creates a new multi-agent orchestrator
func NewAgentOrchestrator(ollamaBaseURL, fastModel, deepModel string) *AgentOrchestrator {
	ao := &AgentOrchestrator{
		agents:        make(map[AgentType]*SpecializedAgent),
		ollamaBaseURL: ollamaBaseURL,
		fastModel:     fastModel,
		deepModel:     deepModel,
		stats: &OrchestratorStats{
			AgentCalls:    make(map[AgentType]int),
			AvgConfidence: make(map[AgentType]float64),
		},
	}

	// Initialize all specialized agents
	ao.initializeAgents()

	// Initialize coordinator
	ao.coordinator = NewCoordinatorAgent(ollamaBaseURL, fastModel)

	return ao
}

// initializeAgents creates all specialized agents
func (ao *AgentOrchestrator) initializeAgents() {
	ao.agents[AgentTypeXSS] = NewSpecializedAgent(AgentTypeXSS, ao.ollamaBaseURL, ao.deepModel)
	ao.agents[AgentTypeSQLi] = NewSpecializedAgent(AgentTypeSQLi, ao.ollamaBaseURL, ao.deepModel)
	ao.agents[AgentTypeAuth] = NewSpecializedAgent(AgentTypeAuth, ao.ollamaBaseURL, ao.deepModel)
	ao.agents[AgentTypeAPI] = NewSpecializedAgent(AgentTypeAPI, ao.ollamaBaseURL, ao.deepModel)
	ao.agents[AgentTypeCrypto] = NewSpecializedAgent(AgentTypeCrypto, ao.ollamaBaseURL, ao.deepModel)
	ao.agents[AgentTypeSecrets] = NewSpecializedAgent(AgentTypeSecrets, ao.ollamaBaseURL, ao.deepModel)
	ao.agents[AgentTypeHeaders] = NewSpecializedAgent(AgentTypeHeaders, ao.ollamaBaseURL, ao.deepModel)
	ao.agents[AgentTypeGeneral] = NewSpecializedAgent(AgentTypeGeneral, ao.ollamaBaseURL, ao.deepModel)
}

// Analyze performs intelligent analysis by routing to specialized agents
func (ao *AgentOrchestrator) Analyze(ctx context.Context, finding Finding) (*AgentResult, error) {
	start := time.Now()

	// Step 1: Fast context classification by Coordinator
	agentType, confidence, reasoning := ao.coordinator.ClassifyContext(ctx, finding)

	ao.stats.mu.Lock()
	ao.stats.TotalAnalyses++
	ao.stats.mu.Unlock()

	// Step 2: If low confidence, use general agent
	if confidence < 0.6 {
		agentType = AgentTypeGeneral
	}

	// Step 3: Route to specialized agent
	ao.mu.RLock()
	agent, exists := ao.agents[agentType]
	ao.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("agent not found: %s", agentType)
	}

	// Step 4: Analyze with specialized agent
	result, err := agent.Analyze(ctx, finding)
	if err != nil {
		return nil, err
	}

	// Add metadata
	result.Duration = time.Since(start)
	result.Reasoning = reasoning

	// Always use coordinator confidence (fast classification is more reliable than LLM output parsing)
	result.Confidence = confidence

	// Update stats
	ao.updateStats(agentType, result.Confidence, result.Duration)

	// Step 5: Check for handoff opportunities
	handoffResult := ao.checkHandoff(ctx, finding, result)
	if handoffResult != nil {
		result.Findings = append(result.Findings, handoffResult.Findings...)
		ao.stats.mu.Lock()
		ao.stats.HandoffCount++
		ao.stats.mu.Unlock()
	}

	return result, nil
}

// AnalyzeParallel analyzes multiple findings concurrently
func (ao *AgentOrchestrator) AnalyzeParallel(ctx context.Context, findings []Finding, maxConcurrent int) []*AgentResult {
	results := make([]*AgentResult, len(findings))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrent)

	for i, finding := range findings {
		wg.Add(1)
		go func(idx int, f Finding) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			result, err := ao.Analyze(ctx, f)
			if err != nil {
				results[idx] = &AgentResult{
					AgentType: AgentTypeGeneral,
					Findings: []AgentFinding{{
						Severity:    "info",
						Title:       "Analysis failed",
						Description: err.Error(),
					}},
				}
			} else {
				results[idx] = result
			}
		}(i, finding)
	}

	wg.Wait()

	// Filter nil results
	validResults := make([]*AgentResult, 0, len(results))
	for _, r := range results {
		if r != nil {
			validResults = append(validResults, r)
		}
	}

	return validResults
}

// checkHandoff determines if another agent should also analyze the finding
func (ao *AgentOrchestrator) checkHandoff(ctx context.Context, finding Finding, primaryResult *AgentResult) *AgentResult {
	// Define handoff rules based on finding characteristics
	handoffs := ao.coordinator.DetermineHandoffs(finding, primaryResult)

	if len(handoffs) == 0 {
		return nil
	}

	// Only do one handoff to avoid cascade
	handoffAgent := handoffs[0]

	ao.mu.RLock()
	agent, exists := ao.agents[handoffAgent]
	ao.mu.RUnlock()

	if !exists {
		return nil
	}

	result, err := agent.Analyze(ctx, finding)
	if err != nil {
		return nil
	}

	result.HandoffFrom = primaryResult.AgentType
	return result
}

// updateStats updates orchestrator statistics
func (ao *AgentOrchestrator) updateStats(agentType AgentType, confidence float64, duration time.Duration) {
	ao.stats.mu.Lock()
	defer ao.stats.mu.Unlock()

	ao.stats.AgentCalls[agentType]++
	ao.stats.TotalDuration += duration

	// Update running average confidence
	calls := float64(ao.stats.AgentCalls[agentType])
	prevAvg := ao.stats.AvgConfidence[agentType]
	ao.stats.AvgConfidence[agentType] = prevAvg + (confidence-prevAvg)/calls
}

// GetStats returns current orchestrator statistics
func (ao *AgentOrchestrator) GetStats() *OrchestratorStats {
	ao.stats.mu.Lock()
	defer ao.stats.mu.Unlock()

	// Return a copy
	statsCopy := &OrchestratorStats{
		TotalAnalyses: ao.stats.TotalAnalyses,
		AgentCalls:    make(map[AgentType]int),
		AvgConfidence: make(map[AgentType]float64),
		TotalDuration: ao.stats.TotalDuration,
		HandoffCount:  ao.stats.HandoffCount,
		CacheHits:     ao.stats.CacheHits,
	}

	for k, v := range ao.stats.AgentCalls {
		statsCopy.AgentCalls[k] = v
	}
	for k, v := range ao.stats.AvgConfidence {
		statsCopy.AvgConfidence[k] = v
	}

	return statsCopy
}

// GetAgentInfo returns information about available agents
func (ao *AgentOrchestrator) GetAgentInfo() map[AgentType]string {
	return map[AgentType]string{
		AgentTypeXSS:     "Cross-Site Scripting specialist - DOM XSS, Reflected XSS, Stored XSS patterns",
		AgentTypeSQLi:    "SQL Injection specialist - Error-based, Blind, Time-based, Union-based",
		AgentTypeAuth:    "Authentication bypass specialist - IDOR, Session, JWT, OAuth flaws",
		AgentTypeAPI:     "API security specialist - REST, GraphQL, gRPC vulnerabilities",
		AgentTypeCrypto:  "Cryptographic issues - Weak ciphers, Key exposure, TLS misconfigs",
		AgentTypeSecrets: "Secrets detection - API keys, tokens, credentials in code",
		AgentTypeHeaders: "HTTP headers security - CSP, CORS, HSTS, security headers",
		AgentTypeGeneral: "General security analysis - Fallback for unclassified findings",
	}
}

// FormatResults formats agent results for display
func FormatResults(results []*AgentResult) string {
	var sb strings.Builder

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, result := range results {
		for _, finding := range result.Findings {
			switch finding.Severity {
			case "critical":
				criticalCount++
			case "high":
				highCount++
			case "medium":
				mediumCount++
			case "low":
				lowCount++
			}
		}
	}

	sb.WriteString(fmt.Sprintf("Analysis Summary: %d critical, %d high, %d medium, %d low\n\n",
		criticalCount, highCount, mediumCount, lowCount))

	for _, result := range results {
		if len(result.Findings) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf("[%s Agent] (confidence: %.0f%%)\n",
			strings.ToUpper(string(result.AgentType)), result.Confidence*100))

		for _, finding := range result.Findings {
			icon := "i"
			switch finding.Severity {
			case "critical":
				icon = "!"
			case "high":
				icon = "H"
			case "medium":
				icon = "M"
			case "low":
				icon = "L"
			}

			sb.WriteString(fmt.Sprintf("  [%s] %s: %s\n", icon, finding.Severity, finding.Title))
			if finding.Description != "" {
				sb.WriteString(fmt.Sprintf("      %s\n", finding.Description))
			}
			if finding.OWASP != "" {
				sb.WriteString(fmt.Sprintf("      OWASP: %s\n", finding.OWASP))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
