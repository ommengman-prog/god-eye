package output

import (
	"encoding/json"
	"io"
	"sort"
	"time"

	"god-eye/internal/config"
)

// ScanReport represents the complete JSON output structure
type ScanReport struct {
	// Metadata
	Meta ScanMeta `json:"meta"`

	// Statistics
	Stats ScanStats `json:"stats"`

	// Results
	Subdomains []*config.SubdomainResult `json:"subdomains"`

	// Wildcard info (if detected)
	Wildcard *WildcardReport `json:"wildcard,omitempty"`

	// Findings summary
	Findings FindingsSummary `json:"findings"`
}

// ScanMeta contains metadata about the scan
type ScanMeta struct {
	Version     string    `json:"version"`
	ToolName    string    `json:"tool_name"`
	Target      string    `json:"target"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Duration    string    `json:"duration"`
	DurationMs  int64     `json:"duration_ms"`
	Concurrency int       `json:"concurrency"`
	Timeout     int       `json:"timeout"`
	Options     ScanOptions `json:"options"`
}

// ScanOptions contains the scan configuration
type ScanOptions struct {
	BruteForce      bool   `json:"brute_force"`
	HTTPProbe       bool   `json:"http_probe"`
	PortScan        bool   `json:"port_scan"`
	TakeoverCheck   bool   `json:"takeover_check"`
	AIAnalysis      bool   `json:"ai_analysis"`
	OnlyActive      bool   `json:"only_active"`
	CustomWordlist  bool   `json:"custom_wordlist"`
	CustomResolvers bool   `json:"custom_resolvers"`
	CustomPorts     string `json:"custom_ports,omitempty"`
}

// ScanStats contains scan statistics
type ScanStats struct {
	TotalSubdomains    int `json:"total_subdomains"`
	ActiveSubdomains   int `json:"active_subdomains"`
	InactiveSubdomains int `json:"inactive_subdomains"`
	WithIPs            int `json:"with_ips"`
	WithHTTP           int `json:"with_http"`
	WithHTTPS          int `json:"with_https"`
	WithPorts          int `json:"with_ports"`
	TakeoverVulnerable int `json:"takeover_vulnerable"`
	Vulnerabilities    int `json:"vulnerabilities"`
	CloudHosted        int `json:"cloud_hosted"`
	AIFindings         int `json:"ai_findings"`
	CVEFindings        int `json:"cve_findings"`
	PassiveSources     int `json:"passive_sources"`
	BruteForceFound    int `json:"brute_force_found"`
}

// WildcardReport contains wildcard detection info
type WildcardReport struct {
	Detected   bool     `json:"detected"`
	IPs        []string `json:"ips,omitempty"`
	CNAME      string   `json:"cname,omitempty"`
	StatusCode int      `json:"status_code,omitempty"`
	Confidence float64  `json:"confidence,omitempty"`
}

// FindingsSummary categorizes findings by severity
type FindingsSummary struct {
	Critical []Finding `json:"critical,omitempty"`
	High     []Finding `json:"high,omitempty"`
	Medium   []Finding `json:"medium,omitempty"`
	Low      []Finding `json:"low,omitempty"`
	Info     []Finding `json:"info,omitempty"`
}

// Finding represents a single finding
type Finding struct {
	Subdomain   string `json:"subdomain"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"`
}

// ReportBuilder helps construct the JSON report
type ReportBuilder struct {
	report    *ScanReport
	startTime time.Time
}

// NewReportBuilder creates a new report builder
func NewReportBuilder(domain string, cfg config.Config) *ReportBuilder {
	now := time.Now()
	return &ReportBuilder{
		startTime: now,
		report: &ScanReport{
			Meta: ScanMeta{
				Version:     "0.1",
				ToolName:    "God's Eye",
				Target:      domain,
				StartTime:   now,
				Concurrency: cfg.Concurrency,
				Timeout:     cfg.Timeout,
				Options: ScanOptions{
					BruteForce:      !cfg.NoBrute,
					HTTPProbe:       !cfg.NoProbe,
					PortScan:        !cfg.NoPorts,
					TakeoverCheck:   !cfg.NoTakeover,
					AIAnalysis:      cfg.EnableAI,
					OnlyActive:      cfg.OnlyActive,
					CustomWordlist:  cfg.Wordlist != "",
					CustomResolvers: cfg.Resolvers != "",
					CustomPorts:     cfg.Ports,
				},
			},
			Stats: ScanStats{},
			Findings: FindingsSummary{
				Critical: []Finding{},
				High:     []Finding{},
				Medium:   []Finding{},
				Low:      []Finding{},
				Info:     []Finding{},
			},
		},
	}
}

// SetWildcard sets wildcard detection info
func (rb *ReportBuilder) SetWildcard(detected bool, ips []string, cname string, statusCode int, confidence float64) {
	rb.report.Wildcard = &WildcardReport{
		Detected:   detected,
		IPs:        ips,
		CNAME:      cname,
		StatusCode: statusCode,
		Confidence: confidence,
	}
}

// SetPassiveSources sets the number of passive sources used
func (rb *ReportBuilder) SetPassiveSources(count int) {
	rb.report.Stats.PassiveSources = count
}

// SetBruteForceFound sets the number of subdomains found via brute force
func (rb *ReportBuilder) SetBruteForceFound(count int) {
	rb.report.Stats.BruteForceFound = count
}

// Finalize completes the report with results and calculates stats
func (rb *ReportBuilder) Finalize(results map[string]*config.SubdomainResult) *ScanReport {
	endTime := time.Now()
	duration := endTime.Sub(rb.startTime)

	rb.report.Meta.EndTime = endTime
	rb.report.Meta.Duration = duration.String()
	rb.report.Meta.DurationMs = duration.Milliseconds()

	// Sort subdomains
	var sortedSubs []string
	for sub := range results {
		sortedSubs = append(sortedSubs, sub)
	}
	sort.Strings(sortedSubs)

	// Build results list and calculate stats
	rb.report.Subdomains = make([]*config.SubdomainResult, 0, len(results))
	for _, sub := range sortedSubs {
		r := results[sub]
		rb.report.Subdomains = append(rb.report.Subdomains, r)

		// Calculate stats
		rb.report.Stats.TotalSubdomains++

		if len(r.IPs) > 0 {
			rb.report.Stats.WithIPs++
		}

		if r.StatusCode >= 200 && r.StatusCode < 400 {
			rb.report.Stats.ActiveSubdomains++
		} else if r.StatusCode >= 400 {
			rb.report.Stats.InactiveSubdomains++
		}

		if r.TLSVersion != "" {
			rb.report.Stats.WithHTTPS++
		}
		if r.StatusCode > 0 {
			rb.report.Stats.WithHTTP++
		}

		if len(r.Ports) > 0 {
			rb.report.Stats.WithPorts++
		}

		if r.CloudProvider != "" {
			rb.report.Stats.CloudHosted++
		}

		if r.Takeover != "" {
			rb.report.Stats.TakeoverVulnerable++
			rb.addFinding("critical", sub, "Subdomain Takeover", r.Takeover)
		}

		// Count vulnerabilities
		vulnCount := 0
		if r.OpenRedirect {
			vulnCount++
			rb.addFinding("high", sub, "Open Redirect", "Vulnerable to open redirect attacks")
		}
		if r.CORSMisconfig != "" {
			vulnCount++
			rb.addFinding("medium", sub, "CORS Misconfiguration", r.CORSMisconfig)
		}
		if len(r.DangerousMethods) > 0 {
			vulnCount++
			rb.addFinding("medium", sub, "Dangerous HTTP Methods", join(r.DangerousMethods, ", "))
		}
		if r.GitExposed {
			vulnCount++
			rb.addFinding("high", sub, "Git Repository Exposed", ".git directory accessible")
		}
		if r.SvnExposed {
			vulnCount++
			rb.addFinding("high", sub, "SVN Repository Exposed", ".svn directory accessible")
		}
		if len(r.BackupFiles) > 0 {
			vulnCount++
			rb.addFinding("high", sub, "Backup Files Exposed", join(r.BackupFiles, ", "))
		}
		if len(r.JSSecrets) > 0 {
			vulnCount++
			for _, secret := range r.JSSecrets {
				rb.addFinding("high", sub, "Secret in JavaScript", secret)
			}
		}
		if vulnCount > 0 {
			rb.report.Stats.Vulnerabilities += vulnCount
		}

		// AI findings
		if len(r.AIFindings) > 0 {
			rb.report.Stats.AIFindings += len(r.AIFindings)
			severity := "info"
			if r.AISeverity != "" {
				severity = r.AISeverity
			}
			for _, finding := range r.AIFindings {
				rb.addFinding(severity, sub, "AI Analysis", finding)
			}
		}

		// CVE findings
		if len(r.CVEFindings) > 0 {
			rb.report.Stats.CVEFindings += len(r.CVEFindings)
			for _, cve := range r.CVEFindings {
				rb.addFinding("high", sub, "CVE Vulnerability", cve)
			}
		}

		// Info findings
		if len(r.AdminPanels) > 0 {
			for _, panel := range r.AdminPanels {
				rb.addFinding("info", sub, "Admin Panel Found", panel)
			}
		}
		if len(r.APIEndpoints) > 0 {
			for _, endpoint := range r.APIEndpoints {
				rb.addFinding("info", sub, "API Endpoint Found", endpoint)
			}
		}
	}

	return rb.report
}

// addFinding adds a finding to the appropriate severity category
func (rb *ReportBuilder) addFinding(severity, subdomain, findingType, description string) {
	finding := Finding{
		Subdomain:   subdomain,
		Type:        findingType,
		Description: description,
	}

	switch severity {
	case "critical":
		rb.report.Findings.Critical = append(rb.report.Findings.Critical, finding)
	case "high":
		rb.report.Findings.High = append(rb.report.Findings.High, finding)
	case "medium":
		rb.report.Findings.Medium = append(rb.report.Findings.Medium, finding)
	case "low":
		rb.report.Findings.Low = append(rb.report.Findings.Low, finding)
	default:
		rb.report.Findings.Info = append(rb.report.Findings.Info, finding)
	}
}

// WriteJSON writes the report as JSON to a writer
func (rb *ReportBuilder) WriteJSON(w io.Writer, indent bool) error {
	encoder := json.NewEncoder(w)
	if indent {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(rb.report)
}

// GetReport returns the built report
func (rb *ReportBuilder) GetReport() *ScanReport {
	return rb.report
}

// Helper function
func join(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for _, s := range strs[1:] {
		result += sep + s
	}
	return result
}
