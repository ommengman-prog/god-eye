package fingerprint

import (
	"strings"

	"god-eye/internal/ai"
)

// CVEMatch represents a CVE found for a technology
type CVEMatch struct {
	CVEID       string `json:"cve_id"`
	Product     string `json:"product"`
	Vendor      string `json:"vendor"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // critical, high, medium, low
	Ransomware  bool   `json:"ransomware_used"`
	DateAdded   string `json:"date_added"`
}

// techNameMappings maps common technology names to KEV product/vendor names
var techNameMappings = map[string][]string{
	// Web servers
	"nginx":         {"nginx"},
	"apache":        {"apache", "http server", "httpd"},
	"microsoft-iis": {"iis", "internet information services"},
	"litespeed":     {"litespeed"},

	// CMS
	"wordpress":   {"wordpress"},
	"drupal":      {"drupal"},
	"joomla":      {"joomla"},
	"magento":     {"magento"},

	// Frameworks
	"php":           {"php"},
	"asp.net":       {"asp.net", ".net framework"},
	"django":        {"django"},
	"ruby on rails": {"ruby on rails", "rails"},
	"spring":        {"spring"},
	"laravel":       {"laravel"},

	// JavaScript
	"jquery":   {"jquery"},
	"angular":  {"angular"},
	"react":    {"react"},
	"vue.js":   {"vue", "vuejs"},
	"next.js":  {"next.js", "nextjs"},
	"node.js":  {"node.js", "nodejs"},

	// Security/CDN
	"cloudflare":     {"cloudflare"},
	"cloudflare waf": {"cloudflare"},
	"aws waf":        {"amazon", "aws"},
	"akamai":         {"akamai"},

	// Databases (if detected via error messages)
	"mysql":      {"mysql"},
	"postgresql": {"postgresql", "postgres"},
	"mongodb":    {"mongodb"},
	"redis":      {"redis"},

	// Infrastructure
	"amazon s3": {"amazon", "s3"},
	"vercel":    {"vercel"},
	"heroku":    {"heroku"},
}

// EnrichWithCVEs enriches technologies with CVE data from KEV database
func EnrichWithCVEs(techs []Technology) []Technology {
	kevStore := ai.GetKEVStore()

	// Ensure KEV is loaded
	if !kevStore.IsLoaded() {
		if err := kevStore.Load(); err != nil {
			return techs // Return unchanged if KEV not available
		}
	}

	enriched := make([]Technology, len(techs))
	copy(enriched, techs)

	for i := range enriched {
		tech := &enriched[i]
		cves := findCVEsForTech(kevStore, tech.Name, tech.Version)
		if len(cves) > 0 {
			tech.CVEs = make([]string, 0, len(cves))
			for _, cve := range cves {
				tech.CVEs = append(tech.CVEs, cve.CVEID)
			}
		}
	}

	return enriched
}

// findCVEsForTech searches KEV database for CVEs matching a technology
func findCVEsForTech(kevStore *ai.KEVStore, techName string, version string) []CVEMatch {
	var matches []CVEMatch
	seen := make(map[string]bool)

	techLower := strings.ToLower(techName)

	// Get search terms for this technology
	searchTerms := []string{techLower}
	if mappings, ok := techNameMappings[techLower]; ok {
		searchTerms = append(searchTerms, mappings...)
	}

	// Search KEV for each term
	for _, term := range searchTerms {
		vulns := kevStore.SearchByProduct(term)
		for _, vuln := range vulns {
			if seen[vuln.CveID] {
				continue
			}
			seen[vuln.CveID] = true

			severity := classifyKEVSeverity(vuln)
			matches = append(matches, CVEMatch{
				CVEID:       vuln.CveID,
				Product:     vuln.Product,
				Vendor:      vuln.VendorProject,
				Description: vuln.ShortDescription,
				Severity:    severity,
				Ransomware:  strings.ToLower(vuln.KnownRansomwareCampaignUse) == "known",
				DateAdded:   vuln.DateAdded,
			})
		}
	}

	return matches
}

// classifyKEVSeverity assigns severity based on KEV characteristics
// All KEV entries are actively exploited, so minimum is "high"
func classifyKEVSeverity(vuln ai.KEVulnerability) string {
	// Ransomware-associated vulnerabilities are critical
	if strings.ToLower(vuln.KnownRansomwareCampaignUse) == "known" {
		return "critical"
	}

	// Keywords that indicate critical severity
	criticalKeywords := []string{
		"remote code execution", "rce",
		"unauthenticated", "authentication bypass",
		"privilege escalation", "root",
		"arbitrary code", "command injection",
	}

	descLower := strings.ToLower(vuln.ShortDescription)
	for _, keyword := range criticalKeywords {
		if strings.Contains(descLower, keyword) {
			return "critical"
		}
	}

	return "high" // Minimum for KEV (all are actively exploited)
}

// GetCVEDetails returns detailed CVE matches for a technology
func GetCVEDetails(techName string, version string) []CVEMatch {
	kevStore := ai.GetKEVStore()

	if !kevStore.IsLoaded() {
		if err := kevStore.Load(); err != nil {
			return nil
		}
	}

	return findCVEsForTech(kevStore, techName, version)
}

// HasKnownVulnerabilities checks if any technology has known CVEs
func HasKnownVulnerabilities(techs []Technology) bool {
	kevStore := ai.GetKEVStore()
	if !kevStore.IsLoaded() {
		return false
	}

	for _, tech := range techs {
		cves := findCVEsForTech(kevStore, tech.Name, tech.Version)
		if len(cves) > 0 {
			return true
		}
	}
	return false
}

// GetCriticalCVEs returns only critical/ransomware CVEs for technologies
func GetCriticalCVEs(techs []Technology) []CVEMatch {
	var critical []CVEMatch
	kevStore := ai.GetKEVStore()

	if !kevStore.IsLoaded() {
		return critical
	}

	seen := make(map[string]bool)
	for _, tech := range techs {
		cves := findCVEsForTech(kevStore, tech.Name, tech.Version)
		for _, cve := range cves {
			if seen[cve.CVEID] {
				continue
			}
			if cve.Severity == "critical" || cve.Ransomware {
				seen[cve.CVEID] = true
				critical = append(critical, cve)
			}
		}
	}

	return critical
}
