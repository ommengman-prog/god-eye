package ai

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CVEInfo represents CVE vulnerability information
type CVEInfo struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Score       float64 `json:"score"`
	Published   string  `json:"published"`
	References  []string `json:"references"`
}

// NVDResponse represents the response from NVD API
type NVDResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID          string `json:"id"`
			Published   string `json:"published"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore      float64 `json:"baseScore"`
						BaseSeverity   string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31,omitempty"`
				CVSSMetricV2 []struct {
					CVSSData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssMetricV2,omitempty"`
			} `json:"metrics,omitempty"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// CVECacheEntry holds cached CVE results
type CVECacheEntry struct {
	Result    string
	Timestamp time.Time
}

var (
	nvdClient = &http.Client{
		Timeout: 15 * time.Second,
	}
	nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	// Rate limiting: NVD allows 5 req/30s without API key
	lastNVDRequest time.Time
	nvdRateLimit   = 7 * time.Second // Wait 7 seconds between requests (safer)
	nvdMutex       sync.Mutex

	// CVE Cache to avoid duplicate lookups across subdomains
	cveCache      = make(map[string]*CVECacheEntry)
	cveCacheMutex sync.RWMutex
)

// SearchCVE searches for CVE vulnerabilities with caching to avoid duplicates
// Returns a concise format: "CVE-ID (SEVERITY/SCORE), CVE-ID2 (SEVERITY/SCORE)"
func SearchCVE(technology string, version string) (string, error) {
	// Normalize technology name
	tech := normalizeTechnology(technology)
	cacheKey := tech // Use normalized tech as cache key

	// Check cache first
	cveCacheMutex.RLock()
	if entry, ok := cveCache[cacheKey]; ok {
		cveCacheMutex.RUnlock()
		// Cache valid for 1 hour
		if time.Since(entry.Timestamp) < time.Hour {
			return entry.Result, nil
		}
	} else {
		cveCacheMutex.RUnlock()
	}

	var allCVEs []CVEInfo

	// Layer 1: Check CISA KEV first (instant, offline, most critical)
	if kevResult, err := SearchKEV(tech); err == nil && kevResult != "" {
		// Parse KEV result for CVE IDs
		lines := strings.Split(kevResult, "\n")
		for _, line := range lines {
			if strings.Contains(line, "CVE-") {
				parts := strings.Fields(line)
				for _, part := range parts {
					if strings.HasPrefix(part, "CVE-") {
						allCVEs = append(allCVEs, CVEInfo{
							ID:       strings.TrimSuffix(part, ":"),
							Severity: "CRITICAL",
							Score:    9.8, // KEV = actively exploited
						})
					}
				}
			}
		}
	}

	// Layer 2: Query NVD API for additional CVEs
	if nvdCVEs, err := queryNVD(tech); err == nil {
		allCVEs = append(allCVEs, nvdCVEs...)
	}
	// Don't fail on NVD errors - just use what we have

	// Format result
	result := formatCVEsConcise(allCVEs)

	// Cache the result
	cveCacheMutex.Lock()
	cveCache[cacheKey] = &CVECacheEntry{
		Result:    result,
		Timestamp: time.Now(),
	}
	cveCacheMutex.Unlock()

	return result, nil
}

// formatCVEsConcise returns a concise CVE summary
func formatCVEsConcise(cves []CVEInfo) string {
	if len(cves) == 0 {
		return ""
	}

	// Sort by score (highest first)
	sort.Slice(cves, func(i, j int) bool {
		return cves[i].Score > cves[j].Score
	})

	// Deduplicate by CVE ID
	seen := make(map[string]bool)
	var uniqueCVEs []CVEInfo
	for _, cve := range cves {
		if !seen[cve.ID] && cve.ID != "" {
			seen[cve.ID] = true
			uniqueCVEs = append(uniqueCVEs, cve)
		}
	}

	if len(uniqueCVEs) == 0 {
		return ""
	}

	// Show top 3 most critical
	maxShow := 3
	if len(uniqueCVEs) < maxShow {
		maxShow = len(uniqueCVEs)
	}

	var parts []string
	for i := 0; i < maxShow; i++ {
		cve := uniqueCVEs[i]
		severity := cve.Severity
		if severity == "" {
			severity = "UNK"
		}
		parts = append(parts, fmt.Sprintf("%s (%s/%.1f)", cve.ID, severity, cve.Score))
	}

	result := strings.Join(parts, ", ")
	if len(uniqueCVEs) > maxShow {
		result += fmt.Sprintf(" +%d more", len(uniqueCVEs)-maxShow)
	}

	return result
}

// queryNVD queries the NVD API for CVE information with thread-safe rate limiting
func queryNVD(keyword string) ([]CVEInfo, error) {
	nvdMutex.Lock()
	// Rate limiting: wait if necessary
	if !lastNVDRequest.IsZero() {
		elapsed := time.Since(lastNVDRequest)
		if elapsed < nvdRateLimit {
			time.Sleep(nvdRateLimit - elapsed)
		}
	}
	lastNVDRequest = time.Now()
	nvdMutex.Unlock()

	// Build URL with query parameters
	params := url.Values{}
	params.Add("keywordSearch", keyword)
	params.Add("resultsPerPage", "5") // Limit results for speed

	reqURL := fmt.Sprintf("%s?%s", nvdBaseURL, params.Encode())

	// Create request
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// NVD recommends including a user agent
	req.Header.Set("User-Agent", "GodEye-Security-Scanner/0.1")

	// Execute request
	resp, err := nvdClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query NVD: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("NVD API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("failed to parse NVD response: %w", err)
	}

	// Convert to CVEInfo
	var cves []CVEInfo
	cutoffYear := time.Now().Year() - 10 // Filter CVEs older than 10 years

	for _, vuln := range nvdResp.Vulnerabilities {
		// Filter old CVEs - extract year from CVE ID (format: CVE-YYYY-NNNNN)
		if len(vuln.CVE.ID) >= 8 {
			yearStr := vuln.CVE.ID[4:8]
			if year, err := strconv.Atoi(yearStr); err == nil && year < cutoffYear {
				continue // Skip CVEs older than cutoff
			}
		}

		cve := CVEInfo{
			ID:        vuln.CVE.ID,
			Published: formatDate(vuln.CVE.Published),
		}

		// Get description
		for _, desc := range vuln.CVE.Descriptions {
			if desc.Lang == "en" {
				cve.Description = desc.Value
				break
			}
		}

		// Get severity and score (prefer CVSS v3.1)
		if len(vuln.CVE.Metrics.CVSSMetricV31) > 0 {
			metric := vuln.CVE.Metrics.CVSSMetricV31[0]
			cve.Score = metric.CVSSData.BaseScore
			cve.Severity = metric.CVSSData.BaseSeverity
		} else if len(vuln.CVE.Metrics.CVSSMetricV2) > 0 {
			metric := vuln.CVE.Metrics.CVSSMetricV2[0]
			cve.Score = metric.CVSSData.BaseScore
			cve.Severity = metric.BaseSeverity
		}

		// Get references
		for _, ref := range vuln.CVE.References {
			cve.References = append(cve.References, ref.URL)
		}

		cves = append(cves, cve)
	}

	return cves, nil
}

// normalizeTechnology normalizes technology names for better CVE search results
func normalizeTechnology(tech string) string {
	tech = strings.ToLower(tech)

	// Common normalizations
	replacements := map[string]string{
		"microsoft-iis": "iis",
		"apache httpd": "apache",
		"apache http server": "apache",
		"nginx/": "nginx",
		"wordpress": "wordpress",
		"asp.net": "asp.net",
		"next.js": "nextjs",
		"react": "react",
		"angular": "angular",
		"vue": "vue",
		"express": "express",
		"django": "django",
		"flask": "flask",
		"spring": "spring",
		"tomcat": "tomcat",
		"jetty": "jetty",
		"php": "php",
		"mysql": "mysql",
		"postgresql": "postgresql",
		"mongodb": "mongodb",
		"redis": "redis",
		"elasticsearch": "elasticsearch",
		"docker": "docker",
		"kubernetes": "kubernetes",
		"jenkins": "jenkins",
		"gitlab": "gitlab",
		"grafana": "grafana",
	}

	for old, new := range replacements {
		if strings.Contains(tech, old) {
			return new
		}
	}

	// Remove version numbers and extra info
	parts := strings.Fields(tech)
	if len(parts) > 0 {
		return parts[0]
	}

	return tech
}

// formatDate formats ISO 8601 date to a more readable format
func formatDate(isoDate string) string {
	t, err := time.Parse(time.RFC3339, isoDate)
	if err != nil {
		return isoDate
	}
	return t.Format("2006-01-02")
}
