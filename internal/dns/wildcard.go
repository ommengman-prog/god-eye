package dns

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// WildcardInfo holds information about wildcard DNS detection
type WildcardInfo struct {
	IsWildcard     bool
	WildcardIPs    []string
	WildcardCNAME  string
	HTTPStatusCode int
	HTTPBodyHash   string
	HTTPBodySize   int64
	Confidence     float64 // 0-1 confidence level
}

// WildcardDetector performs comprehensive wildcard detection
type WildcardDetector struct {
	resolvers      []string
	timeout        int
	httpClient     *http.Client
	testSubdomains []string
}

// NewWildcardDetector creates a new wildcard detector
func NewWildcardDetector(resolvers []string, timeout int) *WildcardDetector {
	return &WildcardDetector{
		resolvers: resolvers,
		timeout:   timeout,
		httpClient: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		testSubdomains: generateTestSubdomains(),
	}
}

// generateTestSubdomains creates random non-existent subdomain patterns
func generateTestSubdomains() []string {
	timestamp := time.Now().UnixNano()
	return []string{
		fmt.Sprintf("wildcard-test-%d-abc", timestamp),
		fmt.Sprintf("random-xyz-%d-def", timestamp%1000000),
		fmt.Sprintf("nonexistent-%d-ghi", timestamp%999999),
		fmt.Sprintf("fake-sub-%d-jkl", timestamp%888888),
		fmt.Sprintf("test-random-%d-mno", timestamp%777777),
	}
}

// Detect performs comprehensive wildcard detection on a domain
func (wd *WildcardDetector) Detect(domain string) *WildcardInfo {
	info := &WildcardInfo{
		WildcardIPs: make([]string, 0),
	}

	// Phase 1: DNS-based detection (multiple random subdomains)
	ipCounts := make(map[string]int)
	var cnames []string

	for _, pattern := range wd.testSubdomains {
		testDomain := fmt.Sprintf("%s.%s", pattern, domain)

		// Resolve A records
		ips := ResolveSubdomain(testDomain, wd.resolvers, wd.timeout)
		for _, ip := range ips {
			ipCounts[ip]++
		}

		// Resolve CNAME
		cname := ResolveCNAME(testDomain, wd.resolvers, wd.timeout)
		if cname != "" {
			cnames = append(cnames, cname)
		}
	}

	// Analyze DNS results
	totalTests := len(wd.testSubdomains)
	for ip, count := range ipCounts {
		// If same IP appears in >= 60% of tests, it's likely wildcard
		if float64(count)/float64(totalTests) >= 0.6 {
			info.WildcardIPs = append(info.WildcardIPs, ip)
		}
	}

	// Check CNAME consistency
	if len(cnames) > 0 && allEqual(cnames) {
		info.WildcardCNAME = cnames[0]
	}

	// If no DNS wildcard detected, we're done
	if len(info.WildcardIPs) == 0 && info.WildcardCNAME == "" {
		info.IsWildcard = false
		info.Confidence = 0.95 // High confidence no wildcard
		return info
	}

	// Phase 2: HTTP-based validation (if DNS wildcard detected)
	if len(info.WildcardIPs) > 0 {
		httpResults := wd.validateHTTP(domain)
		info.HTTPStatusCode = httpResults.statusCode
		info.HTTPBodyHash = httpResults.bodyHash
		info.HTTPBodySize = httpResults.bodySize

		// Calculate confidence based on HTTP consistency
		if httpResults.consistent {
			info.Confidence = 0.95 // Very confident it's a wildcard
		} else {
			info.Confidence = 0.7 // DNS wildcard but inconsistent HTTP
		}
	}

	info.IsWildcard = true
	sort.Strings(info.WildcardIPs)

	return info
}

type httpValidationResult struct {
	statusCode int
	bodyHash   string
	bodySize   int64
	consistent bool
}

// validateHTTP checks if random subdomains return consistent HTTP responses
func (wd *WildcardDetector) validateHTTP(domain string) httpValidationResult {
	result := httpValidationResult{}

	var statusCodes []int
	var bodySizes []int64
	var bodyHashes []string

	// Test 3 random subdomains via HTTP
	for i := 0; i < 3; i++ {
		testDomain := fmt.Sprintf("%s.%s", wd.testSubdomains[i], domain)

		for _, scheme := range []string{"https", "http"} {
			url := fmt.Sprintf("%s://%s", scheme, testDomain)
			resp, err := wd.httpClient.Get(url)
			if err != nil {
				continue
			}

			statusCodes = append(statusCodes, resp.StatusCode)

			// Read body (limited)
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 50000))
			resp.Body.Close()

			bodySizes = append(bodySizes, int64(len(body)))
			bodyHashes = append(bodyHashes, fmt.Sprintf("%x", md5.Sum(body)))
			break // Only need one successful scheme
		}
	}

	if len(statusCodes) == 0 {
		return result
	}

	// Check consistency
	result.statusCode = statusCodes[0]
	if len(bodySizes) > 0 {
		result.bodySize = bodySizes[0]
	}
	if len(bodyHashes) > 0 {
		result.bodyHash = bodyHashes[0]
	}

	// Check if all results are consistent (same status and similar size)
	result.consistent = allEqualInts(statusCodes) && similarSizes(bodySizes)

	return result
}

// IsWildcardIP checks if an IP is a known wildcard IP for this domain
func (wd *WildcardDetector) IsWildcardIP(ip string, wildcardInfo *WildcardInfo) bool {
	if wildcardInfo == nil || !wildcardInfo.IsWildcard {
		return false
	}

	for _, wip := range wildcardInfo.WildcardIPs {
		if ip == wip {
			return true
		}
	}

	return false
}

// IsWildcardResponse checks if an HTTP response matches wildcard pattern
func (wd *WildcardDetector) IsWildcardResponse(statusCode int, bodySize int64, wildcardInfo *WildcardInfo) bool {
	if wildcardInfo == nil || !wildcardInfo.IsWildcard {
		return false
	}

	// Check status code match
	if wildcardInfo.HTTPStatusCode != 0 && statusCode != wildcardInfo.HTTPStatusCode {
		return false
	}

	// Check body size similarity (within 10%)
	if wildcardInfo.HTTPBodySize > 0 {
		ratio := float64(bodySize) / float64(wildcardInfo.HTTPBodySize)
		if ratio < 0.9 || ratio > 1.1 {
			return false
		}
	}

	return true
}

// Helper functions

func allEqual(strs []string) bool {
	if len(strs) == 0 {
		return true
	}
	first := strs[0]
	for _, s := range strs[1:] {
		if s != first {
			return false
		}
	}
	return true
}

func allEqualInts(ints []int) bool {
	if len(ints) == 0 {
		return true
	}
	first := ints[0]
	for _, i := range ints[1:] {
		if i != first {
			return false
		}
	}
	return true
}

func similarSizes(sizes []int64) bool {
	if len(sizes) < 2 {
		return true
	}

	// Find min and max
	min, max := sizes[0], sizes[0]
	for _, s := range sizes[1:] {
		if s < min {
			min = s
		}
		if s > max {
			max = s
		}
	}

	// Allow 20% variance
	if min == 0 {
		return max < 100 // Small empty responses
	}
	return float64(max)/float64(min) <= 1.2
}

// FilterWildcardSubdomains removes subdomains that match wildcard pattern
func FilterWildcardSubdomains(subdomains []string, domain string, resolvers []string, timeout int) (filtered []string, wildcardInfo *WildcardInfo) {
	detector := NewWildcardDetector(resolvers, timeout)
	wildcardInfo = detector.Detect(domain)

	if !wildcardInfo.IsWildcard {
		return subdomains, wildcardInfo
	}

	// Filter out subdomains that resolve to wildcard IPs
	filtered = make([]string, 0, len(subdomains))
	wildcardIPSet := make(map[string]bool)
	for _, ip := range wildcardInfo.WildcardIPs {
		wildcardIPSet[ip] = true
	}

	for _, subdomain := range subdomains {
		ips := ResolveSubdomain(subdomain, resolvers, timeout)

		// Check if all IPs are wildcard IPs
		allWildcard := true
		for _, ip := range ips {
			if !wildcardIPSet[ip] {
				allWildcard = false
				break
			}
		}

		// Keep if not all IPs are wildcards, or if no IPs resolved
		if !allWildcard || len(ips) == 0 {
			filtered = append(filtered, subdomain)
		}
	}

	return filtered, wildcardInfo
}

// GetWildcardSummary returns a human-readable summary of wildcard detection
func (wi *WildcardInfo) GetSummary() string {
	if !wi.IsWildcard {
		return "No wildcard DNS detected"
	}

	var parts []string
	parts = append(parts, "Wildcard DNS DETECTED")

	if len(wi.WildcardIPs) > 0 {
		ips := wi.WildcardIPs
		if len(ips) > 3 {
			ips = ips[:3]
		}
		parts = append(parts, fmt.Sprintf("IPs: %s", strings.Join(ips, ", ")))
	}

	if wi.WildcardCNAME != "" {
		parts = append(parts, fmt.Sprintf("CNAME: %s", wi.WildcardCNAME))
	}

	if wi.HTTPStatusCode > 0 {
		parts = append(parts, fmt.Sprintf("HTTP: %d (%dB)", wi.HTTPStatusCode, wi.HTTPBodySize))
	}

	parts = append(parts, fmt.Sprintf("Confidence: %.0f%%", wi.Confidence*100))

	return strings.Join(parts, " | ")
}
