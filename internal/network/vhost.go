package network

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// VHostResult holds virtual host discovery results
type VHostResult struct {
	IP          string   `json:"ip"`
	Domains     []string `json:"domains"`
	Source      string   `json:"source"` // bing, hackertarget, tls, reverse_dns
	Confidence  string   `json:"confidence"` // high, medium, low
}

// VHostScanner discovers virtual hosts on shared IPs
type VHostScanner struct {
	client      *http.Client
	timeout     int
	concurrency int
}

// NewVHostScanner creates a new virtual host scanner
func NewVHostScanner(timeout int) *VHostScanner {
	return &VHostScanner{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		timeout:     timeout,
		concurrency: 5,
	}
}

// DiscoverVHosts finds all domains hosted on the same IP
func (vs *VHostScanner) DiscoverVHosts(ctx context.Context, ip string) *VHostResult {
	result := &VHostResult{
		IP:      ip,
		Domains: make([]string, 0),
	}

	var allDomains []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 1. HackerTarget Reverse IP (50/day free)
	wg.Add(1)
	go func() {
		defer wg.Done()
		domains, err := vs.queryHackerTarget(ctx, ip)
		if err == nil && len(domains) > 0 {
			mu.Lock()
			allDomains = append(allDomains, domains...)
			mu.Unlock()
		}
	}()

	// 2. TLS Certificate SAN extraction
	wg.Add(1)
	go func() {
		defer wg.Done()
		domains := vs.extractTLSNames(ip)
		if len(domains) > 0 {
			mu.Lock()
			allDomains = append(allDomains, domains...)
			mu.Unlock()
		}
	}()

	// 3. Reverse DNS
	wg.Add(1)
	go func() {
		defer wg.Done()
		domains := vs.reverseDNS(ip)
		if len(domains) > 0 {
			mu.Lock()
			allDomains = append(allDomains, domains...)
			mu.Unlock()
		}
	}()

	// 4. Bing IP search (scraping, no API)
	wg.Add(1)
	go func() {
		defer wg.Done()
		domains, err := vs.queryBing(ctx, ip)
		if err == nil && len(domains) > 0 {
			mu.Lock()
			allDomains = append(allDomains, domains...)
			mu.Unlock()
		}
	}()

	wg.Wait()

	// Deduplicate results
	result.Domains = deduplicateDomains(allDomains)

	// Set confidence based on number of sources
	if len(result.Domains) > 10 {
		result.Confidence = "high"
	} else if len(result.Domains) > 3 {
		result.Confidence = "medium"
	} else {
		result.Confidence = "low"
	}

	result.Source = "multi-source"

	return result
}

// queryHackerTarget uses HackerTarget reverse IP lookup
func (vs *VHostScanner) queryHackerTarget(ctx context.Context, ip string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/reverseiplookup/?q=%s", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := vs.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("hackertarget returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	bodyStr := string(body)

	// Check for error responses
	if strings.Contains(bodyStr, "error") || strings.Contains(bodyStr, "API count exceeded") {
		return nil, fmt.Errorf("API limit or error")
	}

	var domains []string
	scanner := bufio.NewScanner(strings.NewReader(bodyStr))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && isValidDomain(line) {
			domains = append(domains, line)
		}
	}

	return domains, nil
}

// extractTLSNames extracts domain names from TLS certificates
func (vs *VHostScanner) extractTLSNames(ip string) []string {
	var domains []string

	// Try common HTTPS ports
	ports := []string{"443", "8443", "8080", "8000"}

	for _, port := range ports {
		addr := fmt.Sprintf("%s:%s", ip, port)

		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 3 * time.Second},
			"tcp",
			addr,
			&tls.Config{InsecureSkipVerify: true},
		)
		if err != nil {
			continue
		}

		// Extract names from certificate
		state := conn.ConnectionState()
		for _, cert := range state.PeerCertificates {
			// Subject CN
			if cert.Subject.CommonName != "" && isValidDomain(cert.Subject.CommonName) {
				domains = append(domains, cert.Subject.CommonName)
			}

			// SANs (Subject Alternative Names)
			for _, san := range cert.DNSNames {
				if isValidDomain(san) {
					domains = append(domains, san)
				}
			}
		}

		conn.Close()
	}

	return domains
}

// reverseDNS performs reverse DNS lookup
func (vs *VHostScanner) reverseDNS(ip string) []string {
	var domains []string

	names, err := net.LookupAddr(ip)
	if err != nil {
		return domains
	}

	for _, name := range names {
		// Remove trailing dot
		name = strings.TrimSuffix(name, ".")
		if isValidDomain(name) {
			domains = append(domains, name)
		}
	}

	return domains
}

// queryBing scrapes Bing for IP:xxx search (passive, no API)
func (vs *VHostScanner) queryBing(ctx context.Context, ip string) ([]string, error) {
	// Bing IP search operator
	url := fmt.Sprintf("https://www.bing.com/search?q=ip%%3A%s&count=50", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := vs.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bing returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 500*1024))

	// Extract domains from search results
	// Match href="https://domain.com/..." patterns
	domainRegex := regexp.MustCompile(`href="https?://([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)["/]`)
	matches := domainRegex.FindAllStringSubmatch(string(body), -1)

	seen := make(map[string]bool)
	var domains []string

	for _, match := range matches {
		if len(match) > 1 {
			domain := strings.ToLower(match[1])
			// Filter out Bing/Microsoft domains
			if !strings.Contains(domain, "bing.") &&
				!strings.Contains(domain, "microsoft.") &&
				!strings.Contains(domain, "msn.") &&
				!seen[domain] &&
				isValidDomain(domain) {
				seen[domain] = true
				domains = append(domains, domain)
			}
		}
	}

	return domains, nil
}

// BruteForceVHost tries to discover virtual hosts by sending requests with different Host headers
func (vs *VHostScanner) BruteForceVHost(ctx context.Context, ip string, hostnames []string) []string {
	var validHosts []string
	var mu sync.Mutex

	// Get baseline response for comparison
	baselineStatus, baselineSize := vs.getBaselineResponse(ip)
	baseline := struct{ status, size int }{baselineStatus, baselineSize}

	sem := make(chan struct{}, vs.concurrency)
	var wg sync.WaitGroup

	for _, hostname := range hostnames {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		go func(host string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			if vs.isValidVHost(ip, host, baseline) {
				mu.Lock()
				validHosts = append(validHosts, host)
				mu.Unlock()
			}
		}(hostname)
	}

	wg.Wait()
	return validHosts
}

// getBaselineResponse gets response for invalid host to compare against
func (vs *VHostScanner) getBaselineResponse(ip string) (int, int) {
	url := fmt.Sprintf("https://%s/", ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, 0
	}

	// Use invalid hostname
	req.Host = "invalid.nonexistent.host.local"
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

	resp, err := vs.client.Do(req)
	if err != nil {
		return 0, 0
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))

	return resp.StatusCode, len(body)
}

// isValidVHost checks if a hostname is a valid virtual host on the IP
func (vs *VHostScanner) isValidVHost(ip, hostname string, baseline struct{ status, size int }) bool {
	url := fmt.Sprintf("https://%s/", ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	req.Host = hostname
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

	resp, err := vs.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))

	// Compare with baseline - different response indicates valid vhost
	if resp.StatusCode == 200 && baseline.status != 200 {
		return true
	}

	// Check for different content length (allowing 10% variance)
	if baseline.size > 0 {
		sizeDiff := abs(len(body) - baseline.size)
		if float64(sizeDiff)/float64(baseline.size) > 0.1 {
			return true
		}
	}

	return false
}

// DiscoverMultipleIPs discovers vhosts for multiple IPs concurrently
func (vs *VHostScanner) DiscoverMultipleIPs(ctx context.Context, ips []string, maxConcurrent int) map[string]*VHostResult {
	results := make(map[string]*VHostResult)
	var mu sync.Mutex

	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		go func(ipAddr string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			result := vs.DiscoverVHosts(ctx, ipAddr)
			if len(result.Domains) > 0 {
				mu.Lock()
				results[ipAddr] = result
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return results
}

// Helper functions

func deduplicateDomains(domains []string) []string {
	seen := make(map[string]bool)
	var unique []string

	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		// Remove wildcards
		d = strings.TrimPrefix(d, "*.")

		if d != "" && !seen[d] {
			seen[d] = true
			unique = append(unique, d)
		}
	}

	return unique
}

func isValidDomain(domain string) bool {
	// Basic domain validation
	if len(domain) < 3 || len(domain) > 253 {
		return false
	}

	// Must contain at least one dot
	if !strings.Contains(domain, ".") {
		return false
	}

	// Must not be an IP address
	if net.ParseIP(domain) != nil {
		return false
	}

	// Basic character check
	for _, c := range domain {
		if !((c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '_') {
			return false
		}
	}

	return true
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
