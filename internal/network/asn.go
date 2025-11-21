package network

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ASNInfo holds ASN information for an IP
type ASNInfo struct {
	ASN         string   `json:"asn"`
	Name        string   `json:"name"`
	Country     string   `json:"country"`
	CIDR        string   `json:"cidr"`
	Range       string   `json:"range"`
	NumHosts    int      `json:"num_hosts"`
	RelatedIPs  []string `json:"related_ips,omitempty"`
}

// ASNScanner discovers ASN/CIDR information and related IPs
type ASNScanner struct {
	client  *http.Client
	timeout int
}

// NewASNScanner creates a new ASN scanner
func NewASNScanner(timeout int) *ASNScanner {
	return &ASNScanner{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
		timeout: timeout,
	}
}

// GetASNInfo retrieves ASN information for an IP using free services
func (as *ASNScanner) GetASNInfo(ctx context.Context, ip string) (*ASNInfo, error) {
	// Use ip-api.com (free, no API key needed, 45 requests/minute)
	info, err := as.queryIPAPI(ctx, ip)
	if err == nil && info != nil {
		return info, nil
	}

	// Fallback to Team Cymru DNS-based ASN lookup (no rate limits)
	return as.queryTeamCymruDNS(ip)
}

// queryIPAPI queries ip-api.com for ASN info
func (as *ASNScanner) queryIPAPI(ctx context.Context, ip string) (*ASNInfo, error) {
	url := fmt.Sprintf("http://ip-api.com/line/%s?fields=as,org,country,query", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := as.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ip-api returned status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	lines := strings.Split(string(body), "\n")

	if len(lines) < 3 {
		return nil, fmt.Errorf("invalid response from ip-api")
	}

	// Parse ASN from "AS12345 Name" format
	asnParts := strings.SplitN(lines[0], " ", 2)
	asn := ""
	name := ""
	if len(asnParts) >= 1 {
		asn = strings.TrimPrefix(asnParts[0], "AS")
	}
	if len(asnParts) >= 2 {
		name = asnParts[1]
	}

	return &ASNInfo{
		ASN:     asn,
		Name:    name,
		Country: lines[2],
	}, nil
}

// queryTeamCymruDNS uses Team Cymru DNS for ASN lookup (free, no limits)
func (as *ASNScanner) queryTeamCymruDNS(ip string) (*ASNInfo, error) {
	// Reverse IP for DNS query
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid IPv4 address")
	}

	// Reverse the IP
	reversed := fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])

	// Query Team Cymru origin.asn.cymru.com
	query := fmt.Sprintf("%s.origin.asn.cymru.com", reversed)

	txtRecords, err := net.LookupTXT(query)
	if err != nil || len(txtRecords) == 0 {
		return nil, fmt.Errorf("DNS ASN lookup failed: %v", err)
	}

	// Parse response: "ASN | CIDR | Country | Registry | Date"
	record := txtRecords[0]
	fields := strings.Split(record, "|")
	if len(fields) < 3 {
		return nil, fmt.Errorf("invalid TXT record format")
	}

	asn := strings.TrimSpace(fields[0])
	cidr := strings.TrimSpace(fields[1])
	country := strings.TrimSpace(fields[2])

	// Get ASN name from asn.cymru.com
	name := ""
	nameQuery := fmt.Sprintf("AS%s.asn.cymru.com", asn)
	nameRecords, err := net.LookupTXT(nameQuery)
	if err == nil && len(nameRecords) > 0 {
		// Parse: "ASN | Country | Registry | Date | Name"
		nameFields := strings.Split(nameRecords[0], "|")
		if len(nameFields) >= 5 {
			name = strings.TrimSpace(nameFields[4])
		}
	}

	// Calculate number of hosts in CIDR
	numHosts := 0
	if cidr != "" {
		numHosts = calculateCIDRHosts(cidr)
	}

	return &ASNInfo{
		ASN:      asn,
		Name:     name,
		Country:  country,
		CIDR:     cidr,
		NumHosts: numHosts,
	}, nil
}

// GetRelatedIPs discovers other IPs in the same CIDR range
// Only scans a subset for large ranges to avoid abuse
func (as *ASNScanner) GetRelatedIPs(ctx context.Context, cidr string, maxIPs int) []string {
	if cidr == "" || maxIPs <= 0 {
		return nil
	}

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}

	var relatedIPs []string

	// Get network size
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	totalHosts := 1 << hostBits

	// Limit scanning for large networks
	if totalHosts > maxIPs {
		// Sample IPs from the range instead of scanning all
		return as.sampleCIDR(ipnet, maxIPs)
	}

	// For smaller ranges, enumerate all
	ip := ipnet.IP
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		select {
		case <-ctx.Done():
			return relatedIPs
		default:
		}

		// Skip network and broadcast addresses
		if ip[3] == 0 || ip[3] == 255 {
			continue
		}

		relatedIPs = append(relatedIPs, ip.String())
		if len(relatedIPs) >= maxIPs {
			break
		}
	}

	return relatedIPs
}

// sampleCIDR samples IPs from a large CIDR range
func (as *ASNScanner) sampleCIDR(ipnet *net.IPNet, maxIPs int) []string {
	var samples []string

	ip := make(net.IP, len(ipnet.IP))
	copy(ip, ipnet.IP)

	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	totalHosts := 1 << hostBits

	// Step size to get approximately maxIPs samples
	step := totalHosts / maxIPs
	if step < 1 {
		step = 1
	}

	for i := 1; i < totalHosts && len(samples) < maxIPs; i += step {
		// Calculate IP at position i
		sampleIP := make(net.IP, 4)
		baseIP := ipToInt(ipnet.IP)
		sampleIP = intToIP(baseIP + uint32(i))

		if ipnet.Contains(sampleIP) && sampleIP[3] != 0 && sampleIP[3] != 255 {
			samples = append(samples, sampleIP.String())
		}
	}

	return samples
}

// ExpandASN expands an ASN to find all related CIDR ranges using BGPView (free API)
func (as *ASNScanner) ExpandASN(ctx context.Context, asn string) ([]string, error) {
	// Clean ASN format
	asn = strings.TrimPrefix(strings.ToUpper(asn), "AS")

	url := fmt.Sprintf("https://api.bgpview.io/asn/%s/prefixes", asn)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "god-eye/1.0 (security scanner)")

	resp, err := as.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bgpview returned status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))

	// Simple parsing without json package
	var cidrs []string

	// Match IPv4 prefixes: "prefix": "1.2.3.0/24"
	prefixRegex := regexp.MustCompile(`"prefix":\s*"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+)"`)
	matches := prefixRegex.FindAllStringSubmatch(string(body), -1)

	for _, match := range matches {
		if len(match) > 1 {
			cidrs = append(cidrs, match[1])
		}
	}

	return cidrs, nil
}

// ScanASNRange performs a concurrent scan of IPs in an ASN
func (as *ASNScanner) ScanASNRange(ctx context.Context, ips []string, concurrency int,
	checkFunc func(string) bool) []string {

	var activeIPs []string
	var mu sync.Mutex

	sem := make(chan struct{}, concurrency)
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

			if checkFunc(ipAddr) {
				mu.Lock()
				activeIPs = append(activeIPs, ipAddr)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return activeIPs
}

// Helper functions

func calculateCIDRHosts(cidr string) int {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0
	}
	ones, bits := ipnet.Mask.Size()
	return 1 << (bits - ones)
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ipToInt(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func intToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// ReverseWhois performs reverse whois lookup to find related domains (uses ViewDNS free tier)
func (as *ASNScanner) ReverseWhois(ctx context.Context, domain string) ([]string, error) {
	// Note: This is rate-limited but doesn't require API key
	// Extract organization from domain whois and search for it

	// For now, use HackerTarget free API (50 queries/day)
	url := fmt.Sprintf("https://api.hackertarget.com/reverseiplookup/?q=%s", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := as.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("hackertarget returned status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	bodyStr := string(body)

	// Check for error response
	if strings.Contains(bodyStr, "error") || strings.Contains(bodyStr, "API count exceeded") {
		return nil, fmt.Errorf("API error: %s", bodyStr)
	}

	var domains []string
	scanner := bufio.NewScanner(strings.NewReader(bodyStr))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.Contains(line, "error") {
			domains = append(domains, line)
		}
	}

	return domains, nil
}
