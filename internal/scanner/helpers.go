package scanner

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"god-eye/internal/config"
)

// LoadWordlist loads words from a file
func LoadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}
	return words, scanner.Err()
}

// ScanPorts scans ports on an IP address
func ScanPorts(ip string, ports []int, timeout int) []int {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", address, time.Duration(timeout)*time.Second)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	sort.Ints(openPorts)
	return openPorts
}

// Helper functions for AI analysis

func countSubdomainsWithAI(results map[string]*config.SubdomainResult) int {
	count := 0
	for _, r := range results {
		if len(r.AIFindings) > 0 {
			count++
		}
	}
	return count
}

func countActive(results map[string]*config.SubdomainResult) int {
	count := 0
	for _, r := range results {
		if r.StatusCode >= 200 && r.StatusCode < 400 {
			count++
		}
	}
	return count
}

func countVulns(results map[string]*config.SubdomainResult) int {
	count := 0
	for _, r := range results {
		if r.OpenRedirect || r.CORSMisconfig != "" || len(r.DangerousMethods) > 0 ||
			r.GitExposed || r.SvnExposed || len(r.BackupFiles) > 0 {
			count++
		}
	}
	return count
}

func buildAISummary(results map[string]*config.SubdomainResult) string {
	var summary strings.Builder

	criticalCount := 0
	highCount := 0
	mediumCount := 0

	for sub, r := range results {
		if len(r.AIFindings) == 0 {
			continue
		}

		switch r.AISeverity {
		case "critical":
			criticalCount++
			summary.WriteString(fmt.Sprintf("\n[CRITICAL] %s:\n", sub))
		case "high":
			highCount++
			summary.WriteString(fmt.Sprintf("\n[HIGH] %s:\n", sub))
		case "medium":
			mediumCount++
			summary.WriteString(fmt.Sprintf("\n[MEDIUM] %s:\n", sub))
		default:
			continue
		}

		// Add first 3 findings
		for i, finding := range r.AIFindings {
			if i >= 3 {
				break
			}
			summary.WriteString(fmt.Sprintf("  - %s\n", finding))
		}

		// Add CVE findings
		if len(r.CVEFindings) > 0 {
			summary.WriteString("  CVEs:\n")
			for _, cve := range r.CVEFindings {
				summary.WriteString(fmt.Sprintf("    - %s\n", cve))
			}
		}
	}

	header := fmt.Sprintf("Summary: %d critical, %d high, %d medium findings\n", criticalCount, highCount, mediumCount)
	return header + summary.String()
}

// ParseResolvers parses custom resolvers string
func ParseResolvers(resolversStr string) []string {
	var resolvers []string
	if resolversStr != "" {
		for _, r := range strings.Split(resolversStr, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				if !strings.Contains(r, ":") {
					r = r + ":53"
				}
				resolvers = append(resolvers, r)
			}
		}
	}
	if len(resolvers) == 0 {
		resolvers = config.DefaultResolvers
	}
	return resolvers
}

// ParsePorts parses custom ports string
func ParsePorts(portsStr string) []int {
	var customPorts []int
	if portsStr != "" {
		for _, p := range strings.Split(portsStr, ",") {
			p = strings.TrimSpace(p)
			var port int
			if _, err := fmt.Sscanf(p, "%d", &port); err == nil && port > 0 && port < 65536 {
				customPorts = append(customPorts, port)
			}
		}
	}
	if len(customPorts) == 0 {
		customPorts = []int{80, 443, 8080, 8443}
	}
	return customPorts
}
