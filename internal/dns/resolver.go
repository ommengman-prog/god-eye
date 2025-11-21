package dns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"god-eye/internal/cache"
	"god-eye/internal/config"
	"god-eye/internal/retry"
)

// ResolveSubdomain resolves a subdomain to IP addresses with retry logic
func ResolveSubdomain(subdomain string, resolvers []string, timeout int) []string {
	return ResolveSubdomainWithRetry(subdomain, resolvers, timeout, true)
}

// ResolveSubdomainWithRetry resolves with optional retry
func ResolveSubdomainWithRetry(subdomain string, resolvers []string, timeout int, useRetry bool) []string {
	c := dns.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(subdomain), dns.TypeA)

	// Try each resolver
	for _, resolver := range resolvers {
		var ips []string

		if useRetry {
			// Use retry logic
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout*2)*time.Second)
			result := retry.Do(ctx, retry.DNSConfig(), func() (interface{}, error) {
				r, _, err := c.Exchange(&m, resolver)
				if err != nil {
					return nil, err
				}
				if r == nil {
					return nil, fmt.Errorf("nil response")
				}

				var resolvedIPs []string
				for _, ans := range r.Answer {
					if a, ok := ans.(*dns.A); ok {
						resolvedIPs = append(resolvedIPs, a.A.String())
					}
				}

				if len(resolvedIPs) == 0 {
					return nil, fmt.Errorf("no A records")
				}
				return resolvedIPs, nil
			})
			cancel()

			if result.Error == nil && result.Value != nil {
				ips = result.Value.([]string)
			}
		} else {
			// Direct resolution without retry
			r, _, err := c.Exchange(&m, resolver)
			if err == nil && r != nil {
				for _, ans := range r.Answer {
					if a, ok := ans.(*dns.A); ok {
						ips = append(ips, a.A.String())
					}
				}
			}
		}

		if len(ips) > 0 {
			return ips
		}
	}

	return nil
}

func CheckWildcard(domain string, resolvers []string) []string {
	// Test multiple random patterns for better wildcard detection
	patterns := []string{
		fmt.Sprintf("random%d.%s", time.Now().UnixNano(), domain),
		fmt.Sprintf("xyz%d.%s", time.Now().UnixNano()%1000000, domain),
		fmt.Sprintf("nonexistent-%s.%s", "abc123xyz", domain),
	}

	allIPs := make(map[string]int)
	for _, pattern := range patterns {
		ips := ResolveSubdomain(pattern, resolvers, 3)
		for _, ip := range ips {
			allIPs[ip]++
		}
	}

	// If same IP(s) appear in multiple patterns, it's a wildcard
	var wildcardIPs []string
	for ip, count := range allIPs {
		if count >= 2 {
			wildcardIPs = append(wildcardIPs, ip)
		}
	}

	return wildcardIPs
}

func ResolveCNAME(subdomain string, resolvers []string, timeout int) string {
	c := dns.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(subdomain), dns.TypeCNAME)

	for _, resolver := range resolvers {
		r, _, err := c.Exchange(&m, resolver)
		if err != nil || r == nil {
			continue
		}

		for _, ans := range r.Answer {
			if cname, ok := ans.(*dns.CNAME); ok {
				return strings.TrimSuffix(cname.Target, ".")
			}
		}
	}

	return ""
}

func ResolvePTR(ip string, resolvers []string, timeout int) string {
	c := dns.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	// Convert IP to reverse DNS format
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	reverseIP := fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa.", parts[3], parts[2], parts[1], parts[0])

	m := dns.Msg{}
	m.SetQuestion(reverseIP, dns.TypePTR)

	for _, resolver := range resolvers {
		r, _, err := c.Exchange(&m, resolver)
		if err != nil || r == nil {
			continue
		}

		for _, ans := range r.Answer {
			if ptr, ok := ans.(*dns.PTR); ok {
				return strings.TrimSuffix(ptr.Ptr, ".")
			}
		}
	}

	return ""
}

func ResolveMX(domain string, resolvers []string, timeout int) []string {
	c := dns.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)

	for _, resolver := range resolvers {
		r, _, err := c.Exchange(&m, resolver)
		if err != nil || r == nil {
			continue
		}

		var records []string
		for _, ans := range r.Answer {
			if mx, ok := ans.(*dns.MX); ok {
				records = append(records, strings.TrimSuffix(mx.Mx, "."))
			}
		}
		if len(records) > 0 {
			return records
		}
	}

	return nil
}

func ResolveTXT(domain string, resolvers []string, timeout int) []string {
	c := dns.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)

	for _, resolver := range resolvers {
		r, _, err := c.Exchange(&m, resolver)
		if err != nil || r == nil {
			continue
		}

		var records []string
		for _, ans := range r.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				for _, t := range txt.Txt {
					// Limit length for display
					if len(t) > 100 {
						t = t[:97] + "..."
					}
					records = append(records, t)
				}
			}
		}
		if len(records) > 0 {
			return records
		}
	}

	return nil
}

func ResolveNS(domain string, resolvers []string, timeout int) []string {
	c := dns.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)

	for _, resolver := range resolvers {
		r, _, err := c.Exchange(&m, resolver)
		if err != nil || r == nil {
			continue
		}

		var records []string
		for _, ans := range r.Answer {
			if ns, ok := ans.(*dns.NS); ok {
				records = append(records, strings.TrimSuffix(ns.Ns, "."))
			}
		}
		if len(records) > 0 {
			return records
		}
	}

	return nil
}

// GetIPInfo retrieves IP geolocation info with caching (10x faster for repeated IPs)
func GetIPInfo(ip string) (*config.IPInfo, error) {
	return cache.GetIPInfoCached(ip)
}

// GetIPInfoBatch retrieves IP info for multiple IPs efficiently
// Uses LRU cache and batches uncached lookups
func GetIPInfoBatch(ips []string) map[string]*config.IPInfo {
	return cache.BatchIPLookup(ips)
}

// ResolveSubdomainCached resolves with DNS caching
func ResolveSubdomainCached(subdomain string, resolvers []string, timeout int) []string {
	dnsCache := cache.GetDNSCache()

	// Check cache first
	if ips, found := dnsCache.Get(subdomain); found {
		return ips
	}

	// Resolve and cache
	ips := ResolveSubdomain(subdomain, resolvers, timeout)
	if len(ips) > 0 {
		dnsCache.Set(subdomain, ips)
	}

	return ips
}
