package discovery

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"god-eye/internal/dns"
)

// RecursiveDiscovery performs recursive subdomain enumeration
type RecursiveDiscovery struct {
	domain      string
	resolvers   []string
	timeout     int
	maxDepth    int
	concurrency int

	// Results tracking
	found   map[string]bool
	foundMu sync.RWMutex

	// Pattern learning
	patterns *PatternLearner
}

// RecursiveConfig contains configuration for recursive discovery
type RecursiveConfig struct {
	Domain      string
	Resolvers   []string
	Timeout     int
	MaxDepth    int    // Maximum recursion depth (default: 3)
	Concurrency int
}

// NewRecursiveDiscovery creates a new recursive discovery engine
func NewRecursiveDiscovery(cfg RecursiveConfig) *RecursiveDiscovery {
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = 3
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 50
	}

	return &RecursiveDiscovery{
		domain:      cfg.Domain,
		resolvers:   cfg.Resolvers,
		timeout:     cfg.Timeout,
		maxDepth:    cfg.MaxDepth,
		concurrency: cfg.Concurrency,
		found:       make(map[string]bool),
		patterns:    NewPatternLearner(),
	}
}

// Discover performs recursive discovery starting from initial subdomains
func (rd *RecursiveDiscovery) Discover(ctx context.Context, initial []string) []string {
	// Add initial subdomains
	rd.foundMu.Lock()
	for _, sub := range initial {
		rd.found[sub] = true
		rd.patterns.Learn(sub, rd.domain)
	}
	rd.foundMu.Unlock()

	// Process each depth level
	currentLevel := initial
	for depth := 1; depth <= rd.maxDepth; depth++ {
		select {
		case <-ctx.Done():
			break
		default:
		}

		// Generate permutations for current level
		candidates := rd.generateCandidates(currentLevel, depth)
		if len(candidates) == 0 {
			break
		}

		// Resolve candidates
		newFound := rd.resolveParallel(ctx, candidates)
		if len(newFound) == 0 {
			break
		}

		// Learn patterns from new discoveries
		rd.foundMu.Lock()
		for _, sub := range newFound {
			rd.patterns.Learn(sub, rd.domain)
		}
		rd.foundMu.Unlock()

		currentLevel = newFound
	}

	// Return all found subdomains
	rd.foundMu.RLock()
	defer rd.foundMu.RUnlock()

	result := make([]string, 0, len(rd.found))
	for sub := range rd.found {
		result = append(result, sub)
	}
	sort.Strings(result)
	return result
}

// generateCandidates generates subdomain candidates based on patterns
func (rd *RecursiveDiscovery) generateCandidates(bases []string, depth int) []string {
	seen := make(map[string]bool)
	var candidates []string

	// Common prefixes for recursion
	commonPrefixes := []string{
		"api", "v1", "v2", "v3", "internal", "staging", "dev", "test",
		"prod", "admin", "app", "web", "cdn", "static", "assets",
		"auth", "login", "portal", "dashboard", "backend", "frontend",
		"data", "db", "cache", "redis", "elastic", "kafka", "queue",
		"mail", "smtp", "imap", "mx", "ns", "dns",
		"vpn", "proxy", "gateway", "lb", "loadbalancer",
		"monitor", "metrics", "logs", "trace", "health",
		"git", "svn", "repo", "ci", "cd", "jenkins", "gitlab",
		"k8s", "kubernetes", "docker", "container", "pod",
	}

	// Add learned prefixes from patterns
	learnedPrefixes := rd.patterns.GetLearnedPrefixes()
	commonPrefixes = append(commonPrefixes, learnedPrefixes...)

	// Common suffixes
	commonSuffixes := []string{
		"01", "02", "03", "1", "2", "3",
		"a", "b", "c",
		"east", "west", "eu", "us", "asia",
		"primary", "secondary", "backup",
	}

	for _, base := range bases {
		// Extract the subdomain part (remove domain suffix)
		subPart := strings.TrimSuffix(base, "."+rd.domain)
		if subPart == base {
			continue // Not a subdomain of target
		}

		// Generate prefix variations: prefix.existing.domain.com
		for _, prefix := range commonPrefixes {
			candidate := fmt.Sprintf("%s.%s", prefix, base)
			if !seen[candidate] && !rd.isFound(candidate) {
				seen[candidate] = true
				candidates = append(candidates, candidate)
			}
		}

		// Generate suffix variations for multi-part subdomains
		parts := strings.Split(subPart, ".")
		if len(parts) >= 1 {
			basePart := parts[0]
			for _, suffix := range commonSuffixes {
				// api.example.com -> api1.example.com, api-01.example.com
				var newBase string
				if len(parts) > 1 {
					newBase = fmt.Sprintf("%s%s.%s.%s", basePart, suffix, strings.Join(parts[1:], "."), rd.domain)
				} else {
					newBase = fmt.Sprintf("%s%s.%s", basePart, suffix, rd.domain)
				}
				if !seen[newBase] && !rd.isFound(newBase) {
					seen[newBase] = true
					candidates = append(candidates, newBase)
				}

				// With dash: api-1.example.com
				if len(parts) > 1 {
					newBase = fmt.Sprintf("%s-%s.%s.%s", basePart, suffix, strings.Join(parts[1:], "."), rd.domain)
				} else {
					newBase = fmt.Sprintf("%s-%s.%s", basePart, suffix, rd.domain)
				}
				if !seen[newBase] && !rd.isFound(newBase) {
					seen[newBase] = true
					candidates = append(candidates, newBase)
				}
			}
		}
	}

	// Limit candidates per depth to avoid explosion
	maxCandidates := 5000 / depth
	if len(candidates) > maxCandidates {
		candidates = candidates[:maxCandidates]
	}

	return candidates
}

// resolveParallel resolves candidates in parallel
func (rd *RecursiveDiscovery) resolveParallel(ctx context.Context, candidates []string) []string {
	var results []string
	var resultsMu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, rd.concurrency)

	for _, candidate := range candidates {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check context
			select {
			case <-ctx.Done():
				return
			default:
			}

			ips := dns.ResolveSubdomain(sub, rd.resolvers, rd.timeout)
			if len(ips) > 0 {
				rd.foundMu.Lock()
				if !rd.found[sub] {
					rd.found[sub] = true
					resultsMu.Lock()
					results = append(results, sub)
					resultsMu.Unlock()
				}
				rd.foundMu.Unlock()
			}
		}(candidate)
	}

	wg.Wait()
	return results
}

// isFound checks if subdomain was already found
func (rd *RecursiveDiscovery) isFound(sub string) bool {
	rd.foundMu.RLock()
	defer rd.foundMu.RUnlock()
	return rd.found[sub]
}

// GetPatterns returns the learned patterns
func (rd *RecursiveDiscovery) GetPatterns() *PatternLearner {
	return rd.patterns
}

// DiscoveryStats returns statistics about the discovery
type DiscoveryStats struct {
	TotalFound      int
	ByDepth         map[int]int
	LearnedPatterns int
}

// GetStats returns discovery statistics
func (rd *RecursiveDiscovery) GetStats() DiscoveryStats {
	rd.foundMu.RLock()
	defer rd.foundMu.RUnlock()

	return DiscoveryStats{
		TotalFound:      len(rd.found),
		LearnedPatterns: len(rd.patterns.prefixes),
	}
}
