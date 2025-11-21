package discovery

import (
	"regexp"
	"sort"
	"strings"
	"sync"
)

// PatternLearner learns naming patterns from discovered subdomains
type PatternLearner struct {
	mu sync.RWMutex

	// Learned components
	prefixes    map[string]int // prefix -> count
	suffixes    map[string]int // suffix -> count
	separators  map[string]int // separator chars -> count
	words       map[string]int // common words -> count
	numbers     map[string]int // number patterns -> count
	environments map[string]int // env indicators -> count

	// Regex patterns for extraction
	numberPattern *regexp.Regexp
	envPattern    *regexp.Regexp
}

// NewPatternLearner creates a new pattern learner
func NewPatternLearner() *PatternLearner {
	return &PatternLearner{
		prefixes:     make(map[string]int),
		suffixes:     make(map[string]int),
		separators:   make(map[string]int),
		words:        make(map[string]int),
		numbers:      make(map[string]int),
		environments: make(map[string]int),
		numberPattern: regexp.MustCompile(`\d+`),
		envPattern:    regexp.MustCompile(`(?i)(dev|test|stage|staging|prod|production|qa|uat|demo|sandbox|beta|alpha|preview|canary)`),
	}
}

// Learn extracts patterns from a subdomain
func (pl *PatternLearner) Learn(subdomain, domain string) {
	// Extract subdomain part
	subPart := strings.TrimSuffix(subdomain, "."+domain)
	if subPart == subdomain || subPart == "" {
		return
	}

	pl.mu.Lock()
	defer pl.mu.Unlock()

	// Split by common separators
	parts := splitByAny(subPart, ".-_")

	// Learn separators used
	for _, sep := range []string{".", "-", "_"} {
		if strings.Contains(subPart, sep) {
			pl.separators[sep]++
		}
	}

	// Learn each part
	for i, part := range parts {
		part = strings.ToLower(part)
		if part == "" {
			continue
		}

		// Track words
		pl.words[part]++

		// First part is typically a prefix
		if i == 0 && len(parts) > 1 {
			pl.prefixes[part]++
		}

		// Last part before domain is often significant
		if i == len(parts)-1 {
			pl.suffixes[part]++
		}

		// Learn number patterns
		if pl.numberPattern.MatchString(part) {
			// Extract just the number pattern style
			numbers := pl.numberPattern.FindAllString(part, -1)
			for _, num := range numbers {
				if len(num) <= 4 { // Reasonable number length
					pl.numbers[num]++
				}
			}
		}

		// Learn environment indicators
		if pl.envPattern.MatchString(part) {
			env := pl.envPattern.FindString(part)
			pl.environments[strings.ToLower(env)]++
		}
	}
}

// GetLearnedPrefixes returns learned prefixes sorted by frequency
func (pl *PatternLearner) GetLearnedPrefixes() []string {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	return pl.getTopN(pl.prefixes, 20)
}

// GetLearnedSuffixes returns learned suffixes sorted by frequency
func (pl *PatternLearner) GetLearnedSuffixes() []string {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	return pl.getTopN(pl.suffixes, 20)
}

// GetLearnedWords returns learned words sorted by frequency
func (pl *PatternLearner) GetLearnedWords() []string {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	return pl.getTopN(pl.words, 50)
}

// GetEnvironments returns detected environment indicators
func (pl *PatternLearner) GetEnvironments() []string {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	return pl.getTopN(pl.environments, 10)
}

// GenerateSmartWordlist generates a wordlist based on learned patterns
func (pl *PatternLearner) GenerateSmartWordlist(baseWordlist []string) []string {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	seen := make(map[string]bool)
	var result []string

	// Add base wordlist
	for _, word := range baseWordlist {
		if !seen[word] {
			seen[word] = true
			result = append(result, word)
		}
	}

	// Get learned components
	learnedWords := pl.getTopN(pl.words, 30)
	learnedEnvs := pl.getTopN(pl.environments, 5)
	learnedNumbers := pl.getTopN(pl.numbers, 10)

	// Detect preferred separator
	separator := "-"
	maxSep := 0
	for sep, count := range pl.separators {
		if count > maxSep && sep != "." {
			separator = sep
			maxSep = count
		}
	}

	// Generate combinations
	for _, word := range learnedWords {
		// Word alone
		if !seen[word] {
			seen[word] = true
			result = append(result, word)
		}

		// Word + number
		for _, num := range learnedNumbers {
			combo := word + num
			if !seen[combo] {
				seen[combo] = true
				result = append(result, combo)
			}
			combo = word + separator + num
			if !seen[combo] {
				seen[combo] = true
				result = append(result, combo)
			}
		}

		// Word + environment
		for _, env := range learnedEnvs {
			combo := word + separator + env
			if !seen[combo] {
				seen[combo] = true
				result = append(result, combo)
			}
			combo = env + separator + word
			if !seen[combo] {
				seen[combo] = true
				result = append(result, combo)
			}
		}
	}

	// Environment permutations
	for _, env := range learnedEnvs {
		for _, num := range learnedNumbers {
			combo := env + num
			if !seen[combo] {
				seen[combo] = true
				result = append(result, combo)
			}
			combo = env + separator + num
			if !seen[combo] {
				seen[combo] = true
				result = append(result, combo)
			}
		}
	}

	return result
}

// GeneratePermutations generates permutations for a specific subdomain
func (pl *PatternLearner) GeneratePermutations(subdomain, domain string) []string {
	subPart := strings.TrimSuffix(subdomain, "."+domain)
	if subPart == subdomain || subPart == "" {
		return nil
	}

	pl.mu.RLock()
	defer pl.mu.RUnlock()

	seen := make(map[string]bool)
	var results []string

	parts := splitByAny(subPart, ".-_")
	if len(parts) == 0 {
		return nil
	}

	// Detect separator used
	separator := "-"
	if strings.Contains(subPart, "-") {
		separator = "-"
	} else if strings.Contains(subPart, "_") {
		separator = "_"
	}

	basePart := parts[0]
	learnedEnvs := pl.getTopN(pl.environments, 5)
	learnedNumbers := pl.getTopN(pl.numbers, 5)

	// Generate variations
	// base -> base-dev, base-staging, etc.
	for _, env := range learnedEnvs {
		perm := basePart + separator + env + "." + domain
		if !seen[perm] {
			seen[perm] = true
			results = append(results, perm)
		}
		perm = env + separator + basePart + "." + domain
		if !seen[perm] {
			seen[perm] = true
			results = append(results, perm)
		}
	}

	// base -> base1, base2, base-01, etc.
	for _, num := range learnedNumbers {
		perm := basePart + num + "." + domain
		if !seen[perm] {
			seen[perm] = true
			results = append(results, perm)
		}
		perm = basePart + separator + num + "." + domain
		if !seen[perm] {
			seen[perm] = true
			results = append(results, perm)
		}
	}

	// If multi-part, try variations of inner parts
	if len(parts) > 1 {
		for _, env := range learnedEnvs {
			// api.example.com -> api-dev.example.com
			perm := basePart + separator + env + "." + strings.Join(parts[1:], ".") + "." + domain
			if !seen[perm] {
				seen[perm] = true
				results = append(results, perm)
			}
		}
	}

	return results
}

// getTopN returns top N items from a frequency map
func (pl *PatternLearner) getTopN(m map[string]int, n int) []string {
	type kv struct {
		Key   string
		Value int
	}

	var sorted []kv
	for k, v := range m {
		sorted = append(sorted, kv{k, v})
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	var result []string
	for i := 0; i < n && i < len(sorted); i++ {
		result = append(result, sorted[i].Key)
	}
	return result
}

// Stats returns statistics about learned patterns
type PatternStats struct {
	UniquePrefixes    int
	UniqueSuffixes    int
	UniqueWords       int
	UniqueNumbers     int
	Environments      []string
	PreferredSeparator string
}

// GetStats returns pattern statistics
func (pl *PatternLearner) GetStats() PatternStats {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	// Find preferred separator
	separator := "."
	maxCount := 0
	for sep, count := range pl.separators {
		if count > maxCount {
			separator = sep
			maxCount = count
		}
	}

	return PatternStats{
		UniquePrefixes:     len(pl.prefixes),
		UniqueSuffixes:     len(pl.suffixes),
		UniqueWords:        len(pl.words),
		UniqueNumbers:      len(pl.numbers),
		Environments:       pl.getTopN(pl.environments, 10),
		PreferredSeparator: separator,
	}
}

// splitByAny splits a string by any of the given separators
func splitByAny(s string, seps string) []string {
	splitter := func(r rune) bool {
		return strings.ContainsRune(seps, r)
	}
	return strings.FieldsFunc(s, splitter)
}
