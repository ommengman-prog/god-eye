package stealth

import (
	"crypto/rand"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// Mode defines the stealth level
type Mode int

const (
	ModeOff      Mode = iota // No stealth - maximum speed
	ModeLight                // Light stealth - reduced concurrency, basic delays
	ModeModerate             // Moderate - random delays, UA rotation, throttling
	ModeAggressive           // Aggressive - slow, distributed, evasive
	ModeParanoid             // Paranoid - ultra slow, maximum evasion
)

// Config holds stealth configuration
type Config struct {
	Mode            Mode
	MinDelay        time.Duration // Minimum delay between requests
	MaxDelay        time.Duration // Maximum delay (for randomization)
	MaxReqPerSecond float64       // Rate limit per second
	MaxReqPerHost   int           // Max concurrent requests per host
	RotateUA        bool          // Rotate User-Agent
	RandomizeOrder  bool          // Randomize request order
	JitterPercent   int           // Jitter percentage (0-100)
	DNSSpread       bool          // Spread DNS queries across resolvers
}

// Manager handles stealth operations
type Manager struct {
	cfg           Config
	userAgents    []string
	uaIndex       int
	uaMutex       sync.Mutex
	hostLimiters  map[string]*rateLimiter
	hostMutex     sync.RWMutex
	globalLimiter *rateLimiter
}

// rateLimiter implements token bucket rate limiting
type rateLimiter struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

// NewManager creates a new stealth manager
func NewManager(mode Mode) *Manager {
	cfg := GetPreset(mode)
	return NewManagerWithConfig(cfg)
}

// NewManagerWithConfig creates a manager with custom config
func NewManagerWithConfig(cfg Config) *Manager {
	m := &Manager{
		cfg:          cfg,
		userAgents:   getUserAgents(),
		hostLimiters: make(map[string]*rateLimiter),
	}

	if cfg.MaxReqPerSecond > 0 {
		m.globalLimiter = newRateLimiter(cfg.MaxReqPerSecond, cfg.MaxReqPerSecond)
	}

	return m
}

// GetPreset returns configuration for a stealth mode
func GetPreset(mode Mode) Config {
	switch mode {
	case ModeLight:
		return Config{
			Mode:            ModeLight,
			MinDelay:        10 * time.Millisecond,
			MaxDelay:        50 * time.Millisecond,
			MaxReqPerSecond: 100,
			MaxReqPerHost:   20,
			RotateUA:        true,
			RandomizeOrder:  false,
			JitterPercent:   10,
			DNSSpread:       false,
		}
	case ModeModerate:
		return Config{
			Mode:            ModeModerate,
			MinDelay:        50 * time.Millisecond,
			MaxDelay:        200 * time.Millisecond,
			MaxReqPerSecond: 30,
			MaxReqPerHost:   5,
			RotateUA:        true,
			RandomizeOrder:  true,
			JitterPercent:   30,
			DNSSpread:       true,
		}
	case ModeAggressive:
		return Config{
			Mode:            ModeAggressive,
			MinDelay:        200 * time.Millisecond,
			MaxDelay:        1 * time.Second,
			MaxReqPerSecond: 10,
			MaxReqPerHost:   2,
			RotateUA:        true,
			RandomizeOrder:  true,
			JitterPercent:   50,
			DNSSpread:       true,
		}
	case ModeParanoid:
		return Config{
			Mode:            ModeParanoid,
			MinDelay:        1 * time.Second,
			MaxDelay:        5 * time.Second,
			MaxReqPerSecond: 2,
			MaxReqPerHost:   1,
			RotateUA:        true,
			RandomizeOrder:  true,
			JitterPercent:   70,
			DNSSpread:       true,
		}
	default: // ModeOff
		return Config{
			Mode:            ModeOff,
			MinDelay:        0,
			MaxDelay:        0,
			MaxReqPerSecond: 0, // unlimited
			MaxReqPerHost:   0, // unlimited
			RotateUA:        false,
			RandomizeOrder:  false,
			JitterPercent:   0,
			DNSSpread:       false,
		}
	}
}

// Wait applies stealth delay before a request
func (m *Manager) Wait() {
	if m.cfg.Mode == ModeOff {
		return
	}

	// Apply rate limiting
	if m.globalLimiter != nil {
		m.globalLimiter.wait()
	}

	// Apply random delay
	if m.cfg.MaxDelay > 0 {
		delay := m.randomDelay()
		time.Sleep(delay)
	}
}

// WaitForHost applies per-host rate limiting
func (m *Manager) WaitForHost(host string) {
	if m.cfg.Mode == ModeOff || m.cfg.MaxReqPerHost <= 0 {
		return
	}

	m.hostMutex.Lock()
	limiter, exists := m.hostLimiters[host]
	if !exists {
		limiter = newRateLimiter(float64(m.cfg.MaxReqPerHost), float64(m.cfg.MaxReqPerHost))
		m.hostLimiters[host] = limiter
	}
	m.hostMutex.Unlock()

	limiter.wait()
}

// GetUserAgent returns a User-Agent string (rotated if enabled)
func (m *Manager) GetUserAgent() string {
	if !m.cfg.RotateUA || len(m.userAgents) == 0 {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}

	m.uaMutex.Lock()
	defer m.uaMutex.Unlock()

	ua := m.userAgents[m.uaIndex]
	m.uaIndex = (m.uaIndex + 1) % len(m.userAgents)
	return ua
}

// GetRandomUserAgent returns a random User-Agent
func (m *Manager) GetRandomUserAgent() string {
	if len(m.userAgents) == 0 {
		return m.GetUserAgent()
	}
	idx := secureRandomInt(len(m.userAgents))
	return m.userAgents[idx]
}

// ApplyToRequest applies stealth settings to an HTTP request
func (m *Manager) ApplyToRequest(req *http.Request) {
	// Set User-Agent
	req.Header.Set("User-Agent", m.GetUserAgent())

	// Add realistic browser headers
	if m.cfg.Mode >= ModeModerate {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
		req.Header.Set("Accept-Language", m.getRandomAcceptLanguage())
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Cache-Control", "max-age=0")
	}
}

// SelectResolver picks a DNS resolver (distributed if enabled)
func (m *Manager) SelectResolver(resolvers []string, index int) string {
	if len(resolvers) == 0 {
		return "8.8.8.8:53"
	}

	if m.cfg.DNSSpread {
		// Random selection for distribution
		return resolvers[secureRandomInt(len(resolvers))]
	}

	// Sequential selection
	return resolvers[index%len(resolvers)]
}

// ShuffleSlice randomizes slice order if enabled
func (m *Manager) ShuffleSlice(items []string) []string {
	if !m.cfg.RandomizeOrder || len(items) <= 1 {
		return items
	}

	// Fisher-Yates shuffle
	shuffled := make([]string, len(items))
	copy(shuffled, items)

	for i := len(shuffled) - 1; i > 0; i-- {
		j := secureRandomInt(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	return shuffled
}

// GetEffectiveConcurrency returns adjusted concurrency for stealth mode
func (m *Manager) GetEffectiveConcurrency(requested int) int {
	switch m.cfg.Mode {
	case ModeLight:
		return min(requested, 100)
	case ModeModerate:
		return min(requested, 30)
	case ModeAggressive:
		return min(requested, 10)
	case ModeParanoid:
		return min(requested, 3)
	default:
		return requested
	}
}

// GetConfig returns current stealth configuration
func (m *Manager) GetConfig() Config {
	return m.cfg
}

// GetModeName returns the name of the stealth mode
func (m *Manager) GetModeName() string {
	return ModeName(m.cfg.Mode)
}

// ModeName returns human-readable mode name
func ModeName(mode Mode) string {
	switch mode {
	case ModeLight:
		return "light"
	case ModeModerate:
		return "moderate"
	case ModeAggressive:
		return "aggressive"
	case ModeParanoid:
		return "paranoid"
	default:
		return "off"
	}
}

// ParseMode converts string to Mode
func ParseMode(s string) Mode {
	switch s {
	case "light", "1":
		return ModeLight
	case "moderate", "medium", "2":
		return ModeModerate
	case "aggressive", "3":
		return ModeAggressive
	case "paranoid", "4":
		return ModeParanoid
	default:
		return ModeOff
	}
}

// randomDelay returns a random delay with jitter
func (m *Manager) randomDelay() time.Duration {
	if m.cfg.MaxDelay <= m.cfg.MinDelay {
		return m.cfg.MinDelay
	}

	// Calculate range
	rangeNs := int64(m.cfg.MaxDelay - m.cfg.MinDelay)
	randomNs := secureRandomInt64(rangeNs)
	delay := m.cfg.MinDelay + time.Duration(randomNs)

	// Apply jitter
	if m.cfg.JitterPercent > 0 {
		jitterRange := int64(delay) * int64(m.cfg.JitterPercent) / 100
		jitter := secureRandomInt64(jitterRange*2) - jitterRange
		delay = time.Duration(int64(delay) + jitter)
		if delay < 0 {
			delay = m.cfg.MinDelay
		}
	}

	return delay
}

func (m *Manager) getRandomAcceptLanguage() string {
	languages := []string{
		"en-US,en;q=0.9",
		"en-GB,en;q=0.9",
		"en-US,en;q=0.9,es;q=0.8",
		"de-DE,de;q=0.9,en;q=0.8",
		"fr-FR,fr;q=0.9,en;q=0.8",
		"es-ES,es;q=0.9,en;q=0.8",
		"it-IT,it;q=0.9,en;q=0.8",
		"pt-BR,pt;q=0.9,en;q=0.8",
		"nl-NL,nl;q=0.9,en;q=0.8",
		"ja-JP,ja;q=0.9,en;q=0.8",
	}
	return languages[secureRandomInt(len(languages))]
}

// Rate limiter implementation

func newRateLimiter(maxTokens, refillRate float64) *rateLimiter {
	return &rateLimiter{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

func (rl *rateLimiter) wait() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(rl.lastRefill).Seconds()
	rl.tokens += elapsed * rl.refillRate
	if rl.tokens > rl.maxTokens {
		rl.tokens = rl.maxTokens
	}
	rl.lastRefill = now

	// Wait if no tokens available
	if rl.tokens < 1 {
		waitTime := time.Duration((1 - rl.tokens) / rl.refillRate * float64(time.Second))
		rl.mu.Unlock()
		time.Sleep(waitTime)
		rl.mu.Lock()
		rl.tokens = 0
	} else {
		rl.tokens--
	}
}

// Secure random helpers

func secureRandomInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

func secureRandomInt64(max int64) int64 {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0
	}
	return n.Int64()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// User-Agent pool

func getUserAgents() []string {
	return []string{
		// Chrome Windows
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
		// Chrome macOS
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		// Firefox Windows
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
		// Firefox macOS
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
		// Safari macOS
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		// Edge Windows
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
		// Chrome Linux
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		// Firefox Linux
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
		// Mobile Chrome Android
		"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
		// Mobile Safari iOS
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
		// Brave
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/120",
		// Opera
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
	}
}
