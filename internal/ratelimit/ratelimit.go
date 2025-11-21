package ratelimit

import (
	"sync"
	"sync/atomic"
	"time"
)

// AdaptiveRateLimiter implements intelligent rate limiting that adapts based on errors
type AdaptiveRateLimiter struct {
	// Configuration
	minDelay     time.Duration
	maxDelay     time.Duration
	currentDelay time.Duration

	// Error tracking
	consecutiveErrors int64
	totalErrors       int64
	totalRequests     int64

	// Backoff settings
	backoffMultiplier float64
	recoveryRate      float64

	// State
	lastRequest time.Time
	mu          sync.Mutex
}

// Config holds configuration for the rate limiter
type Config struct {
	MinDelay          time.Duration // Minimum delay between requests
	MaxDelay          time.Duration // Maximum delay (during backoff)
	BackoffMultiplier float64       // How much to increase delay on error (default 2.0)
	RecoveryRate      float64       // How much to decrease delay on success (default 0.9)
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		MinDelay:          50 * time.Millisecond,
		MaxDelay:          5 * time.Second,
		BackoffMultiplier: 2.0,
		RecoveryRate:      0.9,
	}
}

// AggressiveConfig returns config for fast scanning
func AggressiveConfig() Config {
	return Config{
		MinDelay:          10 * time.Millisecond,
		MaxDelay:          2 * time.Second,
		BackoffMultiplier: 1.5,
		RecoveryRate:      0.8,
	}
}

// ConservativeConfig returns config for careful scanning
func ConservativeConfig() Config {
	return Config{
		MinDelay:          200 * time.Millisecond,
		MaxDelay:          10 * time.Second,
		BackoffMultiplier: 3.0,
		RecoveryRate:      0.95,
	}
}

// New creates a new adaptive rate limiter
func New(cfg Config) *AdaptiveRateLimiter {
	if cfg.BackoffMultiplier == 0 {
		cfg.BackoffMultiplier = 2.0
	}
	if cfg.RecoveryRate == 0 {
		cfg.RecoveryRate = 0.9
	}

	return &AdaptiveRateLimiter{
		minDelay:          cfg.MinDelay,
		maxDelay:          cfg.MaxDelay,
		currentDelay:      cfg.MinDelay,
		backoffMultiplier: cfg.BackoffMultiplier,
		recoveryRate:      cfg.RecoveryRate,
	}
}

// Wait blocks until it's safe to make another request
func (r *AdaptiveRateLimiter) Wait() {
	r.mu.Lock()
	defer r.mu.Unlock()

	elapsed := time.Since(r.lastRequest)
	if elapsed < r.currentDelay {
		time.Sleep(r.currentDelay - elapsed)
	}
	r.lastRequest = time.Now()
	atomic.AddInt64(&r.totalRequests, 1)
}

// Success reports a successful request
func (r *AdaptiveRateLimiter) Success() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Reset consecutive errors
	atomic.StoreInt64(&r.consecutiveErrors, 0)

	// Gradually reduce delay (recover)
	newDelay := time.Duration(float64(r.currentDelay) * r.recoveryRate)
	if newDelay < r.minDelay {
		newDelay = r.minDelay
	}
	r.currentDelay = newDelay
}

// Error reports a failed request (timeout, 429, etc)
func (r *AdaptiveRateLimiter) Error(isRateLimited bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	atomic.AddInt64(&r.consecutiveErrors, 1)
	atomic.AddInt64(&r.totalErrors, 1)

	// Increase delay on error
	multiplier := r.backoffMultiplier
	if isRateLimited {
		// More aggressive backoff for rate limit errors (429)
		multiplier *= 2
	}

	newDelay := time.Duration(float64(r.currentDelay) * multiplier)
	if newDelay > r.maxDelay {
		newDelay = r.maxDelay
	}
	r.currentDelay = newDelay
}

// GetCurrentDelay returns the current delay
func (r *AdaptiveRateLimiter) GetCurrentDelay() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.currentDelay
}

// GetStats returns error statistics
func (r *AdaptiveRateLimiter) GetStats() (total int64, errors int64, currentDelay time.Duration) {
	return atomic.LoadInt64(&r.totalRequests),
		atomic.LoadInt64(&r.totalErrors),
		r.GetCurrentDelay()
}

// ShouldBackoff returns true if we're experiencing too many errors
func (r *AdaptiveRateLimiter) ShouldBackoff() bool {
	return atomic.LoadInt64(&r.consecutiveErrors) > 5
}

// HostRateLimiter manages rate limits per host
type HostRateLimiter struct {
	limiters map[string]*AdaptiveRateLimiter
	config   Config
	mu       sync.RWMutex
}

// NewHostRateLimiter creates a per-host rate limiter
func NewHostRateLimiter(cfg Config) *HostRateLimiter {
	return &HostRateLimiter{
		limiters: make(map[string]*AdaptiveRateLimiter),
		config:   cfg,
	}
}

// Get returns or creates a rate limiter for a host
func (h *HostRateLimiter) Get(host string) *AdaptiveRateLimiter {
	h.mu.RLock()
	limiter, exists := h.limiters[host]
	h.mu.RUnlock()

	if exists {
		return limiter
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Double check after acquiring write lock
	if limiter, exists = h.limiters[host]; exists {
		return limiter
	}

	limiter = New(h.config)
	h.limiters[host] = limiter
	return limiter
}

// GetStats returns aggregated stats for all hosts
func (h *HostRateLimiter) GetStats() (hosts int, totalRequests, totalErrors int64) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	hosts = len(h.limiters)
	for _, limiter := range h.limiters {
		requests, errors, _ := limiter.GetStats()
		totalRequests += requests
		totalErrors += errors
	}
	return
}

// ConcurrencyController manages dynamic concurrency based on errors
type ConcurrencyController struct {
	maxConcurrency int64
	minConcurrency int64
	current        int64
	errorCount     int64
	successCount   int64
	checkInterval  int64
	mu             sync.Mutex
}

// NewConcurrencyController creates a new concurrency controller
func NewConcurrencyController(max, min int) *ConcurrencyController {
	return &ConcurrencyController{
		maxConcurrency: int64(max),
		minConcurrency: int64(min),
		current:        int64(max),
		checkInterval:  100, // Check every 100 requests
	}
}

// GetCurrent returns current concurrency level
func (c *ConcurrencyController) GetCurrent() int {
	return int(atomic.LoadInt64(&c.current))
}

// ReportSuccess reports a successful request
func (c *ConcurrencyController) ReportSuccess() {
	atomic.AddInt64(&c.successCount, 1)
	c.maybeAdjust()
}

// ReportError reports an error
func (c *ConcurrencyController) ReportError() {
	atomic.AddInt64(&c.errorCount, 1)
	c.maybeAdjust()
}

// maybeAdjust checks if we should adjust concurrency
func (c *ConcurrencyController) maybeAdjust() {
	total := atomic.LoadInt64(&c.successCount) + atomic.LoadInt64(&c.errorCount)
	if total%c.checkInterval != 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	errors := atomic.LoadInt64(&c.errorCount)
	successes := atomic.LoadInt64(&c.successCount)

	if successes == 0 {
		return
	}

	errorRate := float64(errors) / float64(total)

	if errorRate > 0.1 { // More than 10% errors
		// Reduce concurrency
		newConcurrency := int64(float64(c.current) * 0.8)
		if newConcurrency < c.minConcurrency {
			newConcurrency = c.minConcurrency
		}
		atomic.StoreInt64(&c.current, newConcurrency)
	} else if errorRate < 0.02 { // Less than 2% errors
		// Increase concurrency
		newConcurrency := int64(float64(c.current) * 1.1)
		if newConcurrency > c.maxConcurrency {
			newConcurrency = c.maxConcurrency
		}
		atomic.StoreInt64(&c.current, newConcurrency)
	}

	// Reset counters
	atomic.StoreInt64(&c.errorCount, 0)
	atomic.StoreInt64(&c.successCount, 0)
}
