package retry

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"time"
)

// Config holds retry configuration
type Config struct {
	MaxRetries      int           // Maximum number of retry attempts
	InitialDelay    time.Duration // Initial delay before first retry
	MaxDelay        time.Duration // Maximum delay between retries
	Multiplier      float64       // Delay multiplier for exponential backoff
	Jitter          float64       // Random jitter factor (0-1)
	RetryableErrors []error       // Specific errors to retry on (nil = retry all)
}

// DefaultConfig returns sensible defaults for network operations
func DefaultConfig() Config {
	return Config{
		MaxRetries:   3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     5 * time.Second,
		Multiplier:   2.0,
		Jitter:       0.1,
	}
}

// DNSConfig returns config optimized for DNS queries
func DNSConfig() Config {
	return Config{
		MaxRetries:   3,
		InitialDelay: 50 * time.Millisecond,
		MaxDelay:     2 * time.Second,
		Multiplier:   2.0,
		Jitter:       0.2,
	}
}

// HTTPConfig returns config optimized for HTTP requests
func HTTPConfig() Config {
	return Config{
		MaxRetries:   2,
		InitialDelay: 200 * time.Millisecond,
		MaxDelay:     3 * time.Second,
		Multiplier:   2.0,
		Jitter:       0.15,
	}
}

// AggressiveConfig returns config for fast scanning with fewer retries
func AggressiveConfig() Config {
	return Config{
		MaxRetries:   1,
		InitialDelay: 50 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   1.5,
		Jitter:       0.1,
	}
}

// Result wraps the result of a retryable operation
type Result struct {
	Value    interface{}
	Error    error
	Attempts int
}

// Do executes a function with retry logic
func Do(ctx context.Context, cfg Config, fn func() (interface{}, error)) Result {
	var lastErr error
	attempts := 0

	for attempts <= cfg.MaxRetries {
		attempts++

		// Check context cancellation
		select {
		case <-ctx.Done():
			return Result{Error: ctx.Err(), Attempts: attempts}
		default:
		}

		// Execute the function
		result, err := fn()
		if err == nil {
			return Result{Value: result, Attempts: attempts}
		}

		lastErr = err

		// Check if error is retryable
		if !isRetryable(err, cfg.RetryableErrors) {
			return Result{Error: err, Attempts: attempts}
		}

		// If this was the last attempt, don't sleep
		if attempts > cfg.MaxRetries {
			break
		}

		// Calculate delay with exponential backoff and jitter
		delay := calculateDelay(attempts, cfg)

		// Wait before retrying
		select {
		case <-ctx.Done():
			return Result{Error: ctx.Err(), Attempts: attempts}
		case <-time.After(delay):
		}
	}

	return Result{Error: lastErr, Attempts: attempts}
}

// DoSimple executes a function with default config and no context
func DoSimple(fn func() (interface{}, error)) Result {
	return Do(context.Background(), DefaultConfig(), fn)
}

// DoWithTimeout executes with a timeout
func DoWithTimeout(timeout time.Duration, cfg Config, fn func() (interface{}, error)) Result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return Do(ctx, cfg, fn)
}

// calculateDelay computes the delay for a given attempt
func calculateDelay(attempt int, cfg Config) time.Duration {
	// Exponential backoff: initialDelay * multiplier^(attempt-1)
	delay := float64(cfg.InitialDelay) * math.Pow(cfg.Multiplier, float64(attempt-1))

	// Apply max cap
	if delay > float64(cfg.MaxDelay) {
		delay = float64(cfg.MaxDelay)
	}

	// Apply jitter: delay * (1 +/- jitter)
	if cfg.Jitter > 0 {
		jitter := delay * cfg.Jitter * (2*rand.Float64() - 1)
		delay += jitter
	}

	return time.Duration(delay)
}

// isRetryable checks if an error should be retried
func isRetryable(err error, retryableErrors []error) bool {
	if err == nil {
		return false
	}

	// If no specific errors defined, retry all
	if len(retryableErrors) == 0 {
		return true
	}

	// Check if error matches any retryable error
	for _, retryableErr := range retryableErrors {
		if errors.Is(err, retryableErr) {
			return true
		}
	}

	return false
}

// Common retryable error types
var (
	ErrTimeout       = errors.New("operation timeout")
	ErrTemporary     = errors.New("temporary error")
	ErrConnectionReset = errors.New("connection reset")
	ErrDNSLookup     = errors.New("dns lookup failed")
)

// IsTemporaryError checks if an error is temporary/transient
func IsTemporaryError(err error) bool {
	if err == nil {
		return false
	}

	// Check for common temporary error strings
	errStr := err.Error()
	temporaryPatterns := []string{
		"timeout",
		"temporary",
		"connection reset",
		"connection refused",
		"no such host",
		"i/o timeout",
		"TLS handshake timeout",
		"context deadline exceeded",
		"server misbehaving",
		"too many open files",
	}

	for _, pattern := range temporaryPatterns {
		if containsIgnoreCase(errStr, pattern) {
			return true
		}
	}

	return false
}

func containsIgnoreCase(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if equalFold(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		sr := s[i]
		tr := t[i]
		if sr >= 'A' && sr <= 'Z' {
			sr += 'a' - 'A'
		}
		if tr >= 'A' && tr <= 'Z' {
			tr += 'a' - 'A'
		}
		if sr != tr {
			return false
		}
	}
	return true
}
