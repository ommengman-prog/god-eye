package sources

import (
	"fmt"
	"time"
)

// ErrorType categorizes source errors
type ErrorType string

const (
	ErrTypeTimeout   ErrorType = "timeout"
	ErrTypeHTTP      ErrorType = "http_error"
	ErrTypeParse     ErrorType = "parse_error"
	ErrTypeRateLimit ErrorType = "rate_limit"
	ErrTypeNetwork   ErrorType = "network_error"
	ErrTypeEmpty     ErrorType = "empty_response"
	ErrTypeUnknown   ErrorType = "unknown"
)

// SourceError represents an error from a passive source
type SourceError struct {
	Source    string
	Type      ErrorType
	Message   string
	StatusCode int
	Duration  time.Duration
	Retryable bool
}

func (e *SourceError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("[%s] %s: %s (status: %d, took: %v)",
			e.Type, e.Source, e.Message, e.StatusCode, e.Duration)
	}
	return fmt.Sprintf("[%s] %s: %s (took: %v)",
		e.Type, e.Source, e.Message, e.Duration)
}

// NewTimeoutError creates a timeout error
func NewTimeoutError(source string, duration time.Duration) *SourceError {
	return &SourceError{
		Source:    source,
		Type:      ErrTypeTimeout,
		Message:   "request timed out",
		Duration:  duration,
		Retryable: true,
	}
}

// NewHTTPError creates an HTTP error
func NewHTTPError(source string, statusCode int, duration time.Duration) *SourceError {
	retryable := statusCode >= 500 || statusCode == 429
	return &SourceError{
		Source:     source,
		Type:       ErrTypeHTTP,
		Message:    fmt.Sprintf("HTTP %d", statusCode),
		StatusCode: statusCode,
		Duration:   duration,
		Retryable:  retryable,
	}
}

// NewParseError creates a parse error
func NewParseError(source string, msg string, duration time.Duration) *SourceError {
	return &SourceError{
		Source:    source,
		Type:      ErrTypeParse,
		Message:   msg,
		Duration:  duration,
		Retryable: false,
	}
}

// NewRateLimitError creates a rate limit error
func NewRateLimitError(source string, duration time.Duration) *SourceError {
	return &SourceError{
		Source:    source,
		Type:      ErrTypeRateLimit,
		Message:   "rate limited",
		Duration:  duration,
		Retryable: true,
	}
}

// NewNetworkError creates a network error
func NewNetworkError(source string, msg string, duration time.Duration) *SourceError {
	return &SourceError{
		Source:    source,
		Type:      ErrTypeNetwork,
		Message:   msg,
		Duration:  duration,
		Retryable: true,
	}
}

// NewEmptyError creates an empty response error
func NewEmptyError(source string, duration time.Duration) *SourceError {
	return &SourceError{
		Source:    source,
		Type:      ErrTypeEmpty,
		Message:   "empty response",
		Duration:  duration,
		Retryable: false,
	}
}

// SourceResult represents the result from a passive source
type SourceResult struct {
	Source     string
	Subdomains []string
	Error      *SourceError
	Duration   time.Duration
	Cached     bool
}

// IsSuccess returns true if the result has no error
func (r *SourceResult) IsSuccess() bool {
	return r.Error == nil
}

// Count returns the number of subdomains found
func (r *SourceResult) Count() int {
	return len(r.Subdomains)
}

// SourceStats tracks statistics for all sources
type SourceStats struct {
	TotalSources   int
	SuccessSources int
	FailedSources  int
	TotalFound     int
	TotalDuration  time.Duration
	Errors         []*SourceError
}

// AddResult adds a result to the stats
func (s *SourceStats) AddResult(result *SourceResult) {
	s.TotalSources++
	s.TotalDuration += result.Duration

	if result.IsSuccess() {
		s.SuccessSources++
		s.TotalFound += result.Count()
	} else {
		s.FailedSources++
		s.Errors = append(s.Errors, result.Error)
	}
}

// SuccessRate returns the percentage of successful sources
func (s *SourceStats) SuccessRate() float64 {
	if s.TotalSources == 0 {
		return 0
	}
	return float64(s.SuccessSources) / float64(s.TotalSources) * 100
}

// Summary returns a human-readable summary
func (s *SourceStats) Summary() string {
	return fmt.Sprintf("%d/%d sources succeeded (%.0f%%), found %d subdomains in %v",
		s.SuccessSources, s.TotalSources, s.SuccessRate(),
		s.TotalFound, s.TotalDuration.Round(time.Millisecond))
}

// ErrorsByType returns errors grouped by type
func (s *SourceStats) ErrorsByType() map[ErrorType][]*SourceError {
	result := make(map[ErrorType][]*SourceError)
	for _, err := range s.Errors {
		result[err.Type] = append(result[err.Type], err)
	}
	return result
}
