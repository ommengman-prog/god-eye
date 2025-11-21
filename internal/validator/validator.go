package validator

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// ValidationError represents an input validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// DomainValidator validates domain inputs
type DomainValidator struct {
	MaxLength       int
	AllowWildcard   bool
	AllowSubdomains bool
}

// DefaultDomainValidator returns a validator with sensible defaults
func DefaultDomainValidator() *DomainValidator {
	return &DomainValidator{
		MaxLength:       253, // RFC 1035 max domain length
		AllowWildcard:   false,
		AllowSubdomains: true,
	}
}

// ValidateDomain validates a domain name for security and correctness
func (v *DomainValidator) ValidateDomain(domain string) error {
	// Trim whitespace
	domain = strings.TrimSpace(domain)

	// Check empty
	if domain == "" {
		return &ValidationError{Field: "domain", Message: "domain cannot be empty"}
	}

	// Check length
	if len(domain) > v.MaxLength {
		return &ValidationError{
			Field:   "domain",
			Message: fmt.Sprintf("domain exceeds maximum length of %d characters", v.MaxLength),
		}
	}

	// Check for dangerous characters (path traversal, command injection)
	dangerousChars := []string{
		"..", "/", "\\", ";", "|", "&", "$", "`", "'", "\"",
		"\n", "\r", "\t", "\x00", "%", "<", ">", "(", ")", "{", "}",
	}
	for _, char := range dangerousChars {
		if strings.Contains(domain, char) {
			return &ValidationError{
				Field:   "domain",
				Message: fmt.Sprintf("domain contains invalid character: %q", char),
			}
		}
	}

	// Check for URL scheme (common mistake)
	if strings.HasPrefix(strings.ToLower(domain), "http://") ||
		strings.HasPrefix(strings.ToLower(domain), "https://") {
		return &ValidationError{
			Field:   "domain",
			Message: "domain should not include protocol (http:// or https://)",
		}
	}

	// Validate domain format using regex
	// Valid: example.com, sub.example.com, test-site.co.uk
	// Invalid: -example.com, example-.com, example..com
	domainRegex := regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	if !domainRegex.MatchString(domain) {
		return &ValidationError{
			Field:   "domain",
			Message: "invalid domain format",
		}
	}

	// Check each label length (max 63 chars per RFC 1035)
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) > 63 {
			return &ValidationError{
				Field:   "domain",
				Message: fmt.Sprintf("domain label %q exceeds 63 characters", label),
			}
		}
		if len(label) == 0 {
			return &ValidationError{
				Field:   "domain",
				Message: "domain contains empty label",
			}
		}
	}

	// Check TLD is not just numbers
	tld := labels[len(labels)-1]
	if regexp.MustCompile(`^\d+$`).MatchString(tld) {
		return &ValidationError{
			Field:   "domain",
			Message: "TLD cannot be numeric only",
		}
	}

	return nil
}

// ValidateIP validates an IP address
func ValidateIP(ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return &ValidationError{Field: "ip", Message: "IP cannot be empty"}
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return &ValidationError{Field: "ip", Message: "invalid IP address format"}
	}

	return nil
}

// ValidatePort validates a port number
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return &ValidationError{
			Field:   "port",
			Message: fmt.Sprintf("port must be between 1 and 65535, got %d", port),
		}
	}
	return nil
}

// ValidateWordlistPath validates a wordlist file path for security
func ValidateWordlistPath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil // Empty is allowed (uses default)
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return &ValidationError{
			Field:   "wordlist",
			Message: "path traversal not allowed in wordlist path",
		}
	}

	// Check for null bytes (truncation attack)
	if strings.Contains(path, "\x00") {
		return &ValidationError{
			Field:   "wordlist",
			Message: "null bytes not allowed in path",
		}
	}

	return nil
}

// ValidateOutputPath validates output file path for security
func ValidateOutputPath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil // Empty is allowed (no output file)
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return &ValidationError{
			Field:   "output",
			Message: "path traversal not allowed in output path",
		}
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return &ValidationError{
			Field:   "output",
			Message: "null bytes not allowed in path",
		}
	}

	// Disallow writing to sensitive paths
	sensitivePatterns := []string{
		"/etc/", "/var/", "/usr/", "/bin/", "/sbin/",
		"/root/", "/home/", "/proc/", "/sys/", "/dev/",
	}
	lowerPath := strings.ToLower(path)
	for _, pattern := range sensitivePatterns {
		if strings.HasPrefix(lowerPath, pattern) {
			return &ValidationError{
				Field:   "output",
				Message: fmt.Sprintf("cannot write to system path: %s", pattern),
			}
		}
	}

	return nil
}

// ValidateResolvers validates a comma-separated list of DNS resolvers
func ValidateResolvers(resolvers string) error {
	resolvers = strings.TrimSpace(resolvers)
	if resolvers == "" {
		return nil // Empty uses defaults
	}

	parts := strings.Split(resolvers, ",")
	for _, resolver := range parts {
		resolver = strings.TrimSpace(resolver)
		if resolver == "" {
			continue
		}

		// Check if it's a valid IP
		if err := ValidateIP(resolver); err != nil {
			return &ValidationError{
				Field:   "resolvers",
				Message: fmt.Sprintf("invalid resolver IP: %s", resolver),
			}
		}
	}

	return nil
}

// ValidateConcurrency validates concurrency settings
func ValidateConcurrency(concurrency int) error {
	if concurrency < 1 {
		return &ValidationError{
			Field:   "concurrency",
			Message: "concurrency must be at least 1",
		}
	}
	if concurrency > 10000 {
		return &ValidationError{
			Field:   "concurrency",
			Message: "concurrency exceeds maximum of 10000",
		}
	}
	return nil
}

// ValidateTimeout validates timeout settings
func ValidateTimeout(timeout int) error {
	if timeout < 1 {
		return &ValidationError{
			Field:   "timeout",
			Message: "timeout must be at least 1 second",
		}
	}
	if timeout > 300 {
		return &ValidationError{
			Field:   "timeout",
			Message: "timeout exceeds maximum of 300 seconds",
		}
	}
	return nil
}

// SanitizeDomain returns a cleaned domain string
func SanitizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.ToLower(domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")
	return domain
}
