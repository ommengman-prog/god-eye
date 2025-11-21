package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// APIFinding represents an API-related discovery
type APIFinding struct {
	Type        string            `json:"type"`         // graphql, rest, swagger, openapi
	URL         string            `json:"url"`
	Method      string            `json:"method,omitempty"`
	Issue       string            `json:"issue,omitempty"`       // introspection_enabled, etc.
	Severity    string            `json:"severity,omitempty"`    // critical, high, medium, low
	Details     map[string]string `json:"details,omitempty"`
	Endpoints   []string          `json:"endpoints,omitempty"`   // discovered endpoints
	Version     string            `json:"version,omitempty"`     // API version
	Auth        string            `json:"auth,omitempty"`        // none, api_key, oauth, etc.
}

// APIScanner discovers and analyzes APIs
type APIScanner struct {
	client      *http.Client
	concurrency int
}

// NewAPIScanner creates a new API scanner
func NewAPIScanner(timeout int) *APIScanner {
	return &APIScanner{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		concurrency: 10,
	}
}

// ScanHost performs comprehensive API discovery on a host
func (as *APIScanner) ScanHost(ctx context.Context, host string) []APIFinding {
	var findings []APIFinding
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Check GraphQL endpoints
	wg.Add(1)
	go func() {
		defer wg.Done()
		gqlFindings := as.checkGraphQL(ctx, host)
		mu.Lock()
		findings = append(findings, gqlFindings...)
		mu.Unlock()
	}()

	// Check Swagger/OpenAPI
	wg.Add(1)
	go func() {
		defer wg.Done()
		swaggerFindings := as.checkSwagger(ctx, host)
		mu.Lock()
		findings = append(findings, swaggerFindings...)
		mu.Unlock()
	}()

	// Check common API paths
	wg.Add(1)
	go func() {
		defer wg.Done()
		apiFindings := as.checkCommonAPIPaths(ctx, host)
		mu.Lock()
		findings = append(findings, apiFindings...)
		mu.Unlock()
	}()

	// Check API versioning issues
	wg.Add(1)
	go func() {
		defer wg.Done()
		versionFindings := as.checkAPIVersions(ctx, host)
		mu.Lock()
		findings = append(findings, versionFindings...)
		mu.Unlock()
	}()

	wg.Wait()
	return findings
}

// GraphQL introspection query
const graphqlIntrospectionQuery = `{"query":"query IntrospectionQuery { __schema { queryType { name } types { name kind description fields { name } } } }"}`

// checkGraphQL checks for GraphQL endpoints and introspection
func (as *APIScanner) checkGraphQL(ctx context.Context, host string) []APIFinding {
	var findings []APIFinding

	// Common GraphQL paths
	paths := []string{
		"/graphql",
		"/graphiql",
		"/v1/graphql",
		"/v2/graphql",
		"/api/graphql",
		"/query",
		"/gql",
		"/playground",
		"/console",
	}

	for _, path := range paths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		for _, scheme := range []string{"https", "http"} {
			url := fmt.Sprintf("%s://%s%s", scheme, host, path)

			// Try POST with introspection query
			req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(graphqlIntrospectionQuery))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

			resp, err := as.client.Do(req)
			if err != nil {
				continue
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
			resp.Body.Close()

			// Check if introspection is enabled
			if resp.StatusCode == 200 && strings.Contains(string(body), "__schema") {
				finding := APIFinding{
					Type:     "graphql",
					URL:      url,
					Method:   "POST",
					Issue:    "introspection_enabled",
					Severity: "high",
					Details: map[string]string{
						"description": "GraphQL introspection is enabled, exposing schema",
					},
				}

				// Extract type names
				var gqlResp map[string]interface{}
				if json.Unmarshal(body, &gqlResp) == nil {
					if data, ok := gqlResp["data"].(map[string]interface{}); ok {
						if schema, ok := data["__schema"].(map[string]interface{}); ok {
							if types, ok := schema["types"].([]interface{}); ok {
								for i, t := range types {
									if i >= 20 {
										break
									}
									if typeMap, ok := t.(map[string]interface{}); ok {
										if name, ok := typeMap["name"].(string); ok {
											if !strings.HasPrefix(name, "__") {
												finding.Endpoints = append(finding.Endpoints, name)
											}
										}
									}
								}
							}
						}
					}
				}

				findings = append(findings, finding)
				break // Found on this scheme, don't check http if https worked
			}

			// Check for GraphQL endpoint without introspection
			if resp.StatusCode == 200 || resp.StatusCode == 400 {
				contentType := resp.Header.Get("Content-Type")
				if strings.Contains(contentType, "json") || strings.Contains(string(body), "errors") {
					findings = append(findings, APIFinding{
						Type:     "graphql",
						URL:      url,
						Method:   "POST",
						Issue:    "endpoint_found",
						Severity: "info",
						Details: map[string]string{
							"introspection": "disabled",
						},
					})
					break
				}
			}
		}
	}

	return findings
}

// checkSwagger checks for Swagger/OpenAPI documentation with proper JSON validation
func (as *APIScanner) checkSwagger(ctx context.Context, host string) []APIFinding {
	var findings []APIFinding

	// Common Swagger/OpenAPI paths
	paths := []string{
		"/swagger.json",
		"/swagger.yaml",
		"/swagger/v1/swagger.json",
		"/api/swagger.json",
		"/openapi.json",
		"/openapi.yaml",
		"/api-docs",
		"/api-docs.json",
		"/v1/api-docs",
		"/v2/api-docs",
		"/v3/api-docs",
		"/docs/api",
		"/swagger-ui.html",
		"/swagger-ui/",
		"/swagger/",
		"/api/docs",
		"/api/v1/docs",
		"/.well-known/openapi.json",
		"/redoc",
	}

	for _, path := range paths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		for _, scheme := range []string{"https", "http"} {
			url := fmt.Sprintf("%s://%s%s", scheme, host, path)

			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

			resp, err := as.client.Do(req)
			if err != nil {
				continue
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 500*1024))
			resp.Body.Close()

			if resp.StatusCode == 200 {
				contentType := resp.Header.Get("Content-Type")
				bodyStr := string(body)

				// IMPROVED: Validate actual Swagger/OpenAPI JSON structure, not just strings
				isValidSwagger, swaggerVersion := validateSwaggerStructure(body)

				// Check for Swagger UI (HTML page)
				isSwaggerUI := strings.Contains(bodyStr, "swagger-ui") &&
					strings.Contains(contentType, "text/html")

				if isValidSwagger {
					finding := APIFinding{
						Type:     "swagger",
						URL:      url,
						Method:   "GET",
						Severity: "medium",
						Issue:    "api_documentation_exposed",
						Details: map[string]string{
							"description":     "API documentation is publicly accessible",
							"swagger_version": swaggerVersion,
							"confidence":      "high",
						},
					}

					// Extract endpoints from swagger
					finding.Endpoints = extractSwaggerEndpoints(body)
					finding.Version = swaggerVersion

					findings = append(findings, finding)
					break
				} else if isSwaggerUI {
					// Swagger UI is still useful to report, but with lower confidence
					findings = append(findings, APIFinding{
						Type:     "swagger",
						URL:      url,
						Method:   "GET",
						Severity: "low",
						Issue:    "swagger_ui_exposed",
						Details: map[string]string{
							"description": "Swagger UI page detected",
							"confidence":  "medium",
						},
					})
					break
				}
			}
		}
	}

	return findings
}

// validateSwaggerStructure validates actual Swagger/OpenAPI JSON structure
// Returns (isValid, version) - reduces false positives by checking real structure
func validateSwaggerStructure(body []byte) (bool, string) {
	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return false, ""
	}

	// Check for OpenAPI 3.x format
	if openapi, ok := doc["openapi"].(string); ok {
		if strings.HasPrefix(openapi, "3.") {
			// Validate required OpenAPI 3.x fields
			if _, hasInfo := doc["info"].(map[string]interface{}); hasInfo {
				if _, hasPaths := doc["paths"].(map[string]interface{}); hasPaths {
					return true, openapi
				}
			}
		}
	}

	// Check for Swagger 2.0 format
	if swagger, ok := doc["swagger"].(string); ok {
		if swagger == "2.0" {
			// Validate required Swagger 2.0 fields
			if _, hasInfo := doc["info"].(map[string]interface{}); hasInfo {
				if _, hasPaths := doc["paths"].(map[string]interface{}); hasPaths {
					return true, "2.0"
				}
			}
		}
	}

	// Check for minimal valid structure (paths with actual endpoints)
	if paths, ok := doc["paths"].(map[string]interface{}); ok {
		if len(paths) > 0 {
			// Verify at least one path has HTTP methods
			for _, pathDef := range paths {
				if pathObj, ok := pathDef.(map[string]interface{}); ok {
					for method := range pathObj {
						if isHTTPMethod(method) {
							return true, "unknown"
						}
					}
				}
			}
		}
	}

	return false, ""
}

// isHTTPMethod checks if a string is a valid HTTP method
func isHTTPMethod(s string) bool {
	methods := []string{"get", "post", "put", "delete", "patch", "options", "head"}
	lower := strings.ToLower(s)
	for _, m := range methods {
		if lower == m {
			return true
		}
	}
	return false
}

// checkCommonAPIPaths checks for common API endpoints with improved false positive filtering
func (as *APIScanner) checkCommonAPIPaths(ctx context.Context, host string) []APIFinding {
	var findings []APIFinding

	// First, get baseline responses to detect WAF/global auth
	baselineStatus := as.getBaselineResponse(ctx, host)

	// Sensitive API paths
	sensitivePaths := map[string]string{
		"/api/users":           "User enumeration possible",
		"/api/v1/users":        "User enumeration possible",
		"/api/admin":           "Admin API exposed",
		"/api/v1/admin":        "Admin API exposed",
		"/api/config":          "Configuration endpoint exposed",
		"/api/settings":        "Settings endpoint exposed",
		"/api/debug":           "Debug endpoint exposed",
		"/api/health":          "Health check exposed",
		"/api/status":          "Status endpoint exposed",
		"/api/metrics":         "Metrics endpoint exposed",
		"/api/internal":        "Internal API exposed",
		"/api/private":         "Private API exposed",
		"/actuator":            "Spring Boot Actuator exposed",
		"/actuator/env":        "Environment variables exposed",
		"/actuator/heapdump":   "Heap dump endpoint exposed",
		"/actuator/mappings":   "API mappings exposed",
		"/metrics":             "Prometheus metrics exposed",
		"/debug/pprof":         "Go pprof exposed",
		"/debug/vars":          "Debug vars exposed",
		"/__debug__":           "Debug mode enabled",
		"/api/v1/internal":     "Internal API exposed",
		"/api/keys":            "API keys endpoint exposed",
		"/api/tokens":          "Tokens endpoint exposed",
	}

	for path, description := range sensitivePaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		for _, scheme := range []string{"https", "http"} {
			url := fmt.Sprintf("%s://%s%s", scheme, host, path)

			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

			resp, err := as.client.Do(req)
			if err != nil {
				continue
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024))
			resp.Body.Close()

			// IMPROVED: Skip if this is likely a WAF/global response
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				// If baseline returns same status, this is likely WAF/global auth, not endpoint-specific
				if baselineStatus == resp.StatusCode {
					continue
				}
			}

			// Found if not 404 and not generic error
			if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
				// IMPROVED: Validate the response looks like an actual API response
				confidence := validateAPIResponse(body, resp.Header.Get("Content-Type"), resp.StatusCode)
				if confidence == "none" {
					continue
				}

				severity := "low"
				if strings.Contains(path, "admin") || strings.Contains(path, "internal") ||
					strings.Contains(path, "debug") || strings.Contains(path, "actuator") {
					severity = "high"
				} else if strings.Contains(path, "users") || strings.Contains(path, "config") {
					severity = "medium"
				}

				// Lower severity for protected endpoints
				if resp.StatusCode == 401 || resp.StatusCode == 403 {
					if severity == "high" {
						severity = "medium"
					} else {
						severity = "low"
					}
				}

				auth := "none"
				if resp.StatusCode == 401 {
					auth = "required"
				} else if resp.StatusCode == 403 {
					auth = "forbidden"
				}

				findings = append(findings, APIFinding{
					Type:     "rest",
					URL:      url,
					Method:   "GET",
					Issue:    "sensitive_endpoint",
					Severity: severity,
					Auth:     auth,
					Details: map[string]string{
						"description": description,
						"status_code": fmt.Sprintf("%d", resp.StatusCode),
						"confidence":  confidence,
					},
				})
				break
			}
		}
	}

	return findings
}

// getBaselineResponse gets the response for a random non-existent path
// to detect global WAF/auth that returns same response for all paths
func (as *APIScanner) getBaselineResponse(ctx context.Context, host string) int {
	// Use a random path that shouldn't exist
	url := fmt.Sprintf("https://%s/___baseline_test_path_12345___", host)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

	resp, err := as.client.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()

	return resp.StatusCode
}

// validateAPIResponse checks if a response looks like a real API response
// Returns confidence level: "high", "medium", "low", "none"
func validateAPIResponse(body []byte, contentType string, statusCode int) string {
	bodyStr := string(body)

	// If it's a generic HTML error page, it's likely not a real API endpoint
	if strings.Contains(contentType, "text/html") {
		// Check for common error page patterns
		if strings.Contains(bodyStr, "<!DOCTYPE") || strings.Contains(bodyStr, "<html") {
			// HTML pages for API endpoints are suspicious
			// Unless it's a documentation or login page
			if strings.Contains(bodyStr, "login") || strings.Contains(bodyStr, "sign in") {
				return "medium"
			}
			return "none"
		}
	}

	// JSON responses are good indicators of real API endpoints
	if strings.Contains(contentType, "application/json") {
		var js interface{}
		if json.Unmarshal(body, &js) == nil {
			return "high"
		}
	}

	// For 200 status, we expect some content
	if statusCode == 200 {
		if len(body) == 0 {
			return "low"
		}
		// Check for JSON-like structure
		if (bodyStr[0] == '{' || bodyStr[0] == '[') {
			return "high"
		}
		return "medium"
	}

	// For 401/403, check for API-style error messages
	if statusCode == 401 || statusCode == 403 {
		// Common API error patterns
		if strings.Contains(bodyStr, "unauthorized") ||
			strings.Contains(bodyStr, "forbidden") ||
			strings.Contains(bodyStr, "\"error\"") ||
			strings.Contains(bodyStr, "\"message\"") {
			return "high"
		}
		// Short responses are likely API responses
		if len(body) < 500 {
			return "medium"
		}
		return "low"
	}

	return "medium"
}

// checkAPIVersions checks for deprecated/old API versions
func (as *APIScanner) checkAPIVersions(ctx context.Context, host string) []APIFinding {
	var findings []APIFinding

	// API version paths to check
	versions := []string{
		"/api/v0/",
		"/api/v1/",
		"/api/v2/",
		"/api/v3/",
		"/v0/",
		"/v1/",
		"/v2/",
		"/v3/",
	}

	foundVersions := []string{}

	for _, version := range versions {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		url := fmt.Sprintf("https://%s%s", host, version)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

		resp, err := as.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 404 && resp.StatusCode != 0 {
			foundVersions = append(foundVersions, version)
		}
	}

	// If multiple versions found, report potential issue
	if len(foundVersions) > 1 {
		findings = append(findings, APIFinding{
			Type:     "rest",
			URL:      fmt.Sprintf("https://%s", host),
			Issue:    "multiple_api_versions",
			Severity: "low",
			Details: map[string]string{
				"description": "Multiple API versions detected, old versions may be deprecated",
			},
			Endpoints: foundVersions,
		})
	}

	// Check for v0 specifically (often test/dev)
	for _, v := range foundVersions {
		if strings.Contains(v, "v0") {
			findings = append(findings, APIFinding{
				Type:     "rest",
				URL:      fmt.Sprintf("https://%s%s", host, v),
				Issue:    "dev_api_version",
				Severity: "medium",
				Details: map[string]string{
					"description": "Version 0 API found, may be development/test version",
				},
			})
		}
	}

	return findings
}

// extractSwaggerEndpoints extracts API paths from swagger JSON
func extractSwaggerEndpoints(body []byte) []string {
	var endpoints []string
	seen := make(map[string]bool)

	// Try to parse as JSON
	var swagger map[string]interface{}
	if err := json.Unmarshal(body, &swagger); err != nil {
		return endpoints
	}

	// Extract from "paths" object
	if paths, ok := swagger["paths"].(map[string]interface{}); ok {
		for path := range paths {
			if !seen[path] {
				seen[path] = true
				endpoints = append(endpoints, path)
			}
		}
	}

	// Limit to 50 endpoints
	if len(endpoints) > 50 {
		endpoints = endpoints[:50]
	}

	return endpoints
}

// ExtractAPIURLs extracts API-related URLs from content
func ExtractAPIURLs(content string) []string {
	var urls []string
	seen := make(map[string]bool)

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`["'](/api/[^"'\s]+)["']`),
		regexp.MustCompile(`["'](/v\d+/[^"'\s]+)["']`),
		regexp.MustCompile(`["'](https?://[^"'\s]+/api/[^"'\s]+)["']`),
		regexp.MustCompile(`["'](https?://api\.[^"'\s]+)["']`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 && !seen[match[1]] {
				seen[match[1]] = true
				urls = append(urls, match[1])
			}
		}
	}

	return urls
}
