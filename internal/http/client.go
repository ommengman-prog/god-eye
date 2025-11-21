package http

import (
	"crypto/tls"
	"net/http"
	"sync"
	"time"
)

// SharedTransport is a global shared HTTP transport for connection pooling
var SharedTransport = &http.Transport{
	TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	MaxIdleConns:        100,
	MaxIdleConnsPerHost: 10,
	IdleConnTimeout:     30 * time.Second,
	DisableCompression:  true, // Keep Content-Length header for SPA detection
}

// GetSharedClient returns an HTTP client with connection pooling
func GetSharedClient(timeout int) *http.Client {
	return &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: SharedTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// UserAgentManager handles User-Agent rotation
type UserAgentManager struct {
	agents []string
	index  int
	mu     sync.Mutex
}

var defaultUAManager = &UserAgentManager{
	agents: []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	},
}

// GetUserAgent returns the next User-Agent in rotation
func GetUserAgent() string {
	defaultUAManager.mu.Lock()
	defer defaultUAManager.mu.Unlock()

	ua := defaultUAManager.agents[defaultUAManager.index]
	defaultUAManager.index = (defaultUAManager.index + 1) % len(defaultUAManager.agents)
	return ua
}

// NewRequestWithUA creates an HTTP request with a rotated User-Agent
func NewRequestWithUA(method, url string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", GetUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")
	return req, nil
}
