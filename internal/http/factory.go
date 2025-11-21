package http

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"
)

// ClientFactory manages shared HTTP clients with connection pooling
type ClientFactory struct {
	// Shared transports for connection reuse
	secureTransport   *http.Transport
	insecureTransport *http.Transport

	// Pre-configured clients
	defaultClient  *http.Client
	fastClient     *http.Client
	noRedirect     *http.Client
	insecureClient *http.Client

	mu sync.RWMutex
}

var (
	factory     *ClientFactory
	factoryOnce sync.Once
)

// GetFactory returns the singleton client factory
func GetFactory() *ClientFactory {
	factoryOnce.Do(func() {
		factory = newClientFactory()
	})
	return factory
}

func newClientFactory() *ClientFactory {
	// Secure transport with TLS verification
	secureTransport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 20,
		MaxConnsPerHost:     50,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2:     true,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Insecure transport (for scanning targets with invalid certs)
	insecureTransport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 20,
		MaxConnsPerHost:     50,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10, // Support older servers
		},
		ForceAttemptHTTP2:     true,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &ClientFactory{
		secureTransport:   secureTransport,
		insecureTransport: insecureTransport,

		defaultClient: &http.Client{
			Transport: insecureTransport,
			Timeout:   15 * time.Second,
		},

		fastClient: &http.Client{
			Transport: insecureTransport,
			Timeout:   5 * time.Second,
		},

		noRedirect: &http.Client{
			Transport: insecureTransport,
			Timeout:   10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},

		insecureClient: &http.Client{
			Transport: insecureTransport,
			Timeout:   10 * time.Second,
		},
	}
}

// Default returns the default client with 15s timeout
func (f *ClientFactory) Default() *http.Client {
	return f.defaultClient
}

// Fast returns a client with 5s timeout for quick checks
func (f *ClientFactory) Fast() *http.Client {
	return f.fastClient
}

// NoRedirect returns a client that doesn't follow redirects
func (f *ClientFactory) NoRedirect() *http.Client {
	return f.noRedirect
}

// Insecure returns a client with TLS verification disabled
func (f *ClientFactory) Insecure() *http.Client {
	return f.insecureClient
}

// WithTimeout creates a client with custom timeout (reuses transport)
func (f *ClientFactory) WithTimeout(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: f.insecureTransport,
		Timeout:   timeout,
	}
}

// WithTimeoutNoRedirect creates a client with custom timeout that doesn't follow redirects
func (f *ClientFactory) WithTimeoutNoRedirect(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: f.insecureTransport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Secure returns a client with TLS verification enabled (for passive sources)
func (f *ClientFactory) Secure() *http.Client {
	return &http.Client{
		Transport: f.secureTransport,
		Timeout:   30 * time.Second,
	}
}

// SecureWithTimeout creates a secure client with custom timeout
func (f *ClientFactory) SecureWithTimeout(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: f.secureTransport,
		Timeout:   timeout,
	}
}

// CloseIdleConnections closes idle connections in all transports
func (f *ClientFactory) CloseIdleConnections() {
	f.secureTransport.CloseIdleConnections()
	f.insecureTransport.CloseIdleConnections()
}

// Stats returns connection pool statistics
type PoolStats struct {
	SecureIdleConns   int
	InsecureIdleConns int
}

// GetStats returns current pool statistics (approximation)
func (f *ClientFactory) GetStats() PoolStats {
	// Note: Go's http.Transport doesn't expose detailed stats
	// This is a placeholder for future monitoring
	return PoolStats{}
}

// Convenience functions for direct access

// DefaultClient returns the default shared client
func DefaultClient() *http.Client {
	return GetFactory().Default()
}

// FastClient returns the fast shared client (5s timeout)
func FastClient() *http.Client {
	return GetFactory().Fast()
}

// NoRedirectClient returns a client that doesn't follow redirects
func NoRedirectClient() *http.Client {
	return GetFactory().NoRedirect()
}

// InsecureClient returns a client with TLS verification disabled
func InsecureClient() *http.Client {
	return GetFactory().Insecure()
}

// SecureClient returns a client with TLS verification enabled
func SecureClient() *http.Client {
	return GetFactory().Secure()
}

// ClientWithTimeout returns a client with custom timeout
func ClientWithTimeout(timeout time.Duration) *http.Client {
	return GetFactory().WithTimeout(timeout)
}
