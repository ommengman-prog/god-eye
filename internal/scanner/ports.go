package scanner

import (
	"context"
	"net"
	"sync"
	"time"

	"god-eye/internal/config"
	"god-eye/internal/progress"
)

// PortConfig contains configuration for port scanning
type PortConfig struct {
	Ports       []int
	Timeout     int
	Concurrency int
	Silent      bool
	JsonOutput  bool
}

// DefaultPorts returns the default ports to scan
func DefaultPorts() []int {
	return []int{80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9443}
}

// Note: ScanPorts is defined in helpers.go

// RunPortScan performs port scanning on all resolved subdomains
func RunPortScan(ctx context.Context, results map[string]*config.SubdomainResult,
	resultsMu *sync.Mutex, cfg PortConfig) {

	if len(results) == 0 {
		return
	}

	// Count hosts with IPs
	hostCount := 0
	for _, result := range results {
		if len(result.IPs) > 0 {
			hostCount++
		}
	}

	if hostCount == 0 {
		return
	}

	portBar := progress.New(hostCount, "Ports", cfg.Silent || cfg.JsonOutput)
	pool := NewWorkerPool(ctx, cfg.Concurrency)

	for sub, result := range results {
		if len(result.IPs) == 0 {
			continue
		}

		subdomain := sub
		ip := result.IPs[0]

		pool.Submit(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			defer portBar.Increment()

			openPorts := scanPortsInternal(ip, cfg.Ports, cfg.Timeout)

			resultsMu.Lock()
			if r, ok := results[subdomain]; ok {
				r.Ports = openPorts
			}
			resultsMu.Unlock()

			return nil
		})
	}

	pool.Wait()
	portBar.Finish()
}

// scanPortsInternal is the internal port scanner
func scanPortsInternal(ip string, ports []int, timeout int) []int {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 20)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			address := net.JoinHostPort(ip, intToStr(p))
			conn, err := net.DialTimeout("tcp", address, time.Duration(timeout)*time.Second)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()

	return openPorts
}

// intToStr converts int to string without importing strconv
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
