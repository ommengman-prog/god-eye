package scanner

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"god-eye/internal/output"
)

// ScanContext wraps context.Context with scan-specific functionality
type ScanContext struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.RWMutex

	// Stats
	startTime      time.Time
	subdomains     int
	activeHosts    int
	vulnerabilities int
	errors         int

	// Shutdown handling
	shutdownOnce sync.Once
	shutdownCh   chan struct{}
}

// NewScanContext creates a context that handles graceful shutdown
func NewScanContext() *ScanContext {
	ctx, cancel := context.WithCancel(context.Background())
	sc := &ScanContext{
		ctx:        ctx,
		cancel:     cancel,
		startTime:  time.Now(),
		shutdownCh: make(chan struct{}),
	}

	// Handle interrupt signals
	go sc.handleSignals()

	return sc
}

// NewScanContextWithTimeout creates a context with a maximum duration
func NewScanContextWithTimeout(timeout time.Duration) *ScanContext {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	sc := &ScanContext{
		ctx:        ctx,
		cancel:     cancel,
		startTime:  time.Now(),
		shutdownCh: make(chan struct{}),
	}

	go sc.handleSignals()

	return sc
}

// handleSignals listens for interrupt signals and triggers graceful shutdown
func (sc *ScanContext) handleSignals() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		sc.shutdownOnce.Do(func() {
			fmt.Printf("\n%s Received %v, initiating graceful shutdown...\n",
				output.Yellow("⚠️"), sig)
			fmt.Println(output.Dim("   Press Ctrl+C again to force quit"))

			// Give time for cleanup
			close(sc.shutdownCh)
			sc.cancel()

			// Second signal = force quit
			go func() {
				<-sigCh
				fmt.Println(output.Red("\n[!] Force quit"))
				os.Exit(1)
			}()
		})
	case <-sc.ctx.Done():
		return
	}
}

// Context returns the underlying context
func (sc *ScanContext) Context() context.Context {
	return sc.ctx
}

// Cancel cancels the context
func (sc *ScanContext) Cancel() {
	sc.cancel()
}

// Done returns a channel that's closed when the context is cancelled
func (sc *ScanContext) Done() <-chan struct{} {
	return sc.ctx.Done()
}

// IsCancelled returns true if the context has been cancelled
func (sc *ScanContext) IsCancelled() bool {
	select {
	case <-sc.ctx.Done():
		return true
	default:
		return false
	}
}

// ShuttingDown returns a channel that's closed when shutdown is initiated
func (sc *ScanContext) ShuttingDown() <-chan struct{} {
	return sc.shutdownCh
}

// Stats methods
func (sc *ScanContext) IncrementSubdomains(n int) {
	sc.mu.Lock()
	sc.subdomains += n
	sc.mu.Unlock()
}

func (sc *ScanContext) IncrementActive() {
	sc.mu.Lock()
	sc.activeHosts++
	sc.mu.Unlock()
}

func (sc *ScanContext) IncrementVulns() {
	sc.mu.Lock()
	sc.vulnerabilities++
	sc.mu.Unlock()
}

func (sc *ScanContext) IncrementErrors() {
	sc.mu.Lock()
	sc.errors++
	sc.mu.Unlock()
}

func (sc *ScanContext) GetStats() (subdomains, active, vulns, errors int, elapsed time.Duration) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.subdomains, sc.activeHosts, sc.vulnerabilities, sc.errors, time.Since(sc.startTime)
}

// Elapsed returns time since scan started
func (sc *ScanContext) Elapsed() time.Duration {
	return time.Since(sc.startTime)
}

// WorkerPool manages concurrent workers with context cancellation
type WorkerPool struct {
	ctx        context.Context
	wg         sync.WaitGroup
	semaphore  chan struct{}
	errCh      chan error
	errOnce    sync.Once
	firstError error
}

// NewWorkerPool creates a pool with max concurrent workers
func NewWorkerPool(ctx context.Context, maxWorkers int) *WorkerPool {
	return &WorkerPool{
		ctx:       ctx,
		semaphore: make(chan struct{}, maxWorkers),
		errCh:     make(chan error, 1),
	}
}

// Submit submits a task to the pool
// Returns false if context is cancelled
func (wp *WorkerPool) Submit(task func() error) bool {
	// Check if cancelled before acquiring semaphore
	select {
	case <-wp.ctx.Done():
		return false
	default:
	}

	// Acquire semaphore (with cancellation check)
	select {
	case wp.semaphore <- struct{}{}:
	case <-wp.ctx.Done():
		return false
	}

	wp.wg.Add(1)
	go func() {
		defer wp.wg.Done()
		defer func() { <-wp.semaphore }()

		// Check again before running
		select {
		case <-wp.ctx.Done():
			return
		default:
		}

		if err := task(); err != nil {
			wp.errOnce.Do(func() {
				wp.firstError = err
				select {
				case wp.errCh <- err:
				default:
				}
			})
		}
	}()

	return true
}

// Wait waits for all workers to complete
func (wp *WorkerPool) Wait() error {
	wp.wg.Wait()
	close(wp.errCh)
	return wp.firstError
}

// WaitWithTimeout waits with a timeout, returning early if timeout expires
func (wp *WorkerPool) WaitWithTimeout(timeout time.Duration) error {
	done := make(chan struct{})
	go func() {
		wp.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		close(wp.errCh)
		return wp.firstError
	case <-time.After(timeout):
		return fmt.Errorf("worker pool timed out after %v", timeout)
	}
}
