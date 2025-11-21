package progress

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"god-eye/internal/output"
)

// Bar represents a progress bar
type Bar struct {
	total      int64
	current    int64
	width      int
	prefix     string
	startTime  time.Time
	lastUpdate time.Time
	mu         sync.Mutex
	done       bool
	silent     bool
}

// New creates a new progress bar
func New(total int, prefix string, silent bool) *Bar {
	return &Bar{
		total:     int64(total),
		current:   0,
		width:     40,
		prefix:    prefix,
		startTime: time.Now(),
		silent:    silent,
	}
}

// Increment increases the progress by 1
func (b *Bar) Increment() {
	atomic.AddInt64(&b.current, 1)
	b.render()
}

// Add increases the progress by n
func (b *Bar) Add(n int) {
	atomic.AddInt64(&b.current, int64(n))
	b.render()
}

// SetCurrent sets the current progress value
func (b *Bar) SetCurrent(n int) {
	atomic.StoreInt64(&b.current, int64(n))
	b.render()
}

// render displays the progress bar
func (b *Bar) render() {
	if b.silent {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Throttle updates to avoid flickering (max 10 updates/sec)
	if time.Since(b.lastUpdate) < 100*time.Millisecond && !b.done {
		return
	}
	b.lastUpdate = time.Now()

	current := atomic.LoadInt64(&b.current)
	total := b.total

	// Calculate percentage
	var percent float64
	if total > 0 {
		percent = float64(current) / float64(total) * 100
	}

	// Calculate filled width
	filled := int(float64(b.width) * percent / 100)
	if filled > b.width {
		filled = b.width
	}

	// Build progress bar
	bar := strings.Repeat("█", filled) + strings.Repeat("░", b.width-filled)

	// Calculate ETA
	elapsed := time.Since(b.startTime)
	var eta string
	if current > 0 && current < total {
		remaining := time.Duration(float64(elapsed) / float64(current) * float64(total-current))
		eta = formatDuration(remaining)
	} else if current >= total {
		eta = "done"
	} else {
		eta = "..."
	}

	// Calculate speed
	var speed float64
	if elapsed.Seconds() > 0 {
		speed = float64(current) / elapsed.Seconds()
	}

	// Print progress bar (overwrite line with \r) - clean style without box characters
	fmt.Printf("\r    %s [%s] %s/%s %.0f%% %s ETA %s    ",
		b.prefix,
		output.Green(bar),
		output.BoldWhite(fmt.Sprintf("%d", current)),
		output.Dim(fmt.Sprintf("%d", total)),
		percent,
		output.Dim(fmt.Sprintf("%.0f/s", speed)),
		output.Dim(eta),
	)
}

// Finish completes the progress bar
func (b *Bar) Finish() {
	if b.silent {
		return
	}

	b.mu.Lock()
	b.done = true
	b.mu.Unlock()

	current := atomic.LoadInt64(&b.current)
	elapsed := time.Since(b.startTime)

	// Clear the line and print final status - clean style
	fmt.Printf("\r    %s %s %s completed in %s                              \n",
		output.Green("✓"),
		output.BoldWhite(fmt.Sprintf("%d", current)),
		b.prefix,
		output.Green(formatDuration(elapsed)),
	)
}

// FinishWithMessage completes with a custom message
func (b *Bar) FinishWithMessage(msg string) {
	if b.silent {
		return
	}

	b.mu.Lock()
	b.done = true
	b.mu.Unlock()

	// Clear the line and print message - clean style
	fmt.Printf("\r    %s %s                                    \n",
		output.Green("✓"),
		msg,
	)
}

// formatDuration formats a duration nicely
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return "<1s"
	} else if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	} else if d < time.Hour {
		mins := int(d.Minutes())
		secs := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm%ds", mins, secs)
	}
	hours := int(d.Hours())
	mins := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh%dm", hours, mins)
}

// MultiBar manages multiple progress bars
type MultiBar struct {
	bars   []*Bar
	mu     sync.Mutex
	silent bool
}

// NewMulti creates a new multi-bar manager
func NewMulti(silent bool) *MultiBar {
	return &MultiBar{
		bars:   make([]*Bar, 0),
		silent: silent,
	}
}

// AddBar adds a new progress bar
func (m *MultiBar) AddBar(total int, prefix string) *Bar {
	m.mu.Lock()
	defer m.mu.Unlock()

	bar := New(total, prefix, m.silent)
	m.bars = append(m.bars, bar)
	return bar
}
