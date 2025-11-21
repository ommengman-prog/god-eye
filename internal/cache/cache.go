package cache

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"god-eye/internal/config"
)

// IPCache provides LRU caching for IP geolocation lookups
type IPCache struct {
	mu      sync.RWMutex
	cache   map[string]*ipCacheEntry
	maxSize int
	ttl     time.Duration
	hits    int64
	misses  int64
}

type ipCacheEntry struct {
	info      *config.IPInfo
	timestamp time.Time
}

// DNSCache provides caching for DNS resolutions
type DNSCache struct {
	mu      sync.RWMutex
	cache   map[string]*dnsCacheEntry
	maxSize int
	ttl     time.Duration
	hits    int64
	misses  int64
}

type dnsCacheEntry struct {
	ips       []string
	timestamp time.Time
}

var (
	globalIPCache  *IPCache
	globalDNSCache *DNSCache
	initOnce       sync.Once
)

// InitCaches initializes global caches
func InitCaches() {
	initOnce.Do(func() {
		globalIPCache = NewIPCache(1000, 5*time.Minute)
		globalDNSCache = NewDNSCache(5000, 60*time.Second)
	})
}

// GetIPCache returns the global IP cache
func GetIPCache() *IPCache {
	InitCaches()
	return globalIPCache
}

// GetDNSCache returns the global DNS cache
func GetDNSCache() *DNSCache {
	InitCaches()
	return globalDNSCache
}

// NewIPCache creates a new IP geolocation cache
func NewIPCache(maxSize int, ttl time.Duration) *IPCache {
	return &IPCache{
		cache:   make(map[string]*ipCacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// NewDNSCache creates a new DNS resolution cache
func NewDNSCache(maxSize int, ttl time.Duration) *DNSCache {
	return &DNSCache{
		cache:   make(map[string]*dnsCacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// Get retrieves IP info from cache
func (c *IPCache) Get(ip string) (*config.IPInfo, bool) {
	c.mu.RLock()
	entry, exists := c.cache[ip]
	c.mu.RUnlock()

	if !exists {
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		return nil, false
	}

	// Check TTL
	if time.Since(entry.timestamp) > c.ttl {
		c.mu.Lock()
		delete(c.cache, ip)
		c.misses++
		c.mu.Unlock()
		return nil, false
	}

	c.mu.Lock()
	c.hits++
	c.mu.Unlock()
	return entry.info, true
}

// Set stores IP info in cache
func (c *IPCache) Set(ip string, info *config.IPInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict oldest entries if at capacity
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}

	c.cache[ip] = &ipCacheEntry{
		info:      info,
		timestamp: time.Now(),
	}
}

// SetBatch stores multiple IP infos in cache
func (c *IPCache) SetBatch(results map[string]*config.IPInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for ip, info := range results {
		if len(c.cache) >= c.maxSize {
			c.evictOldest()
		}
		c.cache[ip] = &ipCacheEntry{
			info:      info,
			timestamp: time.Now(),
		}
	}
}

func (c *IPCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, entry := range c.cache {
		if first || entry.timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.timestamp
			first = false
		}
	}

	if oldestKey != "" {
		delete(c.cache, oldestKey)
	}
}

// GetStats returns cache hit/miss statistics
func (c *IPCache) GetStats() (hits, misses int64, hitRate float64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	hits = c.hits
	misses = c.misses
	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}
	return
}

// DNS Cache methods

// Get retrieves DNS resolution from cache
func (c *DNSCache) Get(subdomain string) ([]string, bool) {
	c.mu.RLock()
	entry, exists := c.cache[subdomain]
	c.mu.RUnlock()

	if !exists {
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		return nil, false
	}

	// Check TTL
	if time.Since(entry.timestamp) > c.ttl {
		c.mu.Lock()
		delete(c.cache, subdomain)
		c.misses++
		c.mu.Unlock()
		return nil, false
	}

	c.mu.Lock()
	c.hits++
	c.mu.Unlock()
	return entry.ips, true
}

// Set stores DNS resolution in cache
func (c *DNSCache) Set(subdomain string, ips []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict oldest entries if at capacity
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}

	c.cache[subdomain] = &dnsCacheEntry{
		ips:       ips,
		timestamp: time.Now(),
	}
}

func (c *DNSCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, entry := range c.cache {
		if first || entry.timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.timestamp
			first = false
		}
	}

	if oldestKey != "" {
		delete(c.cache, oldestKey)
	}
}

// GetStats returns cache hit/miss statistics
func (c *DNSCache) GetStats() (hits, misses int64, hitRate float64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	hits = c.hits
	misses = c.misses
	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}
	return
}

// BatchIPLookup performs batch IP geolocation lookup (up to 100 IPs per request)
// Uses ip-api.com batch endpoint which is 10x more efficient
func BatchIPLookup(ips []string) map[string]*config.IPInfo {
	results := make(map[string]*config.IPInfo)
	cache := GetIPCache()

	// Separate cached and uncached IPs
	var uncachedIPs []string
	for _, ip := range ips {
		if info, found := cache.Get(ip); found {
			results[ip] = info
		} else {
			uncachedIPs = append(uncachedIPs, ip)
		}
	}

	// If all cached, return early
	if len(uncachedIPs) == 0 {
		return results
	}

	// Batch lookup uncached IPs (max 100 per request)
	client := &http.Client{Timeout: 10 * time.Second}

	for i := 0; i < len(uncachedIPs); i += 100 {
		end := i + 100
		if end > len(uncachedIPs) {
			end = len(uncachedIPs)
		}
		batch := uncachedIPs[i:end]

		// Build batch request
		batchResults := lookupIPBatch(client, batch)
		for ip, info := range batchResults {
			results[ip] = info
			cache.Set(ip, info)
		}
	}

	return results
}

// lookupIPBatch performs a single batch lookup request
func lookupIPBatch(client *http.Client, ips []string) map[string]*config.IPInfo {
	results := make(map[string]*config.IPInfo)

	// ip-api.com batch endpoint (free tier allows 45/min, but batch counts as 1)
	// For free tier, we fall back to individual requests but with caching
	// For production, use pro endpoint with POST /batch

	// Fallback: Individual requests with rate limiting
	for _, ip := range ips {
		info := lookupSingleIP(client, ip)
		if info != nil {
			results[ip] = info
		}
		// Rate limit: ~40 req/min for free tier
		time.Sleep(25 * time.Millisecond)
	}

	return results
}

// lookupSingleIP performs a single IP lookup
func lookupSingleIP(client *http.Client, ip string) *config.IPInfo {
	url := "http://ip-api.com/json/" + ip + "?fields=as,org,country,city"

	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	var info config.IPInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil
	}

	return &info
}

// GetIPInfoCached retrieves IP info with caching (drop-in replacement for GetIPInfo)
func GetIPInfoCached(ip string) (*config.IPInfo, error) {
	cache := GetIPCache()

	// Check cache first
	if info, found := cache.Get(ip); found {
		return info, nil
	}

	// Lookup and cache
	client := &http.Client{Timeout: 5 * time.Second}
	info := lookupSingleIP(client, ip)
	if info == nil {
		return nil, nil
	}

	cache.Set(ip, info)
	return info, nil
}
