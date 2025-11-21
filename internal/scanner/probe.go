package scanner

import (
	"context"
	"sync"

	"god-eye/internal/config"
	gohttp "god-eye/internal/http"
	"god-eye/internal/progress"
	"god-eye/internal/ratelimit"
	"god-eye/internal/security"
	"god-eye/internal/stealth"
)

// ProbeConfig contains configuration for HTTP probing
type ProbeConfig struct {
	Timeout     int
	Concurrency int
	Silent      bool
	JsonOutput  bool
	Verbose     bool
}

// ProbeResults contains the results from HTTP probing
type ProbeResults struct {
	RateLimitStats struct {
		Hosts    int
		Requests int
		Errors   int
	}
}

// RunHTTPProbe performs HTTP probing on all resolved subdomains
func RunHTTPProbe(ctx context.Context, results map[string]*config.SubdomainResult,
	resultsMu *sync.Mutex, cfg ProbeConfig, stealthMgr *stealth.Manager) *ProbeResults {

	if len(results) == 0 {
		return &ProbeResults{}
	}

	probeResults := &ProbeResults{}

	// Create progress bar and rate limiter
	httpBar := progress.New(len(results), "HTTP", cfg.Silent || cfg.JsonOutput)
	httpLimiter := ratelimit.NewHostRateLimiter(ratelimit.DefaultConfig())
	pool := NewWorkerPool(ctx, cfg.Concurrency)

	for sub := range results {
		subdomain := sub // capture for closure
		pool.Submit(func() error {
			// Check context cancellation
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			defer httpBar.Increment()

			// Apply stealth delays
			if stealthMgr != nil {
				stealthMgr.Wait()
				stealthMgr.WaitForHost(subdomain)
			}

			// Apply adaptive rate limiting
			limiter := httpLimiter.Get(subdomain)
			limiter.Wait()

			// Use shared client
			client := gohttp.GetSharedClient(cfg.Timeout)

			// Primary HTTP probe
			result := gohttp.ProbeHTTP(subdomain, cfg.Timeout)

			// Run all HTTP checks in parallel
			var checkWg sync.WaitGroup
			var checkMu sync.Mutex

			var robotsTxt, sitemapXml bool
			var faviconHash string
			var openRedirect bool
			var corsMisconfig string
			var allowedMethods, dangerousMethods []string
			var adminPanels, backupFiles, apiEndpoints []string
			var gitExposed, svnExposed bool
			var s3Buckets, tlsAltNames []string
			var jsFiles, jsSecrets []string

			// Check robots.txt
			checkWg.Add(1)
			go func() {
				defer checkWg.Done()
				r := CheckRobotsTxtWithClient(subdomain, client)
				checkMu.Lock()
				robotsTxt = r
				checkMu.Unlock()
			}()

			// Check sitemap.xml
			checkWg.Add(1)
			go func() {
				defer checkWg.Done()
				s := CheckSitemapXmlWithClient(subdomain, client)
				checkMu.Lock()
				sitemapXml = s
				checkMu.Unlock()
			}()

			// Check favicon
			checkWg.Add(1)
			go func() {
				defer checkWg.Done()
				f := GetFaviconHashWithClient(subdomain, client)
				checkMu.Lock()
				faviconHash = f
				checkMu.Unlock()
			}()

			// Check open redirect
			checkWg.Add(1)
			go func() {
				defer checkWg.Done()
				o := security.CheckOpenRedirectWithClient(subdomain, client)
				checkMu.Lock()
				openRedirect = o
				checkMu.Unlock()
			}()

			// Check CORS
			checkWg.Add(1)
			go func() {
				defer checkWg.Done()
				c := security.CheckCORSWithClient(subdomain, client)
				checkMu.Lock()
				corsMisconfig = c
				checkMu.Unlock()
			}()

			// Check HTTP methods
			checkWg.Add(1)
			go func() {
				defer checkWg.Done()
				a, d := security.CheckHTTPMethodsWithClient(subdomain, client)
				checkMu.Lock()
				allowedMethods = a
				dangerousMethods = d
				checkMu.Unlock()
			}()

			// Check admin panels
			checkWg.Add(1)
			go func() {
				defer checkWg.Done()
				p := security.CheckAdminPanelsWithClient(subdomain, client)
				checkMu.Lock()
				adminPanels = p
				checkMu.Unlock()
			}()

			// Check Git/SVN exposure
			checkWg.Add(1)
			go func() {
				defer checkWg.Done()
				g, s := security.CheckGitSvnExposureWithClient(subdomain, client)
				checkMu.Lock()
				gitExposed = g
				svnExposed = s
				checkMu.Unlock()
			}()

			// Check backup files
			checkWg.Add(1)
			go func() {
				defer checkWg.Done()
				b := security.CheckBackupFilesWithClient(subdomain, client)
				checkMu.Lock()
				backupFiles = b
				checkMu.Unlock()
			}()

			// Check API endpoints
			checkWg.Add(1)
			go func() {
				defer checkWg.Done()
				e := security.CheckAPIEndpointsWithClient(subdomain, client)
				checkMu.Lock()
				apiEndpoints = e
				checkMu.Unlock()
			}()

			// Check S3 buckets
			checkWg.Add(1)
			go func() {
				defer checkWg.Done()
				b := CheckS3BucketsWithClient(subdomain, client)
				checkMu.Lock()
				s3Buckets = b
				checkMu.Unlock()
			}()

			// Get TLS alt names
			checkWg.Add(1)
			go func() {
				defer checkWg.Done()
				t := GetTLSAltNames(subdomain, cfg.Timeout)
				checkMu.Lock()
				tlsAltNames = t
				checkMu.Unlock()
			}()

			// Analyze JavaScript files
			checkWg.Add(1)
			go func() {
				defer checkWg.Done()
				f, s := AnalyzeJSFiles(subdomain, client)
				checkMu.Lock()
				jsFiles = f
				jsSecrets = s
				checkMu.Unlock()
			}()

			// Wait for all checks
			checkWg.Wait()

			// Update results
			resultsMu.Lock()
			if r, ok := results[subdomain]; ok {
				r.StatusCode = result.StatusCode
				r.ContentLength = result.ContentLength
				r.RedirectURL = result.RedirectURL
				r.Title = result.Title
				r.Server = result.Server
				r.Tech = result.Tech
				r.Headers = result.Headers
				r.WAF = result.WAF
				r.TLSVersion = result.TLSVersion
				r.TLSIssuer = result.TLSIssuer
				r.TLSExpiry = result.TLSExpiry
				r.ResponseMs = result.ResponseMs
				r.RobotsTxt = robotsTxt
				r.SitemapXml = sitemapXml
				r.FaviconHash = faviconHash
				r.SecurityHeaders = result.SecurityHeaders
				r.MissingHeaders = result.MissingHeaders
				r.OpenRedirect = openRedirect
				r.CORSMisconfig = corsMisconfig
				r.AllowedMethods = allowedMethods
				r.DangerousMethods = dangerousMethods
				r.AdminPanels = adminPanels
				r.GitExposed = gitExposed
				r.S3Buckets = s3Buckets
				r.TLSAltNames = tlsAltNames
				r.SvnExposed = svnExposed
				r.BackupFiles = backupFiles
				r.APIEndpoints = apiEndpoints
				r.JSFiles = jsFiles
				r.JSSecrets = jsSecrets
			}
			resultsMu.Unlock()

			return nil
		})
	}

	pool.Wait()
	httpBar.Finish()

	// Collect rate limiting stats
	h, r, e := httpLimiter.GetStats()
	probeResults.RateLimitStats.Hosts = int(h)
	probeResults.RateLimitStats.Requests = int(r)
	probeResults.RateLimitStats.Errors = int(e)

	return probeResults
}
