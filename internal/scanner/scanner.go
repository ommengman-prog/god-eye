package scanner

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"god-eye/internal/ai"
	"god-eye/internal/config"
	"god-eye/internal/dns"
	gohttp "god-eye/internal/http"
	"god-eye/internal/output"
	"god-eye/internal/progress"
	"god-eye/internal/ratelimit"
	"god-eye/internal/security"
	"god-eye/internal/sources"
	"god-eye/internal/stealth"
)

func Run(cfg config.Config) {
	startTime := time.Now()

	// Pre-load KEV database if AI is enabled (auto-downloads if not present)
	if cfg.EnableAI && !cfg.Silent && !cfg.JsonOutput {
		kevStore := ai.GetKEVStore()
		if !kevStore.IsLoaded() {
			if err := kevStore.LoadWithProgress(true); err != nil {
				fmt.Printf("%s Failed to load KEV database: %v\n", output.Yellow("⚠️"), err)
				fmt.Println(output.Dim("   CVE lookups will use NVD API only (slower)"))
			}
			fmt.Println()
		}
	}

	// Parse custom resolvers and ports using helpers
	resolvers := ParseResolvers(cfg.Resolvers)
	customPorts := ParsePorts(cfg.Ports)

	// Initialize stealth manager
	stealthMode := stealth.ParseMode(cfg.StealthMode)
	stealthMgr := stealth.NewManager(stealthMode)

	// Adjust concurrency based on stealth mode
	effectiveConcurrency := stealthMgr.GetEffectiveConcurrency(cfg.Concurrency)

	if !cfg.Silent && !cfg.JsonOutput {
		output.PrintBanner()
		output.PrintSection("🎯", "TARGET CONFIGURATION")
		output.PrintSubSection(fmt.Sprintf("%s %s", output.Dim("Target:"), output.BoldCyan(cfg.Domain)))

		// Show stealth status
		if stealthMode != stealth.ModeOff {
			stealthColor := output.Yellow
			if stealthMode >= stealth.ModeAggressive {
				stealthColor = output.Red
			}
			output.PrintSubSection(fmt.Sprintf("%s %s  %s %s",
				output.Dim("Stealth:"), stealthColor(stealthMgr.GetModeName()),
				output.Dim("Effective Threads:"), output.BoldGreen(fmt.Sprintf("%d", effectiveConcurrency))))
		}

		output.PrintSubSection(fmt.Sprintf("%s %s  %s %s  %s %s",
			output.Dim("Threads:"), output.BoldGreen(fmt.Sprintf("%d", effectiveConcurrency)),
			output.Dim("Timeout:"), output.Yellow(fmt.Sprintf("%ds", cfg.Timeout)),
			output.Dim("Resolvers:"), output.Blue(fmt.Sprintf("%d", len(resolvers)))))
		if !cfg.NoPorts {
			portStr := ""
			for i, p := range customPorts {
				if i > 0 {
					portStr += ", "
				}
				portStr += fmt.Sprintf("%d", p)
			}
			output.PrintSubSection(fmt.Sprintf("%s %s", output.Dim("Ports:"), output.Magenta(portStr)))
		}
		output.PrintEndSection()
	}

	// Load wordlist
	wordlist := config.DefaultWordlist
	if cfg.Wordlist != "" {
		if wl, err := LoadWordlist(cfg.Wordlist); err == nil {
			wordlist = wl
		} else if cfg.Verbose {
			fmt.Printf("%s Failed to load wordlist: %v\n", output.Red("[-]"), err)
		}
	}

	if !cfg.Silent && !cfg.JsonOutput {
		output.PrintSection("📚", "WORDLIST")
		output.PrintSubSection(fmt.Sprintf("%s %s words loaded", output.BoldGreen(fmt.Sprintf("%d", len(wordlist))), output.Dim("DNS brute-force")))
		output.PrintEndSection()
	}

	// Results storage
	results := make(map[string]*config.SubdomainResult)
	var resultsMu sync.Mutex
	seen := make(map[string]bool)
	var seenMu sync.Mutex

	// Channel for subdomains
	subdomainChan := make(chan string, 10000)

	// Passive sources
	if !cfg.Silent && !cfg.JsonOutput {
		output.PrintSection("🔍", "PASSIVE ENUMERATION")
		output.PrintSubSection(fmt.Sprintf("%s passive sources launching...", output.BoldYellow("20")))
	}

	var sourcesWg sync.WaitGroup
	sourceResults := make(chan config.SourceResult, 100)

	sourceList := []struct {
		name string
		fn   func(string) ([]string, error)
	}{
		// Free sources (no API key required)
		{"crt.sh", sources.FetchCrtsh},
		{"Certspotter", sources.FetchCertspotter},
		{"AlienVault", sources.FetchAlienVault},
		{"HackerTarget", sources.FetchHackerTarget},
		{"URLScan", sources.FetchURLScan},
		{"RapidDNS", sources.FetchRapidDNS},
		{"Anubis", sources.FetchAnubis},
		{"ThreatMiner", sources.FetchThreatMiner},
		{"DNSRepo", sources.FetchDNSRepo},
		{"SubdomainCenter", sources.FetchSubdomainCenter},
		{"Wayback", sources.FetchWayback},
		{"CommonCrawl", sources.FetchCommonCrawl},
		{"Sitedossier", sources.FetchSitedossier},
		{"Riddler", sources.FetchRiddler},
		{"Robtex", sources.FetchRobtex},
		{"DNSHistory", sources.FetchDNSHistory},
		{"ArchiveToday", sources.FetchArchiveToday},
		{"JLDC", sources.FetchJLDC},
		{"SynapsInt", sources.FetchSynapsInt},
		{"CensysFree", sources.FetchCensysFree},
	}

	for _, src := range sourceList {
		sourcesWg.Add(1)
		go func(name string, fn func(string) ([]string, error)) {
			defer sourcesWg.Done()
			subs, err := fn(cfg.Domain)
			sourceResults <- config.SourceResult{Name: name, Subs: subs, Err: err}
		}(src.name, src.fn)
	}

	// Collect source results
	go func() {
		sourcesWg.Wait()
		close(sourceResults)
	}()

	// Process source results
	var processWg sync.WaitGroup
	processWg.Add(1)
	go func() {
		defer processWg.Done()
		for result := range sourceResults {
			if result.Err != nil {
				if cfg.Verbose {
					fmt.Printf("%s %s: %v\n", output.Red("[-]"), result.Name, result.Err)
				}
				continue
			}

			count := 0
			seenMu.Lock()
			for _, sub := range result.Subs {
				sub = strings.ToLower(strings.TrimSpace(sub))
				if sub != "" && !seen[sub] && strings.HasSuffix(sub, cfg.Domain) {
					seen[sub] = true
					subdomainChan <- sub
					count++
				}
			}
			seenMu.Unlock()

			if !cfg.Silent && !cfg.JsonOutput && count > 0 {
				output.PrintSubSection(fmt.Sprintf("%s %s: %s new", output.Green("✓"), output.BoldWhite(result.Name), output.BoldGreen(fmt.Sprintf("%d", count))))
			} else if cfg.Verbose && !cfg.JsonOutput && count == 0 {
				output.PrintSubSection(fmt.Sprintf("%s %s: %s", output.Dim("○"), output.Dim(result.Name), output.Dim("0 results")))
			}
		}
	}()

	// Wildcard detection (always run for JSON output accuracy)
	var wildcardInfo *dns.WildcardInfo
	wildcardDetector := dns.NewWildcardDetector(resolvers, cfg.Timeout)
	wildcardInfo = wildcardDetector.Detect(cfg.Domain)

	// DNS Brute-force
	var bruteWg sync.WaitGroup
	if !cfg.NoBrute {
		// Display wildcard detection results
		if !cfg.Silent && !cfg.JsonOutput {
			if wildcardInfo.IsWildcard {
				output.PrintSubSection(fmt.Sprintf("%s Wildcard DNS: %s (confidence: %.0f%%)",
					output.Yellow("⚠"), output.BoldYellow("DETECTED"), wildcardInfo.Confidence*100))
				if len(wildcardInfo.WildcardIPs) > 0 {
					ips := wildcardInfo.WildcardIPs
					if len(ips) > 3 {
						ips = ips[:3]
					}
					output.PrintSubSection(fmt.Sprintf("  %s Wildcard IPs: %s", output.Dim("→"), output.Yellow(strings.Join(ips, ", "))))
				}
				if wildcardInfo.HTTPStatusCode > 0 {
					output.PrintSubSection(fmt.Sprintf("  %s HTTP response: %d (%d bytes)",
						output.Dim("→"), wildcardInfo.HTTPStatusCode, wildcardInfo.HTTPBodySize))
				}
			} else {
				output.PrintSubSection(fmt.Sprintf("%s Wildcard DNS: %s", output.Green("✓"), output.Green("not detected")))
			}
		}

		// Brute-force with wildcard filtering
		semaphore := make(chan struct{}, effectiveConcurrency)
		wildcardIPSet := make(map[string]bool)
		if wildcardInfo != nil {
			for _, ip := range wildcardInfo.WildcardIPs {
				wildcardIPSet[ip] = true
			}
		}

		// Shuffle wordlist if stealth mode randomization is enabled
		shuffledWordlist := stealthMgr.ShuffleSlice(wordlist)

		for _, word := range shuffledWordlist {
			bruteWg.Add(1)
			go func(word string) {
				defer bruteWg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				// Apply stealth delay
				stealthMgr.Wait()

				subdomain := fmt.Sprintf("%s.%s", word, cfg.Domain)
				ips := dns.ResolveSubdomain(subdomain, resolvers, cfg.Timeout)

				if len(ips) > 0 {
					// Check if ALL IPs are wildcard IPs
					allWildcard := true
					for _, ip := range ips {
						if !wildcardIPSet[ip] {
							allWildcard = false
							break
						}
					}

					// Only add if not all IPs are wildcards
					if !allWildcard || len(wildcardIPSet) == 0 {
						seenMu.Lock()
						if !seen[subdomain] {
							seen[subdomain] = true
							subdomainChan <- subdomain
						}
						seenMu.Unlock()
					}
				}
			}(word)
		}
	}

	// Collect all subdomains in a separate goroutine
	var subdomains []string
	var subdomainsMu sync.Mutex
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for sub := range subdomainChan {
			subdomainsMu.Lock()
			subdomains = append(subdomains, sub)
			subdomainsMu.Unlock()
		}
	}()

	// Wait for sources and brute-force to complete
	processWg.Wait()
	bruteWg.Wait()
	close(subdomainChan)

	// Wait for collection to complete
	collectWg.Wait()

	// Resolve all subdomains
	if !cfg.Silent && !cfg.JsonOutput {
		output.PrintEndSection()
		output.PrintSection("🌐", "DNS RESOLUTION")
	}

	// Create progress bar for DNS resolution
	dnsBar := progress.New(len(subdomains), "DNS", cfg.Silent || cfg.JsonOutput)

	var resolveWg sync.WaitGroup
	dnsSemaphore := make(chan struct{}, effectiveConcurrency)

	for _, subdomain := range subdomains {
		resolveWg.Add(1)
		go func(sub string) {
			defer resolveWg.Done()
			defer dnsBar.Increment()
			dnsSemaphore <- struct{}{}
			defer func() { <-dnsSemaphore }()

			// Apply stealth delay for DNS
			stealthMgr.Wait()

			ips := dns.ResolveSubdomain(sub, resolvers, cfg.Timeout)
			if len(ips) > 0 {
				cname := dns.ResolveCNAME(sub, resolvers, cfg.Timeout)
				ptr := dns.ResolvePTR(ips[0], resolvers, cfg.Timeout)

				// Get IP info (ASN, Org, Country, City)
				var asn, org, country, city string
				if ipInfo, err := dns.GetIPInfo(ips[0]); err == nil && ipInfo != nil {
					asn = ipInfo.ASN
					org = ipInfo.Org
					country = ipInfo.Country
					city = ipInfo.City
				}

				// Get MX/TXT/NS records for the subdomain
				mx := dns.ResolveMX(sub, resolvers, cfg.Timeout)
				txt := dns.ResolveTXT(sub, resolvers, cfg.Timeout)
				ns := dns.ResolveNS(sub, resolvers, cfg.Timeout)

				// Detect cloud provider
				cloudProvider := DetectCloudProvider(ips, cname, asn)

				// Check email security (only once, for the target domain)
				// SPF/DMARC records are always on the root domain, so we check cfg.Domain
				var spfRecord, dmarcRecord, emailSecurity string
				if sub == cfg.Domain {
					spfRecord, dmarcRecord, emailSecurity = CheckEmailSecurity(cfg.Domain, resolvers, cfg.Timeout)
				}

				resultsMu.Lock()
				results[sub] = &config.SubdomainResult{
					Subdomain:     sub,
					IPs:           ips,
					CNAME:         cname,
					PTR:           ptr,
					ASN:           asn,
					Org:           org,
					Country:       country,
					City:          city,
					MXRecords:     mx,
					TXTRecords:    txt,
					NSRecords:     ns,
					CloudProvider: cloudProvider,
					SPFRecord:     spfRecord,
					DMARCRecord:   dmarcRecord,
					EmailSecurity: emailSecurity,
				}
				resultsMu.Unlock()
			}
		}(subdomain)
	}
	resolveWg.Wait()
	dnsBar.Finish()

	// HTTP Probing
	if !cfg.NoProbe && len(results) > 0 {
		if !cfg.Silent && !cfg.JsonOutput {
			output.PrintEndSection()
			output.PrintSection("🌍", "HTTP PROBING & SECURITY CHECKS")
		}

		// Create progress bar and rate limiter for HTTP probing
		httpBar := progress.New(len(results), "HTTP", cfg.Silent || cfg.JsonOutput)
		httpLimiter := ratelimit.NewHostRateLimiter(ratelimit.DefaultConfig())
		httpSemaphore := make(chan struct{}, effectiveConcurrency)

		var probeWg sync.WaitGroup
		for sub := range results {
			probeWg.Add(1)
			go func(subdomain string) {
				defer probeWg.Done()
				defer httpBar.Increment()
				httpSemaphore <- struct{}{}
				defer func() { <-httpSemaphore }()

				// Apply stealth delay and host-specific throttling
				stealthMgr.Wait()
				stealthMgr.WaitForHost(subdomain)

				// Apply adaptive rate limiting
				limiter := httpLimiter.Get(subdomain)
				limiter.Wait()

				// Use shared client for connection pooling
				client := gohttp.GetSharedClient(cfg.Timeout)

				// Primary HTTP probe
				result := gohttp.ProbeHTTP(subdomain, cfg.Timeout)

				// Run all HTTP checks in parallel using goroutines
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

				// Wait for all checks to complete
				checkWg.Wait()

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
			}(sub)
		}
		probeWg.Wait()
		httpBar.Finish()

		// Log rate limiting stats if verbose
		if cfg.Verbose && !cfg.JsonOutput {
			hosts, requests, errors := httpLimiter.GetStats()
			if errors > 0 {
				output.PrintSubSection(fmt.Sprintf("%s Rate limiting: %d hosts, %d requests, %d errors",
					output.Yellow("⚠️"), hosts, requests, errors))
			}
		}
	}

	// Port Scanning
	if !cfg.NoPorts && len(results) > 0 {
		if !cfg.Silent && !cfg.JsonOutput {
			output.PrintEndSection()
			output.PrintSection("🔌", "PORT SCANNING")
		}

		// Count hosts with IPs
		hostCount := 0
		for _, result := range results {
			if len(result.IPs) > 0 {
				hostCount++
			}
		}

		portBar := progress.New(hostCount, "Ports", cfg.Silent || cfg.JsonOutput)
		var portWg sync.WaitGroup

		for sub, result := range results {
			if len(result.IPs) == 0 {
				continue
			}
			portWg.Add(1)
			go func(subdomain string, ip string) {
				defer portWg.Done()
				defer portBar.Increment()
				openPorts := ScanPorts(ip, customPorts, cfg.Timeout)
				resultsMu.Lock()
				if r, ok := results[subdomain]; ok {
					r.Ports = openPorts
				}
				resultsMu.Unlock()
			}(sub, result.IPs[0])
		}
		portWg.Wait()
		portBar.Finish()
	}

	// Subdomain Takeover Check
	var takeoverCount int32
	if !cfg.NoTakeover && len(results) > 0 {
		if !cfg.Silent && !cfg.JsonOutput {
			output.PrintEndSection()
			output.PrintSection("🎯", "SUBDOMAIN TAKEOVER")
		}

		takeoverBar := progress.New(len(results), "Takeover", cfg.Silent || cfg.JsonOutput)
		var takeoverWg sync.WaitGroup
		for sub := range results {
			takeoverWg.Add(1)
			go func(subdomain string) {
				defer takeoverWg.Done()
				defer takeoverBar.Increment()
				if takeover := CheckTakeover(subdomain, cfg.Timeout); takeover != "" {
					resultsMu.Lock()
					if r, ok := results[subdomain]; ok {
						r.Takeover = takeover
					}
					resultsMu.Unlock()
					atomic.AddInt32(&takeoverCount, 1)
				}
			}(sub)
		}
		takeoverWg.Wait()
		takeoverBar.Finish()

		if takeoverCount > 0 && !cfg.Silent && !cfg.JsonOutput {
			output.PrintSubSection(fmt.Sprintf("%s Found %s potential takeover(s)!", output.Red("⚠"), output.BoldRed(fmt.Sprintf("%d", takeoverCount))))
		}
		if !cfg.Silent && !cfg.JsonOutput {
			output.PrintEndSection()
		}
	}

	// AI-Powered Analysis
	var aiClient *ai.OllamaClient
	var aiFindings int32
	if cfg.EnableAI && len(results) > 0 {
		aiClient = ai.NewOllamaClient(cfg.AIUrl, cfg.AIFastModel, cfg.AIDeepModel, cfg.AICascade)

		// Check if Ollama is available
		if !aiClient.IsAvailable() {
			if cfg.Verbose && !cfg.JsonOutput {
				fmt.Printf("%s Ollama is not available at %s. Skipping AI analysis.\n", output.Yellow("⚠"), cfg.AIUrl)
				fmt.Printf("%s Run: ollama serve\n", output.Dim("→"))
			}
		} else {
			if !cfg.Silent && !cfg.JsonOutput {
				output.PrintEndSection()
				output.PrintSection("🧠", "AI-POWERED ANALYSIS")
				cascadeStr := ""
				if cfg.AICascade {
					cascadeStr = fmt.Sprintf(" (cascade: %s + %s)", cfg.AIFastModel, cfg.AIDeepModel)
				} else {
					cascadeStr = fmt.Sprintf(" (model: %s)", cfg.AIDeepModel)
				}
				output.PrintSubSection(fmt.Sprintf("Analyzing findings with local LLM%s", output.Dim(cascadeStr)))
			}

			var aiWg sync.WaitGroup
			aiSemaphore := make(chan struct{}, 5) // Limit concurrent AI requests

			for sub, result := range results {
				// Determine what types of analysis to perform
				shouldAnalyzeVulns := false
				shouldAnalyzeCVE := len(result.Tech) > 0 // CVE for ALL subdomains with tech

				// Analyze JS files if found
				if len(result.JSFiles) > 0 || len(result.JSSecrets) > 0 {
					shouldAnalyzeVulns = true
				}

				// Analyze if vulnerabilities detected
				if result.OpenRedirect || result.CORSMisconfig != "" ||
				   len(result.DangerousMethods) > 0 || result.GitExposed ||
				   result.SvnExposed || len(result.BackupFiles) > 0 {
					shouldAnalyzeVulns = true
				}

				// Analyze takeovers
				if result.Takeover != "" {
					shouldAnalyzeVulns = true
				}

				// Deep analysis mode: analyze everything
				if cfg.AIDeepAnalysis {
					shouldAnalyzeVulns = true
				}

				// Skip if nothing to analyze
				if !shouldAnalyzeVulns && !shouldAnalyzeCVE {
					continue
				}

				analyzeVulns := shouldAnalyzeVulns // Capture for goroutine
				aiWg.Add(1)
				go func(subdomain string, r *config.SubdomainResult, doVulnAnalysis bool) {
					defer aiWg.Done()
					aiSemaphore <- struct{}{}
					defer func() { <-aiSemaphore }()

					var aiResults []*ai.AnalysisResult

					// Filter JS secrets using AI before analysis
					if len(r.JSSecrets) > 0 {
						if filteredSecrets, err := aiClient.FilterSecrets(r.JSSecrets); err == nil && len(filteredSecrets) > 0 {
							resultsMu.Lock()
							r.JSSecrets = filteredSecrets // Replace with AI-filtered secrets
							resultsMu.Unlock()
						} else if err == nil {
							// No real secrets found after filtering
							resultsMu.Lock()
							r.JSSecrets = nil
							resultsMu.Unlock()
						}
					}

					// Analyze JavaScript if present (only if vuln analysis enabled)
					if doVulnAnalysis && len(r.JSFiles) > 0 && len(r.JSSecrets) > 0 {
						// Build context from secrets
						jsContext := strings.Join(r.JSSecrets, "\n")
						if analysis, err := aiClient.AnalyzeJavaScript(jsContext); err == nil {
							aiResults = append(aiResults, analysis)
						}
					}

					// Analyze HTTP response for misconfigurations (only if vuln analysis enabled)
					if doVulnAnalysis && r.StatusCode > 0 && (len(r.MissingHeaders) > 3 || r.GitExposed || r.SvnExposed) {
						bodyContext := r.Title
						if analysis, err := aiClient.AnalyzeHTTPResponse(subdomain, r.StatusCode, r.Headers, bodyContext); err == nil {
							aiResults = append(aiResults, analysis)
						}
					}

					// CVE matching for detected technologies (always done if tech detected)
					if len(r.Tech) > 0 {
						for _, tech := range r.Tech {
							if cve, err := aiClient.CVEMatch(tech, ""); err == nil && cve != "" {
								resultsMu.Lock()
								r.CVEFindings = append(r.CVEFindings, fmt.Sprintf("%s: %s", tech, cve))
								resultsMu.Unlock()
							}
						}
					}

					// Aggregate findings
					resultsMu.Lock()
					defer resultsMu.Unlock()

					highestSeverity := "info"
					for _, analysis := range aiResults {
						for _, finding := range analysis.Findings {
							finding = strings.TrimSpace(finding)
							if finding != "" && !strings.HasPrefix(finding, "Skipped") && !strings.HasPrefix(finding, "Normal") {
								r.AIFindings = append(r.AIFindings, finding)
								atomic.AddInt32(&aiFindings, 1)
							}
						}

						// Track highest severity
						severities := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
						if severities[analysis.Severity] > severities[highestSeverity] {
							highestSeverity = analysis.Severity
						}
					}

					if len(r.AIFindings) > 0 {
						r.AISeverity = highestSeverity
						if cfg.AICascade {
							r.AIModel = fmt.Sprintf("%s→%s", cfg.AIFastModel, cfg.AIDeepModel)
						} else {
							r.AIModel = cfg.AIDeepModel
						}

						if !cfg.JsonOutput && !cfg.Silent {
							severityColor := output.Blue
							if highestSeverity == "critical" {
								severityColor = output.BgRed
							} else if highestSeverity == "high" {
								severityColor = output.Red
							} else if highestSeverity == "medium" {
								severityColor = output.Yellow
							}

							output.PrintSubSection(fmt.Sprintf("%s %s → %s",
								severityColor(fmt.Sprintf(" AI:%s ", strings.ToUpper(highestSeverity[:1]))),
								output.BoldWhite(subdomain),
								output.Dim(fmt.Sprintf("%d findings", len(r.AIFindings)))))
						}
					}
				}(sub, result, analyzeVulns)
			}

			aiWg.Wait()

			// Generate summary report
			if aiFindings > 0 && !cfg.JsonOutput {
				output.PrintSubSection(fmt.Sprintf("%s AI analysis complete: %s findings across %s subdomains",
					output.Green("✓"),
					output.BoldGreen(fmt.Sprintf("%d", aiFindings)),
					output.BoldCyan(fmt.Sprintf("%d", countSubdomainsWithAI(results)))))

				// Generate executive report
				summary := buildAISummary(results)
				stats := map[string]int{
					"total":     len(results),
					"active":    countActive(results),
					"vulns":     countVulns(results),
					"takeovers": int(takeoverCount),
				}

				if report, err := aiClient.GenerateReport(summary, stats); err == nil {
					if !cfg.Silent {
						output.PrintEndSection()
						output.PrintSection("📋", "AI SECURITY REPORT")
						fmt.Println(report)
					}
				}
			}

			if !cfg.Silent && !cfg.JsonOutput {
				output.PrintEndSection()
			}
		}
	}

	// Filter active only if requested
	if cfg.OnlyActive {
		filtered := make(map[string]*config.SubdomainResult)
		for sub, r := range results {
			if r.StatusCode >= 200 && r.StatusCode < 400 {
				filtered[sub] = r
			}
		}
		results = filtered
	}

	// JSON output to stdout (structured report format)
	if cfg.JsonOutput {
		// Build structured JSON report with metadata
		reportBuilder := output.NewReportBuilder(cfg.Domain, cfg)

		// Set wildcard info if available
		if wildcardInfo != nil {
			reportBuilder.SetWildcard(
				wildcardInfo.IsWildcard,
				wildcardInfo.WildcardIPs,
				wildcardInfo.WildcardCNAME,
				wildcardInfo.HTTPStatusCode,
				wildcardInfo.Confidence,
			)
		}

		// Finalize and output the report
		reportBuilder.Finalize(results)
		reportBuilder.WriteJSON(os.Stdout, true)
		return
	}

	// Print results using output module
	PrintResults(results, startTime, takeoverCount)

	// Save output
	if cfg.Output != "" {
		output.SaveOutput(cfg.Output, cfg.Format, results)
	}
}
