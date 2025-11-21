package scanner

import (
	"context"
	"strings"
	"sync"

	"god-eye/internal/api"
	"god-eye/internal/cloud"
	"god-eye/internal/config"
	"god-eye/internal/fingerprint"
	"god-eye/internal/network"
	"god-eye/internal/output"
	"god-eye/internal/progress"
	"god-eye/internal/secrets"
)

// AdvancedConfig holds configuration for advanced scanning
type AdvancedConfig struct {
	Domain      string
	Timeout     int
	Concurrency int
	CloudScan   bool
	APIScan     bool
	SecretsScan bool
	TechScan    bool
	ASNScan     bool
	VHostScan   bool
	Silent      bool
	JsonOutput  bool
}

// AdvancedResults holds results from advanced scanning
type AdvancedResults struct {
	CloudAssets  []cloud.CloudAsset
	APIFindings  []api.APIFinding
	Secrets      []secrets.SecretFinding
	Technologies map[string][]fingerprint.Technology // host -> technologies
	ASNInfo      map[string]*network.ASNInfo         // ip -> ASN info
	VHosts       map[string]*network.VHostResult     // ip -> virtual hosts
}

// RunAdvancedScans performs cloud, API, and secrets scanning (sequential for ordered output)
func RunAdvancedScans(ctx context.Context, results map[string]*config.SubdomainResult,
	resultsMu *sync.Mutex, cfg AdvancedConfig) *AdvancedResults {

	advResults := &AdvancedResults{}

	// 1. Cloud Asset Discovery (first)
	if cfg.CloudScan {
		if !cfg.Silent && !cfg.JsonOutput {
			output.PrintEndSection()
			output.PrintSection("☁️", "CLOUD ASSET DISCOVERY")
		}

		cloudScanner := cloud.NewCloudScanner(cfg.Domain, cfg.Timeout)
		assets := cloudScanner.ScanAll(ctx)

		// Also check for Lambda/Cloud Functions
		lambdaAssets := cloudScanner.CheckLambdaEndpoints(ctx)
		assets = append(assets, lambdaAssets...)
		advResults.CloudAssets = assets

		if !cfg.Silent && !cfg.JsonOutput {
			publicCount := 0
			privateCount := 0
			for _, asset := range assets {
				if asset.Status == "public" {
					publicCount++
				} else if asset.Status == "private" {
					privateCount++
				}
			}

			if len(assets) > 0 {
				output.PrintSubSection(output.Green("✓") + " Found " +
					output.BoldRed(intToString(publicCount)) + " public, " +
					output.BoldYellow(intToString(privateCount)) + " private cloud assets")

				// Show top findings
				shown := 0
				for _, asset := range assets {
					if shown >= 5 {
						break
					}
					if asset.Status == "public" {
						output.PrintSubSection("  " + output.Red("⚠ ") +
							output.BoldWhite(asset.Type) + " " +
							output.Cyan(asset.Name) + " - " +
							output.Red("PUBLIC"))
						shown++
					}
				}
			} else {
				output.PrintSubSection(output.Dim("No public cloud assets found"))
			}
		}
	}

	// 2. API Intelligence (second)
	if cfg.APIScan {
		if !cfg.Silent && !cfg.JsonOutput {
			output.PrintEndSection()
			output.PrintSection("🔌", "API INTELLIGENCE")
		}

		apiScanner := api.NewAPIScanner(cfg.Timeout)

		// Scan each active subdomain
		resultsMu.Lock()
		hosts := make([]string, 0)
		for sub, result := range results {
			if result.StatusCode >= 200 && result.StatusCode < 500 {
				hosts = append(hosts, sub)
			}
		}
		resultsMu.Unlock()

		var allFindings []api.APIFinding
		var findingsMu sync.Mutex

		// Limit concurrent API scans
		sem := make(chan struct{}, 5)
		var apiWg sync.WaitGroup

		for _, host := range hosts {
			apiWg.Add(1)
			go func(h string) {
				defer apiWg.Done()
				select {
				case <-ctx.Done():
					return
				case sem <- struct{}{}:
					defer func() { <-sem }()
				}

				findings := apiScanner.ScanHost(ctx, h)
				if len(findings) > 0 {
					findingsMu.Lock()
					allFindings = append(allFindings, findings...)
					findingsMu.Unlock()
				}
			}(host)
		}

		apiWg.Wait()
		advResults.APIFindings = allFindings

		if !cfg.Silent && !cfg.JsonOutput {
			graphqlCount := 0
			swaggerCount := 0
			sensitiveCount := 0
			for _, f := range allFindings {
				switch f.Type {
				case "graphql":
					graphqlCount++
				case "swagger":
					swaggerCount++
				case "rest":
					if f.Issue == "sensitive_endpoint" {
						sensitiveCount++
					}
				}
			}

			if len(allFindings) > 0 {
				output.PrintSubSection(output.Green("✓") + " Found " +
					output.BoldCyan(intToString(graphqlCount)) + " GraphQL, " +
					output.BoldCyan(intToString(swaggerCount)) + " Swagger, " +
					output.BoldYellow(intToString(sensitiveCount)) + " sensitive endpoints")

				// Show critical findings
				for _, f := range allFindings {
					if f.Issue == "introspection_enabled" {
						output.PrintSubSection("  " + output.Red("⚠ ") +
							"GraphQL introspection enabled at " + output.Cyan(f.URL))
					}
					if f.Issue == "api_documentation_exposed" {
						output.PrintSubSection("  " + output.Yellow("! ") +
							"API docs exposed at " + output.Cyan(f.URL))
					}
				}
			} else {
				output.PrintSubSection(output.Dim("No critical API findings"))
			}
		}
	}

	// 3. Secrets Discovery (third)
	if cfg.SecretsScan {
		if !cfg.Silent && !cfg.JsonOutput {
			output.PrintEndSection()
			output.PrintSection("🔑", "PASSIVE CREDENTIAL DISCOVERY")
		}

		secretScanner := secrets.NewSecretScanner(cfg.Domain, cfg.Timeout)
		secretFindings := secretScanner.ScanAll(ctx)
		advResults.Secrets = secretFindings

		if !cfg.Silent && !cfg.JsonOutput {
			criticalCount := 0
			highCount := 0
			for _, s := range secretFindings {
				if s.Severity == "critical" {
					criticalCount++
				} else if s.Severity == "high" {
					highCount++
				}
			}

			if len(secretFindings) > 0 {
				output.PrintSubSection(output.Green("✓") + " Found " +
					output.BoldRed(intToString(criticalCount)) + " critical, " +
					output.BoldYellow(intToString(highCount)) + " high severity findings")

				// Show critical findings
				shown := 0
				for _, s := range secretFindings {
					if shown >= 5 {
						break
					}
					if s.Severity == "critical" || s.Severity == "high" {
						output.PrintSubSection("  " + output.Red("⚠ ") +
							output.BoldWhite(s.Type) + " in " +
							output.Cyan(s.Source) + ": " +
							output.Dim(s.Description))
						shown++
					}
				}
			} else {
				output.PrintSubSection(output.Dim("No secrets found in public sources"))
			}
		}
	}

	// 4. Technology Fingerprinting
	if cfg.TechScan {
		if !cfg.Silent && !cfg.JsonOutput {
			output.PrintEndSection()
			output.PrintSection("🔍", "TECHNOLOGY FINGERPRINTING")
		}

		techScanner := fingerprint.NewTechScanner(cfg.Timeout)

		// Get active hosts
		resultsMu.Lock()
		hosts := make([]string, 0)
		for sub, result := range results {
			if result.StatusCode >= 200 && result.StatusCode < 500 {
				hosts = append(hosts, sub)
			}
		}
		resultsMu.Unlock()

		// Scan for technologies
		advResults.Technologies = techScanner.ScanMultipleHosts(ctx, hosts, 10)

		// Enrich with CVEs
		for host, techs := range advResults.Technologies {
			advResults.Technologies[host] = fingerprint.EnrichWithCVEs(techs)
		}

		if !cfg.Silent && !cfg.JsonOutput {
			totalTechs := 0
			techCounts := make(map[string]int)
			var criticalCVEs []fingerprint.CVEMatch

			for _, techs := range advResults.Technologies {
				totalTechs += len(techs)
				for _, tech := range techs {
					techCounts[tech.Category]++
				}
				criticalCVEs = append(criticalCVEs, fingerprint.GetCriticalCVEs(techs)...)
			}

			if totalTechs > 0 {
				output.PrintSubSection(output.Green("✓") + " Detected " +
					output.BoldCyan(intToString(totalTechs)) + " technologies across " +
					output.BoldWhite(intToString(len(advResults.Technologies))) + " hosts")

				// Show category breakdown
				for category, count := range techCounts {
					if count > 0 {
						output.PrintSubSection("  " + output.Dim(category+": ") + output.Cyan(intToString(count)))
					}
				}

				// Show critical CVEs
				if len(criticalCVEs) > 0 {
					output.PrintSubSection("")
					output.PrintSubSection(output.BoldRed("⚠ ") + output.BoldRed(intToString(len(criticalCVEs))) +
						output.Red(" CRITICAL CVEs found (actively exploited):"))
					shown := 0
					for _, cve := range criticalCVEs {
						if shown >= 5 {
							break
						}
						ransomware := ""
						if cve.Ransomware {
							ransomware = output.Red(" [RANSOMWARE]")
						}
						output.PrintSubSection("  " + output.Red("• ") +
							output.BoldYellow(cve.CVEID) + " - " +
							output.Cyan(cve.Product) + ransomware)
						shown++
					}
				}
			} else {
				output.PrintSubSection(output.Dim("No technologies detected"))
			}
		}
	}

	// 5. ASN/CIDR Expansion
	if cfg.ASNScan {
		if !cfg.Silent && !cfg.JsonOutput {
			output.PrintEndSection()
			output.PrintSection("🌐", "ASN/CIDR EXPANSION")
		}

		asnScanner := network.NewASNScanner(cfg.Timeout)
		advResults.ASNInfo = make(map[string]*network.ASNInfo)

		// Get unique IPs from results
		resultsMu.Lock()
		seenIPs := make(map[string]bool)
		var uniqueIPs []string
		for _, result := range results {
			for _, ip := range result.IPs {
				if !seenIPs[ip] {
					seenIPs[ip] = true
					uniqueIPs = append(uniqueIPs, ip)
				}
			}
		}
		resultsMu.Unlock()

		// Limit to first 10 unique IPs for ASN lookups (rate limit friendly)
		if len(uniqueIPs) > 10 {
			uniqueIPs = uniqueIPs[:10]
		}

		var asnMu sync.Mutex
		var asnWg sync.WaitGroup
		asnSem := make(chan struct{}, 3) // Conservative concurrency

		for _, ip := range uniqueIPs {
			asnWg.Add(1)
			go func(ipAddr string) {
				defer asnWg.Done()
				select {
				case <-ctx.Done():
					return
				case asnSem <- struct{}{}:
					defer func() { <-asnSem }()
				}

				info, err := asnScanner.GetASNInfo(ctx, ipAddr)
				if err == nil && info != nil {
					asnMu.Lock()
					advResults.ASNInfo[ipAddr] = info
					asnMu.Unlock()
				}
			}(ip)
		}

		asnWg.Wait()

		if !cfg.Silent && !cfg.JsonOutput {
			if len(advResults.ASNInfo) > 0 {
				// Count unique ASNs
				asnSet := make(map[string]bool)
				for _, info := range advResults.ASNInfo {
					if info.ASN != "" {
						asnSet[info.ASN] = true
					}
				}

				output.PrintSubSection(output.Green("✓") + " Discovered " +
					output.BoldCyan(intToString(len(asnSet))) + " unique ASNs across " +
					output.BoldWhite(intToString(len(advResults.ASNInfo))) + " IPs")

				// Show ASN details
				shown := 0
				shownASN := make(map[string]bool)
				for ip, info := range advResults.ASNInfo {
					if shown >= 5 {
						break
					}
					if info.ASN != "" && !shownASN[info.ASN] {
						shownASN[info.ASN] = true
						cidrInfo := ""
						if info.CIDR != "" {
							cidrInfo = output.Dim(" (") + output.Yellow(info.CIDR) + output.Dim(")")
						}
						output.PrintSubSection("  " + output.Cyan("AS"+info.ASN) + " - " +
							output.BoldWhite(info.Name) + cidrInfo +
							output.Dim(" ["+ip+"]"))
						shown++
					}
				}
			} else {
				output.PrintSubSection(output.Dim("No ASN information discovered"))
			}
		}
	}

	// 6. Virtual Host Discovery
	if cfg.VHostScan {
		if !cfg.Silent && !cfg.JsonOutput {
			output.PrintEndSection()
			output.PrintSection("🏠", "VIRTUAL HOST DISCOVERY")
		}

		vhostScanner := network.NewVHostScanner(cfg.Timeout)
		advResults.VHosts = make(map[string]*network.VHostResult)

		// Get unique IPs from results
		resultsMu.Lock()
		seenIPs := make(map[string]bool)
		var uniqueIPs []string
		for _, result := range results {
			for _, ip := range result.IPs {
				if !seenIPs[ip] {
					seenIPs[ip] = true
					uniqueIPs = append(uniqueIPs, ip)
				}
			}
		}
		resultsMu.Unlock()

		// Limit to first 5 IPs for vhost discovery (rate limit friendly)
		if len(uniqueIPs) > 5 {
			uniqueIPs = uniqueIPs[:5]
		}

		advResults.VHosts = vhostScanner.DiscoverMultipleIPs(ctx, uniqueIPs, 3)

		if !cfg.Silent && !cfg.JsonOutput {
			totalVHosts := 0
			for _, vhost := range advResults.VHosts {
				totalVHosts += len(vhost.Domains)
			}

			if totalVHosts > 0 {
				output.PrintSubSection(output.Green("✓") + " Found " +
					output.BoldCyan(intToString(totalVHosts)) + " virtual hosts across " +
					output.BoldWhite(intToString(len(advResults.VHosts))) + " IPs")

				// Show top vhosts
				shown := 0
				for ip, vhost := range advResults.VHosts {
					if shown >= 3 {
						break
					}
					if len(vhost.Domains) > 0 {
						domainList := ""
						for i, d := range vhost.Domains {
							if i >= 3 {
								domainList += output.Dim(", +"+intToString(len(vhost.Domains)-3)+" more")
								break
							}
							if i > 0 {
								domainList += ", "
							}
							domainList += output.Cyan(d)
						}
						output.PrintSubSection("  " + output.Yellow(ip) + ": " + domainList)
						shown++
					}
				}
			} else {
				output.PrintSubSection(output.Dim("No additional virtual hosts discovered"))
			}
		}
	}

	// Update results with findings
	updateResultsWithAdvanced(results, resultsMu, advResults)

	return advResults
}

// updateResultsWithAdvanced adds advanced findings to subdomain results
func updateResultsWithAdvanced(results map[string]*config.SubdomainResult, resultsMu *sync.Mutex, adv *AdvancedResults) {
	resultsMu.Lock()
	defer resultsMu.Unlock()

	// Add cloud assets to relevant subdomains
	for _, asset := range adv.CloudAssets {
		// Add to the main domain result or first result
		for _, result := range results {
			result.CloudAssets = append(result.CloudAssets, config.CloudAssetResult{
				Type:        asset.Type,
				Name:        asset.Name,
				URL:         asset.URL,
				Provider:    asset.Provider,
				Status:      asset.Status,
				Permissions: asset.Permissions,
			})
			break // Add to first result only to avoid duplication
		}
	}

	// Add API findings to relevant subdomains
	for _, finding := range adv.APIFindings {
		// Find the subdomain this finding belongs to
		for sub, result := range results {
			if containsHost(finding.URL, sub) {
				result.APIFindings = append(result.APIFindings, config.APIFindingResult{
					Type:      finding.Type,
					URL:       finding.URL,
					Issue:     finding.Issue,
					Severity:  finding.Severity,
					Endpoints: finding.Endpoints,
				})
				break
			}
		}
	}

	// Add secrets to relevant subdomains
	for _, secret := range adv.Secrets {
		// Add to the main domain result
		for _, result := range results {
			result.SecretsFound = append(result.SecretsFound, config.SecretResult{
				Type:        secret.Type,
				Source:      secret.Source,
				Match:       secret.Match,
				Severity:    secret.Severity,
				Description: secret.Description,
			})
			break // Add to first result only
		}
	}
}

// containsHost checks if a URL contains a specific host
func containsHost(urlStr, host string) bool {
	if len(urlStr) == 0 || len(host) == 0 {
		return false
	}
	// Simple string contains check
	return strings.Contains(urlStr, host)
}

// intToString converts int to string
func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	negative := n < 0
	if negative {
		n = -n
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if negative {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}

// RunAdvancedWithProgress runs advanced scans with progress bar
func RunAdvancedWithProgress(ctx context.Context, results map[string]*config.SubdomainResult,
	resultsMu *sync.Mutex, cfg AdvancedConfig) *AdvancedResults {

	// Count total scans to perform
	total := 0
	if cfg.CloudScan {
		total++
	}
	if cfg.APIScan {
		total++
	}
	if cfg.SecretsScan {
		total++
	}

	if total == 0 {
		return &AdvancedResults{}
	}

	bar := progress.New(total, "Advanced", cfg.Silent || cfg.JsonOutput)
	defer bar.Finish()

	advResults := &AdvancedResults{}
	var mu sync.Mutex

	// Cloud scanning
	if cfg.CloudScan {
		cloudScanner := cloud.NewCloudScanner(cfg.Domain, cfg.Timeout)
		assets := cloudScanner.ScanAll(ctx)
		lambdaAssets := cloudScanner.CheckLambdaEndpoints(ctx)
		assets = append(assets, lambdaAssets...)

		mu.Lock()
		advResults.CloudAssets = assets
		mu.Unlock()
		bar.Increment()
	}

	// API scanning
	if cfg.APIScan {
		apiScanner := api.NewAPIScanner(cfg.Timeout)
		resultsMu.Lock()
		hosts := make([]string, 0)
		for sub, result := range results {
			if result.StatusCode >= 200 && result.StatusCode < 500 {
				hosts = append(hosts, sub)
			}
		}
		resultsMu.Unlock()

		var allFindings []api.APIFinding
		for _, host := range hosts {
			select {
			case <-ctx.Done():
				break
			default:
			}
			findings := apiScanner.ScanHost(ctx, host)
			allFindings = append(allFindings, findings...)
		}

		mu.Lock()
		advResults.APIFindings = allFindings
		mu.Unlock()
		bar.Increment()
	}

	// Secrets scanning
	if cfg.SecretsScan {
		secretScanner := secrets.NewSecretScanner(cfg.Domain, cfg.Timeout)
		secretFindings := secretScanner.ScanAll(ctx)

		mu.Lock()
		advResults.Secrets = secretFindings
		mu.Unlock()
		bar.Increment()
	}

	updateResultsWithAdvanced(results, resultsMu, advResults)

	return advResults
}
