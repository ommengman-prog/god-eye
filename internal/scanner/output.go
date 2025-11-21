package scanner

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"god-eye/internal/config"
	"god-eye/internal/output"
)

// PrintResults displays scan results to stdout
func PrintResults(results map[string]*config.SubdomainResult, startTime time.Time, takeoverCount int32) {
	elapsed := time.Since(startTime)

	// Count statistics
	var activeCount, vulnCount, cloudCount int
	for _, r := range results {
		if r.StatusCode >= 200 && r.StatusCode < 400 {
			activeCount++
		}
		if r.OpenRedirect || r.CORSMisconfig != "" || len(r.DangerousMethods) > 0 || r.GitExposed || r.SvnExposed || len(r.BackupFiles) > 0 {
			vulnCount++
		}
		if r.CloudProvider != "" {
			cloudCount++
		}
	}

	// Summary box
	fmt.Println()
	fmt.Println(output.BoldCyan("╔══════════════════════════════════════════════════════════════════════════════╗"))
	fmt.Println(output.BoldCyan("║") + "                              " + output.BoldWhite("📊 SCAN SUMMARY") + "                              " + output.BoldCyan("║"))
	fmt.Println(output.BoldCyan("╠══════════════════════════════════════════════════════════════════════════════╣"))
	fmt.Printf("%s  %-20s %s  %-20s %s  %-20s %s\n",
		output.BoldCyan("║"),
		fmt.Sprintf("🌐 Total: %s", output.BoldCyan(fmt.Sprintf("%d", len(results)))),
		output.Dim("|"),
		fmt.Sprintf("✅ Active: %s", output.BoldGreen(fmt.Sprintf("%d", activeCount))),
		output.Dim("|"),
		fmt.Sprintf("⏱️  Time: %s", output.BoldYellow(fmt.Sprintf("%.1fs", elapsed.Seconds()))),
		output.BoldCyan("║"))
	fmt.Printf("%s  %-20s %s  %-20s %s  %-20s %s\n",
		output.BoldCyan("║"),
		fmt.Sprintf("⚠️  Vulns: %s", output.BoldRed(fmt.Sprintf("%d", vulnCount))),
		output.Dim("|"),
		fmt.Sprintf("☁️  OnCloud: %s", output.Blue(fmt.Sprintf("%d", cloudCount))),
		output.Dim("|"),
		fmt.Sprintf("🎯 Takeover: %s", output.BoldRed(fmt.Sprintf("%d", takeoverCount))),
		output.BoldCyan("║"))
	fmt.Println(output.BoldCyan("╚══════════════════════════════════════════════════════════════════════════════╝"))
	fmt.Println()
	fmt.Println(output.BoldCyan("═══════════════════════════════════════════════════════════════════════════════"))

	// Sort subdomains
	var sortedSubs []string
	for sub := range results {
		sortedSubs = append(sortedSubs, sub)
	}
	sort.Strings(sortedSubs)

	for _, sub := range sortedSubs {
		r := results[sub]
		printSubdomainResult(sub, r)
	}

	fmt.Println()
	fmt.Println(output.BoldCyan("═══════════════════════════════════════════════════════════════════════════════"))
}

func printSubdomainResult(sub string, r *config.SubdomainResult) {
	// Color code by status
	var statusColor func(a ...interface{}) string
	var statusIcon string
	if r.StatusCode >= 200 && r.StatusCode < 300 {
		statusColor = output.Green
		statusIcon = "●"
	} else if r.StatusCode >= 300 && r.StatusCode < 400 {
		statusColor = output.Yellow
		statusIcon = "◐"
	} else if r.StatusCode >= 400 {
		statusColor = output.Red
		statusIcon = "○"
	} else {
		statusColor = output.Blue
		statusIcon = "◌"
	}

	// Line 1: Subdomain name with status
	statusBadge := ""
	if r.StatusCode > 0 {
		statusBadge = fmt.Sprintf(" %s", statusColor(fmt.Sprintf("[%d]", r.StatusCode)))
	}

	// Response time badge
	timeBadge := ""
	if r.ResponseMs > 0 {
		if r.ResponseMs < 200 {
			timeBadge = fmt.Sprintf(" %s", output.Green(fmt.Sprintf("⚡%dms", r.ResponseMs)))
		} else if r.ResponseMs < 500 {
			timeBadge = fmt.Sprintf(" %s", output.Yellow(fmt.Sprintf("⏱️%dms", r.ResponseMs)))
		} else {
			timeBadge = fmt.Sprintf(" %s", output.Red(fmt.Sprintf("🐢%dms", r.ResponseMs)))
		}
	}

	fmt.Printf("\n%s %s%s%s\n", statusColor(statusIcon), output.BoldCyan(sub), statusBadge, timeBadge)

	// IPs
	if len(r.IPs) > 0 {
		ips := r.IPs
		if len(ips) > 3 {
			ips = ips[:3]
		}
		fmt.Printf("    %s %s\n", output.Dim("IP:"), output.White(strings.Join(ips, ", ")))
	}

	// CNAME
	if r.CNAME != "" {
		fmt.Printf("    %s %s\n", output.Dim("CNAME:"), output.Blue(r.CNAME))
	}

	// Location + ASN
	if r.Country != "" || r.City != "" || r.ASN != "" {
		loc := ""
		if r.City != "" && r.Country != "" {
			loc = r.City + ", " + r.Country
		} else if r.Country != "" {
			loc = r.Country
		} else if r.City != "" {
			loc = r.City
		}

		asnStr := ""
		if r.ASN != "" {
			asnStr = r.ASN
			if len(asnStr) > 40 {
				asnStr = asnStr[:37] + "..."
			}
		}

		if loc != "" && asnStr != "" {
			fmt.Printf("    Location: %s | %s\n", output.Cyan(loc), output.Blue(asnStr))
		} else if loc != "" {
			fmt.Printf("    Location: %s\n", output.Cyan(loc))
		} else if asnStr != "" {
			fmt.Printf("    ASN: %s\n", output.Blue(asnStr))
		}
	}

	// PTR
	if r.PTR != "" {
		fmt.Printf("    PTR: %s\n", output.Magenta(r.PTR))
	}

	// HTTP Info (Title, Size)
	if r.Title != "" || r.ContentLength > 0 {
		httpInfo := "    HTTP: "
		if r.Title != "" {
			title := r.Title
			if len(title) > 50 {
				title = title[:47] + "..."
			}
			httpInfo += fmt.Sprintf("\"%s\"", title)
		}
		if r.ContentLength > 0 {
			sizeStr := formatSize(r.ContentLength)
			if r.Title != "" {
				httpInfo += fmt.Sprintf(" (%s)", sizeStr)
			} else {
				httpInfo += sizeStr
			}
		}
		fmt.Println(httpInfo)
	}

	// Redirect
	if r.RedirectURL != "" {
		redirectURL := r.RedirectURL
		if len(redirectURL) > 60 {
			redirectURL = redirectURL[:57] + "..."
		}
		fmt.Printf("    Redirect: %s\n", output.Yellow(redirectURL))
	}

	// Tech
	if len(r.Tech) > 0 {
		techMap := make(map[string]bool)
		var uniqueTech []string
		for _, t := range r.Tech {
			if !techMap[t] {
				techMap[t] = true
				uniqueTech = append(uniqueTech, t)
			}
		}
		if len(uniqueTech) > 5 {
			uniqueTech = uniqueTech[:5]
		}
		if len(uniqueTech) > 0 {
			fmt.Printf("    Tech: %s\n", output.Yellow(strings.Join(uniqueTech, ", ")))
		}
	}

	// Security (WAF, TLS)
	var securityInfo []string
	if r.WAF != "" {
		securityInfo = append(securityInfo, fmt.Sprintf("WAF: %s", output.Red(r.WAF)))
	}
	if r.TLSVersion != "" {
		tlsInfo := fmt.Sprintf("TLS: %s", output.Cyan(r.TLSVersion))
		if r.TLSSelfSigned {
			tlsInfo += " " + output.Yellow("(self-signed)")
		}
		securityInfo = append(securityInfo, tlsInfo)
	}
	if len(securityInfo) > 0 {
		fmt.Printf("    Security: %s\n", strings.Join(securityInfo, " | "))
	}

	// TLS Fingerprint (appliance detection)
	if r.TLSFingerprint != nil {
		fp := r.TLSFingerprint
		if fp.Vendor != "" {
			applianceInfo := fmt.Sprintf("%s %s", fp.Vendor, fp.Product)
			if fp.Version != "" {
				applianceInfo += " v" + fp.Version
			}
			if fp.ApplianceType != "" {
				applianceInfo += fmt.Sprintf(" (%s)", fp.ApplianceType)
			}
			fmt.Printf("    %s %s\n", output.BoldYellow("APPLIANCE:"), output.Yellow(applianceInfo))
		}
		// Show internal hostnames found in certificate
		if len(fp.InternalHosts) > 0 {
			hosts := fp.InternalHosts
			if len(hosts) > 5 {
				hosts = hosts[:5]
			}
			fmt.Printf("    %s %s\n", output.BoldMagenta("INTERNAL:"), output.Magenta(strings.Join(hosts, ", ")))
		}
		// Show certificate subject info if no vendor matched but has org info
		if fp.Vendor == "" && (fp.SubjectOrg != "" || fp.SubjectOU != "") {
			certInfo := ""
			if fp.SubjectOrg != "" {
				certInfo = "Org: " + fp.SubjectOrg
			}
			if fp.SubjectOU != "" {
				if certInfo != "" {
					certInfo += ", "
				}
				certInfo += "OU: " + fp.SubjectOU
			}
			fmt.Printf("    Cert: %s\n", output.Dim(certInfo))
		}
	}

	// Ports
	if len(r.Ports) > 0 {
		var portStrs []string
		for _, p := range r.Ports {
			portStrs = append(portStrs, fmt.Sprintf("%d", p))
		}
		fmt.Printf("    Ports: %s\n", output.Magenta(strings.Join(portStrs, ", ")))
	}

	// Extra files
	var extras []string
	if r.RobotsTxt {
		extras = append(extras, "robots.txt")
	}
	if r.SitemapXml {
		extras = append(extras, "sitemap.xml")
	}
	if r.FaviconHash != "" {
		extras = append(extras, fmt.Sprintf("favicon:%s", r.FaviconHash[:8]))
	}
	if len(extras) > 0 {
		fmt.Printf("    Files: %s\n", output.Green(strings.Join(extras, ", ")))
	}

	// DNS Records
	if len(r.MXRecords) > 0 {
		mx := r.MXRecords
		if len(mx) > 2 {
			mx = mx[:2]
		}
		fmt.Printf("    MX: %s\n", strings.Join(mx, ", "))
	}

	// Security Headers
	if len(r.MissingHeaders) > 0 && len(r.MissingHeaders) < 7 {
		if len(r.SecurityHeaders) > 0 {
			fmt.Printf("    Headers: %s | Missing: %s\n",
				output.Green(strings.Join(r.SecurityHeaders, ", ")),
				output.Yellow(strings.Join(r.MissingHeaders, ", ")))
		}
	} else if len(r.SecurityHeaders) > 0 {
		fmt.Printf("    Headers: %s\n", output.Green(strings.Join(r.SecurityHeaders, ", ")))
	}

	// Cloud Provider
	if r.CloudProvider != "" {
		fmt.Printf("    Cloud: %s\n", output.Cyan(r.CloudProvider))
	}

	// Email Security
	if r.EmailSecurity != "" {
		emailColor := output.Green
		if r.EmailSecurity == "Weak" {
			emailColor = output.Yellow
		} else if r.EmailSecurity == "None" {
			emailColor = output.Red
		}
		fmt.Printf("    Email: %s\n", emailColor(r.EmailSecurity))
	}

	// TLS Alt Names
	if len(r.TLSAltNames) > 0 {
		altNames := r.TLSAltNames
		if len(altNames) > 5 {
			altNames = altNames[:5]
		}
		fmt.Printf("    TLS Alt: %s\n", output.Blue(strings.Join(altNames, ", ")))
	}

	// S3 Buckets
	if len(r.S3Buckets) > 0 {
		for _, bucket := range r.S3Buckets {
			if strings.Contains(bucket, "PUBLIC") {
				fmt.Printf("    %s %s\n", output.Red("S3:"), output.Red(bucket))
			} else {
				fmt.Printf("    S3: %s\n", output.Yellow(bucket))
			}
		}
	}

	// Security Issues (vulnerabilities)
	var vulns []string
	if r.OpenRedirect {
		vulns = append(vulns, "Open Redirect")
	}
	if r.CORSMisconfig != "" {
		vulns = append(vulns, fmt.Sprintf("CORS: %s", r.CORSMisconfig))
	}
	if len(r.DangerousMethods) > 0 {
		vulns = append(vulns, fmt.Sprintf("Methods: %s", strings.Join(r.DangerousMethods, ", ")))
	}
	if r.GitExposed {
		vulns = append(vulns, ".git Exposed")
	}
	if r.SvnExposed {
		vulns = append(vulns, ".svn Exposed")
	}
	if len(r.BackupFiles) > 0 {
		files := r.BackupFiles
		if len(files) > 3 {
			files = files[:3]
		}
		vulns = append(vulns, fmt.Sprintf("Backup: %s", strings.Join(files, ", ")))
	}
	if len(vulns) > 0 {
		fmt.Printf("    %s %s\n", output.Red("VULNS:"), output.Red(strings.Join(vulns, " | ")))
	}

	// Discovery (admin panels, API endpoints)
	var discoveries []string
	if len(r.AdminPanels) > 0 {
		panels := r.AdminPanels
		if len(panels) > 5 {
			panels = panels[:5]
		}
		discoveries = append(discoveries, fmt.Sprintf("Admin: %s", strings.Join(panels, ", ")))
	}
	if len(r.APIEndpoints) > 0 {
		endpoints := r.APIEndpoints
		if len(endpoints) > 5 {
			endpoints = endpoints[:5]
		}
		discoveries = append(discoveries, fmt.Sprintf("API: %s", strings.Join(endpoints, ", ")))
	}
	if len(discoveries) > 0 {
		fmt.Printf("    %s %s\n", output.Magenta("FOUND:"), output.Magenta(strings.Join(discoveries, " | ")))
	}

	// JavaScript Analysis
	if len(r.JSFiles) > 0 {
		files := r.JSFiles
		if len(files) > 3 {
			files = files[:3]
		}
		fmt.Printf("    JS Files: %s\n", output.Blue(strings.Join(files, ", ")))
	}
	if len(r.JSSecrets) > 0 {
		for _, secret := range r.JSSecrets {
			fmt.Printf("    %s %s\n", output.Red("JS SECRET:"), output.Red(secret))
		}
	}

	// Takeover
	if r.Takeover != "" {
		fmt.Printf("    %s %s\n", output.BgRed(" TAKEOVER "), output.BoldRed(r.Takeover))
	}

	// AI Findings
	if len(r.AIFindings) > 0 {
		severityColor := output.Cyan
		severityLabel := "AI"
		if r.AISeverity == "critical" {
			severityColor = output.BoldRed
			severityLabel = "AI:CRITICAL"
		} else if r.AISeverity == "high" {
			severityColor = output.Red
			severityLabel = "AI:HIGH"
		} else if r.AISeverity == "medium" {
			severityColor = output.Yellow
			severityLabel = "AI:MEDIUM"
		}

		for i, finding := range r.AIFindings {
			if i == 0 {
				fmt.Printf("    %s %s\n", severityColor(severityLabel+":"), finding)
			} else {
				fmt.Printf("    %s %s\n", output.Dim("     "), finding)
			}
			if i >= 4 {
				remaining := len(r.AIFindings) - 5
				if remaining > 0 {
					fmt.Printf("    %s (%d more findings...)\n", output.Dim("     "), remaining)
				}
				break
			}
		}

		if r.AIModel != "" {
			fmt.Printf("    %s model: %s\n", output.Dim("     "), output.Dim(r.AIModel))
		}
	}

	// CVE Findings
	if len(r.CVEFindings) > 0 {
		for _, cve := range r.CVEFindings {
			fmt.Printf("    %s %s\n", output.BoldRed("CVE:"), output.Red(cve))
		}
	}
}

func formatSize(size int64) string {
	if size > 1024*1024 {
		return fmt.Sprintf("%.1fMB", float64(size)/(1024*1024))
	} else if size > 1024 {
		return fmt.Sprintf("%.1fKB", float64(size)/1024)
	}
	return fmt.Sprintf("%dB", size)
}
