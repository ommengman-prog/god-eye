package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"god-eye/internal/ai"
	"god-eye/internal/config"
	"god-eye/internal/output"
	"god-eye/internal/scanner"
)

func main() {
	var cfg config.Config

	rootCmd := &cobra.Command{
		Use:   "god-eye -d <domain> [flags]",
		Short: "Ultra-fast subdomain enumeration tool",
		Long: `God's Eye - Ultra-fast subdomain enumeration & reconnaissance tool written in Go

Examples:
  god-eye -d example.com                    Basic scan with all features
  god-eye -d example.com --no-brute         Skip DNS brute-force
  god-eye -d example.com --active           Only show active (HTTP 2xx/3xx)
  god-eye -d example.com -o out.json -f json Export to JSON
  god-eye -d example.com -r 1.1.1.1,8.8.8.8 Custom resolvers
  god-eye -d example.com -p 80,443,8080     Custom ports to scan
  god-eye -d example.com --json             JSON output to stdout
  god-eye -d example.com -s                 Silent mode (subdomains only)
  god-eye -d example.com --stealth moderate Moderate stealth (evasion mode)
  god-eye -d example.com --stealth paranoid Maximum stealth (very slow)`,
		Run: func(cmd *cobra.Command, args []string) {
			if cfg.Domain == "" {
				fmt.Println(output.Red("[-]"), "Domain is required. Use -d flag.")
				cmd.Help()
				os.Exit(1)
			}

			// Legal disclaimer
			if !cfg.Silent && !cfg.JsonOutput {
				fmt.Println(output.Yellow("⚠️  LEGAL NOTICE:"), "This tool is for authorized security testing only.")
				fmt.Println(output.Dim("   Ensure you have explicit permission to scan"), output.BoldWhite(cfg.Domain))
				fmt.Println(output.Dim("   Unauthorized access is illegal. You accept all responsibility."))
				fmt.Println()
			}

			scanner.Run(cfg)
		},
	}

	rootCmd.Flags().StringVarP(&cfg.Domain, "domain", "d", "", "Target domain to enumerate")
	rootCmd.Flags().StringVarP(&cfg.Wordlist, "wordlist", "w", "", "Custom wordlist file path")
	rootCmd.Flags().IntVarP(&cfg.Concurrency, "concurrency", "c", 1000, "Number of concurrent workers")
	rootCmd.Flags().IntVarP(&cfg.Timeout, "timeout", "t", 5, "Timeout in seconds")
	rootCmd.Flags().StringVarP(&cfg.Output, "output", "o", "", "Output file path")
	rootCmd.Flags().StringVarP(&cfg.Format, "format", "f", "txt", "Output format (txt, json, csv)")
	rootCmd.Flags().BoolVarP(&cfg.Silent, "silent", "s", false, "Silent mode (only subdomains)")
	rootCmd.Flags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Verbose mode (show errors)")
	rootCmd.Flags().BoolVar(&cfg.NoBrute, "no-brute", false, "Disable DNS brute-force")
	rootCmd.Flags().BoolVar(&cfg.NoProbe, "no-probe", false, "Disable HTTP probing")
	rootCmd.Flags().BoolVar(&cfg.NoPorts, "no-ports", false, "Disable port scanning")
	rootCmd.Flags().BoolVar(&cfg.NoTakeover, "no-takeover", false, "Disable takeover detection")
	rootCmd.Flags().StringVarP(&cfg.Resolvers, "resolvers", "r", "", "Custom resolvers (comma-separated)")
	rootCmd.Flags().StringVarP(&cfg.Ports, "ports", "p", "", "Custom ports to scan (comma-separated)")
	rootCmd.Flags().BoolVar(&cfg.OnlyActive, "active", false, "Only show active subdomains (HTTP 2xx/3xx)")
	rootCmd.Flags().BoolVar(&cfg.JsonOutput, "json", false, "Output results as JSON to stdout")

	// AI flags
	rootCmd.Flags().BoolVar(&cfg.EnableAI, "enable-ai", false, "Enable AI-powered analysis with Ollama (includes CVE search)")
	rootCmd.Flags().StringVar(&cfg.AIUrl, "ai-url", "http://localhost:11434", "Ollama API URL")
	rootCmd.Flags().StringVar(&cfg.AIFastModel, "ai-fast-model", "deepseek-r1:1.5b", "Fast triage model")
	rootCmd.Flags().StringVar(&cfg.AIDeepModel, "ai-deep-model", "qwen2.5-coder:7b", "Deep analysis model (supports function calling)")
	rootCmd.Flags().BoolVar(&cfg.AICascade, "ai-cascade", true, "Use cascade (fast triage + deep analysis)")
	rootCmd.Flags().BoolVar(&cfg.AIDeepAnalysis, "ai-deep", false, "Enable deep AI analysis on all findings")

	// Stealth flags
	rootCmd.Flags().StringVar(&cfg.StealthMode, "stealth", "", "Stealth mode: light, moderate, aggressive, paranoid (reduces detection)")

	// Database update subcommand
	updateDbCmd := &cobra.Command{
		Use:   "update-db",
		Short: "Update vulnerability databases (CISA KEV)",
		Long: `Downloads and updates local vulnerability databases:
  - CISA KEV (Known Exploited Vulnerabilities) - ~500KB, updated daily by CISA

The KEV database contains vulnerabilities that are actively exploited in the wild.
This data is used for instant, offline CVE lookups during scans.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(output.BoldCyan("🔄 Updating vulnerability databases..."))
			fmt.Println()

			// Update KEV
			fmt.Print(output.Dim("   Downloading CISA KEV catalog... "))
			kevStore := ai.GetKEVStore()
			if err := kevStore.Update(); err != nil {
				fmt.Println(output.Red("FAILED"))
				fmt.Printf("   %s %v\n", output.Red("Error:"), err)
				os.Exit(1)
			}

			version, count, date := kevStore.GetCatalogInfo()
			fmt.Println(output.Green("OK"))
			fmt.Printf("   %s %s vulnerabilities (v%s, released %s)\n",
				output.Green("✓"), output.BoldWhite(fmt.Sprintf("%d", count)), version, date)
			fmt.Println()
			fmt.Println(output.Green("✅ Database update complete!"))
			fmt.Println(output.Dim("   KEV data cached at: ~/.god-eye/kev.json"))
		},
	}
	rootCmd.AddCommand(updateDbCmd)

	// Database info subcommand
	dbInfoCmd := &cobra.Command{
		Use:   "db-info",
		Short: "Show vulnerability database status",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(output.BoldCyan("📊 Vulnerability Database Status"))
			fmt.Println()

			kevStore := ai.GetKEVStore()

			// Check if KEV needs update
			if kevStore.NeedUpdate() {
				fmt.Println(output.Yellow("⚠️  CISA KEV: Not downloaded or outdated"))
				fmt.Println(output.Dim("   Run 'god-eye update-db' to download"))
			} else {
				if err := kevStore.Load(); err != nil {
					fmt.Printf("%s CISA KEV: Error loading - %v\n", output.Red("❌"), err)
				} else {
					version, count, date := kevStore.GetCatalogInfo()
					fmt.Printf("%s CISA KEV: %s vulnerabilities\n", output.Green("✓"), output.BoldWhite(fmt.Sprintf("%d", count)))
					fmt.Printf("   Version: %s | Released: %s\n", version, date)
					fmt.Println(output.Dim("   Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog"))
				}
			}
		},
	}
	rootCmd.AddCommand(dbInfoCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
