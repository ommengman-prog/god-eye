package ai

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// CISA KEV Catalog URL
	kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// Cache settings
	kevCacheFile = "kev.json"
	kevCacheTTL  = 24 * time.Hour // Refresh once per day
)

// KEVCatalog represents the CISA Known Exploited Vulnerabilities catalog
type KEVCatalog struct {
	Title           string           `json:"title"`
	CatalogVersion  string           `json:"catalogVersion"`
	DateReleased    string           `json:"dateReleased"`
	Count           int              `json:"count"`
	Vulnerabilities []KEVulnerability `json:"vulnerabilities"`
}

// KEVulnerability represents a single KEV entry
type KEVulnerability struct {
	CveID                     string `json:"cveID"`
	VendorProject             string `json:"vendorProject"`
	Product                   string `json:"product"`
	VulnerabilityName         string `json:"vulnerabilityName"`
	DateAdded                 string `json:"dateAdded"`
	ShortDescription          string `json:"shortDescription"`
	RequiredAction            string `json:"requiredAction"`
	DueDate                   string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                     string `json:"notes"`
}

// KEVStore manages the local KEV database
type KEVStore struct {
	catalog    *KEVCatalog
	productMap map[string][]KEVulnerability // Maps product names to vulnerabilities
	cacheDir   string
	mu         sync.RWMutex
	loaded     bool
}

var (
	kevStore     *KEVStore
	kevStoreOnce sync.Once
)

// GetKEVStore returns the singleton KEV store instance
func GetKEVStore() *KEVStore {
	kevStoreOnce.Do(func() {
		cacheDir := getKEVCacheDir()
		kevStore = &KEVStore{
			cacheDir:   cacheDir,
			productMap: make(map[string][]KEVulnerability),
		}
	})
	return kevStore
}

// getKEVCacheDir returns the cache directory path
func getKEVCacheDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".god-eye"
	}
	return filepath.Join(homeDir, ".god-eye")
}

// getCachePath returns the full path to the cache file
func (k *KEVStore) getCachePath() string {
	return filepath.Join(k.cacheDir, kevCacheFile)
}

// IsLoaded returns whether the KEV database is loaded
func (k *KEVStore) IsLoaded() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.loaded
}

// GetCatalogInfo returns catalog metadata
func (k *KEVStore) GetCatalogInfo() (version string, count int, date string) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.catalog == nil {
		return "", 0, ""
	}
	return k.catalog.CatalogVersion, k.catalog.Count, k.catalog.DateReleased
}

// NeedUpdate checks if the cache needs to be updated
func (k *KEVStore) NeedUpdate() bool {
	cachePath := k.getCachePath()
	info, err := os.Stat(cachePath)
	if err != nil {
		return true // File doesn't exist
	}
	return time.Since(info.ModTime()) > kevCacheTTL
}

// Update downloads and updates the KEV database
func (k *KEVStore) Update() error {
	// Ensure cache directory exists
	if err := os.MkdirAll(k.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Download KEV catalog
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(kevURL)
	if err != nil {
		return fmt.Errorf("failed to download KEV catalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("KEV download failed with status: %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read KEV response: %w", err)
	}

	// Parse to validate JSON
	var catalog KEVCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return fmt.Errorf("failed to parse KEV catalog: %w", err)
	}

	// Write to cache file
	cachePath := k.getCachePath()
	if err := os.WriteFile(cachePath, body, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	// Load into memory
	return k.loadFromCatalog(&catalog)
}

// Load loads the KEV database from cache or downloads if needed
func (k *KEVStore) Load() error {
	return k.LoadWithProgress(false)
}

// LoadWithProgress loads the KEV database with optional progress output
func (k *KEVStore) LoadWithProgress(showProgress bool) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.loaded {
		return nil
	}

	cachePath := k.getCachePath()

	// Try to load from cache
	data, err := os.ReadFile(cachePath)
	if err == nil {
		var catalog KEVCatalog
		if err := json.Unmarshal(data, &catalog); err == nil {
			return k.loadFromCatalog(&catalog)
		}
	}

	// Cache doesn't exist or is invalid, need to download
	if showProgress {
		fmt.Print("📥 First run: downloading CISA KEV database... ")
	}

	k.mu.Unlock()
	err = k.Update()
	k.mu.Lock()

	if err != nil {
		if showProgress {
			fmt.Println("FAILED")
		}
		return err
	}

	if showProgress {
		fmt.Println("OK")
		fmt.Printf("   ✓ Loaded %d known exploited vulnerabilities\n", k.catalog.Count)
	}

	return nil
}

// loadFromCatalog builds the internal index from catalog data
func (k *KEVStore) loadFromCatalog(catalog *KEVCatalog) error {
	k.catalog = catalog
	k.productMap = make(map[string][]KEVulnerability)

	for _, vuln := range catalog.Vulnerabilities {
		// Index by product name (lowercase for matching)
		productKey := strings.ToLower(vuln.Product)
		k.productMap[productKey] = append(k.productMap[productKey], vuln)

		// Also index by vendor
		vendorKey := strings.ToLower(vuln.VendorProject)
		if vendorKey != productKey {
			k.productMap[vendorKey] = append(k.productMap[vendorKey], vuln)
		}
	}

	k.loaded = true
	return nil
}

// SearchByProduct searches for KEV vulnerabilities by product name
func (k *KEVStore) SearchByProduct(product string) []KEVulnerability {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if !k.loaded || k.catalog == nil {
		return nil
	}

	product = strings.ToLower(product)
	var results []KEVulnerability

	// Direct match
	if vulns, ok := k.productMap[product]; ok {
		results = append(results, vulns...)
	}

	// Partial match for products that might have different naming
	for key, vulns := range k.productMap {
		if key != product && (strings.Contains(key, product) || strings.Contains(product, key)) {
			results = append(results, vulns...)
		}
	}

	return deduplicateKEV(results)
}

// SearchByCVE searches for a specific CVE ID in the KEV catalog
func (k *KEVStore) SearchByCVE(cveID string) *KEVulnerability {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if !k.loaded || k.catalog == nil {
		return nil
	}

	cveID = strings.ToUpper(cveID)
	for _, vuln := range k.catalog.Vulnerabilities {
		if vuln.CveID == cveID {
			return &vuln
		}
	}
	return nil
}

// SearchByTechnology searches for KEV entries matching a technology name
func (k *KEVStore) SearchByTechnology(technology string) []KEVulnerability {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if !k.loaded || k.catalog == nil {
		return nil
	}

	technology = strings.ToLower(technology)
	var results []KEVulnerability

	// Normalize common technology names
	aliases := getTechnologyAliases(technology)

	for _, vuln := range k.catalog.Vulnerabilities {
		productLower := strings.ToLower(vuln.Product)
		vendorLower := strings.ToLower(vuln.VendorProject)
		nameLower := strings.ToLower(vuln.VulnerabilityName)

		for _, alias := range aliases {
			if strings.Contains(productLower, alias) ||
				strings.Contains(vendorLower, alias) ||
				strings.Contains(nameLower, alias) {
				results = append(results, vuln)
				break
			}
		}
	}

	return deduplicateKEV(results)
}

// getTechnologyAliases returns common aliases for a technology
func getTechnologyAliases(tech string) []string {
	aliases := []string{tech}

	// Common mappings
	mappings := map[string][]string{
		"nginx":      {"nginx"},
		"apache":     {"apache", "httpd"},
		"iis":        {"iis", "internet information services"},
		"wordpress":  {"wordpress"},
		"drupal":     {"drupal"},
		"joomla":     {"joomla"},
		"tomcat":     {"tomcat"},
		"jenkins":    {"jenkins"},
		"gitlab":     {"gitlab"},
		"exchange":   {"exchange"},
		"sharepoint": {"sharepoint"},
		"citrix":     {"citrix"},
		"vmware":     {"vmware", "vcenter", "esxi"},
		"fortinet":   {"fortinet", "fortigate", "fortios"},
		"paloalto":   {"palo alto", "pan-os"},
		"cisco":      {"cisco"},
		"f5":         {"f5", "big-ip"},
		"pulse":      {"pulse", "pulse secure"},
		"sonicwall":  {"sonicwall"},
		"zyxel":      {"zyxel"},
		"nextjs":     {"next.js", "nextjs"},
		"react":      {"react"},
		"angular":    {"angular"},
		"vue":        {"vue"},
		"php":        {"php"},
		"java":       {"java"},
		"log4j":      {"log4j", "log4shell"},
		"spring":     {"spring"},
		"struts":     {"struts"},
		"confluence": {"confluence"},
		"jira":       {"jira"},
		"atlassian":  {"atlassian"},
	}

	if mapped, ok := mappings[tech]; ok {
		aliases = append(aliases, mapped...)
	}

	return aliases
}

// deduplicateKEV removes duplicate KEV entries
func deduplicateKEV(vulns []KEVulnerability) []KEVulnerability {
	seen := make(map[string]bool)
	var result []KEVulnerability

	for _, v := range vulns {
		if !seen[v.CveID] {
			seen[v.CveID] = true
			result = append(result, v)
		}
	}
	return result
}

// FormatKEVResult formats KEV search results for display
func FormatKEVResult(vulns []KEVulnerability, technology string) string {
	if len(vulns) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🚨 CISA KEV Alert for %s:\n", technology))
	sb.WriteString(fmt.Sprintf("   Found %d ACTIVELY EXPLOITED vulnerabilities!\n\n", len(vulns)))

	// Show up to 5 most relevant
	maxShow := 5
	if len(vulns) < maxShow {
		maxShow = len(vulns)
	}

	for i := 0; i < maxShow; i++ {
		v := vulns[i]
		sb.WriteString(fmt.Sprintf("   🔴 %s - %s\n", v.CveID, v.VulnerabilityName))

		// Truncate description if too long
		desc := v.ShortDescription
		if len(desc) > 150 {
			desc = desc[:150] + "..."
		}
		sb.WriteString(fmt.Sprintf("      %s\n", desc))

		// Ransomware indicator
		if v.KnownRansomwareCampaignUse == "Known" {
			sb.WriteString("      ⚠️  USED IN RANSOMWARE CAMPAIGNS\n")
		}

		sb.WriteString(fmt.Sprintf("      Added: %s | Due: %s\n", v.DateAdded, v.DueDate))
		sb.WriteString("\n")
	}

	if len(vulns) > maxShow {
		sb.WriteString(fmt.Sprintf("   ... and %d more KEV entries\n", len(vulns)-maxShow))
	}

	sb.WriteString("   ℹ️  These vulnerabilities are CONFIRMED to be exploited in the wild.\n")
	sb.WriteString("   ⚡ IMMEDIATE patching is strongly recommended.\n")

	return sb.String()
}

// SearchKEV is a convenience function for searching KEV by technology
func SearchKEV(technology string) (string, error) {
	return SearchKEVWithProgress(technology, false)
}

// SearchKEVWithProgress searches KEV with optional download progress
func SearchKEVWithProgress(technology string, showProgress bool) (string, error) {
	store := GetKEVStore()

	// Auto-load if not loaded (with auto-download if needed)
	if !store.IsLoaded() {
		if err := store.LoadWithProgress(showProgress); err != nil {
			return "", fmt.Errorf("failed to load KEV database: %w", err)
		}
	}

	vulns := store.SearchByTechnology(technology)
	if len(vulns) == 0 {
		return "", nil // No KEV found, not an error
	}

	return FormatKEVResult(vulns, technology), nil
}
