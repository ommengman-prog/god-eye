package config

import (
	"time"
)

// Config holds the scan configuration
type Config struct {
	Domain      string
	Wordlist    string
	Concurrency int
	Timeout     int
	Output      string
	Format      string
	Silent      bool
	Verbose     bool
	NoBrute    bool
	NoProbe    bool
	NoPorts    bool
	NoTakeover bool
	Resolvers   string
	Ports       string
	OnlyActive  bool
	JsonOutput  bool
	// AI Configuration
	EnableAI       bool
	AIUrl          string
	AIFastModel    string
	AIDeepModel    string
	AICascade      bool
	AIDeepAnalysis bool
	MultiAgent     bool // Enable multi-agent orchestration
	// Stealth Configuration
	StealthMode string // off, light, moderate, aggressive, paranoid
	// Recursive Discovery
	Recursive      bool // Enable recursive subdomain discovery
	RecursiveDepth int  // Max recursion depth (default: 3)
	NoRecursive    bool // Disable recursive (override when --enable-ai)
	// Advanced Features
	CloudScan    bool // Enable cloud asset discovery
	APIScan      bool // Enable API intelligence
	SecretsScan  bool // Enable passive credential discovery
	TechScan     bool // Enable technology fingerprinting
	ASNScan      bool // Enable ASN/CIDR expansion
	VHostScan    bool // Enable virtual host discovery
	NoCloudScan  bool // Disable cloud scan (override when --enable-ai)
	NoAPIScan    bool // Disable API scan (override when --enable-ai)
	NoSecrets    bool // Disable secrets scan (override when --enable-ai)
	NoTechScan   bool // Disable tech scan (override when --enable-ai)
	NoASNScan    bool // Disable ASN scan (override when --enable-ai)
	NoVHostScan  bool // Disable vhost scan (override when --enable-ai)
}

// Stats holds scan statistics
type Stats struct {
	TotalFound    int32
	TotalResolved int32
	TotalActive   int32
	TakeoverFound int32
	StartTime     time.Time
}

// SubdomainResult holds all information about a subdomain
type SubdomainResult struct {
	Subdomain     string   `json:"subdomain"`
	IPs           []string `json:"ips,omitempty"`
	CNAME         string   `json:"cname,omitempty"`
	PTR           string   `json:"ptr,omitempty"`
	ASN           string   `json:"asn,omitempty"`
	Org           string   `json:"org,omitempty"`
	Country       string   `json:"country,omitempty"`
	City          string   `json:"city,omitempty"`
	StatusCode    int      `json:"status_code,omitempty"`
	ContentLength int64    `json:"content_length,omitempty"`
	RedirectURL   string   `json:"redirect_url,omitempty"`
	Title         string   `json:"title,omitempty"`
	Server        string   `json:"server,omitempty"`
	Tech          []string `json:"technologies,omitempty"`
	Headers       []string `json:"headers,omitempty"`
	WAF           string   `json:"waf,omitempty"`
	TLSVersion    string   `json:"tls_version,omitempty"`
	TLSIssuer     string   `json:"tls_issuer,omitempty"`
	TLSExpiry     string   `json:"tls_expiry,omitempty"`
	TLSSelfSigned bool     `json:"tls_self_signed,omitempty"`
	// TLS Fingerprint for appliance detection
	TLSFingerprint *TLSFingerprint `json:"tls_fingerprint,omitempty"`
	Ports         []int    `json:"ports,omitempty"`
	Takeover      string   `json:"takeover,omitempty"`
	ResponseMs    int64    `json:"response_ms,omitempty"`
	FaviconHash   string   `json:"favicon_hash,omitempty"`
	RobotsTxt     bool     `json:"robots_txt,omitempty"`
	SitemapXml    bool     `json:"sitemap_xml,omitempty"`
	MXRecords     []string `json:"mx_records,omitempty"`
	TXTRecords    []string `json:"txt_records,omitempty"`
	NSRecords     []string `json:"ns_records,omitempty"`
	// Security checks
	SecurityHeaders  []string `json:"security_headers,omitempty"`
	MissingHeaders   []string `json:"missing_headers,omitempty"`
	OpenRedirect     bool     `json:"open_redirect,omitempty"`
	CORSMisconfig    string   `json:"cors_misconfig,omitempty"`
	AllowedMethods   []string `json:"allowed_methods,omitempty"`
	DangerousMethods []string `json:"dangerous_methods,omitempty"`
	// Discovery checks
	AdminPanels  []string `json:"admin_panels,omitempty"`
	GitExposed   bool     `json:"git_exposed,omitempty"`
	SvnExposed   bool     `json:"svn_exposed,omitempty"`
	BackupFiles  []string `json:"backup_files,omitempty"`
	APIEndpoints []string `json:"api_endpoints,omitempty"`
	// Cloud and Email Security
	CloudProvider string   `json:"cloud_provider,omitempty"`
	S3Buckets     []string `json:"s3_buckets,omitempty"`
	SPFRecord     string   `json:"spf_record,omitempty"`
	DMARCRecord   string   `json:"dmarc_record,omitempty"`
	EmailSecurity string   `json:"email_security,omitempty"`
	TLSAltNames   []string `json:"tls_alt_names,omitempty"`
	// JavaScript Analysis
	JSFiles   []string `json:"js_files,omitempty"`
	JSSecrets []string `json:"js_secrets,omitempty"`
	// AI Analysis
	AIFindings     []string `json:"ai_findings,omitempty"`
	AISeverity     string   `json:"ai_severity,omitempty"`
	AIModel        string   `json:"ai_model,omitempty"`
	CVEFindings    []string `json:"cve_findings,omitempty"`
	// Cloud Assets
	CloudAssets  []CloudAssetResult `json:"cloud_assets,omitempty"`
	// API Intelligence
	APIFindings  []APIFindingResult `json:"api_findings,omitempty"`
	// Secrets Discovery
	SecretsFound []SecretResult `json:"secrets_found,omitempty"`
}

// CloudAssetResult represents a cloud asset finding
type CloudAssetResult struct {
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	Provider    string   `json:"provider"`
	Status      string   `json:"status"`
	Permissions []string `json:"permissions,omitempty"`
}

// APIFindingResult represents an API finding
type APIFindingResult struct {
	Type      string   `json:"type"`
	URL       string   `json:"url"`
	Issue     string   `json:"issue"`
	Severity  string   `json:"severity"`
	Endpoints []string `json:"endpoints,omitempty"`
}

// SecretResult represents a secret finding
type SecretResult struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Match       string `json:"match"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// TLSFingerprint holds detailed certificate information for appliance detection
type TLSFingerprint struct {
	Vendor        string `json:"vendor,omitempty"`          // Detected vendor (Fortinet, Palo Alto, etc.)
	Product       string `json:"product,omitempty"`         // Product name (FortiGate, PA-xxx, etc.)
	Version       string `json:"version,omitempty"`         // Version if detectable
	SubjectCN     string `json:"subject_cn,omitempty"`      // Subject Common Name
	SubjectOrg    string `json:"subject_org,omitempty"`     // Subject Organization
	SubjectOU     string `json:"subject_ou,omitempty"`      // Subject Organizational Unit
	IssuerCN      string `json:"issuer_cn,omitempty"`       // Issuer Common Name
	IssuerOrg     string `json:"issuer_org,omitempty"`      // Issuer Organization
	SerialNumber  string `json:"serial_number,omitempty"`   // Certificate serial number
	InternalHosts []string `json:"internal_hosts,omitempty"` // Potential internal hostnames found
	ApplianceType string `json:"appliance_type,omitempty"`  // firewall, vpn, loadbalancer, proxy, etc.
}

// IPInfo holds IP geolocation data
type IPInfo struct {
	ASN     string `json:"as"`
	Org     string `json:"org"`
	Country string `json:"country"`
	City    string `json:"city"`
}

// SourceResult holds passive source results
type SourceResult struct {
	Name string
	Subs []string
	Err  error
}

// Default values
var DefaultResolvers = []string{
	"8.8.8.8:53",
	"8.8.4.4:53",
	"1.1.1.1:53",
	"1.0.0.1:53",
	"9.9.9.9:53",
}

var DefaultWordlist = []string{
	"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
	"ns3", "ns4", "dns", "dns1", "dns2", "api", "dev", "staging", "prod",
	"admin", "administrator", "app", "apps", "auth", "beta", "blog", "cdn",
	"chat", "cloud", "cms", "cpanel", "dashboard", "db", "demo", "docs",
	"email", "forum", "git", "gitlab", "help", "home", "host", "img",
	"images", "imap", "internal", "intranet", "jenkins", "jira", "lab",
	"legacy", "login", "m", "mobile", "monitor", "mx", "mysql", "new",
	"news", "old", "panel", "portal", "preview", "private", "proxy", "remote",
	"server", "shop", "smtp", "sql", "ssh", "ssl", "stage", "staging",
	"static", "status", "store", "support", "test", "testing", "tools",
	"vpn", "web", "webmail", "wiki", "www1", "www2", "www3",
}
