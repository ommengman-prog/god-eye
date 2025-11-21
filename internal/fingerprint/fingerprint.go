package fingerprint

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Technology represents a detected technology
type Technology struct {
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Version    string   `json:"version,omitempty"`
	Confidence int      `json:"confidence"` // 0-100
	CVEs       []string `json:"cves,omitempty"`
	Website    string   `json:"website,omitempty"`
}

// TechScanner performs technology fingerprinting
type TechScanner struct {
	client   *http.Client
	patterns []*TechPattern
}

// TechPattern defines detection patterns for a technology
type TechPattern struct {
	Name        string
	Category    string
	Website     string
	Headers     map[string]*regexp.Regexp // Header name -> value pattern
	Cookies     []string                  // Cookie names
	HTML        []*regexp.Regexp          // HTML body patterns
	Scripts     []*regexp.Regexp          // Script src patterns
	Meta        map[string]*regexp.Regexp // Meta tag name -> content pattern
	Implies     []string                  // Other technologies implied
	VersionExtr *regexp.Regexp            // Version extraction pattern
}

// NewTechScanner creates a new technology scanner
func NewTechScanner(timeout int) *TechScanner {
	return &TechScanner{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		patterns: getTechPatterns(),
	}
}

// ScanHost scans a host for technologies
func (ts *TechScanner) ScanHost(ctx context.Context, host string) []Technology {
	var techs []Technology
	seen := make(map[string]bool)

	// Try HTTPS first, then HTTP
	urls := []string{
		"https://" + host,
		"http://" + host,
	}

	for _, url := range urls {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := ts.client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()

		// Analyze response
		for _, pattern := range ts.patterns {
			if seen[pattern.Name] {
				continue
			}

			tech := ts.matchPattern(pattern, resp, body)
			if tech != nil {
				seen[pattern.Name] = true
				techs = append(techs, *tech)

				// Add implied technologies
				for _, implied := range pattern.Implies {
					if !seen[implied] {
						seen[implied] = true
						techs = append(techs, Technology{
							Name:       implied,
							Category:   "implied",
							Confidence: 50,
						})
					}
				}
			}
		}

		// If we got results from HTTPS, skip HTTP
		if len(techs) > 0 {
			break
		}
	}

	return techs
}

// matchPattern checks if a response matches a technology pattern
func (ts *TechScanner) matchPattern(pattern *TechPattern, resp *http.Response, body []byte) *Technology {
	confidence := 0
	version := ""

	// Check headers
	for headerName, headerPattern := range pattern.Headers {
		headerValue := resp.Header.Get(headerName)
		if headerValue != "" && headerPattern.MatchString(headerValue) {
			confidence += 30
			// Try to extract version
			if pattern.VersionExtr != nil {
				if match := pattern.VersionExtr.FindStringSubmatch(headerValue); len(match) > 1 {
					version = match[1]
				}
			}
		}
	}

	// Check cookies
	for _, cookieName := range pattern.Cookies {
		for _, cookie := range resp.Cookies() {
			if strings.EqualFold(cookie.Name, cookieName) {
				confidence += 20
			}
		}
	}

	bodyStr := string(body)
	bodyLower := strings.ToLower(bodyStr)

	// Check HTML patterns
	for _, htmlPattern := range pattern.HTML {
		if htmlPattern.MatchString(bodyStr) || htmlPattern.MatchString(bodyLower) {
			confidence += 25
			// Try to extract version
			if pattern.VersionExtr != nil && version == "" {
				if match := pattern.VersionExtr.FindStringSubmatch(bodyStr); len(match) > 1 {
					version = match[1]
				}
			}
		}
	}

	// Check script patterns
	for _, scriptPattern := range pattern.Scripts {
		if scriptPattern.MatchString(bodyStr) {
			confidence += 20
		}
	}

	// Check meta tags
	for metaName, metaPattern := range pattern.Meta {
		metaRegex := regexp.MustCompile(`(?i)<meta[^>]*name=["']` + metaName + `["'][^>]*content=["']([^"']+)["']`)
		if match := metaRegex.FindStringSubmatch(bodyStr); len(match) > 1 {
			if metaPattern.MatchString(match[1]) {
				confidence += 25
				if pattern.VersionExtr != nil && version == "" {
					if verMatch := pattern.VersionExtr.FindStringSubmatch(match[1]); len(verMatch) > 1 {
						version = verMatch[1]
					}
				}
			}
		}
	}

	if confidence >= 20 {
		if confidence > 100 {
			confidence = 100
		}
		return &Technology{
			Name:       pattern.Name,
			Category:   pattern.Category,
			Version:    version,
			Confidence: confidence,
			Website:    pattern.Website,
		}
	}

	return nil
}

// ScanMultipleHosts scans multiple hosts concurrently
func (ts *TechScanner) ScanMultipleHosts(ctx context.Context, hosts []string, concurrency int) map[string][]Technology {
	results := make(map[string][]Technology)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			techs := ts.ScanHost(ctx, h)
			if len(techs) > 0 {
				mu.Lock()
				results[h] = techs
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()
	return results
}

// getTechPatterns returns compiled technology detection patterns
func getTechPatterns() []*TechPattern {
	patterns := []*TechPattern{
		// Web Servers
		{
			Name:     "Nginx",
			Category: "web-server",
			Website:  "https://nginx.org",
			Headers: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)nginx`),
			},
			VersionExtr: regexp.MustCompile(`nginx/([0-9.]+)`),
		},
		{
			Name:     "Apache",
			Category: "web-server",
			Website:  "https://httpd.apache.org",
			Headers: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)apache`),
			},
			VersionExtr: regexp.MustCompile(`Apache/([0-9.]+)`),
		},
		{
			Name:     "Microsoft-IIS",
			Category: "web-server",
			Website:  "https://www.iis.net",
			Headers: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)microsoft-iis`),
			},
			VersionExtr: regexp.MustCompile(`IIS/([0-9.]+)`),
		},
		{
			Name:     "LiteSpeed",
			Category: "web-server",
			Headers: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)litespeed`),
			},
		},
		{
			Name:     "Cloudflare",
			Category: "cdn",
			Website:  "https://cloudflare.com",
			Headers: map[string]*regexp.Regexp{
				"Server":   regexp.MustCompile(`(?i)cloudflare`),
				"Cf-Ray":   regexp.MustCompile(`.+`),
				"Cf-Cache": regexp.MustCompile(`.+`),
			},
		},

		// JavaScript Frameworks
		{
			Name:     "React",
			Category: "javascript-framework",
			Website:  "https://react.dev",
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`data-reactroot`),
				regexp.MustCompile(`__REACT_DEVTOOLS_GLOBAL_HOOK__`),
			},
			Scripts: []*regexp.Regexp{
				regexp.MustCompile(`react(?:\.min)?\.js`),
				regexp.MustCompile(`react-dom`),
			},
		},
		{
			Name:     "Vue.js",
			Category: "javascript-framework",
			Website:  "https://vuejs.org",
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`data-v-[a-f0-9]`),
				regexp.MustCompile(`__VUE__`),
			},
			Scripts: []*regexp.Regexp{
				regexp.MustCompile(`vue(?:\.min)?\.js`),
			},
		},
		{
			Name:     "Angular",
			Category: "javascript-framework",
			Website:  "https://angular.io",
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`ng-version=`),
				regexp.MustCompile(`ng-app`),
				regexp.MustCompile(`\[\(ngModel\)\]`),
			},
			VersionExtr: regexp.MustCompile(`ng-version="([0-9.]+)"`),
		},
		{
			Name:     "jQuery",
			Category: "javascript-library",
			Website:  "https://jquery.com",
			Scripts: []*regexp.Regexp{
				regexp.MustCompile(`jquery[.-]([0-9.]+)(?:\.min)?\.js`),
			},
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`jQuery\s*v?([0-9.]+)`),
			},
			VersionExtr: regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+)`),
		},
		{
			Name:     "Next.js",
			Category: "javascript-framework",
			Website:  "https://nextjs.org",
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`_next/static`),
				regexp.MustCompile(`__NEXT_DATA__`),
			},
			Implies: []string{"React", "Node.js"},
		},
		{
			Name:     "Nuxt.js",
			Category: "javascript-framework",
			Website:  "https://nuxt.com",
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`__NUXT__`),
				regexp.MustCompile(`_nuxt/`),
			},
			Implies: []string{"Vue.js", "Node.js"},
		},

		// CMS
		{
			Name:     "WordPress",
			Category: "cms",
			Website:  "https://wordpress.org",
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`wp-content/`),
				regexp.MustCompile(`wp-includes/`),
			},
			Meta: map[string]*regexp.Regexp{
				"generator": regexp.MustCompile(`(?i)wordpress`),
			},
			VersionExtr: regexp.MustCompile(`WordPress\s*([0-9.]+)`),
			Implies:     []string{"PHP", "MySQL"},
		},
		{
			Name:     "Drupal",
			Category: "cms",
			Website:  "https://drupal.org",
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`Drupal\.settings`),
				regexp.MustCompile(`/sites/default/files`),
			},
			Headers: map[string]*regexp.Regexp{
				"X-Drupal-Cache": regexp.MustCompile(`.+`),
				"X-Generator":    regexp.MustCompile(`(?i)drupal`),
			},
			Implies: []string{"PHP"},
		},
		{
			Name:     "Joomla",
			Category: "cms",
			Website:  "https://joomla.org",
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`/media/jui/`),
				regexp.MustCompile(`Joomla!`),
			},
			Meta: map[string]*regexp.Regexp{
				"generator": regexp.MustCompile(`(?i)joomla`),
			},
			Implies: []string{"PHP"},
		},

		// E-commerce
		{
			Name:     "Shopify",
			Category: "ecommerce",
			Website:  "https://shopify.com",
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`cdn\.shopify\.com`),
				regexp.MustCompile(`Shopify\.theme`),
			},
			Headers: map[string]*regexp.Regexp{
				"X-ShopId": regexp.MustCompile(`.+`),
			},
		},
		{
			Name:     "WooCommerce",
			Category: "ecommerce",
			Website:  "https://woocommerce.com",
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`woocommerce`),
				regexp.MustCompile(`wc-block-`),
			},
			Implies: []string{"WordPress", "PHP"},
		},
		{
			Name:     "Magento",
			Category: "ecommerce",
			Website:  "https://magento.com",
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`/static/version`),
				regexp.MustCompile(`Mage\.Cookies`),
			},
			Cookies: []string{"frontend", "adminhtml"},
			Implies: []string{"PHP"},
		},

		// Backend Frameworks
		{
			Name:     "PHP",
			Category: "programming-language",
			Website:  "https://php.net",
			Headers: map[string]*regexp.Regexp{
				"X-Powered-By": regexp.MustCompile(`(?i)php`),
			},
			Cookies:     []string{"PHPSESSID"},
			VersionExtr: regexp.MustCompile(`PHP/([0-9.]+)`),
		},
		{
			Name:     "ASP.NET",
			Category: "web-framework",
			Website:  "https://dotnet.microsoft.com",
			Headers: map[string]*regexp.Regexp{
				"X-Powered-By": regexp.MustCompile(`(?i)asp\.net`),
				"X-AspNet":     regexp.MustCompile(`.+`),
			},
			Cookies: []string{"ASP.NET_SessionId", ".AspNetCore.Session"},
		},
		{
			Name:     "Express",
			Category: "web-framework",
			Website:  "https://expressjs.com",
			Headers: map[string]*regexp.Regexp{
				"X-Powered-By": regexp.MustCompile(`(?i)express`),
			},
			Implies: []string{"Node.js"},
		},
		{
			Name:     "Django",
			Category: "web-framework",
			Website:  "https://djangoproject.com",
			Cookies: []string{"csrftoken", "django_language"},
			Headers: map[string]*regexp.Regexp{
				"X-Frame-Options": regexp.MustCompile(`SAMEORIGIN`), // Common Django default
			},
			Implies: []string{"Python"},
		},
		{
			Name:     "Ruby on Rails",
			Category: "web-framework",
			Website:  "https://rubyonrails.org",
			Headers: map[string]*regexp.Regexp{
				"X-Powered-By": regexp.MustCompile(`(?i)phusion|passenger`),
			},
			Cookies: []string{"_rails_session"},
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`data-turbo`),
				regexp.MustCompile(`turbolinks`),
			},
			Implies: []string{"Ruby"},
		},
		{
			Name:     "Laravel",
			Category: "web-framework",
			Website:  "https://laravel.com",
			Cookies: []string{"laravel_session", "XSRF-TOKEN"},
			Implies: []string{"PHP"},
		},
		{
			Name:     "Spring",
			Category: "web-framework",
			Website:  "https://spring.io",
			Cookies: []string{"JSESSIONID"},
			Headers: map[string]*regexp.Regexp{
				"X-Application-Context": regexp.MustCompile(`.+`),
			},
			Implies: []string{"Java"},
		},

		// Security
		{
			Name:     "Cloudflare WAF",
			Category: "waf",
			Headers: map[string]*regexp.Regexp{
				"Cf-Ray":             regexp.MustCompile(`.+`),
				"Cf-Cache-Status":   regexp.MustCompile(`.+`),
				"Cf-Request-Id":     regexp.MustCompile(`.+`),
			},
		},
		{
			Name:     "AWS WAF",
			Category: "waf",
			Headers: map[string]*regexp.Regexp{
				"X-Amzn-Waf":     regexp.MustCompile(`.+`),
				"X-Amz-Cf-Id":    regexp.MustCompile(`.+`),
			},
		},
		{
			Name:     "Akamai",
			Category: "cdn",
			Headers: map[string]*regexp.Regexp{
				"X-Akamai-Transformed": regexp.MustCompile(`.+`),
				"Akamai-Origin-Hop":    regexp.MustCompile(`.+`),
			},
		},

		// Analytics
		{
			Name:     "Google Analytics",
			Category: "analytics",
			Website:  "https://analytics.google.com",
			Scripts: []*regexp.Regexp{
				regexp.MustCompile(`google-analytics\.com/analytics\.js`),
				regexp.MustCompile(`googletagmanager\.com/gtag`),
				regexp.MustCompile(`ga\('create'`),
			},
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`UA-[0-9]+-[0-9]+`),
				regexp.MustCompile(`G-[A-Z0-9]+`),
			},
		},
		{
			Name:     "Google Tag Manager",
			Category: "tag-manager",
			Website:  "https://tagmanager.google.com",
			Scripts: []*regexp.Regexp{
				regexp.MustCompile(`googletagmanager\.com/gtm\.js`),
			},
			HTML: []*regexp.Regexp{
				regexp.MustCompile(`GTM-[A-Z0-9]+`),
			},
		},

		// Hosting/Infrastructure
		{
			Name:     "Amazon S3",
			Category: "cloud-storage",
			Headers: map[string]*regexp.Regexp{
				"X-Amz-Request-Id":  regexp.MustCompile(`.+`),
				"X-Amz-Id-2":        regexp.MustCompile(`.+`),
				"Server":            regexp.MustCompile(`AmazonS3`),
			},
		},
		{
			Name:     "Vercel",
			Category: "paas",
			Website:  "https://vercel.com",
			Headers: map[string]*regexp.Regexp{
				"X-Vercel-Id":    regexp.MustCompile(`.+`),
				"X-Vercel-Cache": regexp.MustCompile(`.+`),
			},
		},
		{
			Name:     "Netlify",
			Category: "paas",
			Website:  "https://netlify.com",
			Headers: map[string]*regexp.Regexp{
				"X-Nf-Request-Id": regexp.MustCompile(`.+`),
				"Server":          regexp.MustCompile(`Netlify`),
			},
		},
		{
			Name:     "Heroku",
			Category: "paas",
			Website:  "https://heroku.com",
			Headers: map[string]*regexp.Regexp{
				"Via": regexp.MustCompile(`vegur`),
			},
		},
	}

	return patterns
}
