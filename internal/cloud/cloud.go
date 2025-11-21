package cloud

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// CloudAsset represents a discovered cloud asset
type CloudAsset struct {
	Type        string   `json:"type"`         // s3, gcs, azure, lambda, etc.
	Name        string   `json:"name"`         // bucket/function name
	URL         string   `json:"url"`          // full URL
	Provider    string   `json:"provider"`     // aws, gcp, azure
	Region      string   `json:"region,omitempty"`
	Status      string   `json:"status"`       // public, private, not_found
	Permissions []string `json:"permissions,omitempty"` // read, write, list
	Contents    []string `json:"contents,omitempty"`    // sample file names
	Size        int64    `json:"size,omitempty"`
}

// CloudScanner discovers cloud assets
type CloudScanner struct {
	client      *http.Client
	domain      string
	concurrency int
}

// NewCloudScanner creates a new cloud scanner
func NewCloudScanner(domain string, timeout int) *CloudScanner {
	return &CloudScanner{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		domain:      domain,
		concurrency: 20,
	}
}

// ScanAll performs comprehensive cloud asset discovery
func (cs *CloudScanner) ScanAll(ctx context.Context) []CloudAsset {
	var results []CloudAsset
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Generate bucket name variations
	bucketNames := cs.generateBucketNames()

	sem := make(chan struct{}, cs.concurrency)

	// Scan S3 buckets
	for _, name := range bucketNames {
		wg.Add(1)
		go func(bucketName string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			assets := cs.checkS3Bucket(bucketName)
			if len(assets) > 0 {
				mu.Lock()
				results = append(results, assets...)
				mu.Unlock()
			}
		}(name)
	}

	// Scan GCS buckets
	for _, name := range bucketNames {
		wg.Add(1)
		go func(bucketName string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			assets := cs.checkGCSBucket(bucketName)
			if len(assets) > 0 {
				mu.Lock()
				results = append(results, assets...)
				mu.Unlock()
			}
		}(name)
	}

	// Scan Azure Blob Storage
	for _, name := range bucketNames {
		wg.Add(1)
		go func(bucketName string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			assets := cs.checkAzureBlob(bucketName)
			if len(assets) > 0 {
				mu.Lock()
				results = append(results, assets...)
				mu.Unlock()
			}
		}(name)
	}

	wg.Wait()
	return results
}

// generateBucketNames generates potential bucket names based on domain
func (cs *CloudScanner) generateBucketNames() []string {
	seen := make(map[string]bool)
	var names []string

	// Extract base domain parts
	parts := strings.Split(cs.domain, ".")
	baseName := parts[0]
	if len(parts) > 1 {
		baseName = strings.Join(parts[:len(parts)-1], "-")
	}
	cleanDomain := strings.ReplaceAll(cs.domain, ".", "-")

	// Common patterns
	patterns := []string{
		cs.domain,
		cleanDomain,
		baseName,
		"%s-assets",
		"%s-static",
		"%s-media",
		"%s-images",
		"%s-uploads",
		"%s-files",
		"%s-backup",
		"%s-backups",
		"%s-data",
		"%s-logs",
		"%s-dev",
		"%s-staging",
		"%s-prod",
		"%s-production",
		"%s-test",
		"%s-private",
		"%s-public",
		"%s-internal",
		"%s-cdn",
		"%s-web",
		"%s-api",
		"%s-app",
		"%s-storage",
		"%s-archive",
		"%s-db",
		"%s-database",
		"%s-config",
		"%s-secrets",
		"%s-keys",
		"assets-%s",
		"static-%s",
		"media-%s",
		"backup-%s",
		"dev-%s",
		"staging-%s",
		"prod-%s",
	}

	for _, pattern := range patterns {
		var name string
		if strings.Contains(pattern, "%s") {
			name = fmt.Sprintf(pattern, baseName)
		} else {
			name = pattern
		}
		name = strings.ToLower(name)
		if !seen[name] && len(name) >= 3 && len(name) <= 63 {
			seen[name] = true
			names = append(names, name)
		}
	}

	return names
}

// S3ListBucketResult represents S3 XML listing response
type S3ListBucketResult struct {
	XMLName  xml.Name `xml:"ListBucketResult"`
	Contents []struct {
		Key  string `xml:"Key"`
		Size int64  `xml:"Size"`
	} `xml:"Contents"`
}

// checkS3Bucket checks for S3 bucket existence and permissions
func (cs *CloudScanner) checkS3Bucket(name string) []CloudAsset {
	var assets []CloudAsset

	// AWS regions to check
	regions := []string{
		"", // default (us-east-1)
		"us-east-1",
		"us-west-2",
		"eu-west-1",
		"eu-central-1",
		"ap-southeast-1",
	}

	for _, region := range regions {
		var url string
		if region == "" || region == "us-east-1" {
			url = fmt.Sprintf("https://%s.s3.amazonaws.com/", name)
		} else {
			url = fmt.Sprintf("https://%s.s3.%s.amazonaws.com/", name, region)
		}

		asset := cs.probeS3URL(url, name, region)
		if asset != nil {
			assets = append(assets, *asset)
			break // Found the bucket, no need to check other regions
		}
	}

	return assets
}

func (cs *CloudScanner) probeS3URL(url, name, region string) *CloudAsset {
	resp, err := cs.client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	asset := &CloudAsset{
		Type:     "s3",
		Name:     name,
		URL:      url,
		Provider: "aws",
		Region:   region,
	}

	// Read body for analysis
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))

	switch resp.StatusCode {
	case 200:
		// Bucket exists and is public
		asset.Status = "public"
		asset.Permissions = []string{"read", "list"}

		// Try to parse listing
		var listing S3ListBucketResult
		if xml.Unmarshal(body, &listing) == nil {
			for i, content := range listing.Contents {
				if i >= 10 {
					break
				}
				asset.Contents = append(asset.Contents, content.Key)
				asset.Size += content.Size
			}
		}
		return asset

	case 403:
		// IMPROVED: Validate this is a real S3 403, not a WAF/firewall
		if cs.isRealS3Response(body, resp.Header) {
			asset.Status = "private"
			asset.Permissions = []string{"exists"}
			return asset
		}
		// Likely a WAF block or generic firewall, ignore
		return nil

	case 404:
		// Bucket doesn't exist
		return nil
	}

	return nil
}

// isRealS3Response validates that a 403 response is from S3, not a WAF/firewall
func (cs *CloudScanner) isRealS3Response(body []byte, headers http.Header) bool {
	bodyStr := string(body)

	// Check for S3-specific headers
	if server := headers.Get("Server"); server != "" {
		if strings.Contains(strings.ToLower(server), "amazons3") {
			return true
		}
	}

	// Check for S3-specific error codes in XML response
	s3ErrorCodes := []string{
		"AccessDenied",
		"AllAccessDisabled",
		"AccountProblem",
		"InvalidAccessKeyId",
		"SignatureDoesNotMatch",
		"NoSuchBucket", // 404 would be expected but some configs return 403
	}

	for _, code := range s3ErrorCodes {
		if strings.Contains(bodyStr, code) {
			return true
		}
	}

	// Check for S3 XML error structure
	if strings.Contains(bodyStr, "<Error>") && strings.Contains(bodyStr, "<Code>") {
		return true
	}

	// Check for x-amz headers (S3 specific)
	for key := range headers {
		if strings.HasPrefix(strings.ToLower(key), "x-amz-") {
			return true
		}
	}

	// If response is HTML or generic error page, likely WAF
	if strings.Contains(bodyStr, "<html") || strings.Contains(bodyStr, "<!DOCTYPE") {
		return false
	}

	// Short XML-like responses are more likely real S3
	if len(body) < 1000 && strings.Contains(bodyStr, "<?xml") {
		return true
	}

	return false
}

// checkGCSBucket checks for Google Cloud Storage bucket
func (cs *CloudScanner) checkGCSBucket(name string) []CloudAsset {
	url := fmt.Sprintf("https://storage.googleapis.com/%s/", name)

	resp, err := cs.client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var assets []CloudAsset
	asset := &CloudAsset{
		Type:     "gcs",
		Name:     name,
		URL:      url,
		Provider: "gcp",
	}

	switch resp.StatusCode {
	case 200:
		asset.Status = "public"
		asset.Permissions = []string{"read", "list"}

		// Parse XML listing
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		var listing S3ListBucketResult // GCS uses similar format
		if xml.Unmarshal(body, &listing) == nil {
			for i, content := range listing.Contents {
				if i >= 10 {
					break
				}
				asset.Contents = append(asset.Contents, content.Key)
			}
		}
		assets = append(assets, *asset)

	case 403:
		asset.Status = "private"
		asset.Permissions = []string{"exists"}
		assets = append(assets, *asset)
	}

	return assets
}

// checkAzureBlob checks for Azure Blob Storage
func (cs *CloudScanner) checkAzureBlob(name string) []CloudAsset {
	// Azure uses storage account name + container
	// Try common container names
	containers := []string{"", "public", "files", "data", "assets", "media", "backup"}

	var assets []CloudAsset

	for _, container := range containers {
		var url string
		if container == "" {
			url = fmt.Sprintf("https://%s.blob.core.windows.net/?restype=container&comp=list", name)
		} else {
			url = fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list", name, container)
		}

		resp, err := cs.client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		asset := &CloudAsset{
			Type:     "azure-blob",
			Name:     name,
			URL:      url,
			Provider: "azure",
		}

		switch resp.StatusCode {
		case 200:
			asset.Status = "public"
			asset.Permissions = []string{"read", "list"}
			if container != "" {
				asset.Name = fmt.Sprintf("%s/%s", name, container)
			}
			assets = append(assets, *asset)

		case 403:
			asset.Status = "private"
			asset.Permissions = []string{"exists"}
			if container != "" {
				asset.Name = fmt.Sprintf("%s/%s", name, container)
			}
			assets = append(assets, *asset)
		}
	}

	return assets
}

// ExtractCloudURLs extracts cloud storage URLs from HTML/JS content
func ExtractCloudURLs(content string) []CloudAsset {
	var assets []CloudAsset
	seen := make(map[string]bool)

	patterns := []*regexp.Regexp{
		// S3 patterns
		regexp.MustCompile(`https?://([a-z0-9.-]+)\.s3\.amazonaws\.com`),
		regexp.MustCompile(`https?://s3\.amazonaws\.com/([a-z0-9.-]+)`),
		regexp.MustCompile(`https?://([a-z0-9.-]+)\.s3-([a-z0-9-]+)\.amazonaws\.com`),
		// GCS patterns
		regexp.MustCompile(`https?://storage\.googleapis\.com/([a-z0-9._-]+)`),
		regexp.MustCompile(`https?://([a-z0-9._-]+)\.storage\.googleapis\.com`),
		// Azure patterns
		regexp.MustCompile(`https?://([a-z0-9]+)\.blob\.core\.windows\.net`),
		// CloudFront
		regexp.MustCompile(`https?://([a-z0-9]+)\.cloudfront\.net`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 && !seen[match[0]] {
				seen[match[0]] = true
				provider := "unknown"
				assetType := "cdn"

				if strings.Contains(match[0], "s3") {
					provider = "aws"
					assetType = "s3"
				} else if strings.Contains(match[0], "googleapis") {
					provider = "gcp"
					assetType = "gcs"
				} else if strings.Contains(match[0], "azure") || strings.Contains(match[0], "windows.net") {
					provider = "azure"
					assetType = "azure-blob"
				} else if strings.Contains(match[0], "cloudfront") {
					provider = "aws"
					assetType = "cloudfront"
				}

				assets = append(assets, CloudAsset{
					Type:     assetType,
					Name:     match[1],
					URL:      match[0],
					Provider: provider,
					Status:   "found_in_content",
				})
			}
		}
	}

	return assets
}

// CheckLambdaEndpoints checks for exposed Lambda/Cloud Functions
func (cs *CloudScanner) CheckLambdaEndpoints(ctx context.Context) []CloudAsset {
	var assets []CloudAsset

	// Common Lambda/API Gateway patterns
	patterns := []string{
		"https://%s.execute-api.us-east-1.amazonaws.com/",
		"https://%s.execute-api.us-west-2.amazonaws.com/",
		"https://%s.execute-api.eu-west-1.amazonaws.com/",
		"https://%s-cloudfunctions.net/",
	}

	baseName := strings.Split(cs.domain, ".")[0]

	for _, pattern := range patterns {
		url := fmt.Sprintf(pattern, baseName)
		resp, err := cs.client.Get(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 404 && resp.StatusCode != 0 {
			provider := "aws"
			assetType := "lambda"
			if strings.Contains(pattern, "cloudfunctions") {
				provider = "gcp"
				assetType = "cloud-function"
			}

			assets = append(assets, CloudAsset{
				Type:     assetType,
				URL:      url,
				Provider: provider,
				Status:   fmt.Sprintf("http_%d", resp.StatusCode),
			})
		}
	}

	return assets
}
