package http

import (
	"crypto/x509"
	"regexp"
	"strings"

	"god-eye/internal/config"
)

// AppliancePattern defines a pattern to match vendor/product from certificate fields
type AppliancePattern struct {
	Vendor        string
	Product       string
	ApplianceType string // firewall, vpn, loadbalancer, proxy, waf, appliance
	// Match patterns (any match triggers detection)
	SubjectCNPatterns  []string
	SubjectOrgPatterns []string
	SubjectOUPatterns  []string
	IssuerCNPatterns   []string
	IssuerOrgPatterns  []string
	// Version extraction regex (optional)
	VersionRegex string
}

// appliancePatterns contains known signatures for security appliances
var appliancePatterns = []AppliancePattern{
	// Fortinet FortiGate
	{
		Vendor:        "Fortinet",
		Product:       "FortiGate",
		ApplianceType: "firewall",
		SubjectCNPatterns: []string{
			"FortiGate", "FGT", "fortinet", "FGVM",
		},
		SubjectOrgPatterns: []string{"Fortinet"},
		IssuerCNPatterns:   []string{"FortiGate", "Fortinet"},
		IssuerOrgPatterns:  []string{"Fortinet"},
		VersionRegex:       `(?i)(?:FortiGate|FGT|FGVM)[_-]?(\d+[A-Z]?)`,
	},
	// Palo Alto Networks
	{
		Vendor:        "Palo Alto Networks",
		Product:       "PAN-OS",
		ApplianceType: "firewall",
		SubjectCNPatterns: []string{
			"PA-", "Palo Alto", "PAN-OS", "paloaltonetworks",
		},
		SubjectOrgPatterns: []string{"Palo Alto Networks", "paloaltonetworks"},
		IssuerOrgPatterns:  []string{"Palo Alto Networks"},
		VersionRegex:       `(?i)PA-(\d+)`,
	},
	// Cisco ASA
	{
		Vendor:        "Cisco",
		Product:       "ASA",
		ApplianceType: "firewall",
		SubjectCNPatterns: []string{
			"ASA", "Cisco ASA", "adaptive security",
		},
		SubjectOrgPatterns: []string{"Cisco"},
		IssuerOrgPatterns:  []string{"Cisco"},
		VersionRegex:       `(?i)ASA[_-]?(\d+)`,
	},
	// Cisco Firepower
	{
		Vendor:        "Cisco",
		Product:       "Firepower",
		ApplianceType: "firewall",
		SubjectCNPatterns: []string{
			"Firepower", "FTD", "FMC",
		},
		SubjectOrgPatterns: []string{"Cisco"},
	},
	// SonicWall
	{
		Vendor:        "SonicWall",
		Product:       "SonicWall",
		ApplianceType: "firewall",
		SubjectCNPatterns: []string{
			"SonicWall", "sonicwall", "SonicOS", "NSA", "TZ",
		},
		SubjectOrgPatterns: []string{"SonicWall", "SonicWALL"},
		IssuerOrgPatterns:  []string{"SonicWall", "SonicWALL"},
		VersionRegex:       `(?i)(?:NSA|TZ)[\s-]?(\d+)`,
	},
	// Check Point
	{
		Vendor:        "Check Point",
		Product:       "Gaia",
		ApplianceType: "firewall",
		SubjectCNPatterns: []string{
			"Check Point", "checkpoint", "Gaia", "SmartCenter",
		},
		SubjectOrgPatterns: []string{"Check Point"},
		IssuerOrgPatterns:  []string{"Check Point"},
	},
	// F5 BIG-IP
	{
		Vendor:        "F5",
		Product:       "BIG-IP",
		ApplianceType: "loadbalancer",
		SubjectCNPatterns: []string{
			"BIG-IP", "BIGIP", "F5 Networks", "f5.com",
		},
		SubjectOrgPatterns: []string{"F5 Networks", "F5, Inc"},
		IssuerOrgPatterns:  []string{"F5 Networks", "F5, Inc"},
		VersionRegex:       `(?i)BIG-IP\s+(\d+\.\d+)`,
	},
	// Citrix NetScaler / ADC
	{
		Vendor:        "Citrix",
		Product:       "NetScaler",
		ApplianceType: "loadbalancer",
		SubjectCNPatterns: []string{
			"NetScaler", "Citrix ADC", "ns.citrix", "citrix.com",
		},
		SubjectOrgPatterns: []string{"Citrix"},
		IssuerOrgPatterns:  []string{"Citrix"},
	},
	// Juniper
	{
		Vendor:        "Juniper",
		Product:       "Junos",
		ApplianceType: "firewall",
		SubjectCNPatterns: []string{
			"Juniper", "JunOS", "SRX", "juniper.net",
		},
		SubjectOrgPatterns: []string{"Juniper Networks"},
		IssuerOrgPatterns:  []string{"Juniper Networks"},
		VersionRegex:       `(?i)SRX[_-]?(\d+)`,
	},
	// Barracuda
	{
		Vendor:        "Barracuda",
		Product:       "Barracuda",
		ApplianceType: "waf",
		SubjectCNPatterns: []string{
			"Barracuda", "barracuda", "cudatel",
		},
		SubjectOrgPatterns: []string{"Barracuda Networks"},
		IssuerOrgPatterns:  []string{"Barracuda Networks"},
	},
	// pfSense
	{
		Vendor:        "Netgate",
		Product:       "pfSense",
		ApplianceType: "firewall",
		SubjectCNPatterns: []string{
			"pfSense", "pfsense", "Netgate",
		},
		SubjectOrgPatterns: []string{"pfSense", "Netgate"},
	},
	// OPNsense
	{
		Vendor:        "Deciso",
		Product:       "OPNsense",
		ApplianceType: "firewall",
		SubjectCNPatterns: []string{
			"OPNsense", "opnsense",
		},
	},
	// WatchGuard
	{
		Vendor:        "WatchGuard",
		Product:       "Firebox",
		ApplianceType: "firewall",
		SubjectCNPatterns: []string{
			"WatchGuard", "Firebox", "watchguard",
		},
		SubjectOrgPatterns: []string{"WatchGuard"},
	},
	// Sophos
	{
		Vendor:        "Sophos",
		Product:       "XG Firewall",
		ApplianceType: "firewall",
		SubjectCNPatterns: []string{
			"Sophos", "sophos", "XG Firewall", "Cyberoam",
		},
		SubjectOrgPatterns: []string{"Sophos"},
	},
	// Ubiquiti
	{
		Vendor:        "Ubiquiti",
		Product:       "UniFi",
		ApplianceType: "appliance",
		SubjectCNPatterns: []string{
			"Ubiquiti", "UniFi", "UBNT", "ubnt.com",
		},
		SubjectOrgPatterns: []string{"Ubiquiti"},
	},
	// MikroTik
	{
		Vendor:        "MikroTik",
		Product:       "RouterOS",
		ApplianceType: "router",
		SubjectCNPatterns: []string{
			"MikroTik", "mikrotik", "RouterOS",
		},
		SubjectOrgPatterns: []string{"MikroTik"},
	},
	// OpenVPN
	{
		Vendor:        "OpenVPN",
		Product:       "OpenVPN AS",
		ApplianceType: "vpn",
		SubjectCNPatterns: []string{
			"OpenVPN", "openvpn",
		},
		SubjectOrgPatterns: []string{"OpenVPN"},
	},
	// Pulse Secure / Ivanti
	{
		Vendor:        "Pulse Secure",
		Product:       "Pulse Connect Secure",
		ApplianceType: "vpn",
		SubjectCNPatterns: []string{
			"Pulse Secure", "pulse", "Ivanti",
		},
		SubjectOrgPatterns: []string{"Pulse Secure", "Ivanti"},
	},
	// GlobalProtect (Palo Alto VPN)
	{
		Vendor:        "Palo Alto Networks",
		Product:       "GlobalProtect",
		ApplianceType: "vpn",
		SubjectCNPatterns: []string{
			"GlobalProtect", "globalprotect",
		},
	},
	// Cisco AnyConnect
	{
		Vendor:        "Cisco",
		Product:       "AnyConnect",
		ApplianceType: "vpn",
		SubjectCNPatterns: []string{
			"AnyConnect", "anyconnect",
		},
		SubjectOrgPatterns: []string{"Cisco"},
	},
	// VMware NSX / vSphere
	{
		Vendor:        "VMware",
		Product:       "NSX",
		ApplianceType: "appliance",
		SubjectCNPatterns: []string{
			"NSX", "vSphere", "VMware", "vcenter",
		},
		SubjectOrgPatterns: []string{"VMware"},
	},
	// Imperva / Incapsula
	{
		Vendor:        "Imperva",
		Product:       "WAF",
		ApplianceType: "waf",
		SubjectCNPatterns: []string{
			"Imperva", "Incapsula",
		},
		SubjectOrgPatterns: []string{"Imperva", "Incapsula"},
	},
	// HAProxy
	{
		Vendor:        "HAProxy",
		Product:       "HAProxy",
		ApplianceType: "loadbalancer",
		SubjectCNPatterns: []string{
			"HAProxy", "haproxy",
		},
	},
	// NGINX Plus
	{
		Vendor:        "NGINX",
		Product:       "NGINX Plus",
		ApplianceType: "loadbalancer",
		SubjectCNPatterns: []string{
			"NGINX", "nginx.com",
		},
		SubjectOrgPatterns: []string{"NGINX", "F5 NGINX"},
	},
	// Kemp LoadMaster
	{
		Vendor:        "Kemp",
		Product:       "LoadMaster",
		ApplianceType: "loadbalancer",
		SubjectCNPatterns: []string{
			"Kemp", "LoadMaster",
		},
		SubjectOrgPatterns: []string{"Kemp Technologies"},
	},
	// Zyxel
	{
		Vendor:        "Zyxel",
		Product:       "USG",
		ApplianceType: "firewall",
		SubjectCNPatterns: []string{
			"Zyxel", "zyxel", "USG",
		},
		SubjectOrgPatterns: []string{"Zyxel"},
	},
	// DrayTek
	{
		Vendor:        "DrayTek",
		Product:       "Vigor",
		ApplianceType: "router",
		SubjectCNPatterns: []string{
			"DrayTek", "Vigor", "draytek",
		},
		SubjectOrgPatterns: []string{"DrayTek"},
	},
}

// AnalyzeTLSCertificate analyzes a TLS certificate for appliance fingerprinting
func AnalyzeTLSCertificate(cert *x509.Certificate) *config.TLSFingerprint {
	if cert == nil {
		return nil
	}

	fp := &config.TLSFingerprint{
		SubjectCN:    cert.Subject.CommonName,
		SerialNumber: cert.SerialNumber.String(),
	}

	// Extract organization info
	if len(cert.Subject.Organization) > 0 {
		fp.SubjectOrg = strings.Join(cert.Subject.Organization, ", ")
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		fp.SubjectOU = strings.Join(cert.Subject.OrganizationalUnit, ", ")
	}
	if len(cert.Issuer.CommonName) > 0 {
		fp.IssuerCN = cert.Issuer.CommonName
	}
	if len(cert.Issuer.Organization) > 0 {
		fp.IssuerOrg = strings.Join(cert.Issuer.Organization, ", ")
	}

	// Extract internal hostnames from DNS names
	for _, name := range cert.DNSNames {
		if isInternalHostname(name) {
			fp.InternalHosts = append(fp.InternalHosts, name)
		}
	}

	// Try to match against known appliance patterns
	matchAppliance(fp, cert)

	// Only return if we found something interesting
	if fp.Vendor != "" || len(fp.InternalHosts) > 0 || fp.SubjectOrg != "" {
		return fp
	}

	return nil
}

// matchAppliance tries to identify the appliance vendor/product
func matchAppliance(fp *config.TLSFingerprint, cert *x509.Certificate) {
	subjectCN := strings.ToLower(cert.Subject.CommonName)
	subjectOrg := strings.ToLower(strings.Join(cert.Subject.Organization, " "))
	subjectOU := strings.ToLower(strings.Join(cert.Subject.OrganizationalUnit, " "))
	issuerCN := strings.ToLower(cert.Issuer.CommonName)
	issuerOrg := strings.ToLower(strings.Join(cert.Issuer.Organization, " "))

	for _, pattern := range appliancePatterns {
		matched := false

		// Check Subject CN
		for _, p := range pattern.SubjectCNPatterns {
			if strings.Contains(subjectCN, strings.ToLower(p)) {
				matched = true
				break
			}
		}

		// Check Subject Organization
		if !matched {
			for _, p := range pattern.SubjectOrgPatterns {
				if strings.Contains(subjectOrg, strings.ToLower(p)) {
					matched = true
					break
				}
			}
		}

		// Check Subject OU
		if !matched {
			for _, p := range pattern.SubjectOUPatterns {
				if strings.Contains(subjectOU, strings.ToLower(p)) {
					matched = true
					break
				}
			}
		}

		// Check Issuer CN
		if !matched {
			for _, p := range pattern.IssuerCNPatterns {
				if strings.Contains(issuerCN, strings.ToLower(p)) {
					matched = true
					break
				}
			}
		}

		// Check Issuer Organization
		if !matched {
			for _, p := range pattern.IssuerOrgPatterns {
				if strings.Contains(issuerOrg, strings.ToLower(p)) {
					matched = true
					break
				}
			}
		}

		if matched {
			fp.Vendor = pattern.Vendor
			fp.Product = pattern.Product
			fp.ApplianceType = pattern.ApplianceType

			// Try to extract version
			if pattern.VersionRegex != "" {
				re := regexp.MustCompile(pattern.VersionRegex)
				// Check all relevant fields
				for _, field := range []string{cert.Subject.CommonName, cert.Issuer.CommonName} {
					if matches := re.FindStringSubmatch(field); len(matches) > 1 {
						fp.Version = matches[1]
						break
					}
				}
			}
			return
		}
	}
}

// isInternalHostname checks if a hostname looks like an internal name
func isInternalHostname(name string) bool {
	name = strings.ToLower(name)

	// Common internal TLDs
	internalTLDs := []string{
		".local", ".internal", ".lan", ".corp", ".home",
		".intranet", ".private", ".localdomain",
	}
	for _, tld := range internalTLDs {
		if strings.HasSuffix(name, tld) {
			return true
		}
	}

	// Internal hostname patterns
	internalPatterns := []string{
		"localhost", "fw-", "firewall", "vpn-", "gw-", "gateway",
		"proxy-", "lb-", "router", "switch", "core-", "dc-",
		"srv-", "server-", "host-", "node-", "mgmt", "management",
		"admin-", "internal-", "private-", "corp-", "office-",
	}
	for _, pattern := range internalPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}

	// IP-like patterns in hostname
	ipPattern := regexp.MustCompile(`\d{1,3}[.-]\d{1,3}[.-]\d{1,3}[.-]\d{1,3}`)
	if ipPattern.MatchString(name) {
		return true
	}

	return false
}

// IsSelfSigned checks if a certificate is self-signed
func IsSelfSigned(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}

	// Check if issuer equals subject
	if cert.Issuer.String() == cert.Subject.String() {
		return true
	}

	// Check if it's self-signed by verifying against its own public key
	err := cert.CheckSignatureFrom(cert)
	return err == nil
}
