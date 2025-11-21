package agents

// getAgentSystemPrompt returns the specialized system prompt for each agent type
func getAgentSystemPrompt(agentType AgentType) string {
	switch agentType {
	case AgentTypeXSS:
		return `You are an expert XSS (Cross-Site Scripting) security analyst specializing in:
- DOM-based XSS: Identifying unsafe DOM sinks and sources
- Reflected XSS: Finding user input reflected in responses without proper encoding
- Stored XSS: Detecting persistent XSS in databases/storage
- mXSS (Mutation XSS): HTML parser-based attacks
- Filter bypass techniques: Unicode, encoding, context-specific escapes

Your expertise includes:
- JavaScript analysis for dangerous patterns (eval, innerHTML, document.write)
- CSP bypass detection
- Template injection leading to XSS
- Event handler injection points
- SVG/IMG/IFRAME-based XSS vectors

Always cite OWASP A03:2021-Injection when relevant. Be precise about the attack vector and impact.`

	case AgentTypeSQLi:
		return `You are an expert SQL Injection security analyst specializing in:
- Error-based SQLi: Extracting data through error messages
- Blind SQLi: Boolean and time-based inference attacks
- Union-based SQLi: Combining queries to extract data
- Second-order SQLi: Delayed injection through stored procedures
- NoSQL injection: MongoDB, CouchDB, etc.

Your expertise includes:
- Database fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- WAF bypass techniques (encoding, comments, case manipulation)
- ORM-specific vulnerabilities
- Parameterized query detection
- Error message analysis for database information disclosure

Always cite OWASP A03:2021-Injection when relevant. Focus on exploitability and data exposure risk.`

	case AgentTypeAuth:
		return `You are an expert Authentication/Authorization security analyst specializing in:
- IDOR (Insecure Direct Object Reference): Unauthorized resource access
- BOLA (Broken Object Level Authorization): API authorization flaws
- Session management: Fixation, hijacking, prediction
- JWT vulnerabilities: None algorithm, key confusion, claim manipulation
- OAuth/OIDC flaws: Redirect URI manipulation, token leakage

Your expertise includes:
- Password policy analysis
- Multi-factor authentication bypass
- Privilege escalation patterns
- CSRF in authentication flows
- Account takeover vectors
- Session cookie security (Secure, HttpOnly, SameSite)

Always cite OWASP A01:2021-Broken Access Control or A07:2021-Identification and Authentication Failures when relevant.`

	case AgentTypeAPI:
		return `You are an expert API Security analyst specializing in:
- GraphQL: Introspection exposure, batching attacks, query complexity DoS
- REST: Mass assignment, verbose errors, resource enumeration
- gRPC: Reflection enabled, unvalidated input
- WebSocket: Origin validation, message injection

Your expertise includes:
- Rate limiting analysis
- API versioning exposure
- BFLA (Broken Function Level Authorization)
- Excessive data exposure in responses
- Swagger/OpenAPI security misconfigurations
- API key exposure and management

Always cite OWASP API Security Top 10 categories when relevant.`

	case AgentTypeCrypto:
		return `You are an expert Cryptography security analyst specializing in:
- TLS/SSL: Protocol versions, cipher suites, certificate validation
- Encryption: Weak algorithms (DES, RC4, MD5), ECB mode, key management
- Hashing: Weak hash functions, unsalted passwords
- Key management: Hardcoded keys, weak key generation

Your expertise includes:
- Certificate transparency issues
- HSTS preload status
- Perfect forward secrecy
- CRIME/BREACH/POODLE vulnerabilities
- Cryptographic implementation flaws
- Random number generation weaknesses

Always cite OWASP A02:2021-Cryptographic Failures when relevant.`

	case AgentTypeSecrets:
		return `You are an expert Secrets Detection analyst specializing in:
- API Keys: AWS (AKIA), Google, Azure, GitHub, Stripe, etc.
- Tokens: JWT, OAuth, Bearer tokens
- Credentials: Database connection strings, passwords
- Private keys: RSA, SSH, PGP

Your expertise includes:
- Entropy analysis for secret detection
- False positive filtering (example values, placeholders)
- Cloud provider credential patterns
- CI/CD secrets exposure
- Git history secrets leakage
- Environment variable exposure

Distinguish between test/example secrets and production secrets. Only report high-confidence real secrets.`

	case AgentTypeHeaders:
		return `You are an expert HTTP Security Headers analyst specializing in:
- CSP (Content-Security-Policy): Directive analysis, bypass detection
- CORS: Misconfigured origins, credential exposure
- HSTS: Max-age, preload, includeSubDomains
- X-Frame-Options: Clickjacking protection
- X-Content-Type-Options: MIME sniffing prevention

Your expertise includes:
- Security header completeness assessment
- Cookie security attributes (Secure, HttpOnly, SameSite)
- Information disclosure through headers (Server, X-Powered-By)
- Cache-Control security implications
- Referrer-Policy analysis
- Permissions-Policy evaluation

Provide specific remediation guidance for each missing or misconfigured header.`

	case AgentTypeGeneral:
		return `You are a general security analyst covering:
- Input validation issues
- Business logic flaws
- Information disclosure
- Configuration weaknesses
- SSRF (Server-Side Request Forgery)
- XXE (XML External Entity)
- File upload vulnerabilities
- Path traversal
- Open redirects

Perform broad security analysis and identify any issues that don't fit specific categories.
If you identify a specific vulnerability type (XSS, SQLi, etc.), note it clearly for potential re-routing.`

	default:
		return "You are a security analyst. Identify any security issues in the provided content."
	}
}

// getAgentKnowledge returns domain-specific knowledge for each agent type
func getAgentKnowledge(agentType AgentType) *AgentKnowledge {
	switch agentType {
	case AgentTypeXSS:
		return &AgentKnowledge{
			Patterns: []string{
				`<script[^>]*>`,
				`on\w+\s*=`,
				`javascript:`,
				`innerHTML\s*=`,
				`document\.write`,
				`eval\s*\(`,
				`\.html\s*\(`,
				`v-html\s*=`,
				`dangerouslySetInnerHTML`,
			},
			Indicators: []string{
				"User input reflected in page",
				"Missing output encoding",
				"Unsafe DOM manipulation",
				"CSP allows unsafe-inline",
				"Template injection point",
				"Event handler accepting user data",
			},
			CommonCVEs: []string{
				"CVE-2020-11022", // jQuery < 3.5.0 XSS
				"CVE-2021-23337", // lodash template XSS
				"CVE-2020-7660",  // serialize-javascript XSS
			},
			OWASP: "A03:2021-Injection",
			Remediation: map[string]string{
				"critical": "Implement strict output encoding using context-aware escaping (HTML, JS, URL, CSS). Deploy strict CSP.",
				"high":     "Use framework's built-in XSS protection. Avoid innerHTML, use textContent instead.",
				"medium":   "Review and sanitize all user inputs. Consider using DOMPurify for HTML sanitization.",
			},
		}

	case AgentTypeSQLi:
		return &AgentKnowledge{
			Patterns: []string{
				`'.*?'`,
				`".*?"`,
				`--\s*$`,
				`/\*.*?\*/`,
				`;\s*--`,
				`union\s+select`,
				`or\s+1\s*=\s*1`,
				`'\s+or\s+'`,
				`sleep\s*\(`,
				`benchmark\s*\(`,
			},
			Indicators: []string{
				"SQL error in response",
				"Database-specific syntax visible",
				"Query string parameters with quotes",
				"Numeric ID parameters",
				"Stack trace with SQL",
				"ORM error messages",
			},
			CommonCVEs: []string{
				"CVE-2023-34362", // MOVEit SQL injection
				"CVE-2021-26855", // Exchange ProxyLogon
				"CVE-2019-2725",  // WebLogic SQLi
			},
			OWASP: "A03:2021-Injection",
			Remediation: map[string]string{
				"critical": "Use parameterized queries/prepared statements exclusively. Never concatenate user input into SQL.",
				"high":     "Implement input validation with allowlists. Use ORM properly with parameterized queries.",
				"medium":   "Enable WAF rules for SQL injection. Implement least privilege database accounts.",
			},
		}

	case AgentTypeAuth:
		return &AgentKnowledge{
			Patterns: []string{
				`[?&]id=\d+`,
				`[?&]user_id=`,
				`Authorization:\s*Bearer`,
				`session[_-]?id`,
				`jwt[_\.]`,
				`oauth`,
				`password`,
				`login`,
			},
			Indicators: []string{
				"Direct object reference in URL",
				"Missing authorization checks",
				"Predictable session tokens",
				"JWT without signature validation",
				"OAuth misconfiguration",
				"Session fixation possible",
				"Weak password policy",
			},
			CommonCVEs: []string{
				"CVE-2023-23397", // Outlook privilege escalation
				"CVE-2022-22965", // Spring4Shell
				"CVE-2021-44228", // Log4Shell (auth bypass)
			},
			OWASP: "A01:2021-Broken Access Control",
			Remediation: map[string]string{
				"critical": "Implement proper authorization checks on every request. Use framework's RBAC/ABAC.",
				"high":     "Validate JWT signatures properly. Implement secure session management.",
				"medium":   "Enforce strong password policies. Implement account lockout after failed attempts.",
			},
		}

	case AgentTypeAPI:
		return &AgentKnowledge{
			Patterns: []string{
				`/api/v\d+/`,
				`graphql`,
				`__schema`,
				`introspection`,
				`swagger`,
				`openapi`,
				`/rest/`,
			},
			Indicators: []string{
				"GraphQL introspection enabled",
				"API documentation exposed",
				"Verbose error messages",
				"Mass assignment possible",
				"No rate limiting",
				"CORS misconfiguration",
				"API versioning exposed",
			},
			CommonCVEs: []string{
				"CVE-2023-25136", // OpenSSH double-free
				"CVE-2023-34039", // VMware Aria API auth bypass
				"CVE-2022-26134", // Confluence OGNL injection
			},
			OWASP: "API1:2023-Broken Object Level Authorization",
			Remediation: map[string]string{
				"critical": "Disable introspection in production. Implement proper authorization for all endpoints.",
				"high":     "Configure CORS properly. Implement rate limiting and request validation.",
				"medium":   "Hide API documentation in production. Use API gateway for security controls.",
			},
		}

	case AgentTypeCrypto:
		return &AgentKnowledge{
			Patterns: []string{
				`TLS\s*1\.[01]`,
				`SSL\s*[23]`,
				`RC4`,
				`DES`,
				`MD5`,
				`SHA-?1`,
				`-----BEGIN`,
				`password.*=.*["']`,
			},
			Indicators: []string{
				"Weak TLS version",
				"Deprecated cipher suite",
				"Self-signed certificate",
				"Expired certificate",
				"Missing HSTS",
				"Hardcoded encryption key",
				"Weak random number generation",
			},
			CommonCVEs: []string{
				"CVE-2014-3566", // POODLE
				"CVE-2015-0204", // FREAK
				"CVE-2016-2183", // Sweet32
			},
			OWASP: "A02:2021-Cryptographic Failures",
			Remediation: map[string]string{
				"critical": "Upgrade to TLS 1.3. Remove all weak ciphers. Rotate compromised keys immediately.",
				"high":     "Enable HSTS with long max-age. Use only strong cipher suites.",
				"medium":   "Implement certificate pinning. Use HSM for key management.",
			},
		}

	case AgentTypeSecrets:
		return &AgentKnowledge{
			Patterns: []string{
				`AKIA[0-9A-Z]{16}`,
				`ghp_[a-zA-Z0-9]{36}`,
				`sk_live_[a-zA-Z0-9]+`,
				`-----BEGIN.*PRIVATE KEY`,
				`api[_-]?key\s*[:=]`,
				`password\s*[:=]`,
				`secret\s*[:=]`,
				`token\s*[:=]`,
			},
			Indicators: []string{
				"High entropy string",
				"Known secret pattern",
				"Connection string format",
				"API key prefix pattern",
				"Base64 encoded secret",
				"Environment variable exposure",
			},
			CommonCVEs: []string{}, // Secrets are typically not CVEs
			OWASP:      "A02:2021-Cryptographic Failures",
			Remediation: map[string]string{
				"critical": "Rotate exposed secrets immediately. Use secrets manager (Vault, AWS Secrets Manager).",
				"high":     "Remove secrets from code. Use environment variables or secret management.",
				"medium":   "Implement git-secrets or truffleHog in CI/CD pipeline.",
			},
		}

	case AgentTypeHeaders:
		return &AgentKnowledge{
			Patterns: []string{
				`content-security-policy`,
				`strict-transport-security`,
				`x-frame-options`,
				`x-content-type-options`,
				`x-xss-protection`,
				`referrer-policy`,
				`permissions-policy`,
			},
			Indicators: []string{
				"Missing security headers",
				"Weak CSP directives",
				"CORS allows all origins",
				"Missing HSTS",
				"Cookie without Secure flag",
				"Cookie without HttpOnly flag",
				"Server version disclosed",
			},
			CommonCVEs: []string{},
			OWASP:      "A05:2021-Security Misconfiguration",
			Remediation: map[string]string{
				"critical": "Implement strict CSP. Enable HSTS preloading.",
				"high":     "Add all recommended security headers. Configure proper CORS policy.",
				"medium":   "Set Secure and HttpOnly on all cookies. Remove server version headers.",
			},
		}

	default: // AgentTypeGeneral
		return &AgentKnowledge{
			Patterns:   []string{},
			Indicators: []string{"General security issue", "Configuration weakness", "Information disclosure"},
			CommonCVEs: []string{},
			OWASP:      "A05:2021-Security Misconfiguration",
			Remediation: map[string]string{
				"critical": "Address the specific vulnerability immediately.",
				"high":     "Review and fix the security issue.",
				"medium":   "Plan remediation for the identified issue.",
			},
		}
	}
}
