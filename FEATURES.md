# VAPT Scanner - Complete Features Documentation

**61 Security Tests | OWASP Top 10 Coverage | Enterprise-Grade Penetration Testing**

---

## Quick Reference

| Category | Tests | Key Features |
|----------|-------|--------------|
| Network & Infrastructure | 5 | Port scan, SSL/TLS, DNS, Subdomain takeover |
| Web Headers & Config | 8 | Security headers, CORS, Clickjacking, Cookies |
| Injection Attacks | 15 | SQL, NoSQL, LDAP, XSS, XXE, SSTI, Command |
| File & Path | 6 | LFI, RFI, Path traversal, File upload |
| Auth & Session | 6 | JWT, Session fixation, IDOR, OAuth |
| Server & Protocol | 8 | SSRF, Smuggling, Shellshock, Heartbleed |
| API & Modern Web | 7 | GraphQL, WebSocket, Rate limiting |
| Advanced Security | 6 | Deserialization, Race conditions, Timing |

---

## Network & Infrastructure Security (5 Tests)

### 1. Port Scanning
- Scans common network ports (21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080)
- Identifies open ports on target systems
- Fast timeout-based detection
- Usage: `-p` or `--ports`

### 2. SSL/TLS Certificate Validation
- Validates SSL certificates
- Displays certificate issuer information
- Shows expiration dates
- Checks SSL/TLS version
- Usage: `-s` or `--ssl`

### 3. Subdomain Enumeration
- Discovers common subdomains (www, mail, ftp, admin, api, dev, test, staging)
- DNS-based enumeration
- Identifies active subdomains
- Usage: `-d` or `--subdomain`

### 4. DNS Zone Transfer Check
- Tests AXFR requests
- Enumerates DNS records
- Identifies misconfigured nameservers
- Full zone disclosure detection

### 5. Subdomain Takeover Detection
- CNAME record analysis
- Dangling DNS records
- Third-party service checks (GitHub, Heroku, Azure, AWS)
- Unclaimed subdomain identification

---

## Web Security Headers & Configuration (8 Tests)

### 6. HTTP Security Headers Analysis
Checks for missing security headers:
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-XSS-Protection

### 7. CMS/Framework Detection
Identifies popular platforms:
- WordPress, Joomla, Drupal
- Django, Laravel, React

### 8. robots.txt & security.txt Analysis
- Retrieves and analyzes robots.txt
- Checks for security.txt (RFC 9116)
- Identifies disallowed paths

### 9. Version Disclosure Check
- Server header analysis
- X-Powered-By detection
- Framework version leakage

### 10. CORS Misconfiguration Check
- Tests for wildcard (*) origins
- Checks arbitrary origin reflection

### 11. Clickjacking Vulnerability Test
- Checks X-Frame-Options header
- Validates CSP frame-ancestors directive

### 12. HTTP Methods Testing
- Tests PUT, DELETE, TRACE, CONNECT
- OPTIONS enumeration

### 13. Cookie Security Validation
- Checks Secure, HttpOnly, SameSite flags

---

## Injection Vulnerabilities (15 Tests)

### 14. SQL Injection Detection
- Single quote, Boolean-based, Comment-based injection

### 15. NoSQL Injection Detection
- MongoDB operator injection, JSON payloads

### 16. LDAP Injection Testing
- Wildcard injection, Authentication bypass

### 17. Cross-Site Scripting (XSS) Testing
- Reflected XSS, Script tag, Event handler injection

### 18. XML External Entity (XXE) Injection
- File disclosure via XML

### 19. Server-Side Template Injection (SSTI)
- Jinja2, Twig, Freemarker detection

### 20. Command Injection Detection
- OS command execution, Shell metacharacters

### 21. Server-Side Include (SSI) Injection
- SSI directive testing, Command execution

### 22. XPATH Injection Testing
- XML query manipulation

### 23. Email Header Injection
- SMTP header, Cc/Bcc injection

### 24. CRLF Injection Testing
- HTTP header injection, Response splitting

### 25. Host Header Injection
- Password reset poisoning, Cache poisoning

### 26. XML Bomb (Billion Laughs) Test
- Entity expansion DoS attacks

### 27. Prototype Pollution (JavaScript)
- __proto__ manipulation, Constructor pollution

### 28. Mass Assignment Vulnerability
- Parameter injection, Role escalation

---

## File & Path Vulnerabilities (6 Tests)

### 29. Local File Inclusion (LFI) Testing
- Path traversal, /etc/passwd access

### 30. Remote File Inclusion (RFI) Testing
- Remote file loading, Code execution

### 31. Path Traversal Testing
- Advanced encoding, Double encoding

### 32. Information Disclosure Check
- .env, .git/config, phpinfo.php, config.php

### 33. Backup File Detection
- .bak, .old, .backup, .zip, .tar.gz, ~, .swp

### 34. File Upload Vulnerabilities
- Extension bypass, MIME manipulation

---

## Authentication & Session Security (6 Tests)

### 35. JWT Security Analysis
- 'none' algorithm vulnerability
- JWT header configuration analysis

### 36. Session Fixation Testing
- Session ID prediction, Cookie manipulation

### 37. Insecure Direct Object Reference (IDOR)
- ID enumeration, Sequential ID prediction

### 38. OAuth/OIDC Misconfiguration
- Redirect URI validation, Token endpoint security

### 39. API Authentication Bypass
- Missing auth checks, Broken authorization

### 40. Timing Attack Detection
- Response time analysis, Authentication timing leaks

---

## Server & Protocol Vulnerabilities (8 Tests)

### 41. Server-Side Request Forgery (SSRF)
- Internal network access, AWS metadata

### 42. HTTP Request Smuggling
- CL.TE/TE.CL desync attacks

### 43. HTTP Response Splitting
- Response header injection

### 44. Shellshock Vulnerability Test
- Bash environment variable injection

### 45. Heartbleed / TLS Posture Check
- Reports the negotiated TLS protocol version
- Flags deprecated protocols (SSLv2/3, TLSv1.0/1.1)
- Note: does not send a live heartbeat probe and cannot confirm server-side
  Heartbleed (CVE-2014-0160); use a dedicated tool for definitive testing

### 46. Weak Cipher Detection
- RC4, DES, MD5, NULL ciphers

### 47. Mixed Content Check
- HTTP resources on HTTPS

### 48. Content-Type Confusion
- MIME type mismatch, File upload bypass

---

## API & Modern Web Security (7 Tests)

### 49. API Endpoint Discovery
- GraphQL, Swagger/OpenAPI, REST API

### 50. API Rate Limiting Check
- Brute force protection, DoS assessment

### 51. GraphQL Introspection Check
- Schema enumeration, Query discovery

### 52. WebSocket Security Testing
- WebSocket upgrade detection

### 53. Directory Enumeration
- /admin, /login, /backup, /config, /api

### 54. Open Redirect Detection
- Unvalidated redirect vulnerabilities

### 55. Cache Poisoning Test
- X-Forwarded-Host manipulation, CDN poisoning

---

## Advanced Security Tests (6 Tests)

### 56. Insecure Deserialization Check
- Python pickle, Java serialization detection

### 57. HTTP Parameter Pollution (HPP)
- Duplicate parameters, WAF bypass

### 58. IP Spoofing/Security Bypass
- X-Forwarded-For, X-Real-IP manipulation

### 59. Insecure Cryptographic Storage
- MD5/SHA1 detection, Base64 secrets

### 60. Race Condition Testing
- Concurrent requests, TOCTOU vulnerabilities

### 61. Insufficient Transport Layer Protection
- Protocol downgrade, TLS stripping

---

## Usage Examples

```bash
# Single feature tests
python vapt_scanner.py -t example.com -p --confirm-authorized              # Port scan
python vapt_scanner.py -t example.com -s --confirm-authorized              # SSL check
python vapt_scanner.py -t example.com -d --confirm-authorized              # Subdomain enum

# Web vulnerability scan
python vapt_scanner.py -t example.com -u http://example.com -w --confirm-authorized

# Comprehensive scan (all tests)
python vapt_scanner.py -t example.com -u http://example.com -a --confirm-authorized
```

## Command-Line Options

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-t` | `--target` | Target IP address or domain (required) |
| `-u` | `--url` | Target URL for web vulnerability tests |
| `-p` | `--ports` | Run port scanning |
| `-s` | `--ssl` | Check SSL/TLS certificate |
| `-d` | `--subdomain` | Enumerate subdomains |
| `-w` | `--web` | Run web vulnerability tests |
| `-a` | `--all` | Run all available tests |
| `-o` | `--output` | Write full JSON report to file (captures every executed test) |
|      | `--delay` | Seconds to wait between HTTP requests (politeness/rate control) |
|      | `--confirm-authorized` | Required acknowledgment that you are authorized to test the target |

## Output Indicators

- `[*]` - Information/Status message
- `[+]` - Success/Found/Secure
- `[-]` - Not found/Missing
- `[!]` - Vulnerability detected/Warning

## Vulnerability Coverage

### OWASP Top 10 (Complete Coverage)
1. Injection - 15 different types
2. Broken Authentication - JWT, Session, OAuth
3. Sensitive Data Exposure - Info disclosure, Version leakage
4. XML External Entities (XXE)
5. Broken Access Control - LFI, RFI, IDOR
6. Security Misconfiguration - Headers, CORS, Methods
7. Cross-Site Scripting (XSS)
8. Insecure Deserialization
9. Using Components with Known Vulnerabilities
10. Insufficient Logging & Monitoring

### Additional Coverage
- Protocol-level attacks (HTTP smuggling, response splitting)
- Infrastructure vulnerabilities (DNS, SSL/TLS, Shellshock, Heartbleed)
- Modern web technologies (GraphQL, WebSocket, JWT, OAuth)
- API security (Authentication, rate limiting, endpoint discovery)
- Advanced attacks (Race conditions, Timing, Prototype pollution)

## Security & Legal Notice

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This tool is designed for:
- Security professionals conducting authorized penetration tests
- System administrators testing their own infrastructure
- Educational purposes in controlled environments
- Bug bounty programs with proper authorization

**Unauthorized use is illegal and unethical.**

Always obtain explicit written permission before testing any system you do not own.

## Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- requests >= 2.31.0
- urllib3 >= 2.0.0
- dnspython >= 2.4.0

## Best Practices

1. **Always get authorization** before scanning
2. **Start with passive reconnaissance** (DNS, subdomain enum)
3. **Use rate limiting** to avoid DoS
4. **Document findings** with screenshots and evidence
5. **Verify vulnerabilities** manually before reporting
6. **Follow responsible disclosure** practices
7. **Test in staging environments** first when possible

## Limitations

- Basic vulnerability detection (not comprehensive)
- No exploitation capabilities
- Limited payload coverage
- Designed for educational purposes
- May produce false positives/negatives
- Not a replacement for professional security tools like Burp Suite, OWASP ZAP, or Metasploit

## Future Enhancements

- Report generation (HTML/PDF/JSON)
- Multi-threaded scanning optimization
- Custom payload support
- Proxy support (HTTP/SOCKS)
- Authentication support
- Cloud-specific tests (AWS, Azure, GCP)
- Container security checks
- Compliance reporting (PCI-DSS, HIPAA)
