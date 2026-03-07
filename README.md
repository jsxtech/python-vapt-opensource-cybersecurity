# VAPT Scanner

Lightweight Python-based Vulnerability Assessment and Penetration Testing tool.

## Features

- Port scanning (common ports)
- SSL/TLS certificate validation
- Subdomain enumeration
- HTTP security header analysis
- CMS/Framework detection
- robots.txt & security.txt analysis
- SQL injection detection
- XSS vulnerability testing
- Local File Inclusion (LFI) testing
- Remote File Inclusion (RFI) testing
- XML External Entity (XXE) injection
- Server-Side Request Forgery (SSRF)
- Command injection detection
- CORS misconfiguration check
- Clickjacking vulnerability test
- Open redirect detection
- JWT security analysis
- HTTP methods testing
- Cookie security validation
- Information disclosure check
- API endpoint discovery
- Backup file detection
- Directory enumeration
- LDAP injection testing
- NoSQL injection detection
- Template injection (SSTI)
- Path traversal testing
- Insecure deserialization check
- HTTP parameter pollution
- Host header injection
- Weak cipher detection
- Email header injection
- Race condition testing
- DNS zone transfer check
- Shellshock vulnerability test
- Heartbleed detection
- HTTP request smuggling
- CRLF injection testing
- XML bomb (Billion Laughs) test
- GraphQL introspection check
- WebSocket security testing
- Content-Type confusion
- HTTP response splitting
- Subdomain takeover detection
- LDAP bind bypass testing
- OAuth/OIDC misconfiguration
- API rate limiting check
- Business logic flaws
- Mass assignment vulnerability
- Insecure Direct Object Reference (IDOR)
- Server-Side Include (SSI) injection
- XPATH injection testing
- HTTP security feature bypass
- Insecure cryptographic storage
- Session fixation testing
- Insufficient transport layer protection
- File upload vulnerabilities
- API authentication bypass
- Timing attack detection
- Prototype pollution (JavaScript)

## Installation

```bash
pip install -r requirements.txt
chmod +x vapt_scanner.py
```

## Usage

**Port scan:**
```bash
python vapt_scanner.py -t 192.168.1.1 -p
```

**SSL check:**
```bash
python vapt_scanner.py -t example.com -s
```

**Subdomain enumeration:**
```bash
python vapt_scanner.py -t example.com -d
```

**Web vulnerability scan:**
```bash
python vapt_scanner.py -t example.com -u http://example.com -w
```

**Full scan:**
```bash
python vapt_scanner.py -t example.com -u http://example.com -a
```

## Legal Notice

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

Only use on systems you own or have explicit permission to test. Unauthorized access is illegal.

## License

MIT License - Use responsibly
