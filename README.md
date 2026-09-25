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

> All scans require the `--confirm-authorized` flag to acknowledge you have permission to test the target.

**Port scan:**
```bash
python vapt_scanner.py -t 192.168.1.1 -p --confirm-authorized
```

**SSL check:**
```bash
python vapt_scanner.py -t example.com -s --confirm-authorized
```

**Subdomain enumeration:**
```bash
python vapt_scanner.py -t example.com -d --confirm-authorized
```

**Web vulnerability scan:**
```bash
python vapt_scanner.py -t example.com -u http://example.com -w --confirm-authorized
```

**Full scan:**
```bash
python vapt_scanner.py -t example.com -u http://example.com -a --confirm-authorized
```

**Full scan with JSON report:**
```bash
python vapt_scanner.py -t example.com -u http://example.com -a --confirm-authorized -o report.json
```

**Polite scan (0.5s delay between requests):**
```bash
python vapt_scanner.py -t example.com -u http://example.com -a --confirm-authorized --delay 0.5
```

### Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Target IP or domain (required) |
| `-u, --url` | Target URL for web tests |
| `-p, --ports` | Run port scan |
| `-s, --ssl` | Check SSL/TLS certificate |
| `-d, --subdomain` | Enumerate subdomains |
| `-w, --web` | Run web vulnerability tests |
| `-a, --all` | Run all tests |
| `-o, --output` | Write full JSON report to file (captures every executed test) |
| `--delay` | Seconds to wait between HTTP requests (politeness/rate control) |
| `--confirm-authorized` | Required acknowledgment that you are authorized to test the target |

## Legal Notice

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

Only use on systems you own or have explicit permission to test. Unauthorized access is illegal.

## License

MIT License - Use responsibly
