import requests
import re
import argparse
import json
import time
import concurrent.futures
import ssl
import socket
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from datetime import datetime

class WebSecurityScanner:
    def __init__(self, target_url, threads=5, timeout=10, verbose=False):
        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.visited_urls = set()
        self.vulnerabilities = []
        self.headers = {
            'User-Agent': 'WebSecurityScanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
        }
    
    def scan(self):
        """Main scanning function"""
        print(f"[+] Starting scan of {self.target_url}")
        start_time = time.time()
        
        # Parse base domain for same-origin policy
        parsed_url = urlparse(self.target_url)
        self.base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Check SSL/TLS configuration
        self.check_ssl_tls(parsed_url.netloc)
        
        # Crawl the website and find URLs
        self.crawl(self.target_url)
        
        # Check for security headers
        self.check_security_headers(self.target_url)
        
        # Test all discovered URLs for vulnerabilities
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            urls_to_test = list(self.visited_urls)
            futures = [executor.submit(self.test_url, url) for url in urls_to_test]
            concurrent.futures.wait(futures)
        
        # Generate report
        scan_duration = time.time() - start_time
        report = self.generate_report(scan_duration)
        
        print(f"[+] Scan completed in {scan_duration:.2f} seconds")
        print(f"[+] Found {len(self.vulnerabilities)} potential vulnerabilities")
        
        return report
    
    def crawl(self, url, depth=3):
        """Crawl website to discover URLs"""
        if depth <= 0 or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        
        if self.verbose:
            print(f"[*] Crawling: {url}")
        
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links
            for link in soup.find_all('a', href=True):
                href = link['href']
                
                # Skip empty links, anchors, or javascript
                if not href or href.startswith('#') or href.startswith('javascript:'):
                    continue
                
                # Handle relative URLs
                if not href.startswith(('http://', 'https://')):
                    href = urljoin(url, href)
                
                # Stay within the same domain
                if urlparse(href).netloc == urlparse(self.base_domain).netloc:
                    self.crawl(href, depth - 1)
                    
        except Exception as e:
            if self.verbose:
                print(f"[!] Error crawling {url}: {e}")
    
    def test_url(self, url):
        """Test a single URL for vulnerabilities"""
        if self.verbose:
            print(f"[*] Testing: {url}")
        
        self.test_xss(url)
        self.test_sqli(url)
        self.test_csrf(url)
        self.test_open_redirect(url)
    
    def test_xss(self, url):
        """Test for Cross-Site Scripting (XSS) vulnerabilities"""
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '"><img src=x onerror=alert("XSS")>',
            '?<script>alert("XSS")</script>'
        ]
        
        parsed = urlparse(url)
        if not parsed.query:
            # If no query parameters, try adding some
            for param in ['id', 'search', 'q', 'query', 'page']:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={xss_payloads[0]}"
                self._send_xss_test(test_url, xss_payloads[0])
        else:
            # Test existing query parameters
            params = parsed.query.split('&')
            for param in params:
                if '=' in param:
                    name, value = param.split('=', 1)
                    for payload in xss_payloads:
                        test_url = url.replace(f"{name}={value}", f"{name}={payload}")
                        self._send_xss_test(test_url, payload)
    
    def _send_xss_test(self, url, payload):
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            # Check if our payload is reflected in the response
            if payload in response.text:
                self.add_vulnerability("Cross-Site Scripting (XSS)", url, 
                                     f"Payload {payload} was reflected in the response", "High")
        except Exception as e:
            if self.verbose:
                print(f"[!] Error testing XSS at {url}: {e}")
    
    def test_sqli(self, url):
        """Test for SQL Injection vulnerabilities"""
        sqli_payloads = [
            "' OR '1'='1", 
            "' OR '1'='1' --",
            "1' OR '1'='1",
            "admin' --",
            "1; DROP TABLE users--"
        ]
        
        parsed = urlparse(url)
        if not parsed.query:
            # If no query parameters, try adding some
            for param in ['id', 'user_id', 'product_id', 'page']:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={sqli_payloads[0]}"
                self._send_sqli_test(test_url)
        else:
            # Test existing query parameters
            params = parsed.query.split('&')
            for param in params:
                if '=' in param:
                    name, value = param.split('=', 1)
                    for payload in sqli_payloads:
                        test_url = url.replace(f"{name}={value}", f"{name}={payload}")
                        self._send_sqli_test(test_url)
    
    def _send_sqli_test(self, url):
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            # Look for SQL error messages
            sql_errors = [
                "SQL syntax", "mysql_fetch_array", "ORA-", "Microsoft SQL Server",
                "PostgreSQL", "SQLite3::", "mysqli_fetch_array", "ODBC Driver"
            ]
            
            for error in sql_errors:
                if error in response.text:
                    self.add_vulnerability("SQL Injection", url, 
                                         f"SQL error message detected: {error}", "Critical")
                    break
        except Exception as e:
            if self.verbose:
                print(f"[!] Error testing SQL injection at {url}: {e}")
    
    def test_csrf(self, url):
        """Test for Cross-Site Request Forgery (CSRF) vulnerabilities"""
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            # Check if page contains forms
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                # Check if form has CSRF token
                inputs = form.find_all('input')
                has_csrf_token = False
                
                for input_field in inputs:
                    input_name = input_field.get('name', '').lower()
                    input_id = input_field.get('id', '').lower()
                    
                    if any(csrf_name in input_name or csrf_name in input_id for csrf_name in 
                           ['csrf', 'token', '_token', 'xsrf', 'nonce']):
                        has_csrf_token = True
                        break
                
                if not has_csrf_token and form.get('method', '').lower() != 'get':
                    form_action = form.get('action', '')
                    if form_action.startswith('/'):
                        form_action = urljoin(self.base_domain, form_action)
                    elif not form_action.startswith(('http://', 'https://')):
                        form_action = urljoin(url, form_action)
                    
                    self.add_vulnerability("Cross-Site Request Forgery (CSRF)", form_action, 
                                         "Form doesn't appear to have CSRF protection", "Medium")
        except Exception as e:
            if self.verbose:
                print(f"[!] Error testing CSRF at {url}: {e}")
    
    def test_open_redirect(self, url):
        """Test for Open Redirect vulnerabilities"""
        redirect_payloads = [
            "https://evil-site.com",
            "//evil-site.com",
            "evil-site.com"
        ]
        
        parsed = urlparse(url)
        redirect_params = ['redirect', 'url', 'next', 'return', 'target', 'redir', 'destination', 'return_url']
        
        if not parsed.query:
            # If no query parameters, try adding some
            for param in redirect_params:
                for payload in redirect_payloads:
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                    self._test_redirect(test_url, payload)
        else:
            # Test existing query parameters
            params = parsed.query.split('&')
            for param in params:
                if '=' in param:
                    name, value = param.split('=', 1)
                    if name.lower() in redirect_params:
                        for payload in redirect_payloads:
                            test_url = url.replace(f"{name}={value}", f"{name}={payload}")
                            self._test_redirect(test_url, payload)
    
    def _test_redirect(self, url, payload):
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=False)
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if payload in location:
                    self.add_vulnerability("Open Redirect", url, 
                                         f"Redirects to user-controlled location: {location}", "Medium")
        except Exception as e:
            if self.verbose:
                print(f"[!] Error testing open redirect at {url}: {e}")
    
    def check_security_headers(self, url):
        """Check for missing security headers"""
        security_headers = {
            'Strict-Transport-Security': 'HSTS not implemented',
            'Content-Security-Policy': 'CSP not implemented',
            'X-Content-Type-Options': 'X-Content-Type-Options header missing',
            'X-Frame-Options': 'X-Frame-Options header missing',
            'X-XSS-Protection': 'X-XSS-Protection header missing'
        }
        
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            
            for header, message in security_headers.items():
                if header not in response.headers:
                    self.add_vulnerability("Missing Security Header", url, message, "Low")
        except Exception as e:
            if self.verbose:
                print(f"[!] Error checking security headers at {url}: {e}")
    
    def check_ssl_tls(self, hostname):
        """Check SSL/TLS configuration"""
        port = 443
        try:
            # Check if host supports HTTPS
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = cert.get('notAfter')
                    if not_after:
                        import datetime
                        expire_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expire_date - datetime.datetime.now()).days
                        
                        if days_left < 30:
                            self.add_vulnerability("SSL/TLS", f"https://{hostname}", 
                                                 f"Certificate expires in {days_left} days", "Medium")
                    
                    # Check SSL version
                    version = ssock.version()
                    if version == 'TLSv1' or version == 'TLSv1.1' or version == 'SSLv3':
                        self.add_vulnerability("SSL/TLS", f"https://{hostname}", 
                                             f"Using outdated protocol: {version}", "High")
        except (socket.timeout, ConnectionRefusedError, ssl.SSLError) as e:
            if isinstance(e, socket.timeout):
                message = "Connection timed out"
            elif isinstance(e, ConnectionRefusedError):
                message = "Connection refused"
            else:
                message = f"SSL Error: {str(e)}"
            
            self.add_vulnerability("SSL/TLS", f"https://{hostname}", message, "Info")
        except Exception as e:
            if self.verbose:
                print(f"[!] Error checking SSL/TLS for {hostname}: {e}")
    
    def add_vulnerability(self, vulnerability_type, url, description, severity):
        """Add a vulnerability to the list"""
        vuln = {
            'type': vulnerability_type,
            'url': url,
            'description': description,
            'severity': severity,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        self.vulnerabilities.append(vuln)
        
        if self.verbose:
            print(f"[!] {severity} vulnerability found: {vulnerability_type} at {url}")
    
    def generate_report(self, scan_duration):
        """Generate a JSON report of the scan results"""
        report = {
            'scan_target': self.target_url,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'scan_duration': f"{scan_duration:.2f} seconds",
            'urls_discovered': len(self.visited_urls),
            'vulnerabilities_found': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'vulnerability_summary': self._generate_summary()
        }
        
        return report
    
    def _generate_summary(self):
        """Generate a summary of vulnerability types and severities"""
        summary = {
            'by_severity': {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Info': 0
            },
            'by_type': {}
        }
        
        for vuln in self.vulnerabilities:
            # Count by severity
            severity = vuln['severity']
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Count by type
            vuln_type = vuln['type']
            if vuln_type not in summary['by_type']:
                summary['by_type'][vuln_type] = 0
            summary['by_type'][vuln_type] += 1
        
        return summary


def main():
    parser = argparse.ArgumentParser(description='Web Application Security Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('-o', '--output', help='Output file for the JSON report')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    scanner = WebSecurityScanner(
        args.url,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    try:
        report = scanner.scan()
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=4)
                print(f"[+] Report saved to {args.output}")
        else:
            print(json.dumps(report, indent=4))
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        exit(1)

if __name__ == "__main__":
    main()