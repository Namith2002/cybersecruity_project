import threading
import requests
import time

TARGET_URL = "http://127.0.0.1:8000"  
NUM_THREADS = 50  
REQUESTS_PER_THREAD = 20  

def send_requests():
    for _ in range(REQUESTS_PER_THREAD):
        try:
            response = requests.get(TARGET_URL)
            print(f"Request sent. Response code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
        time.sleep(0.1)

def main():
    print("DDoS Attack Simulator")
    print("-" * 30)

    threads = []
    for _ in range(NUM_THREADS):
        thread = threading.Thread(target=send_requests)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print("DDoS simulation complete.")

if __name__ == "__main__":
    main()
