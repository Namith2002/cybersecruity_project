import time
from itertools import product
import string

# User credentials (for demonstration purposes)
USER_CREDENTIALS = {"admin": "secure123"}

# Countermeasure: Limit login attempts
MAX_ATTEMPTS = 3
LOCKOUT_DURATION = 10  # seconds

class LoginSystem:
    def __init__(self):
        self.failed_attempts = 0
        self.locked_until = None

    def is_locked(self):
        if self.locked_until and time.time() < self.locked_until:
            return True
        self.locked_until = None
        return False

    def login(self, username, password):
        if self.is_locked():
            print(f"Account is locked. Try again later.")
            return False

        if USER_CREDENTIALS.get(username) == password:
            print("Login successful!")
            self.failed_attempts = 0
            return True
        else:
            print("Invalid username or password.")
            self.failed_attempts += 1
            if self.failed_attempts >= MAX_ATTEMPTS:
                print(f"Too many failed attempts. Locking account for {LOCKOUT_DURATION} seconds.")
                self.locked_until = time.time() + LOCKOUT_DURATION
            return False

def brute_force_attack(username, max_length=4):
    """
    Simulate a brute force attack on the login system.
    """
    characters = string.ascii_letters + string.digits  # Characters to try
    login_system = LoginSystem()

    print(f"\nStarting brute force attack on user '{username}'...\n")

    for length in range(1, max_length + 1):
        for attempt in product(characters, repeat=length):
            if login_system.is_locked():
                print(f"Account locked. Waiting for {LOCKOUT_DURATION} seconds...")
                time.sleep(LOCKOUT_DURATION)

            password_attempt = "".join(attempt)
            print(f"Trying password: {password_attempt}")
            if login_system.login(username, password_attempt):
                print(f"Brute force successful! Password is '{password_attempt}'")
                return
    print("Brute force attack failed. Password not found within given length.")

def main():
    print("Brute Force Attack Simulator")
    print("-" * 40)

    print("\nChoose an option:")
    print("1. Simulate Login")
    print("2. Simulate Brute Force Attack")
    print("3. Exit")

    while True:
        choice = input("Enter your choice: ")

        if choice == "1":
            username = input("Enter username: ")
            password = input("Enter password: ")
            login_system = LoginSystem()
            login_system.login(username, password)
        elif choice == "2":
            username = input("Enter the username to attack: ")
            brute_force_attack(username)
        elif choice == "3":
            print("Exiting the simulator.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
