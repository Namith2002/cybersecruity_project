import itertools
import string
import time

def brute_force_attack(target_password, max_length=6):
    characters = string.ascii_letters + string.digits  # a-z, A-Z, 0-9
    attempts = 0
    start_time = time.time()

    for length in range(1, max_length + 1):
        for guess in itertools.product(characters, repeat=length):
            attempts += 1
            guess_password = ''.join(guess)
            
            if guess_password == target_password:
                end_time = time.time()
                print(f"\n🔓 Password cracked: {guess_password}")
                print(f"🕒 Time taken: {end_time - start_time:.2f} seconds")
                print(f"💥 Total attempts: {attempts}")
                return

            if attempts % 10000 == 0:  # Print progress every 10,000 attempts
                print(f"Trying: {guess_password}")

    print("❌ Password not found. Try increasing max_length.")

target_password = input("Enter the password to brute-force (max 6 chars): ")
brute_force_attack(target_password, max_length=6)
