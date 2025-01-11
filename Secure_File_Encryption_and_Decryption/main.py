from cryptography.fernet import Fernet
import os

def generate_key():
    """
    Generate a strong random key for encryption and save it to a file.
    """
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("Key generated and saved as 'secret.key'.")

def load_key():
    """
    Load the encryption key from the file.
    """
    if not os.path.exists("secret.key"):
        print("Key file not found. Generate a new key first.")
        return None
    with open("secret.key", "rb") as key_file:
        return key_file.read()

def encrypt_file(file_path):
    """
    Encrypt a file using the loaded encryption key.
    """
    key = load_key()
    if key is None:
        return

    fernet = Fernet(key)

    try:
        with open(file_path, "rb") as file:
            file_data = file.read()

        encrypted_data = fernet.encrypt(file_data)

        with open(file_path + ".enc", "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)

        print(f"File '{file_path}' has been encrypted and saved as '{file_path}.enc'.")
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")

def decrypt_file(file_path):
    """
    Decrypt a file using the loaded encryption key.
    """
    key = load_key()
    if key is None:
        return

    fernet = Fernet(key)

    try:
        with open(file_path, "rb") as encrypted_file:
            encrypted_data = encrypted_file.read()

        decrypted_data = fernet.decrypt(encrypted_data)

        original_file_path = file_path.replace(".enc", "")
        with open(original_file_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)

        print(f"File '{file_path}' has been decrypted and saved as '{original_file_path}'.")
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    except Exception as e:
        print(f"Decryption failed: {e}")

def main():
    print("Secure File Encryption and Decryption Tool")
    print("-" * 40)

    while True:
        print("\nChoose an option:")
        print("1. Generate Key")
        print("2. Encrypt File")
        print("3. Decrypt File")
        print("4. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            generate_key()
        elif choice == "2":
            file_path = input("Enter the file path to encrypt: ")
            encrypt_file(file_path)
        elif choice == "3":
            file_path = input("Enter the encrypted file path to decrypt: ")
            decrypt_file(file_path)
        elif choice == "4":
            print("Exiting the tool.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
