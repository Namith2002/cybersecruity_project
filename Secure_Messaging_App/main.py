import socket
from cryptography.fernet import Fernet

# Generate or load a key for encryption
def generate_key():
    key = Fernet.generate_key()
    with open(r"C:\Users\namit\Desktop\cyber_projects\Secure_File_Encryption_and_Decryption\secret.key", "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
    with open(r"C:\Users\namit\Desktop\cyber_projects\Secure_File_Encryption_and_Decryption\secret.key", "rb") as key_file:
        return key_file.read()

# Server
def start_server():
    key = load_key()
    fernet = Fernet(key)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 65432))
    server.listen(1)
    print("Server listening on port 65432...")

    conn, addr = server.accept()
    print(f"Connection established with {addr}")

    encrypted_message = conn.recv(1024)
    message = fernet.decrypt(encrypted_message).decode()
    print(f"Received message: {message}")

    conn.close()
    server.close()

# Client
def start_client():
    key = load_key()
    fernet = Fernet(key)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 65432))

    message = input("Enter a message to send: ")
    encrypted_message = fernet.encrypt(message.encode())
    client.send(encrypted_message)
    print("Encrypted message sent.")

    client.close()

def main():
    print("Secure Messaging App")
    print("-" * 30)

    print("Options:")
    print("1. Start Server")
    print("2. Start Client")
    print("3. Generate Encryption Key")
    print("4. Exit")

    while True:
        choice = input("Enter your choice: ")

        if choice == "1":
            start_server()
        elif choice == "2":
            start_client()
        elif choice == "3":
            generate_key()
            print("Encryption key generated and saved.")
        elif choice == "4":
            print("Exiting the app.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
