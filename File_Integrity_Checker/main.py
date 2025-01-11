import hashlib
import os

def compute_file_hash(file_path, algorithm="sha256"):
    """
    Compute the hash of a file using the specified algorithm.
    """
    if not os.path.exists(file_path):
        print(f"File '{file_path}' not found.")
        return None

    hash_func = hashlib.new(algorithm)
    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def verify_file_integrity(file_path, stored_hash, algorithm="sha256"):
    """
    Verify the integrity of a file by comparing its hash with a stored value.
    """
    computed_hash = compute_file_hash(file_path, algorithm)
    if computed_hash == stored_hash:
        print("File integrity verified. No changes detected.")
    else:
        print("File integrity check failed! The file has been modified.")

def main():
    print("File Integrity Checker")
    print("-" * 30)

    while True:
        print("\nOptions:")
        print("1. Compute File Hash")
        print("2. Verify File Integrity")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            file_path = input("Enter the file path: ")
            algorithm = input("Enter hash algorithm (e.g., sha256, md5): ").lower()
            file_hash = compute_file_hash(file_path, algorithm)
            if file_hash:
                print(f"Computed {algorithm.upper()} hash: {file_hash}")
        elif choice == "2":
            file_path = input("Enter the file path: ")
            stored_hash = input("Enter the stored hash value: ")
            algorithm = input("Enter hash algorithm (e.g., sha256, md5): ").lower()
            verify_file_integrity(file_path, stored_hash, algorithm)
        elif choice == "3":
            print("Exiting the tool.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
