import hashlib
import re
import requests

def check_common_passwords(password):
    """
    Check if the password exists in the 'Have I Been Pwned' API.
    """
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    
    if response.status_code != 200:
        print("Error checking password against common breaches.")
        return False
    
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return True
    return False


def password_strength(password):
    """
    Evaluate the strength of the password.
    """
    suggestions = []
    strength = "Strong"

    if len(password) < 8:
        strength = "Weak"
        suggestions.append("Use at least 8 characters.")
    
    if not re.search(r"[A-Z]", password):
        strength = "Medium" if strength == "Strong" else "Weak"
        suggestions.append("Add at least one uppercase letter.")

    if not re.search(r"[a-z]", password):
        strength = "Medium" if strength == "Strong" else "Weak"
        suggestions.append("Add at least one lowercase letter.")

    if not re.search(r"\d", password):
        strength = "Medium" if strength == "Strong" else "Weak"
        suggestions.append("Include at least one number.")

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        strength = "Medium" if strength == "Strong" else "Weak"
        suggestions.append("Add at least one special character (!@#$%^&*).")

    if check_common_passwords(password):
        strength = "Weak"
        suggestions.append("Avoid using common or breached passwords.")

    return strength, suggestions


def main():
    print("Password Strength Checker")
    print("-" * 30)

    password = input("Enter your password: ")
    strength, suggestions = password_strength(password)

    print(f"\nPassword Strength: {strength}")
    if suggestions:
        print("Suggestions to improve your password:")
        for suggestion in suggestions:
            print(f"- {suggestion}")

if __name__ == "__main__":
    main()
