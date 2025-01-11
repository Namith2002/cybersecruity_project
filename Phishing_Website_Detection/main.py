import re
from urllib.parse import urlparse
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# Predefined training dataset (URLs and labels)
data = {
    "url": [
        "https://secure-bank.com/login",
        "http://free-money.xyz",
        "https://google.com",
        "http://ph1shing-site.org",
        "https://paypal.com",
        "http://fraudulent-link.co.uk"
    ],
    "is_phishing": [0, 1, 0, 1, 0, 1]
}

# Convert to DataFrame
df = pd.DataFrame(data)

def extract_features(url):
    """
    Extract features from a URL for phishing detection.
    """
    features = {}
    features["length"] = len(url)  # URL length
    features["has_https"] = int(url.startswith("https"))  # HTTPS present
    features["num_dots"] = url.count(".")  # Count dots
    features["has_suspicious_words"] = int(
        bool(re.search(r"free|money|offer|phish|login|secure|bank", url.lower()))
    )  # Suspicious words
    return features

def prepare_dataset(df):
    """
    Prepare dataset by extracting features from URLs.
    """
    feature_list = []
    for url in df["url"]:
        feature_list.append(extract_features(url))
    return pd.DataFrame(feature_list)

def train_model():
    """
    Train a phishing detection model using Random Forest.
    """
    X = prepare_dataset(df)
    y = df["is_phishing"]

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    return model

def analyze_url(url, model):
    """
    Analyze a URL to determine if it's phishing or legitimate.
    """
    features = extract_features(url)
    features_df = pd.DataFrame([features])
    prediction = model.predict(features_df)[0]
    return prediction

def main():
    print("Phishing Website Detection Tool")
    print("-" * 40)

    # Train the model
    model = train_model()

    while True:
        print("\nOptions:")
        print("1. Analyze a URL")
        print("2. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            url = input("Enter the URL to analyze: ")
            result = analyze_url(url, model)
            if result == 1:
                print(f"The URL '{url}' is likely a phishing site!")
            else:
                print(f"The URL '{url}' appears to be legitimate.")
        elif choice == "2":
            print("Exiting the tool.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
