import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

print("Loading dataset...")
# Load the dataset
df = pd.read_csv('malicious_phish.csv')

print(f"Dataset loaded: {len(df)} URLs")
print(f"Classes: {df['type'].value_counts()}\n")

# Feature extraction function
def extract_features(url):
    """
    Extract numerical features from a URL for machine learning
    
    Features extracted:
    1. url_length: Total characters in URL
    2. domain_length: Length of the domain name
    3. num_dots: Count of '.' characters
    4. num_hyphens: Count of '-' characters
    5. num_underscores: Count of '_' characters
    6. num_slashes: Count of '/' characters
    7. num_question: Count of '?' characters
    8. num_equals: Count of '=' characters
    9. num_at: Count of '@' characters
    10. has_ip: 1 if IP address used, 0 otherwise
    11. has_https: 1 if HTTPS, 0 otherwise
    12. suspicious_words: Count of suspicious keywords
    13. num_subdomains: Number of subdomains
    """
    
    features = {}
    
    # Basic length features
    features['url_length'] = len(url)
    
    # Parse URL
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        domain = parsed.netloc
    except:
        domain = url
    
    features['domain_length'] = len(domain)
    
    # Character count features
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_question'] = url.count('?')
    features['num_equals'] = url.count('=')
    features['num_at'] = url.count('@')
    
    # IP address detection
    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    features['has_ip'] = 1 if ip_pattern.search(url) else 0
    
    # HTTPS detection
    features['has_https'] = 1 if url.startswith('https://') else 0
    
    # Suspicious keywords
    suspicious_keywords = ['login', 'verify', 'account', 'update', 'secure', 'bank', 
                          'confirm', 'password', 'signin', 'ebay', 'paypal', 'amazon',
                          'free', 'bonus', 'click', 'here', 'winner']
    features['suspicious_words'] = sum(1 for word in suspicious_keywords if word in url.lower())
    
    # Subdomain count
    if domain:
        features['num_subdomains'] = domain.count('.') - 1 if domain.count('.') > 0 else 0
    else:
        features['num_subdomains'] = 0
    
    return features

print("Extracting features from URLs...")
# Extract features for all URLs
feature_list = []
for idx, url in enumerate(df['url']):
    if idx % 50000 == 0:
        print(f"Processed {idx}/{len(df)} URLs...")
    try:
        features = extract_features(str(url))
        feature_list.append(features)
    except:
        # If feature extraction fails, use zeros
        feature_list.append({
            'url_length': 0, 'domain_length': 0, 'num_dots': 0,
            'num_hyphens': 0, 'num_underscores': 0, 'num_slashes': 0,
            'num_question': 0, 'num_equals': 0, 'num_at': 0,
            'has_ip': 0, 'has_https': 0, 'suspicious_words': 0,
            'num_subdomains': 0
        })

print("Creating feature matrix...")
# Convert to DataFrame
X = pd.DataFrame(feature_list)
y = df['type']

print(f"\nFeature matrix shape: {X.shape}")
print(f"Features: {list(X.columns)}\n")

# Split data into training and testing sets
print("Splitting data into train (80%) and test (20%)...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print(f"Training set: {len(X_train)} samples")
print(f"Testing set: {len(X_test)} samples\n")

# Train Random Forest Classifier
print("Training Random Forest Classifier...")
print("(This may take a few minutes with 651k samples...)\n")

# Using Random Forest with 100 trees
model = RandomForestClassifier(
    n_estimators=100,      # 100 decision trees
    max_depth=20,          # Maximum depth of each tree
    random_state=42,       # For reproducibility
    n_jobs=-1,            # Use all CPU cores
    verbose=1             # Show progress
)

model.fit(X_train, y_train)

print("\nModel training complete!")

# Evaluate the model
print("\n" + "="*60)
print("MODEL EVALUATION")
print("="*60)

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f"\nAccuracy: {accuracy * 100:.2f}%\n")

print("Classification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Feature importance
print("\n" + "="*60)
print("FEATURE IMPORTANCE")
print("="*60)
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

print(feature_importance.to_string(index=False))

# Save the model
print("\n" + "="*60)
print("SAVING MODEL")
print("="*60)

model_filename = 'phishing_model.pkl'
joblib.dump(model, model_filename)
print(f"✓ Model saved as '{model_filename}'")

# Also save feature names for future use
feature_names = list(X.columns)
joblib.dump(feature_names, 'feature_names.pkl')
print(f"✓ Feature names saved as 'feature_names.pkl'")

print("\n" + "="*60)
print("TRAINING COMPLETE!")
print("="*60)
print(f"You can now use '{model_filename}' in your Flask app for real-time predictions.")
