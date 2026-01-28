from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import joblib
import re
from urllib.parse import urlparse

# app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Load the trained ML model
try:
    ml_model = joblib.load('phishing_model.pkl')
    feature_names = joblib.load('feature_names.pkl')
    print("✓ ML model loaded successfully!")
except FileNotFoundError:
    ml_model = None
    feature_names = None
    print("⚠ Warning: ML model not found. Run train_model.py first.")

def extract_url_features(url):
    """
    Extract features from URL for ML prediction
    Returns a dictionary with 13 numerical features
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

def predict_url_ml(url):
    """
    Predict if URL is malicious using the trained ML model
    Returns: (classification, confidence_percentage)
    """
    if ml_model is None:
        return "Model not loaded", 0
    
    try:
        # Extract features
        features = extract_url_features(url)
        
        # Convert to list in correct order
        feature_values = [features[name] for name in feature_names]
        
        # Make prediction
        prediction = ml_model.predict([feature_values])[0]
        
        # Get prediction probability
        probabilities = ml_model.predict_proba([feature_values])[0]
        confidence = max(probabilities) * 100
        
        return prediction, confidence
    
    except Exception as e:
        return f"Error: {str(e)}", 0

#routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/test')
def test():
    return jsonify({'status': 'working', 'message': 'Flask is running!'})

@app.route('/scan')
def scan():
    return render_template('scan.html')


@app.route('/url', methods=['GET', 'POST'])
def url_scan():
    print(f"\n[DEBUG] ===== URL ROUTE HIT =====")
    print(f"[DEBUG] Method: {request.method}")
    print(f"[DEBUG] Content-Type: {request.content_type}")
    print(f"[DEBUG] Form data: {request.form}")
    
    if request.method == 'POST':
        try:
            url = request.form.get("url", '').strip()
            
            print(f"[DEBUG] ====== NEW URL SCAN REQUEST ======")
            print(f"[DEBUG] Received URL: '{url}'")

            if not url.startswith(('http://', 'https://')):
                print(f"[DEBUG] Invalid URL format")
                return jsonify({
                    'success': False,
                    'message': 'Invalid URL format. Please include http:// or https://'
                })
            
            # Use ML model for prediction
            print(f"[DEBUG] Calling predict_url_ml()...")
            ml_prediction, ml_confidence = predict_url_ml(url)
            print(f"[DEBUG] ML Prediction: '{ml_prediction}', Confidence: {ml_confidence}%")
            
            # Format the result with classification details
            if ml_prediction.lower() == 'benign':
                risk_emoji = "✅"
                risk_level = "Low Risk"
                verdict_class = "safe"
            elif ml_prediction.lower() == 'phishing':
                risk_emoji = "🎣"
                risk_level = "High Risk - Phishing Detected"
                verdict_class = "phishing"
            elif ml_prediction.lower() == 'malware':
                risk_emoji = "🦠"
                risk_level = "Critical Risk - Malware Detected"
                verdict_class = "malicious"
            elif ml_prediction.lower() == 'defacement':
                risk_emoji = "⚠️"
                risk_level = "Medium Risk - Defacement Detected"
                verdict_class = "defacement"
            else:
                risk_emoji = "⚠️"
                risk_level = "Suspicious Activity"
                verdict_class = "warning"
            
            result = {
                'success': True,
                'url': url,
                'classification': ml_prediction.upper(),
                'risk_level': risk_level,
                'confidence': f"{ml_confidence:.1f}%",
                'emoji': risk_emoji,
                'verdict_class': verdict_class,
                'message': f"{risk_emoji} Classification: {ml_prediction.upper()}\n\nRisk Level: {risk_level}\nConfidence: {ml_confidence:.1f}%\n\nThis prediction is based on machine learning analysis of 651,000+ URLs."
            }
            
            print(f"[DEBUG] Returning result: {result}")
            return jsonify(result)
            
        except Exception as e:
            error_msg = str(e)
            print(f"[ERROR] URL scan error: {error_msg}")
            import traceback
            traceback.print_exc()
            return jsonify({
                'success': False,
                'message': f'Analysis error: {error_msg}'
            })
    else:
        # GET request - show empty form
        return render_template('url.html')
    
        
        
if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)