from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import joblib
import re
from urllib.parse import urlparse
import io
try:
    import PyPDF2
except ImportError:
    PyPDF2 = None

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

# --- RISK CONFIGURATION ENGINE ---
RISK_WEIGHTS = {
    "THREAT_SIGNATURE": 35,   # Critical patterns (shells, persistence)
    "MALICIOUS_LINK": 25,     # Detected by ML model
    "SUSPICIOUS_PATTERN": 15, # Obfuscation (base64, etc)
    "THRESHOLD_CRITICAL": 60,
    "THRESHOLD_SUSPICIOUS": 20
}


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

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('scan.html', message="No file part")
        
        file = request.files['file']
        if file.filename == '':
            return render_template('scan.html', message="No selected file")

        try:
            content = ""
            filename = file.filename.lower()
            
            # --- FILE EXTRACTION LOGIC ---
            if filename.endswith('.txt'):
                content = file.read().decode('utf-8', errors='ignore')
            
            elif filename.endswith('.pdf'):
                if PyPDF2 is None:
                    return render_template('scan.html', message="Server Error: PyPDF2 library not installed for PDF analysis.")
                
                pdf_reader = PyPDF2.PdfReader(io.BytesIO(file.read()))
                for page in pdf_reader.pages:
                    content += page.extract_text() + "\n"
            else:
                return render_template('scan.html', message="Unsupported file type. Please use .txt or .pdf")

            # --- ADVANCED CYBERSECURITY THREAT ENGINE ---
            threat_report = []
            risk_score = 0
            
            # 1. Check for System Compromise Patterns (Shells, Registry, Execution)
            threat_signatures = {
                "REVERSE_SHELL": [r"nc -e", r"/bin/bash", r"socket\.socket", r"subprocess\.Popen", r"sh -i"],
                "PERSISTENCE": [r"reg add", r"Software\Microsoft\Windows\CurrentVersion\Run", r"schtasks", r"systemd"],
                "DATA_EXFILTRATION": [r"ftp\.", r"scp ", r"curl -F", r"POST", r"upload_file"],
                "OBFUSCATION": [r"base64", r"eval\(", r"exec\(", r"char\(", r"0x[0-9a-fA-F]{2}"],
                "AUTO_EXECUTION": [r"/OpenAction", r"/JavaScript", r"/JS", r"/EmbeddedFiles"]
            }

            for category, patterns in threat_signatures.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        weight = RISK_WEIGHTS["THREAT_SIGNATURE"] if category != "OBFUSCATION" else RISK_WEIGHTS["SUSPICIOUS_PATTERN"]
                        threat_report.append(f"🔴 {category}: Pattern '{pattern}' detected.")
                        risk_score += weight

            # 2. Extract and Scan URLs
            url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
            found_urls = list(set(url_pattern.findall(content)))
            
            malicious_links = []
            for url in found_urls[:5]:
                ml_pred, conf = predict_url_ml(url)
                # Only flag if the model explicitly identifies a malicious category
                if ml_pred.lower() in ['phishing', 'malware', 'defacement']:
                    malicious_links.append(f"🔗 Malicious Link: {url} ({ml_pred.upper()}) [Model Confidence: {conf:.1f}%]")
                    risk_score += RISK_WEIGHTS["MALICIOUS_LINK"]

            # --- FINAL VERDICT LOGIC ---
            report_data = None
            if risk_score >= RISK_WEIGHTS["THRESHOLD_SUSPICIOUS"]:
                # Generate Professional SOC Report
                severity = "CRITICAL" if risk_score >= RISK_WEIGHTS["THRESHOLD_CRITICAL"] else "HIGH"
                report_data = {
                    "incident_id": f"PG-INC-{re.sub(r'[^0-9]', '', str(hash(filename))[:6])}",
                    "severity": severity,
                    "risk_score": risk_score,
                    "analyst_summary": f"Automated static analysis detected {len(threat_report)} threat signatures and {len(malicious_links)} malicious URLs within the analyzed artifact ({filename}).",
                    "technical_details": threat_report + malicious_links,
                    "action_plan": [
                        "Do not open the file manually or execute any scripts found within.",
                        "Isolate the host system if the file was previously opened.",
                        "Clear browser cache and scan the local system with a secondary EDR tool.",
                        "Report this incident to the IT/Security department immediately."
                    ]
                }
                prediction = f"🚫 {severity} THREAT DETECTED. See Incident Report below."
            else:
                prediction = "✅ CLEAN: No known threat signatures or malicious links detected."

            return render_template('scan.html', prediction=prediction, report=report_data)

        except Exception as e:
            print(f"File Scan Error: {e}")
            return render_template('scan.html', message=f"Error processing file: {str(e)}")

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
            report_data = None
            if ml_prediction.lower() != 'benign':
                report_data = {
                    "incident_id": f"PG-URL-{re.sub(r'[^0-9]', '', str(hash(url))[:6])}",
                    "severity": "HIGH" if ml_prediction.lower() in ['phishing', 'malware'] else "MEDIUM",
                    "risk_score": 75 if ml_prediction.lower() in ['phishing', 'malware'] else 40,
                    "analyst_summary": f"ML-assisted heuristic analysis flagged this URL as {ml_prediction.upper()} (Confidence: {ml_confidence:.1f}%).",
                    "technical_details": [f"Target URL: {url}", f"Classification: {ml_prediction.upper()}", f"Model Confidence: {ml_confidence:.1f}%"],
                    "action_plan": [
                        "Block this domain at the firewall/DNS level.",
                        "Check web proxy logs for any other traffic to this destination.",
                        "Reset user credentials if the user previously interacted with this link."
                    ]
                }

            result = {
                'success': True,
                'url': url,
                'classification': ml_prediction.upper(),
                'risk_level': risk_level,
                'confidence': f"{ml_confidence:.1f}%",
                'emoji': risk_emoji,
                'verdict_class': verdict_class,
                'report': report_data,
                'message': f"{risk_emoji} Classification: {ml_prediction.upper()}\n\nRisk Level: {risk_level}\nModel Confidence: {ml_confidence:.1f}%\n\nThis prediction is based on machine learning analysis of 651,000+ URLs."
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