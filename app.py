from flask import Flask, render_template, request
import os
import google.generativeai as genai
import PyPDF2

# app
app = Flask(__name__)

os.environ["GENAI_API_KEY"] = "AIzaSyCVuTA_qzZfkUG0_ZxfMxs8LEICAAHlf54"
genai.configure(api_key=os.environ["GENAI_API_KEY"])

#Intialize model
model = genai.GenerativeModel("gemini-2.0-flash-exp")

def predict_fake(text):
    prompt = f"""
        You are a cybersecurity expert acting as a Security Operations Center (SOC) analyst.

Your task is to analyze the following text extracted from a file (email, document, PDF, or message content) and determine whether it is legitimate or malicious.

Classification Categories (choose ONE only):
- Authenticated
- Phishing
- Fraud
- Malicious

Definitions:
- Authenticated: Legitimate content with no indicators of deception, fraud, or malicious intent.
- Phishing: Content attempting to steal credentials or sensitive information using impersonation, urgency, or social engineering.
- Fraud: Content designed to deceive users for financial gain, scams, fake offers, or false claims.
- Malicious: Content intended to distribute malware, harmful links, exploit instructions, or encourage unsafe actions.

Analysis Criteria:
Evaluate the text using the following indicators:
- Urgency or fear-based language
- Requests for passwords, OTPs, or sensitive data
- Impersonation of trusted entities (banks, companies, government, brands)
- Suspicious links, shortened URLs, or unknown domains
- Grammar inconsistencies and unnatural phrasing
- Financial诱诱诱 (rewards, refunds, lottery, prizes)
- Threats, warnings, or account suspension claims
- Instructions leading to unsafe actions

Output Rules (STRICT):
- Return ONLY one of the following outputs:
  - "Authenticated"
  - "Phishing – <short reason>"
  - "Fraud – <short reason>"
  - "Malicious – <short reason>"
- Do NOT return null values.
- Do NOT include explanations outside the final output.
- Do NOT include JSON, formatting, or extra text.
- Do NOT ask follow-up questions.
- Be precise and security-focused.

Analyze the following text:
{text}

    """
    
    response = model.generate_content(prompt)
    return response.text.strip() if response else "Classification Failed"

def url_detection(url):
    prompt = f"""
        You are a cybersecurity threat-analysis AI acting as a Security Operations Center (SOC) analyst.

Your task is to analyze a given URL and classify it into one of the following categories ONLY:
1. Phishing
2. Malware
3. Safe

Classification Definitions:
- Phishing: URLs intended to steal user credentials or sensitive information by impersonating trusted brands, using deceptive domains, misleading paths, or social-engineering techniques. 
examples: 
http://secure-paypal-login.verify-account[.]com
https://accounts-google-security[.]net/login
http://amazon-refund-confirm[.]xyz
https://login-microsoft-update[.]com/verify
http://bankofamerica-secure-auth[.]info/login

- Malware: URLs that host, deliver, or redirect to malicious content such as trojans, spyware, ransomware, exploit kits, or drive-by downloads.
examples: 
http://free-software-download[.]ru/setup.exe
https://update-flashplayer[.]cc/install.apk
http://malicious-site[.]xyz/dropper.exe
https://cdn-update-security[.]top/patch.js
http://fileshare-crack[.]site/keygen.zip

- Safe: Legitimate URLs that do not show clear indicators of phishing or malware activity.
examples: 
https://www.google.com
https://www.youtube.com
https://www.facebook.com
https://www.amazon.com
https://www.twitter.com

Analysis Constraints:
- Perform static analysis only.
- Do NOT browse the web or fetch live content.
- Base your decision strictly on the URL string.

Analysis Indicators:
Evaluate the URL using the following factors:
- Domain length, structure, and entropy
- Use of IP address instead of domain name
- Suspicious or misleading keywords (login, verify, secure, update, account, free, bonus, bank, etc.)
- Excessive or abnormal subdomains
- Uncommon or suspicious TLDs
- URL shortening services
- Presence of URL encoding, obfuscation, or hex characters
- HTTPS usage patterns
- Redirection indicators
- Brand impersonation attempts

Output Rules (STRICT):
Return the response in valid JSON format ONLY. Do not include any additional text.

JSON Format:
{{
  "url": "<input_url>",
  "classification": "Phishing | Malware | Safe",
  "risk_level": "Low | Medium | High",
  "confidence_score": "0–100%",
  "reason": [
    "Concise reason 1",
    "Concise reason 2",
    "Concise reason 3"
  ]
}}

Important Instructions:
- Choose exactly ONE classification.
- Be conservative and security-focused.
- Do not ask follow-up questions.
- Do not include disclaimers or explanations outside JSON.
- Assume this output will be used in a real-world cybersecurity system.

Analyze the following URL:
{url}
    """
    
    response = model.generate_content(prompt)
    return response.text.strip() if response else "Detection Failed"

#routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan',methods=['GET','POST'])
def scan():
    if 'file' not in request.files:
        return render_template('scan.html', message='No file selected')

    file = request.files['file']

    extracted_text = ""
    if file.filename.endswith(".pdf"):
        pdf_reader = PyPDF2.PdfReader(file)
        extracted_text = " ".join([page.extract_text() for page in pdf_reader.pages if page.extract_text()])
    elif file.filename.endswith(".txt"):
        extracted_text = file.read().decode("utf-8")
    else:
        return render_template('scan.html', message='Unsupported file format or File is Empty Or text could not be extracted')
    
    try:
        prediction = predict_fake(extracted_text)
        return render_template('scan.html', prediction=prediction)
    except Exception as e:
        error_msg = str(e)
        if 'quota' in error_msg.lower() or '429' in error_msg:
            return render_template('scan.html', message='API quota exceeded. Please try again in a few minutes or check your Gemini API plan.')
        else:
            return render_template('scan.html', message=f'Analysis error: {error_msg[:200]}')


@app.route('/url',methods=['GET','POST'])
def url_scan():
    if request.method == 'POST':
        url = request.form.get("url", '').strip()

        if not url.startswith(('http://', 'https://')):
            return render_template('url.html', message='Invalid URL format. Please include http:// or https://')
        
        try:
            classification = url_detection(url)
            return render_template('url.html', input_url = url, predicted_class = classification)
        except Exception as e:
            error_msg = str(e)
            if 'quota' in error_msg.lower() or '429' in error_msg:
                return render_template('url.html', message='API quota exceeded. Please try again in a few minutes or check your Gemini API plan.')
            else:
                return render_template('url.html', message=f'Analysis error: {error_msg[:200]}')
    
        
        
if __name__ == '__main__':
    app.run(debug=True)