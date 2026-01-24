from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    data = request.json
    url = data.get('url', '')
    print(f"Received URL for scan: {url}")
    
    # Return a simple response indicating the connection works
    return jsonify({
        "status": "success",
        "message": f"Backend received URL: {url}",
        "verdict": "safe",
        "details": "Connection established with Python Backend."
    })

@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    print(f"Received file for scan: {file.filename}")
    
    # Return a simple response indicating the connection works
    return jsonify({
        "status": "success",
        "message": f"Backend received file: {file.filename}",
        "verdict": "safe",
        "details": "Connection established with Python Backend."
    })

if __name__ == '__main__':
    print("PhishGuard AI Backend running on http://localhost:5000")
    app.run(debug=True, port=5000)
