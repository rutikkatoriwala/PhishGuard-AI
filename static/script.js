// Tab Logic for Scan Page
document.querySelectorAll('.tab-btn').forEach(button => {
    button.addEventListener('click', () => {
        const tabId = button.getAttribute('data-tab');

        // Remove active classes
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

        // Add active classes
        button.classList.add('active');
        document.getElementById(`${tabId}-tab`).classList.add('active');
    });
});

// File Upload Trigger
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');

if (dropZone) {
    dropZone.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            handleFileUpload(fileInput.files[0]);
        }
    });
}

async function handleFileUpload(file) {
    const resultArea = document.getElementById('scan-result');
    resultArea.classList.remove('hidden');
    resultArea.innerHTML = `
        <div class="loader-container">
            <div class="loader"></div>
            <p>AI Engine analyzing <strong>${file.name}</strong>...</p>
        </div>
    `;

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            body: formData
        });
        
        const html = await response.text();
        
        // Extract prediction from HTML response
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        
        // Try to extract the prediction/message from the response
        let prediction = '';
        let message = '';
        
        // Check for prediction in the HTML
        const predictionElement = doc.querySelector('[data-prediction]');
        if (predictionElement) {
            prediction = predictionElement.textContent;
        } else {
            // Fallback: look for common patterns in the HTML
            const bodyText = doc.body.textContent;
            if (bodyText.includes('Authenticated')) {
                prediction = 'Authenticated';
            } else if (bodyText.includes('Phishing')) {
                prediction = bodyText.match(/Phishing[^"]*/)?.[0] || 'Phishing detected';
            } else if (bodyText.includes('Fraud')) {
                prediction = bodyText.match(/Fraud[^"]*/)?.[0] || 'Fraud detected';
            } else if (bodyText.includes('Malicious')) {
                prediction = bodyText.match(/Malicious[^"]*/)?.[0] || 'Malicious content detected';
            } else {
                prediction = bodyText.substring(0, 200); // Show first 200 chars
            }
        }

        // Determine verdict class based on prediction
        let verdictClass = 'safe';
        let verdictIcon = '✅';
        
        if (prediction.toLowerCase().includes('phishing')) {
            verdictClass = 'phishing';
            verdictIcon = '⚠️';
        } else if (prediction.toLowerCase().includes('fraud')) {
            verdictClass = 'fraud';
            verdictIcon = '🚫';
        } else if (prediction.toLowerCase().includes('malicious')) {
            verdictClass = 'malicious';
            verdictIcon = '☠️';
        } else if (prediction.toLowerCase().includes('authenticated')) {
            verdictClass = 'safe';
            verdictIcon = '✅';
        }

        resultArea.innerHTML = `
            <div class="scan-verdict ${verdictClass}">
                <span class="verdict-icon">${verdictIcon}</span>
                <h4>Analysis Complete</h4>
                <p><strong>Result:</strong> ${prediction}</p>
                <div class="backend-msg">File: ${file.name}</div>
            </div>
        `;
    } catch (error) {
        resultArea.innerHTML = `<p class="error">Failed to connect to Python Backend. Make sure app.py is running on port 5000.</p>`;
    }
}

async function startScan(type) {
    const urlInput = document.getElementById('url-input');
    const url = urlInput.value;

    if (!url) {
        alert("Please enter a URL first");
        return;
    }

    const resultArea = document.getElementById('scan-result');
    resultArea.classList.remove('hidden');
    resultArea.innerHTML = `
        <div class="loader-container">
            <div class="loader"></div>
            <p>AI Engine analyzing URL patterns...</p>
        </div>
    `;

    try {
        const formData = new FormData();
        formData.append('url', url);

        const response = await fetch('/url', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            const verdictClass = data.verdict_class || 'safe';
            const verdictIcon = data.emoji || '🔍';
            const classification = data.classification || 'Unknown';
            const riskLevel = data.risk_level || 'Unknown';
            const confidence = data.confidence || '0%';
            
            resultArea.innerHTML = `
                <div class="scan-verdict ${verdictClass}">
                    <span class="verdict-icon">${verdictIcon}</span>
                    <h4>URL Analysis Complete</h4>
                    <p><strong>Classification:</strong> ${classification}</p>
                    <p><strong>Risk Level:</strong> ${riskLevel}</p>
                    <p><strong>Confidence:</strong> ${confidence}</p>
                    <p><strong>Analyzed URL:</strong> ${url}</p>
                    <div class="backend-msg" style="margin-top: 15px; font-size: 0.85em; opacity: 0.8;">Based on ML analysis of 651,000+ URLs</div>
                </div>
            `;
        } else {
            resultArea.innerHTML = `
                <div class="scan-verdict error">
                    <span class="verdict-icon">❌</span>
                    <h4>Error</h4>
                    <p>${data.message || 'Unknown error occurred'}</p>
                </div>
            `;
        }
    } catch (error) {
        console.error('Scan error:', error);
        resultArea.innerHTML = `<p class="error">Failed to connect to Python Backend. Make sure app.py is running on port 5000.</p>`;
    }
}

// Add scroll effects for index page
window.addEventListener('scroll', () => {
    const header = document.getElementById('main-header');
    if (header) {
        if (window.scrollY > 50) {
            header.style.height = '80px';
            header.style.background = 'rgba(5, 7, 10, 0.98)';
        } else {
            header.style.height = '100px';
            header.style.background = 'transparent';
        }
    }
});
