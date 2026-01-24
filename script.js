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
            <p>Connecting to Backend for <strong>${file.name}</strong>...</p>
        </div>
    `;

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('http://localhost:5000/api/scan/file', {
            method: 'POST',
            body: formData
        });
        const data = await response.json();

        resultArea.innerHTML = `
            <div class="scan-verdict ${data.verdict}">
                <span class="verdict-icon">✅</span>
                <h4>Backend Connected</h4>
                <p>${data.details}</p>
                <div class="backend-msg">Response: ${data.message}</div>
            </div>
        `;
    } catch (error) {
        resultArea.innerHTML = `<p class="error">Failed to connect to Python Backend. Make sure app.py is running.</p>`;
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
            <p>Sending URL to Backend...</p>
        </div>
    `;

    try {
        const response = await fetch('http://localhost:5000/api/scan/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });
        const data = await response.json();

        resultArea.innerHTML = `
            <div class="scan-verdict ${data.verdict}">
                <span class="verdict-icon">✅</span>
                <h4>Backend Connected</h4>
                <p>${data.details}</p>
                <div class="backend-msg">Response: ${data.message}</div>
            </div>
        `;
    } catch (error) {
        resultArea.innerHTML = `<p class="error">Failed to connect to Python Backend. Make sure app.py is running.</p>`;
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
