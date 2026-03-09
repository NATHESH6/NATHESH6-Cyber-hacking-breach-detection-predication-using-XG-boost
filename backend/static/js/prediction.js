//prediction.js
// Prediction functionality
const PREDICTION_API = '/api/predict';

async function analyzeSingleURL() {
    const urlInput = document.getElementById('singleUrlInput');
    const resultSection = document.getElementById('resultSection');
    const resultContainer = document.getElementById('resultContainer');

    const url = urlInput.value.trim();

    if (!url) {
        alert('Please enter a URL to analyze!');
        return;
    }

    try {
        showLoading(resultContainer, 'Analyzing URL with XGBoost...');
        resultSection.style.display = 'block';

        const response = await fetch(PREDICTION_API, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) throw new Error('API request failed');

        const data = await response.json();
        displayPredictionResult(data, resultContainer);
        saveToHistory(data, 'prediction');

    } catch (error) {
        showError(resultContainer, error.message);
    }
}

async function analyzeBatchURLs() {
    const batchInput = document.getElementById('batchUrlsInput');
    const resultSection = document.getElementById('resultSection');
    const resultContainer = document.getElementById('resultContainer');

    const urlsText = batchInput.value.trim();

    if (!urlsText) {
        alert('Please enter URLs to analyze!');
        return;
    }

    const urls = urlsText.split('\n').filter(url => url.trim() !== '');

    try {
        showLoading(resultContainer, `Analyzing ${urls.length} URLs...`);
        resultSection.style.display = 'block';

        const response = await fetch(PREDICTION_API, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ urls: urls })
        });

        if (!response.ok) throw new Error('API request failed');

        const data = await response.json();
        displayBatchPredictionResults(data, resultContainer);

    } catch (error) {
        showError(resultContainer, error.message);
    }
}

function displayPredictionResult(data, container) {
    const riskColor = getRiskColor(data.threat_score);
    const statusIcon = data.prediction === 'malicious' ? '🚨' : '✅';

    container.innerHTML = `
        <div class="result-card ${data.prediction === 'malicious' ? 'malicious' : 'safe'}">
            <div class="result-header">
                <div class="status-icon">${statusIcon}</div>
                <div class="status-info">
                    <h4>${data.prediction.toUpperCase()} - ${data.threshold_label}</h4>
                    <p>XGBoost Prediction Result</p>
                </div>
            </div>

            <div class="risk-meter">
                <div class="risk-info">
                    <span>Threat Score:</span>
                    <strong style="color: ${riskColor}">${data.threat_score}/100</strong>
                </div>
                <div class="meter">
                    <div class="meter-fill" style="width: ${data.threat_score}%; background: ${riskColor};"></div>
                </div>
            </div>

            <div class="details-grid">
                <div class="detail-item">
                    <label>Probability:</label>
                    <span>${(data.probability * 100).toFixed(2)}%</span>
                </div>
                <div class="detail-item">
                    <label>URL:</label>
                    <span class="url-text">${data.url}</span>
                </div>
                <div class="detail-item">
                    <label>Suspicious Tokens:</label>
                    <span>${data.suspicious_tokens.length > 0 ? data.suspicious_tokens.join(', ') : 'None'}</span>
                </div>
                <div class="detail-item">
                    <label>IP in URL:</label>
                    <span>${data.ip_in_url ? 'Yes' : 'No'}</span>
                </div>
            </div>

            <div class="explanation">
                <strong>Explanation:</strong> ${data.explanation}
            </div>

            <div class="action-buttons">
                <button onclick="viewInDashboard('${data.id}')" class="btn btn-primary">
                    <i class="fas fa-chart-bar"></i> View in Dashboard
                </button>
            </div>
        </div>
    `;
}

function displayBatchPredictionResults(data, container) {
    let html = `
        <div class="batch-summary">
            <h4>Batch Analysis Summary</h4>
            <div class="summary-stats">
                <div class="stat">
                    <span class="stat-value">${data.summary.total}</span>
                    <span class="stat-label">Total URLs</span>
                </div>
                <div class="stat">
                    <span class="stat-value" style="color: #e74c3c;">${data.summary.malicious_count}</span>
                    <span class="stat-label">Malicious</span>
                </div>
                <div class="stat">
                    <span class="stat-value" style="color: #2ecc71;">${data.summary.benign_count}</span>
                    <span class="stat-label">Benign</span>
                </div>
                <div class="stat">
                    <span class="stat-value">${data.summary.breach_percentage}%</span>
                    <span class="stat-label">Breach Risk</span>
                </div>
            </div>
        </div>
    `;

    data.results.forEach(result => {
        const riskColor = getRiskColor(result.threat_score);
        const statusIcon = result.prediction === 'malicious' ? '🚨' : '✅';

        html += `
            <div class="batch-result-card ${result.prediction === 'malicious' ? 'malicious' : 'safe'}">
                <div class="batch-result-header">
                    <span class="status">${statusIcon} ${result.prediction.toUpperCase()}</span>
                    <span class="score" style="color: ${riskColor}">${result.threat_score}</span>
                </div>
                <div class="batch-url">${result.url}</div>
                <div class="batch-details">
                    <span>Probability: ${(result.probability * 100).toFixed(1)}%</span>
                    <span>Tokens: ${result.suspicious_tokens.length}</span>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

function getRiskColor(score) {
    if (score >= 80) return '#e74c3c';
    if (score >= 60) return '#f39c12';
    if (score >= 40) return '#f1c40f';
    return '#2ecc71';
}

function showLoading(container, message) {
    container.innerHTML = `
        <div class="loading-container">
            <div class="loading-spinner"></div>
            <p>${message}</p>
        </div>
    `;
}

function showError(container, message) {
    container.innerHTML = `
        <div class="error-container">
            <i class="fas fa-exclamation-circle"></i>
            <h4>Analysis Failed</h4>
            <p>${message}</p>
        </div>
    `;
}

function saveToHistory(data, type) {
    let history = JSON.parse(localStorage.getItem(`${type}History`) || '[]');
    history.unshift({
        ...data,
        timestamp: new Date().toISOString(),
        type: type
    });
    history = history.slice(0, 50);
    localStorage.setItem(`${type}History`, JSON.stringify(history));
}

function viewInDashboard(id) {
    window.location.href = '/dashboard/predict';
}

// Enter key support
document.addEventListener('DOMContentLoaded', function() {
    const singleInput = document.getElementById('singleUrlInput');
    if (singleInput) {
        singleInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                analyzeSingleURL();
            }
        });
    }
});