//detection.js
// Detection functionality
const DETECTION_API = '/api/detect';

async function detectSingleURL() {
    const urlInput = document.getElementById('singleUrlInput');
    const resultSection = document.getElementById('resultSection');
    const resultContainer = document.getElementById('resultContainer');

    const url = urlInput.value.trim();

    if (!url) {
        alert('Please enter a URL to detect!');
        return;
    }

    try {
        showLoading(resultContainer, 'Scanning URL for real-time threats...');
        resultSection.style.display = 'block';

        const response = await fetch(DETECTION_API, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) throw new Error('API request failed');

        const data = await response.json();
        displayDetectionResult(data, resultContainer);
        saveToHistory(data, 'detection');

    } catch (error) {
        showError(resultContainer, error.message);
    }
}

async function detectBatchURLs() {
    const batchInput = document.getElementById('batchUrlsInput');
    const resultSection = document.getElementById('resultSection');
    const resultContainer = document.getElementById('resultContainer');

    const urlsText = batchInput.value.trim();

    if (!urlsText) {
        alert('Please enter URLs to detect!');
        return;
    }

    const urls = urlsText.split('\n').filter(url => url.trim() !== '');

    try {
        showLoading(resultContainer, `Scanning ${urls.length} URLs for threats...`);
        resultSection.style.display = 'block';

        const response = await fetch(DETECTION_API, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ urls: urls })
        });

        if (!response.ok) throw new Error('API request failed');

        const data = await response.json();
        displayBatchDetectionResults(data, resultContainer);

    } catch (error) {
        showError(resultContainer, error.message);
    }
}

function displayDetectionResult(data, container) {
    const threatColor = getThreatColor(data.threat_level);
    const statusIcon = data.status === 'malicious' ? '🚨' : '✅';

    container.innerHTML = `
        <div class="result-card ${data.status === 'malicious' ? 'malicious' : 'safe'}">
            <div class="result-header">
                <div class="status-icon">${statusIcon}</div>
                <div class="status-info">
                    <h4>${data.status.toUpperCase()} - ${data.threat_level} Threat</h4>
                    <p>Real-Time Detection Result</p>
                </div>
            </div>

            <div class="risk-meter">
                <div class="risk-info">
                    <span>Malicious Score:</span>
                    <strong style="color: ${threatColor}">${data.malicious_score}/100</strong>
                </div>
                <div class="meter">
                    <div class="meter-fill" style="width: ${data.malicious_score}%; background: ${threatColor};"></div>
                </div>
            </div>

            <div class="details-grid">
                <div class="detail-item">
                    <label>Threat Level:</label>
                    <span class="threat-badge ${data.threat_level.toLowerCase()}">${data.threat_level}</span>
                </div>
                <div class="detail-item">
                    <label>Breach Percentage:</label>
                    <span>${data.breach_percentage}%</span>
                </div>
                <div class="detail-item">
                    <label>URL:</label>
                    <span class="url-text">${data.url}</span>
                </div>
                <div class="detail-item">
                    <label>SSL Valid:</label>
                    <span>${data.ssl_valid ? 'Yes' : 'No'}</span>
                </div>
                <div class="detail-item">
                    <label>Suspicious Tokens:</label>
                    <span>${data.suspicious_tokens.length > 0 ? data.suspicious_tokens.join(', ') : 'None'}</span>
                </div>
            </div>

            <div class="threat-intel-card">
                <h5><i class="fas fa-brain"></i> Threat Intelligence</h5>
                <p>${data.threat_intel}</p>
            </div>

            <div class="recommendation-card">
                <h5><i class="fas fa-shield-alt"></i> Recommendation</h5>
                <p><strong>${data.recommendation}</strong> - ${getRecommendationExplanation(data.recommendation)}</p>
            </div>

            <div class="chart-mini">
                <h5><i class="fas fa-chart-pie"></i> Risk Distribution</h5>
                <div class="mini-chart">
                    <div class="chart-bar benign" style="width: ${data.chart_data.benign}%">
                        <span>Benign: ${data.chart_data.benign}%</span>
                    </div>
                    <div class="chart-bar malicious" style="width: ${data.chart_data.malicious}%">
                        <span>Malicious: ${data.chart_data.malicious}%</span>
                    </div>
                </div>
            </div>

            <div class="action-buttons">
                <button onclick="viewInDetectionDashboard('${data.id}')" class="btn btn-primary">
                    <i class="fas fa-tachometer-alt"></i> View in Dashboard
                </button>
                <button onclick="analyzeSimilarThreats()" class="btn btn-secondary">
                    <i class="fas fa-search"></i> Analyze Similar
                </button>
            </div>
        </div>
    `;
}

function displayBatchDetectionResults(data, container) {
    let html = `
        <div class="batch-summary">
            <h4><i class="fas fa-chart-bar"></i> Batch Detection Summary</h4>
            <div class="summary-stats">
                <div class="stat">
                    <span class="stat-value">${data.aggregated.total_scans_today}</span>
                    <span class="stat-label">Total Scans</span>
                </div>
                <div class="stat">
                    <span class="stat-value" style="color: #e74c3c;">${data.aggregated.malicious_today}</span>
                    <span class="stat-label">Malicious</span>
                </div>
                <div class="stat">
                    <span class="stat-value" style="color: #f39c12;">${data.aggregated.false_positives_estimate}</span>
                    <span class="stat-label">False Positives</span>
                </div>
                <div class="stat">
                    <span class="stat-value" style="color: #2ecc71;">${Math.round((data.aggregated.malicious_today / data.aggregated.total_scans_today) * 100)}%</span>
                    <span class="stat-label">Threat Rate</span>
                </div>
            </div>
        </div>
    `;

    data.results.forEach(result => {
        const threatColor = getThreatColor(result.threat_level);
        const statusIcon = result.status === 'malicious' ? '🚨' : '✅';

        html += `
            <div class="batch-result-card ${result.status === 'malicious' ? 'malicious' : 'safe'}">
                <div class="batch-result-header">
                    <div class="batch-status">
                        <span class="status-icon">${statusIcon}</span>
                        <span class="status-text">${result.status.toUpperCase()}</span>
                        <span class="threat-level ${result.threat_level.toLowerCase()}">${result.threat_level}</span>
                    </div>
                    <div class="batch-score" style="color: ${threatColor}">
                        ${result.malicious_score}
                    </div>
                </div>
                <div class="batch-url">${result.url}</div>
                <div class="batch-details">
                    <div class="detail">
                        <span class="label">Recommendation:</span>
                        <span class="value">${result.recommendation}</span>
                    </div>
                    <div class="detail">
                        <span class="label">Tokens:</span>
                        <span class="value">${result.suspicious_tokens.length} found</span>
                    </div>
                </div>
                ${result.threat_intel ? `
                    <div class="batch-threat-intel">
                        <strong>Threat Intel:</strong> ${result.threat_intel}
                    </div>
                ` : ''}
            </div>
        `;
    });

    container.innerHTML = html;
}

function getThreatColor(threatLevel) {
    switch(threatLevel) {
        case 'Critical': return '#e74c3c';
        case 'High': return '#f39c12';
        case 'Medium': return '#f1c40f';
        case 'Low': return '#2ecc71';
        default: return '#95a5a6';
    }
}

function getRecommendationExplanation(recommendation) {
    const explanations = {
        'Block': 'Immediate blocking recommended due to high threat level',
        'Flag': 'Flag for monitoring and further investigation',
        'Monitor': 'Continue monitoring for suspicious activities',
        'Allow': 'No immediate threats detected'
    };
    return explanations[recommendation] || 'No specific recommendation available';
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
            <h4>Detection Failed</h4>
            <p>${message}</p>
            <p>Please check if the URL is valid and try again.</p>
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

function viewInDetectionDashboard(id) {
    window.location.href = '/dashboard/detect';
}

function analyzeSimilarThreats() {
    alert('Similar threat analysis feature would be implemented here!');
}

// Enter key support
document.addEventListener('DOMContentLoaded', function() {
    const singleInput = document.getElementById('singleUrlInput');
    if (singleInput) {
        singleInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                detectSingleURL();
            }
        });
    }
});