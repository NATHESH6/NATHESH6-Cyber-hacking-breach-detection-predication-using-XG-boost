//dashboard.js
// Combined Dashboard functionality for both Prediction and Detection
document.addEventListener('DOMContentLoaded', function() {
    // Check which dashboard we're on
    const isPredictionDashboard = window.location.pathname.includes('predict-dashboard');
    const isDetectionDashboard = window.location.pathname.includes('detect-dashboard');

    if (isPredictionDashboard) {
        loadPredictionDashboard();
    } else if (isDetectionDashboard) {
        loadDetectionDashboard();
    }
});

// ========== PREDICTION DASHBOARD ==========
function loadPredictionDashboard() {
    const history = JSON.parse(localStorage.getItem('predictionHistory') || '[]');

    // Update stats
    updatePredictionStats(history);

    // Load charts
    loadPredictionCharts(history);

    // Load recent predictions
    loadRecentPredictions(history);

    // Load feature importance
    loadFeatureImportance();
}

function updatePredictionStats(history) {
    document.getElementById('totalPredictions').textContent = history.length;

    const maliciousCount = history.filter(p => p.prediction === 'malicious').length;
    document.getElementById('maliciousCount').textContent = maliciousCount;
    document.getElementById('safeCount').textContent = history.length - maliciousCount;

    // Calculate accuracy (simulated)
    const accuracy = history.length > 0 ?
        Math.round((history.filter(p => (p.threat_score > 50) === (p.prediction === 'malicious')).length / history.length) * 100) : 0;
    document.getElementById('accuracyRate').textContent = accuracy + '%';
}

function loadPredictionCharts(history) {
    // Risk Distribution Chart (3D Pie Chart)
    const riskDistribution = {
        'High Risk': history.filter(p => p.threat_score >= 70).length,
        'Medium Risk': history.filter(p => p.threat_score >= 40 && p.threat_score < 70).length,
        'Low Risk': history.filter(p => p.threat_score >= 20 && p.threat_score < 40).length,
        'Very Low Risk': history.filter(p => p.threat_score < 20).length
    };

    const riskCtx = document.getElementById('riskChart').getContext('2d');
    new Chart(riskCtx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(riskDistribution),
            datasets: [{
                data: Object.values(riskDistribution),
                backgroundColor: ['#e74c3c', '#f39c12', '#f1c40f', '#2ecc71'],
                borderWidth: 3,
                borderColor: '#ffffff',
                hoverOffset: 15
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        usePointStyle: true
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            },
            cutout: '50%',
            animation: {
                animateScale: true,
                animateRotate: true
            }
        }
    });

    // Threat Levels Chart
    const threatLevels = {
        'Malicious': history.filter(p => p.prediction === 'malicious').length,
        'Benign': history.filter(p => p.prediction === 'benign').length
    };

    const threatCtx = document.getElementById('threatChart').getContext('2d');
    new Chart(threatCtx, {
        type: 'bar',
        data: {
            labels: Object.keys(threatLevels),
            datasets: [{
                label: 'URL Count',
                data: Object.values(threatLevels),
                backgroundColor: ['#e74c3c', '#2ecc71'],
                borderColor: ['#c0392b', '#27ae60'],
                borderWidth: 2,
                borderRadius: 5,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        drawBorder: false
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

function loadRecentPredictions(history) {
    const container = document.getElementById('recentPredictions');
    const recent = history.slice(0, 8);

    if (recent.length === 0) {
        container.innerHTML = `
            <div class="no-data">
                <i class="fas fa-chart-line"></i>
                <p>No predictions yet</p>
                <p class="subtext">Start analyzing URLs in the Prediction module</p>
            </div>
        `;
        return;
    }

    container.innerHTML = recent.map(prediction => `
        <div class="prediction-item ${prediction.prediction === 'malicious' ? 'malicious' : 'safe'}">
            <div class="prediction-main">
                <div class="prediction-status">
                    <span class="prediction-badge ${prediction.prediction}">
                        ${prediction.prediction.toUpperCase()}
                    </span>
                    <span class="prediction-score" style="color: ${getRiskColor(prediction.threat_score)}">
                        ${prediction.threat_score}
                    </span>
                </div>
                <div class="prediction-info">
                    <div class="prediction-url" title="${prediction.url}">
                        ${prediction.url.length > 50 ? prediction.url.substring(0, 50) + '...' : prediction.url}
                    </div>
                    <div class="prediction-meta">
                        <span class="timestamp">
                            <i class="fas fa-clock"></i>
                            ${new Date(prediction.timestamp).toLocaleDateString()}
                        </span>
                        <span class="probability">
                            ${(prediction.probability * 100).toFixed(1)}% prob
                        </span>
                    </div>
                </div>
            </div>
            <div class="prediction-tokens">
                ${prediction.suspicious_tokens && prediction.suspicious_tokens.length > 0 ?
                    `<i class="fas fa-tags"></i> ${prediction.suspicious_tokens.slice(0, 3).join(', ')}` :
                    '<i class="fas fa-check"></i> No suspicious tokens'
                }
            </div>
        </div>
    `).join('');
}

function loadFeatureImportance() {
    const container = document.getElementById('featureImportance');

    // Simulated feature importance data
    const features = [
        { name: 'Suspicious Keywords', importance: 92, description: 'Presence of malicious keywords' },
        { name: 'URL Length', importance: 85, description: 'Total characters in URL' },
        { name: 'Entropy Score', importance: 78, description: 'Randomness of URL structure' },
        { name: 'Special Characters', importance: 72, description: 'Ratio of special characters' },
        { name: 'IP Address Usage', importance: 88, description: 'URL contains IP instead of domain' },
        { name: 'HTTPS Encryption', importance: 65, description: 'Use of secure protocol' }
    ];

    container.innerHTML = features.map(feature => `
        <div class="feature-item">
            <div class="feature-header">
                <span class="feature-name">${feature.name}</span>
                <span class="feature-percentage">${feature.importance}%</span>
            </div>
            <div class="feature-bar">
                <div class="feature-progress" style="width: ${feature.importance}%"></div>
            </div>
            <div class="feature-description">${feature.description}</div>
        </div>
    `).join('');
}

// ========== DETECTION DASHBOARD ==========
function loadDetectionDashboard() {
    const history = JSON.parse(localStorage.getItem('detectionHistory') || '[]');

    // Update stats
    updateDetectionStats(history);

    // Load charts
    loadDetectionCharts(history);

    // Load threat intelligence
    loadThreatIntelligence(history);

    // Load recent detections
    loadRecentDetections(history);

    // Load security metrics
    loadSecurityMetrics(history);
}

function updateDetectionStats(history) {
    document.getElementById('totalDetections').textContent = history.length;

    const maliciousCount = history.filter(d => d.status === 'malicious').length;
    document.getElementById('attacksBlocked').textContent = maliciousCount;

    // Calculate average response time (simulated)
    const avgResponseTime = history.length > 0 ?
        Math.round(history.reduce((sum, d) => sum + (Math.random() * 50 + 10), 0) / history.length) : 0;
    document.getElementById('responseTime').textContent = avgResponseTime + 'ms';

    const protectionRate = history.length > 0 ?
        Math.round((maliciousCount / history.length) * 100) : 100;
    document.getElementById('protectionRate').textContent = protectionRate + '%';
}

function loadDetectionCharts(history) {
    // Threat Level Distribution Chart
    const threatLevels = {
        'Critical': history.filter(d => d.threat_level === 'Critical').length,
        'High': history.filter(d => d.threat_level === 'High').length,
        'Medium': history.filter(d => d.threat_level === 'Medium').length,
        'Low': history.filter(d => d.threat_level === 'Low').length
    };

    const threatCtx = document.getElementById('threatLevelChart').getContext('2d');
    new Chart(threatCtx, {
        type: 'pie',
        data: {
            labels: Object.keys(threatLevels),
            datasets: [{
                data: Object.values(threatLevels),
                backgroundColor: ['#e74c3c', '#f39c12', '#f1c40f', '#2ecc71'],
                borderWidth: 3,
                borderColor: '#ffffff',
                hoverOffset: 20
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.label}: ${context.raw} detections`;
                        }
                    }
                }
            }
        }
    });

    // Attack Types Chart
    const attackTypes = {
        'Phishing': history.filter(d => d.threat_intel && d.threat_intel.toLowerCase().includes('phishing')).length,
        'Malware': history.filter(d => d.threat_intel && d.threat_intel.toLowerCase().includes('malware')).length,
        'Suspicious': history.filter(d => d.threat_intel && d.threat_intel.toLowerCase().includes('suspicious')).length,
        'Clean': history.filter(d => d.status === 'safe' || d.status === 'benign').length
    };

    const attackCtx = document.getElementById('attackTypeChart').getContext('2d');
    new Chart(attackCtx, {
        type: 'bar',
        data: {
            labels: Object.keys(attackTypes),
            datasets: [{
                label: 'Detection Count',
                data: Object.values(attackTypes),
                backgroundColor: ['#e74c3c', '#f39c12', '#f1c40f', '#2ecc71'],
                borderColor: ['#c0392b', '#d35400', '#f39c12', '#27ae60'],
                borderWidth: 2,
                borderRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Number of Detections'
                    }
                }
            }
        }
    });
}

function loadThreatIntelligence(history) {
    // Top malicious tokens
    const allTokens = [];
    history.forEach(detection => {
        if (detection.suspicious_tokens) {
            allTokens.push(...detection.suspicious_tokens);
        }
    });

    const tokenCounts = {};
    allTokens.forEach(token => {
        tokenCounts[token] = (tokenCounts[token] || 0) + 1;
    });

    const topTokens = Object.entries(tokenCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8);

    const tokensHTML = topTokens.map(([token, count]) => `
        <div class="threat-item">
            <span class="threat-name">${token}</span>
            <span class="threat-count">${count}</span>
        </div>
    `).join('');

    document.getElementById('topTokens').innerHTML = tokensHTML || '<p class="no-data">No tokens detected</p>';

    // Suspicious domains (simulated)
    const domains = [
        { name: 'secure-login.com', count: 15 },
        { name: 'bank-update.xyz', count: 12 },
        { name: 'free-gift.online', count: 8 },
        { name: 'payment-verify.net', count: 6 },
        { name: 'account-recovery.cc', count: 5 }
    ];

    const domainsHTML = domains.map(domain => `
        <div class="threat-item">
            <span class="threat-name">${domain.name}</span>
            <span class="threat-count">${domain.count}</span>
        </div>
    `).join('');

    document.getElementById('suspiciousDomains').innerHTML = domainsHTML;
}

function loadRecentDetections(history) {
    const container = document.getElementById('recentDetections');
    const recent = history.slice(0, 10);

    if (recent.length === 0) {
        container.innerHTML = `
            <div class="no-data">
                <i class="fas fa-shield-alt"></i>
                <p>No detections yet</p>
                <p class="subtext">Start detecting URLs in the Detection module</p>
            </div>
        `;
        return;
    }

    container.innerHTML = recent.map(detection => `
        <div class="detection-item ${detection.status === 'malicious' ? 'malicious' : 'safe'}">
            <div class="detection-main">
                <div class="detection-status">
                    <span class="status-badge ${detection.threat_level?.toLowerCase() || 'low'}">
                        ${detection.threat_level || 'Low'}
                    </span>
                    <span class="detection-score">${detection.malicious_score || 0}</span>
                </div>
                <div class="detection-info">
                    <div class="detection-url">${detection.url}</div>
                    <div class="detection-meta">
                        <span class="timestamp">
                            <i class="fas fa-clock"></i>
                            ${new Date(detection.timestamp).toLocaleString()}
                        </span>
                        <span class="recommendation ${detection.recommendation?.toLowerCase() || 'monitor'}">
                            ${detection.recommendation || 'Monitor'}
                        </span>
                    </div>
                </div>
            </div>
            <div class="detection-details">
                <div class="threat-intel">
                    <i class="fas fa-brain"></i>
                    ${detection.threat_intel || 'No specific threats detected'}
                </div>
                ${detection.suspicious_tokens && detection.suspicious_tokens.length > 0 ?
                    `<div class="tokens">
                        <i class="fas fa-tags"></i>
                        ${detection.suspicious_tokens.join(', ')}
                    </div>` : ''
                }
            </div>
        </div>
    `).join('');
}

function loadSecurityMetrics(history) {
    const maliciousDetections = history.filter(d => d.status === 'malicious');
    const totalDetections = history.length;

    document.getElementById('falsePositives').textContent =
        Math.round(maliciousDetections.length * 0.1); // Simulated false positives

    document.getElementById('detectionAccuracy').textContent =
        totalDetections > 0 ? Math.round((maliciousDetections.length / totalDetections) * 100) + '%' : '0%';

    document.getElementById('highSeverity').textContent =
        history.filter(d => d.threat_level === 'High' || d.threat_level === 'Critical').length;

    const avgScore = history.length > 0 ?
        Math.round(history.reduce((sum, d) => sum + (d.malicious_score || 0), 0) / history.length) : 0;
    document.getElementById('avgMaliciousScore').textContent = avgScore;
}

// Utility functions
function getRiskColor(score) {
    if (score >= 80) return '#e74c3c';
    if (score >= 60) return '#f39c12';
    if (score >= 40) return '#f1c40f';
    return '#2ecc71';
}