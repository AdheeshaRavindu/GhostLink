// GhostLink URL Security Scanner - Frontend Logic

// Configuration
const WORKER_URL = 'https://frosty-thunder-f4fe.adheesharavindu001.workers.dev/analyze';

// DOM Elements
const urlInput = document.getElementById('urlInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const resultsSection = document.getElementById('results');

// Event Listeners
analyzeBtn.addEventListener('click', handleAnalyze);
urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleAnalyze();
});

// Main Analysis Handler
async function handleAnalyze() {
    const url = urlInput.value.trim();

    // Validation
    if (!url) {
        showError('Please enter a URL to analyze');
        return;
    }

    if (!isValidUrl(url)) {
        showError('Please enter a valid URL (e.g., https://example.com)');
        return;
    }

    showLoading();
    
    try {
        const response = await analyzeUrlViaAPI(url);
        displayResults(response);
    } catch (error) {
        showError(`Analysis failed: ${error.message}`);
    }
}

// Validate URL Format
function isValidUrl(str) {
    try {
        // Add https:// if no protocol
        const urlStr = str.startsWith('http://') || str.startsWith('https://') ? str : `https://${str}`;
        new URL(urlStr);
        return true;
    } catch (e) {
        return false;
    }
}

// Call Worker API
async function analyzeUrlViaAPI(url) {
    // Ensure URL has protocol
    const fullUrl = url.startsWith('http://') || url.startsWith('https://') ? url : `https://${url}`;

    const response = await fetch(WORKER_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: fullUrl }),
    });

    if (!response.ok) {
        throw new Error(`Worker returned status ${response.status}`);
    }

    const responseData = await response.json();
    // Extract the nested data object from the API response
    return responseData.data || responseData;
}

// Display Results
function displayResults(result) {
    // Clear results
    resultsSection.innerHTML = '';
    resultsSection.style.display = 'block';

    // Risk Level Color
    const riskLevel = result.riskLevel || 'Unknown';
    const riskLevelClass = riskLevel.toLowerCase();

    // Risk Hints
    const riskHints = {
        'Low': '✓ URL appears safe',
        'Medium': '⚠ Some suspicious indicators',
        'High': '🚨 Multiple security threats detected'
    };

    // Create Score Card
    const scoreCard = document.createElement('div');
    scoreCard.className = 'score-card';

    const scoreDisplay = `
        <div class="score-header">Security Score</div>
        <div class="score-display">
            <span class="score-value">${result.score}</span>
            <span class="score-max">/100</span>
        </div>
        <div class="risk-badge" data-level="${riskLevelClass}">
            ${riskLevel}
        </div>
        <div class="score-hint">${riskHints[riskLevel] || 'Unknown risk level'}</div>
        <div class="score-bar">
            <div class="score-fill" style="width: 0%"></div>
        </div>
    `;

    scoreCard.innerHTML = scoreDisplay;
    resultsSection.appendChild(scoreCard);

    // Animate score bar
    setTimeout(() => {
        const fill = scoreCard.querySelector('.score-fill');
        fill.style.width = `${result.score}%`;
    }, 100);

    // Stats Grid
    if (result.findings && result.findings.length > 0) {
        const statsGrid = document.createElement('div');
        statsGrid.className = 'stats-grid';

        // Count threats and categories
        const threatCount = result.findings.length;
        const categorySet = new Set(result.findings.map(f => f.category));

        statsGrid.innerHTML = `
            <div class="stat-card">
                <span class="stat-value">${threatCount}</span>
                <span class="stat-label">Threats Found</span>
            </div>
            <div class="stat-card">
                <span class="stat-value">${categorySet.size}</span>
                <span class="stat-label">Categories</span>
            </div>
        `;

        scoreCard.appendChild(statsGrid);
    }

    // Display detailed information (URL Intelligence - FIRST)
    if (result.details) {
        displayDetailedInfo(result.details);
    }

    // Findings Card (AFTER URL Intelligence)
    if (result.findings && result.findings.length > 0) {
        const findingsCard = document.createElement('div');
        findingsCard.className = 'findings-card';
        findingsCard.innerHTML = '<div class="findings-header">Security Findings</div>';

        const findingsList = document.createElement('div');
        findingsList.className = 'findings-list';

        // Group findings by category
        const grouped = {};
        result.findings.forEach(finding => {
            if (!grouped[finding.category]) {
                grouped[finding.category] = [];
            }
            grouped[finding.category].push(finding);
        });

        // Display grouped findings
        Object.entries(grouped).forEach(([category, findings]) => {
            const categoryGroup = document.createElement('div');
            categoryGroup.className = 'finding-category-group';

            const categoryTitle = document.createElement('div');
            categoryTitle.className = 'finding-category-title';
            categoryTitle.textContent = category;
            categoryGroup.appendChild(categoryTitle);

            findings.forEach(finding => {
                const item = document.createElement('div');
                item.className = 'finding-item';

                item.innerHTML = `
                    <div class="finding-type">${escapeHtml(finding.type)}</div>
                    <div class="finding-description">${escapeHtml(finding.description)}</div>
                    <div class="finding-points">-${finding.points} points</div>
                `;

                categoryGroup.appendChild(item);
            });

            findingsList.appendChild(categoryGroup);
        });

        findingsCard.appendChild(findingsList);
        resultsSection.appendChild(findingsCard);
    } else {
        const empty = document.createElement('div');
        empty.className = 'empty-state';
        empty.innerHTML = '<p>No security threats detected. This URL appears to be safe!</p>';
        resultsSection.appendChild(empty);
    }

    // Display security recommendations
    if (result.recommendations && result.recommendations.length > 0) {
        displayRecommendations(result.recommendations);
    }
}

// Display Detailed Information
function displayDetailedInfo(details) {
    const detailsCard = document.createElement('div');
    detailsCard.className = 'details-card';
    detailsCard.innerHTML = '<div class="details-header">🔍 URL Intelligence</div>';

    const detailsGrid = document.createElement('div');
    detailsGrid.className = 'details-grid';

    // URL Components
    if (details.components) {
        const comp = details.components;
        const urlInfo = `
            <div class="detail-section">
                <div class="detail-title">🔗 URL Structure</div>
                <div class="detail-item">
                    <span class="detail-label">Protocol:</span>
                    <span class="detail-value">${escapeHtml(comp.protocol)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Domain:</span>
                    <span class="detail-value">${escapeHtml(comp.domain)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Port:</span>
                    <span class="detail-value">${comp.port}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Path Depth:</span>
                    <span class="detail-value">${comp.pathDepth} segment${comp.pathDepth !== 1 ? 's' : ''}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Query Parameters:</span>
                    <span class="detail-value">${comp.queryParamCount}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Domain Parts:</span>
                    <span class="detail-value">${comp.domainParts}</span>
                </div>
            </div>
        `;
        detailsGrid.innerHTML += urlInfo;
    }

    // Page Metadata
    if (details.metadata) {
        const meta = details.metadata;
        let metaInfo = '<div class="detail-section"><div class="detail-title">📄 Page Metadata</div>';
        
        if (meta.title) metaInfo += `<div class="detail-item"><span class="detail-label">Title:</span><span class="detail-value">${escapeHtml(meta.title)}</span></div>`;
        if (meta.description) metaInfo += `<div class="detail-item"><span class="detail-label">Description:</span><span class="detail-value">${escapeHtml(meta.description)}</span></div>`;
        if (meta.language) metaInfo += `<div class="detail-item"><span class="detail-label">Language:</span><span class="detail-value">${escapeHtml(meta.language)}</span></div>`;
        if (meta.charset) metaInfo += `<div class="detail-item"><span class="detail-label">Charset:</span><span class="detail-value">${escapeHtml(meta.charset)}</span></div>`;
        if (meta.contentType) metaInfo += `<div class="detail-item"><span class="detail-label">Content-Type:</span><span class="detail-value">${escapeHtml(meta.contentType)}</span></div>`;
        metaInfo += `<div class="detail-item"><span class="detail-label">Has Form:</span><span class="detail-value">${meta.hasForm ? '⚠️ Yes' : '✓ No'}</span></div>`;
        
        metaInfo += '</div>';
        detailsGrid.innerHTML += metaInfo;
    }

    // Server Information
    if (details.server) {
        const server = details.server;
        let serverInfo = '<div class="detail-section"><div class="detail-title">🖥️ Server Information</div>';
        
        if (server.server) serverInfo += `<div class="detail-item"><span class="detail-label">Server:</span><span class="detail-value">${escapeHtml(server.server)}</span></div>`;
        if (server.statusCode) serverInfo += `<div class="detail-item"><span class="detail-label">Status:</span><span class="detail-value">${server.statusCode} ${escapeHtml(server.statusMessage || '')}</span></div>`;
        if (server.responseTime) serverInfo += `<div class="detail-item"><span class="detail-label">Response Time:</span><span class="detail-value">${server.responseTime}ms</span></div>`;
        if (server.technologies.length > 0) serverInfo += `<div class="detail-item"><span class="detail-label">Technologies:</span><span class="detail-value">${escapeHtml(server.technologies.join(', '))}</span></div>`;
        if (server.cacheControl) serverInfo += `<div class="detail-item"><span class="detail-label">Cache:</span><span class="detail-value">${escapeHtml(server.cacheControl.substring(0, 50))}</span></div>`;
        if (server.contentEncoding) serverInfo += `<div class="detail-item"><span class="detail-label">Encoding:</span><span class="detail-value">${escapeHtml(server.contentEncoding)}</span></div>`;
        
        serverInfo += '</div>';
        detailsGrid.innerHTML += serverInfo;
    }

    // Security Headers
    if (details.server && details.server.securityHeaders) {
        const headers = details.server.securityHeaders;
        let securityInfo = '<div class="detail-section"><div class="detail-title">🔒 Security Headers</div>';
        
        for (const [headerName, headerStatus] of Object.entries(headers)) {
            const isPresent = headerStatus.includes('✓');
            const statusClass = isPresent ? 'header-present' : 'header-missing';
            securityInfo += `<div class="detail-item"><span class="detail-label">${escapeHtml(headerName)}:</span><span class="detail-value ${statusClass}">${escapeHtml(headerStatus)}</span></div>`;
        }
        
        securityInfo += '</div>';
        detailsGrid.innerHTML += securityInfo;
    }

    // DNS Information
    if (details.dns && (details.dns.resolvedIP || details.dns.dnsLookupTime)) {
        const dns = details.dns;
        let dnsInfo = '<div class="detail-section"><div class="detail-title">🌐 DNS Information</div>';
        
        if (dns.domain) dnsInfo += `<div class="detail-item"><span class="detail-label">Domain:</span><span class="detail-value">${escapeHtml(dns.domain)}</span></div>`;
        if (dns.resolvedIP) dnsInfo += `<div class="detail-item"><span class="detail-label">Resolved:</span><span class="detail-value">${escapeHtml(dns.resolvedIP)}</span></div>`;
        if (dns.dnsLookupTime) dnsInfo += `<div class="detail-item"><span class="detail-label">Lookup Time:</span><span class="detail-value">${dns.dnsLookupTime}ms</span></div>`;
        
        dnsInfo += '</div>';
        detailsGrid.innerHTML += dnsInfo;
    }

    detailsCard.appendChild(detailsGrid);
    resultsSection.appendChild(detailsCard);
}

// Display Security Recommendations
function displayRecommendations(recommendations) {
    if (!recommendations || recommendations.length === 0) return;

    const recCard = document.createElement('div');
    recCard.className = 'recommendations-card';
    recCard.innerHTML = '<div class="rec-header">💡 Security Recommendations</div>';

    const recList = document.createElement('div');
    recList.className = 'rec-list';

    recommendations.forEach((rec, index) => {
        const item = document.createElement('div');
        item.className = 'rec-item';
        
        let icon = '💡';
        if (rec.includes('CRITICAL')) icon = '🚨';
        else if (rec.includes('SSL') || rec.includes('HTTPS') || rec.includes('TLS')) icon = '🔐';
        else if (rec.includes('slow') || rec.includes('optimization')) icon = '⚡';

        item.innerHTML = `
            <span class="rec-icon">${icon}</span>
            <span class="rec-text">${escapeHtml(rec)}</span>
        `;
        recList.appendChild(item);
    });

    recCard.appendChild(recList);
    resultsSection.appendChild(recCard);
}

// Show Loading State
function showLoading() {
    resultsSection.innerHTML = `
        <div class="loading">
            <div class="spinner"></div>
            <p>Analyzing URL...</p>
        </div>
    `;
    resultsSection.style.display = 'block';
    analyzeBtn.disabled = true;
}

// Show Error Message
function showError(message) {
    resultsSection.innerHTML = `<div class="error-message">${escapeHtml(message)}</div>`;
    resultsSection.style.display = 'block';
    analyzeBtn.disabled = false;
}

// Escape HTML to Prevent XSS
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, (m) => map[m]);
}

// Re-enable button after analysis
resultsSection.addEventListener('change', () => {
    analyzeBtn.disabled = false;
}, { once: true });

// Allow multiple analyses
document.addEventListener('click', (e) => {
    if (e.target.id === 'analyzeBtn' && !analyzeBtn.disabled) {
        urlInput.value = '';
        resultsSection.innerHTML = '';
        resultsSection.style.display = 'none';
    }
});
