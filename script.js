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

setUiExpanded(false);

// Main Analysis Handler
async function handleAnalyze() {
    const url = urlInput.value.trim();

    // Validation
    if (!url) {
        setUiExpanded(false);
        showError('Please enter a URL to analyze');
        return;
    }

    if (!isValidUrl(url)) {
        setUiExpanded(false);
        showError('Please enter a valid URL (e.g., https://example.com)');
        return;
    }

    setUiExpanded(true);
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

function setUiExpanded(expanded) {
    if (expanded) {
        document.body.classList.add('ui-expanded');
    } else {
        document.body.classList.remove('ui-expanded');
    }
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
        'Low': '✓ This URL appears safe to visit',
        'Medium': '⚠ This URL has some warning signs. Use caution.',
        'High': '🚨 This URL shows multiple security threats. Do not visit.'
    };

    // Risk Score Explanations
    const riskExplanations = {
        'Low': 'Security score of 0-30: URL passes most security checks',
        'Medium': 'Security score of 31-70: URL has moderate security concerns',
        'High': 'Security score above 70: URL has significant security risks'
    };

    // Create Score Card
    const scoreCard = document.createElement('div');
    scoreCard.className = 'score-card';

    const scoreDisplay = `
        <div class="score-container">
            <div class="score-section-title">🛡️ Security Analysis Summary</div>
            <div class="score-explanation">GhostLink analyzed this URL for phishing, malware, security misconfigurations, and other threats.</div>
            <div class="score-display">
                <span class="score-value">${result.score}</span>
                <span class="score-max">/100</span>
            </div>
            <div class="risk-badge" data-level="${riskLevelClass}">
                ${riskLevel}
            </div>
            <div class="score-hint">${riskHints[riskLevel] || 'Unknown risk level'}</div>
            <div class="risk-explanation">${riskExplanations[riskLevel] || 'Unknown'}</div>
            <div class="score-bar">
                <div class="score-fill" style="width: 0%"></div>
            </div>
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
                <span class="stat-icon">⚠️</span>
                <span class="stat-value">${threatCount}</span>
                <span class="stat-label">Issues Detected</span>
                <span class="stat-desc">Security concerns found</span>
            </div>
            <div class="stat-card">
                <span class="stat-icon">📊</span>
                <span class="stat-value">${categorySet.size}</span>
                <span class="stat-label">Risk Categories</span>
                <span class="stat-desc">Types of issues</span>
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
        findingsCard.innerHTML = `
            <div class="findings-header">🔍 Security Findings</div>
            <div class="findings-description">Details of each security issue detected. Issues that remove more points are more serious.</div>
        `;

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

                // Determine severity based on points
                let severity = 'low';
                if (finding.points >= 25) severity = 'high';
                else if (finding.points >= 15) severity = 'medium';

                item.innerHTML = `
                    <div class="finding-header-row">
                        <div class="finding-type">${escapeHtml(finding.type)}</div>
                        <span class="finding-severity severity-${severity}" title="Severity: ${severity.charAt(0).toUpperCase() + severity.slice(1)}">${finding.points > 0 ? '!' : '✓'}</span>
                    </div>
                    <div class="finding-description">${escapeHtml(finding.description)}</div>
                    <div class="finding-points"><span class="points-icon">📉</span> <span class="points-value">-${finding.points} points</span></div>
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
    detailsCard.innerHTML = `
        <div class="details-header">🔍 URL Intelligence</div>
        <div class="details-description">Technical information about this URL including its structure, origin server, and security configuration.</div>
    `;

    const detailsGrid = document.createElement('div');
    detailsGrid.className = 'details-grid';

    // URL Components
    if (details.components) {
        const comp = details.components;
        const urlInfo = `
            <div class="detail-section">
                <div class="detail-title">🔗 URL Structure</div>
                <div class="detail-subtitle">How this URL is organized</div>
                <div class="detail-item">
                    <span class="detail-label">Protocol <span class="detail-tooltip" title="HTTP (unencrypted) or HTTPS (encrypted & secure)">ⓘ</span>:</span>
                    <span class="detail-value">${escapeHtml(comp.protocol)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Domain:</span>
                    <span class="detail-value">${escapeHtml(comp.domain)}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Port <span class="detail-tooltip" title="Network connection point (443 for HTTPS, 80 for HTTP)">ⓘ</span>:</span>
                    <span class="detail-value">${comp.port}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Path Depth:</span>
                    <span class="detail-value">${comp.pathDepth} segment${comp.pathDepth !== 1 ? 's' : ''}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Query Parameters <span class="detail-tooltip" title="Extra data sent in the URL after ?">ⓘ</span>:</span>
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
        let metaInfo = `<div class="detail-section"><div class="detail-title">📄 Page Metadata</div><div class="detail-subtitle">Information from the website's HTML</div>`;
        
        if (meta.title) metaInfo += `<div class="detail-item"><span class="detail-label">Page Title:</span><span class="detail-value">${escapeHtml(meta.title)}</span></div>`;
        if (meta.description) metaInfo += `<div class="detail-item"><span class="detail-label">Description:</span><span class="detail-value">${escapeHtml(meta.description)}</span></div>`;
        if (meta.language) metaInfo += `<div class="detail-item"><span class="detail-label">Language:</span><span class="detail-value">${escapeHtml(meta.language)}</span></div>`;
        if (meta.charset) metaInfo += `<div class="detail-item"><span class="detail-label">Character Set:</span><span class="detail-value">${escapeHtml(meta.charset)}</span></div>`;
        if (meta.contentType) metaInfo += `<div class="detail-item"><span class="detail-label">Content Type:</span><span class="detail-value">${escapeHtml(meta.contentType)}</span></div>`;
        metaInfo += `<div class="detail-item"><span class="detail-label">Has Login Form:</span><span class="detail-value">${meta.hasForm ? '⚠️ Yes (check carefully)' : '✓ No'}</span></div>`;
        
        metaInfo += '</div>';
        detailsGrid.innerHTML += metaInfo;
    }

    // Server Information
    if (details.server) {
        const server = details.server;
        let serverInfo = `<div class="detail-section"><div class="detail-title">🖥️ Server Information</div><div class="detail-subtitle">Details about the server hosting this website</div>`;
        
        if (server.server) serverInfo += `<div class="detail-item"><span class="detail-label">Server Software:</span><span class="detail-value">${escapeHtml(server.server)}</span></div>`;
        if (server.statusCode) serverInfo += `<div class="detail-item"><span class="detail-label">HTTP Status:</span><span class="detail-value">${server.statusCode} ${escapeHtml(server.statusMessage || '')} ${server.statusCode === 200 ? '✓' : '⚠️'}</span></div>`;
        if (server.responseTime) serverInfo += `<div class="detail-item"><span class="detail-label">Response Time:</span><span class="detail-value">${server.responseTime}ms ${server.responseTime < 1000 ? '✓ Fast' : '⚠️ Slow'}</span></div>`;
        if (server.sslInfo) serverInfo += `<div class="detail-item"><span class="detail-label">SSL/TLS Status:</span><span class="detail-value">${escapeHtml(server.sslInfo)} ${server.sslInfo.includes('Secured') ? '✓' : '⚠️'}</span></div>`;
        if (server.finalUrl && server.finalUrl !== details.url) serverInfo += `<div class="detail-item"><span class="detail-label">Final URL <span class="detail-tooltip" title="URL after following redirects">ⓘ</span>:</span><span class="detail-value">${escapeHtml(server.finalUrl.substring(0, 50))}${server.finalUrl.length > 50 ? '...' : ''}</span></div>`;
        if (server.technologies.length > 0) serverInfo += `<div class="detail-item"><span class="detail-label">Web Technologies:</span><span class="detail-value">${escapeHtml(server.technologies.join(', '))}</span></div>`;
        if (server.contentLength) serverInfo += `<div class="detail-item"><span class="detail-label">Content Size:</span><span class="detail-value">${formatBytes(server.contentLength)}</span></div>`;
        if (server.lastModified) serverInfo += `<div class="detail-item"><span class="detail-label">Last Modified:</span><span class="detail-value">${formatDate(server.lastModified)}</span></div>`;
        if (server.age) serverInfo += `<div class="detail-item"><span class="detail-label">Cache Age:</span><span class="detail-value">${server.age} seconds</span></div>`;
        if (server.cacheControl) serverInfo += `<div class="detail-item"><span class="detail-label">Cache Control:</span><span class="detail-value">${escapeHtml(server.cacheControl.substring(0, 50))}</span></div>`;
        if (server.contentEncoding) serverInfo += `<div class="detail-item"><span class="detail-label">Compression:</span><span class="detail-value">${escapeHtml(server.contentEncoding)}</span></div>`;
        
        serverInfo += '</div>';
        detailsGrid.innerHTML += serverInfo;
    }

    // Security Headers
    if (details.server && details.server.securityHeaders) {
        const headers = details.server.securityHeaders;
        let securityInfo = `<div class="detail-section"><div class="detail-title">🔒 Security Headers</div><div class="detail-subtitle">Protection measures implemented by the server. ✓ = Good, ✗ = Missing</div>`;
        
        for (const [headerName, headerStatus] of Object.entries(headers)) {
            const isPresent = headerStatus.includes('✓');
            const statusClass = isPresent ? 'header-present' : 'header-missing';
            const icons = {
                'Content-Security-Policy': '🛡️',
                'X-Frame-Options': '🪟',
                'X-Content-Type-Options': '📝',
                'Strict-Transport-Security': '🔐',
                'Referrer-Policy': '👁️',
                'Permissions-Policy': '⚙️'
            };
            const icon = icons[headerName] || '•';
            securityInfo += `<div class="detail-item"><span class="detail-label">${icon} ${escapeHtml(headerName)}:</span><span class="detail-value ${statusClass}">${escapeHtml(headerStatus)}</span></div>`;
        }
        
        securityInfo += '</div>';
        detailsGrid.innerHTML += securityInfo;
    }

    // DNS Information
    if (details.dns && (details.dns.resolvedIP || details.dns.dnsLookupTime)) {
        const dns = details.dns;
        let dnsInfo = `<div class="detail-section"><div class="detail-title">🌐 DNS Information</div><div class="detail-subtitle">Domain name and server location details</div>`;
        
        if (dns.domain) dnsInfo += `<div class="detail-item"><span class="detail-label">Domain Name:</span><span class="detail-value">${escapeHtml(dns.domain)}</span></div>`;
        if (dns.resolvedIP) dnsInfo += `<div class="detail-item"><span class="detail-label">Server Info:</span><span class="detail-value">${escapeHtml(dns.resolvedIP)}</span></div>`;
        if (dns.dnsLookupTime) dnsInfo += `<div class="detail-item"><span class="detail-label">DNS Lookup Time:</span><span class="detail-value">${dns.dnsLookupTime}ms ${dns.dnsLookupTime < 500 ? '✓ Fast' : '⚠️'}</span></div>`;
        
        dnsInfo += '</div>';
        detailsGrid.innerHTML += dnsInfo;
    }

    // Domain Intelligence
    if (details.domainIntel) {
        const intel = details.domainIntel;
        let domainIntel = `<div class="detail-section"><div class="detail-title">📊 Domain Intelligence</div><div class="detail-subtitle">Hostname structure and naming-pattern indicators</div>`;

        domainIntel += `<div class="detail-item"><span class="detail-label">Registrable Domain:</span><span class="detail-value">${escapeHtml(intel.registrableDomain || 'Unknown')}</span></div>`;
        domainIntel += `<div class="detail-item"><span class="detail-label">TLD Class:</span><span class="detail-value">${escapeHtml(intel.tldClass || 'Unknown')}</span></div>`;
        domainIntel += `<div class="detail-item"><span class="detail-label">Subdomain Profile:</span><span class="detail-value">${escapeHtml(intel.subdomainProfile || 'Unknown')} (${intel.subdomainCount || 0})</span></div>`;
        domainIntel += `<div class="detail-item"><span class="detail-label">Hostname Entropy:</span><span class="detail-value">${intel.hostnameEntropy ?? 'N/A'} (${escapeHtml(intel.entropyLevel || 'Unknown')})</span></div>`;
        domainIntel += `<div class="detail-item"><span class="detail-label">Hyphenated Labels:</span><span class="detail-value">${intel.hasHyphen ? '⚠️ Yes' : '✓ No'}</span></div>`;
        domainIntel += `<div class="detail-item"><span class="detail-label">Numeric Labels:</span><span class="detail-value">${intel.hasNumericLabel ? '⚠️ Yes' : '✓ No'}</span></div>`;

        domainIntel += '</div>';
        detailsGrid.innerHTML += domainIntel;
    }

    detailsCard.appendChild(detailsGrid);
    resultsSection.appendChild(detailsCard);
}

// Display Security Recommendations
function displayRecommendations(recommendations) {
    if (!recommendations || recommendations.length === 0) return;

    const recCard = document.createElement('div');
    recCard.className = 'recommendations-card';
    recCard.innerHTML = `
        <div class="rec-header">💡 Safety Tips</div>
        <div class="rec-description">Recommendations for visitors based on this site's security analysis</div>
    `;

    const recList = document.createElement('div');
    recList.className = 'rec-list';

    recommendations.forEach((rec, index) => {
        const item = document.createElement('div');
        item.className = 'rec-item';
        
        let icon = '💡';
        let priority = 'info';
        if (rec.includes('CRITICAL')) {
            icon = '🚨';
            priority = 'critical';
        } else if (rec.includes('SSL') || rec.includes('HTTPS') || rec.includes('TLS')) {
            icon = '🔐';
            priority = 'high';
        } else if (rec.includes('slow') || rec.includes('optimization')) {
            icon = '⚡';
            priority = 'medium';
        } else if (rec.includes('Content-Security-Policy') || rec.includes('X-Frame-Options') || rec.includes('HSTS')) {
            icon = '🛡️';
            priority = 'high';
        }

        item.className = `rec-item rec-${priority}`;
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

// Format bytes to human-readable size
function formatBytes(bytes) {
    if (!bytes) return '0 Bytes';
    const bytesNum = typeof bytes === 'string' ? parseInt(bytes, 10) : bytes;
    if (!bytesNum || bytesNum === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytesNum) / Math.log(k));
    return Math.round((bytesNum / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

// Format date to readable format
function formatDate(dateString) {
    try {
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now.getTime() - date.getTime();
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        
        if (diffDays === 0) return 'Today';
        if (diffDays === 1) return 'Yesterday';
        if (diffDays < 7) return `${diffDays} days ago`;
        if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
        if (diffDays < 365) return `${Math.floor(diffDays / 30)} months ago`;
        
        return date.toLocaleDateString();
    } catch (e) {
        return dateString;
    }
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
