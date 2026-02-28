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

    // Findings Card
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
                    <div class="finding-category">${finding.category}</div>
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
