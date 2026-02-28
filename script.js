// GhostLink URL Security Scanner - Dashboard
// Sends analysis requests to Cloudflare Worker endpoint

// DOM Elements
const urlInput = document.getElementById('urlInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const resultsSection = document.getElementById('resultsSection');
const loading = document.getElementById('loading');
const errorMessage = document.getElementById('errorMessage');
const scoreValue = document.getElementById('scoreValue');
const riskBadge = document.getElementById('riskBadge');
const findingsList = document.getElementById('findingsList');

// API Configuration
const API_ENDPOINT = 'https://frosty-thunder-f4fe.adheesharavindu001.workers.dev/analyze';

// UI Functions
function showLoading() {
  loading.style.display = 'flex';
  resultsSection.style.display = 'none';
  errorMessage.style.display = 'none';
}

function displayResults(result) {
  loading.style.display = 'none';
  errorMessage.style.display = 'none';
  resultsSection.style.display = 'grid';

  scoreValue.textContent = result.score;

  const level = result.riskLevel.toLowerCase();
  riskBadge.textContent = result.riskLevel;
  riskBadge.setAttribute('data-level', level);

  if (result.findings.length === 0) {
    findingsList.innerHTML = '<div class="empty-state"><p>✓ No threats detected</p></div>';
  } else {
    findingsList.innerHTML = result.findings.map(finding => `
      <div class="finding-item">
        <div class="finding-type">${escapeHtml(finding.type)}</div>
        <div class="finding-description">${escapeHtml(finding.description)}</div>
        <span class="finding-points">+${finding.points} pts</span>
      </div>
    `).join('');
  }
}

function showError(message) {
  loading.style.display = 'none';
  resultsSection.style.display = 'none';
  errorMessage.style.display = 'block';
  errorMessage.textContent = message;
}

// Utility: Escape HTML to prevent XSS
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

// API: Send analysis request
async function analyzeUrlViaAPI(url) {
  try {
    const response = await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Analysis failed');
    }

    const data = await response.json();
    return data.data || data;
  } catch (error) {
    throw new Error(error.message || 'Failed to connect to analysis service');
  }
}

// Event Listeners
analyzeBtn.addEventListener('click', async () => {
  const url = urlInput.value.trim();

  if (!url) {
    showError('Please enter a URL');
    return;
  }

  let urlToAnalyze = url;
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    urlToAnalyze = 'https://' + url;
  }

  try {
    new URL(urlToAnalyze);
  } catch (e) {
    showError('Invalid URL format');
    return;
  }

  showLoading();

  try {
    const result = await analyzeUrlViaAPI(urlToAnalyze);
    displayResults(result);
  } catch (error) {
    showError('Error: ' + error.message);
  }
});

urlInput.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    analyzeBtn.click();
  }
});

console.log('GhostLink Scanner initialized');
