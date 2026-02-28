const SUSPICIOUS_KEYWORDS = ['login', 'verify', 'secure', 'update', 'bank', 'free'];
const SUSPICIOUS_TLDS = ['xyz', 'top', 'click', 'pw', 'tk', 'ml', 'cf', 'ga', 'online', 'site', 'space', 'download'];

// PHISHING RISK CHECKS
function checkIPAddress(url) {
  const ipPattern = /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/;
  if (ipPattern.test(url)) {
    return { found: true, points: 40 };
  }
  return { found: false, points: 0 };
}

function checkAtSymbol(url) {
  if (url.includes('@')) {
    return { found: true, points: 30 };
  }
  return { found: false, points: 0 };
}

function checkSubdomains(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const parts = hostname.split('.');
    const subdomainCount = parts.length - 2;
    
    if (subdomainCount > 3) {
      return { found: true, points: 15, count: subdomainCount };
    }
  } catch (e) {
    //
  }
  return { found: false, points: 0 };
}

function checkSuspiciousKeywords(url) {
  const lowerUrl = url.toLowerCase();
  const found = SUSPICIOUS_KEYWORDS.some(keyword => lowerUrl.includes(keyword));
  
  if (found) {
    return { found: true, points: 10 };
  }
  return { found: false, points: 0 };
}

function checkDomainLength(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    
    if (hostname.length > 40) {
      return { found: true, points: 10, length: hostname.length };
    }
  } catch (e) {
    //
  }
  return { found: false, points: 0 };
}

// HTTPS & SSL CHECKS
function checkHTTPS(url) {
  if (!url.startsWith('https://')) {
    return { found: true, points: 20 };
  }
  return { found: false, points: 0 };
}

async function checkHTTPSRedirect(url) {
  try {
    if (!url.startsWith('http://')) {
      return { found: false, points: 0 };
    }

    const response = await fetch(url, {
      method: 'HEAD',
      redirect: 'manual'
    });

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (location && location.startsWith('https://')) {
        return { found: false, points: 0 };
      }
    }

    return { found: true, points: 15 };
  } catch (e) {
    return { found: false, points: 0 };
  }
}

async function checkHSTS(url) {
  try {
    const urlObj = new URL(url);
    const response = await fetch(url, {
      method: 'HEAD'
    });

    const hsts = response.headers.get('strict-transport-security');
    if (!hsts) {
      return { found: true, points: 10 };
    }
    return { found: false, points: 0 };
  } catch (e) {
    return { found: false, points: 0 };
  }
}

// SECURITY HEADERS CHECK
async function checkSecurityHeaders(url) {
  const findings = [];
  const headers = {
    'content-security-policy': { name: 'CSP', points: 15 },
    'x-frame-options': { name: 'X-Frame-Options', points: 10 },
    'x-content-type-options': { name: 'X-Content-Type-Options', points: 10 },
    'strict-transport-security': { name: 'HSTS', points: 10 },
    'referrer-policy': { name: 'Referrer-Policy', points: 5 }
  };

  try {
    const response = await fetch(url, {
      method: 'HEAD'
    });

    let totalPoints = 0;
    for (const [headerKey, headerInfo] of Object.entries(headers)) {
      if (!response.headers.get(headerKey)) {
        totalPoints += headerInfo.points;
        findings.push({
          name: headerInfo.name,
          points: headerInfo.points
        });
      }
    }

    return { totalPoints, findings };
  } catch (e) {
    return { totalPoints: 0, findings: [] };
  }
}

// DOMAIN INTELLIGENCE
function checkSuspiciousTLD(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const tld = hostname.split('.').pop().toLowerCase();

    if (SUSPICIOUS_TLDS.includes(tld)) {
      return { found: true, points: 20 };
    }
  } catch (e) {
    //
  }
  return { found: false, points: 0 };
}

function checkPunycode(url) {
  if (url.includes('xn--')) {
    return { found: true, points: 25 };
  }
  return { found: false, points: 0 };
}

// REPUTATION HEURISTICS
function checkURLLength(url) {
  if (url.length > 75) {
    return { found: true, points: 10 };
  }
  return { found: false, points: 0 };
}

function checkEncodedCharacters(url) {
  if (url.includes('%')) {
    return { found: true, points: 12 };
  }
  return { found: false, points: 0 };
}

// URL ENTROPY / RANDOMNESS SCORE
function calculateURLEntropy(url) {
  const urlPath = new URL(url).pathname + new URL(url).search;
  const charFreq = {};
  
  for (const char of urlPath) {
    charFreq[char] = (charFreq[char] || 0) + 1;
  }

  let entropy = 0;
  const len = urlPath.length;
  
  for (const freq of Object.values(charFreq)) {
    const p = freq / len;
    entropy -= p * Math.log2(p);
  }

  if (entropy > 4.5) {
    return { found: true, points: 15 };
  }
  return { found: false, points: 0 };
}

// REDIRECT CHAIN ANALYSIS
async function checkRedirectChain(url) {
  try {
    let currentUrl = url;
    let redirectCount = 0;
    const maxRedirects = 10;

    while (redirectCount < maxRedirects) {
      const response = await fetch(currentUrl, {
        method: 'HEAD',
        redirect: 'manual'
      });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (!location) break;

        redirectCount++;
        const newUrl = new URL(location, currentUrl).href;
        
        if (newUrl === currentUrl) break;
        currentUrl = newUrl;
      } else {
        break;
      }
    }

    if (redirectCount > 2) {
      return { found: true, points: 18, count: redirectCount };
    }
    return { found: false, points: 0 };
  } catch (e) {
    return { found: false, points: 0 };
  }
}

// SCORING
function getRiskLevel(score) {
  if (score <= 30) return 'Low';
  if (score <= 70) return 'Medium';
  return 'High';
}

// WEIGHTED RISK ENGINE
const riskWeights = {
  'Phishing Risk': 1.3,
  'HTTPS & SSL': 1.4,
  'Security Headers': 1.2,
  'Domain Intelligence': 1.25,
  'Reputation': 1.0,
  'Redirect Chain': 1.35
};

function calculateWeightedScore(findings) {
  let weightedScore = 0;
  const categoryScores = {};

  for (const finding of findings) {
    const category = finding.category;
    const weight = riskWeights[category] || 1.0;
    const weighted = finding.points * weight;
    
    weightedScore += weighted;
    categoryScores[category] = (categoryScores[category] || 0) + finding.points;
  }

  return Math.min(Math.round(weightedScore / findings.length || 0), 100);
}

// MAIN ANALYSIS
async function analyzeUrl(url) {
  const findings = [];
  let totalScore = 0;

  // 1. PHISHING RISK
  const checks = [
    { name: 'IP Address', fn: checkIPAddress, category: 'Phishing Risk' },
    { name: 'At Symbol', fn: checkAtSymbol, category: 'Phishing Risk' },
    { name: 'Excessive Subdomains', fn: checkSubdomains, category: 'Phishing Risk' },
    { name: 'Suspicious Keywords', fn: checkSuspiciousKeywords, category: 'Phishing Risk' },
    { name: 'Domain Length', fn: checkDomainLength, category: 'Phishing Risk' },
    { name: 'No HTTPS', fn: checkHTTPS, category: 'HTTPS & SSL' },
    { name: 'Suspicious TLD', fn: checkSuspiciousTLD, category: 'Domain Intelligence' },
    { name: 'Punycode Domain', fn: checkPunycode, category: 'Domain Intelligence' },
    { name: 'Long URL', fn: checkURLLength, category: 'Reputation' },
    { name: 'Encoded Characters', fn: checkEncodedCharacters, category: 'Reputation' },
    { name: 'High URL Entropy', fn: calculateURLEntropy, category: 'Reputation' }
  ];

  for (const check of checks) {
    const result = check.fn(url);
    if (result.found) {
      totalScore += result.points;
      let description = '';
      
      if (check.name === 'IP Address') description = 'URL uses IP address instead of domain name';
      else if (check.name === 'At Symbol') description = 'URL contains @ symbol (credential phishing)';
      else if (check.name === 'Excessive Subdomains') description = `URL has ${result.count} subdomains (more than 3)`;
      else if (check.name === 'Suspicious Keywords') description = 'URL contains suspicious keywords (login, verify, bank, etc.)';
      else if (check.name === 'Domain Length') description = `Domain name is ${result.length} characters (exceeds 40)`;
      else if (check.name === 'No HTTPS') description = 'URL does not use HTTPS encryption';
      else if (check.name === 'Suspicious TLD') description = 'Suspicious top-level domain detected';
      else if (check.name === 'Punycode Domain') description = 'Punycode detected (xn-- domain)';
      else if (check.name === 'Long URL') description = 'URL is unusually long (exceeds 75 characters)';
      else if (check.name === 'Encoded Characters') description = 'URL contains encoded characters (% symbols)';
      else if (check.name === 'High URL Entropy') description = 'URL path contains high randomness/entropy';

      findings.push({
        type: check.name,
        category: check.category,
        description: description,
        points: result.points
      });
    }
  }

  // 2. HTTPS/SSL ASYNC CHECKS
  const httpsRedirectResult = await checkHTTPSRedirect(url);
  if (httpsRedirectResult.found) {
    totalScore += httpsRedirectResult.points;
    findings.push({
      type: 'No HTTP → HTTPS Redirect',
      category: 'HTTPS & SSL',
      description: 'HTTP does not redirect to HTTPS',
      points: httpsRedirectResult.points
    });
  }

  const hstsResult = await checkHSTS(url);
  if (hstsResult.found) {
    totalScore += hstsResult.points;
    findings.push({
      type: 'No HSTS Header',
      category: 'HTTPS & SSL',
      description: 'HSTS (HTTP Strict Transport Security) header missing',
      points: hstsResult.points
    });
  }

  // 3. SECURITY HEADERS
  const headersResult = await checkSecurityHeaders(url);
  totalScore += headersResult.totalPoints;
  for (const header of headersResult.findings) {
    findings.push({
      type: `Missing ${header.name}`,
      category: 'Security Headers',
      description: `Security header ${header.name} is missing`,
      points: header.points
    });
  }

  // 4. REDIRECT CHAIN ANALYSIS
  const redirectResult = await checkRedirectChain(url);
  if (redirectResult.found) {
    totalScore += redirectResult.points;
    findings.push({
      type: 'Redirect Chain Detected',
      category: 'Redirect Chain',
      description: `URL has ${redirectResult.count} redirects (exceeds 2)`,
      points: redirectResult.points
    });
  }

  return {
    score: Math.min(totalScore, 100),
    riskLevel: getRiskLevel(Math.min(totalScore, 100)),
    findings: findings
  };
}

export default {
  async fetch(request, env, ctx) {
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Content-Type': 'application/json'
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    if (request.method === 'POST' && new URL(request.url).pathname === '/analyze') {
      try {
        const body = await request.json();
        const { url } = body;

        if (!url || typeof url !== 'string') {
          return new Response(
            JSON.stringify({
              error: 'Invalid input. Please provide a valid URL string.',
              code: 'INVALID_INPUT'
            }),
            { status: 400, headers: corsHeaders }
          );
        }

        try {
          new URL(url);
        } catch (e) {
          return new Response(
            JSON.stringify({
              error: 'Invalid URL format.',
              code: 'INVALID_URL'
            }),
            { status: 400, headers: corsHeaders }
          );
        }

        const result = await analyzeUrl(url);

        return new Response(
          JSON.stringify({
            success: true,
            data: result
          }),
          { status: 200, headers: corsHeaders }
        );
      } catch (error) {
        return new Response(
          JSON.stringify({
            error: 'Failed to process request',
            code: 'INTERNAL_ERROR',
            message: error.message
          }),
          { status: 500, headers: corsHeaders }
        );
      }
    }

    return new Response(
      JSON.stringify({
        error: 'Route not found',
        code: 'NOT_FOUND'
      }),
      { status: 404, headers: corsHeaders }
    );
  }
};
