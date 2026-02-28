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
  try {
    const urlObj = new URL(url);
    const urlPath = urlObj.pathname + urlObj.search;
    
    if (urlPath.length === 0) {
      return { found: false, points: 0 };
    }
    
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
  } catch (e) {
    return { found: false, points: 0 };
  }
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

// URL COMPONENT ANALYSIS
function analyzeURLComponents(url) {
  try {
    const urlObj = new URL(url);
    const pathSegments = urlObj.pathname.split('/').filter(s => s.length > 0);
    
    return {
      protocol: urlObj.protocol,
      domain: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80'),
      pathDepth: pathSegments.length,
      pathLength: urlObj.pathname.length,
      queryParamCount: new URLSearchParams(urlObj.search).size,
      hasFragment: urlObj.hash.length > 0,
      domainParts: urlObj.hostname.split('.').length
    };
  } catch (e) {
    return null;
  }
}

// EXTRACT PAGE METADATA
async function extractPageMetadata(url) {
  const metadata = {
    title: null,
    description: null,
    contentType: null,
    favicon: null,
    language: null,
    charset: null,
    hasForm: false
  };

  try {
    const response = await fetch(url, { method: 'GET' });
    if (!response.ok) return metadata;

    const contentType = response.headers.get('content-type');
    metadata.contentType = contentType;

    if (!contentType || !contentType.includes('text/html')) {
      return metadata;
    }

    const html = await response.text();
    const maxLength = Math.min(html.length, 50000);
    const htmlSnippet = html.substring(0, maxLength);

    // Extract title
    const titleMatch = htmlSnippet.match(/<title[^>]*>([^<]+)<\/title>/i);
    metadata.title = titleMatch ? titleMatch[1].substring(0, 100) : null;

    // Extract meta description
    const descMatch = htmlSnippet.match(/<meta\s+name=["']description["']\s+content=["']([^"']+)["']/i);
    metadata.description = descMatch ? descMatch[1].substring(0, 150) : null;

    // Extract language
    const langMatch = htmlSnippet.match(/<html[^>]*lang=["']([^"']+)["']/i);
    metadata.language = langMatch ? langMatch[1] : null;

    // Extract charset
    const charsetMatch = htmlSnippet.match(/<meta[^>]*charset=["']?([^"'>\s]+)/i);
    metadata.charset = charsetMatch ? charsetMatch[1] : null;

    // Extract favicon
    const faviconMatch = htmlSnippet.match(/<link[^>]*rel=["'](?:shortcut\s)?icon["'][^>]*href=["']([^"']+)["']/i);
    if (faviconMatch) {
      metadata.favicon = faviconMatch[1];
    }

    // Check for forms
    metadata.hasForm = /<form[^>]*>/i.test(htmlSnippet);

    return metadata;
  } catch (e) {
    return metadata;
  }
}

// FETCH DOMAIN AGE FROM RDAP (FREE - NO API KEY REQUIRED)
async function fetchDomainAge(domain) {
  try {
    // Extract TLD to determine RDAP server
    const tld = domain.split('.').pop().toLowerCase();
    
    // RDAP Bootstrap service (redirects to correct RDAP server)
    const rdapUrl = `https://rdap.org/domain/${domain}`;
    
    const response = await fetch(rdapUrl, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(5000)
    });

    if (!response.ok) return null;

    const data = await response.json();
    
    // RDAP returns events array with registration date
    const events = data?.events || [];
    const registrationEvent = events.find(e => e.eventAction === 'registration');
    
    if (!registrationEvent?.eventDate) return null;

    const createdDate = registrationEvent.eventDate;
    const created = new Date(createdDate);
    const now = new Date();
    const ageInDays = Math.floor((now - created) / (1000 * 60 * 60 * 24));
    const ageInYears = (ageInDays / 365).toFixed(1);

    return {
      createdDate: createdDate,
      ageInDays: ageInDays,
      ageInYears: ageInYears,
      ageFormatted: ageInYears >= 1 ? `${ageInYears} years` : `${ageInDays} days`
    };
  } catch (e) {
    return null; // RDAP lookup failed
  }
}

// EXTRACT SERVER INFO
async function extractServerInfo(url, env) {
  const serverInfo = {
    server: null,
    poweredBy: null,
    xFrameOptions: null,
    xContentTypeOptions: null,
    contentSecurityPolicy: null,
    xUaCompatible: null,
    cacheControl: null,
    contentEncoding: null,
    expires: null,
    etag: null,
    responseTime: 0,
    statusCode: null,
    statusMessage: null,
    technologies: [],
    securityHeaders: {},
    redirects: [],
    contentLength: null,
    lastModified: null,
    age: null,
    finalUrl: url,
    sslInfo: null,
    domainAge: null
  };

  const startTime = Date.now();

  try {
    // Follow redirects to get final URL
    let currentUrl = url;
    let redirectChain = [];
    let redirectCount = 0;
    const maxRedirects = 5;

    while (redirectCount < maxRedirects) {
      const response = await fetch(currentUrl, { method: 'HEAD', redirect: 'manual' });
      
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (location) {
          redirectChain.push({ from: currentUrl, to: location });
          currentUrl = new URL(location, currentUrl).href;
          redirectCount++;
        } else {
          break;
        }
      } else {
        break;
      }
    }

    serverInfo.finalUrl = currentUrl;
    if (redirectChain.length > 0) {
      serverInfo.redirects = redirectChain;
    }

    // Fetch final URL
    const response = await fetch(currentUrl, { method: 'HEAD', redirect: 'follow' });
    serverInfo.responseTime = Date.now() - startTime;
    serverInfo.statusCode = response.status;

    // Get friendly status message
    const statusMessages = {
      200: 'OK', 301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified',
      400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
      500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable'
    };
    serverInfo.statusMessage = statusMessages[response.status] || 'Unknown';

    serverInfo.server = response.headers.get('server');
    serverInfo.poweredBy = response.headers.get('x-powered-by');
    serverInfo.xFrameOptions = response.headers.get('x-frame-options');
    serverInfo.xContentTypeOptions = response.headers.get('x-content-type-options');
    serverInfo.xUaCompatible = response.headers.get('x-ua-compatible');
    serverInfo.cacheControl = response.headers.get('cache-control');
    serverInfo.contentEncoding = response.headers.get('content-encoding');
    serverInfo.expires = response.headers.get('expires');
    serverInfo.etag = response.headers.get('etag');
    serverInfo.contentLength = response.headers.get('content-length');
    serverInfo.lastModified = response.headers.get('last-modified');
    serverInfo.age = response.headers.get('age');

    // Check for SSL/TLS info from headers
    const protocol = new URL(currentUrl).protocol;
    if (protocol === 'https:') {
      serverInfo.sslInfo = 'Secured (HTTPS)';
    } else {
      serverInfo.sslInfo = 'Not Secured (HTTP)';
    }

    // Security headers breakdown
    const csp = response.headers.get('content-security-policy');
    serverInfo.securityHeaders = {
      'Content-Security-Policy': csp ? '✓ Present' : '✗ Missing',
      'X-Frame-Options': serverInfo.xFrameOptions || '✗ Missing',
      'X-Content-Type-Options': serverInfo.xContentTypeOptions || '✗ Missing',
      'Strict-Transport-Security': response.headers.get('strict-transport-security') || '✗ Missing',
      'Referrer-Policy': response.headers.get('referrer-policy') || '✗ Missing',
      'Permissions-Policy': response.headers.get('permissions-policy') ? '✓ Present' : '✗ Missing'
    };

    // Check for redirects
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (location) {
        serverInfo.redirects.push({
          from: url,
          to: location,
          status: response.status
        });
      }
    }

    // Detect technologies from headers
    const serverHeader = response.headers.get('server') || '';
    if (serverHeader.includes('Apache')) serverInfo.technologies.push('Apache');
    if (serverHeader.includes('nginx')) serverInfo.technologies.push('Nginx');
    if (serverHeader.includes('Microsoft-IIS')) serverInfo.technologies.push('IIS');
    if (serverHeader.includes('cloudflare')) serverInfo.technologies.push('Cloudflare CDN');
    if (response.headers.get('x-aspnet-version')) serverInfo.technologies.push('ASP.NET');
    if (response.headers.get('x-powered-by')?.includes('Express')) serverInfo.technologies.push('Express.js');
    if (response.headers.get('x-powered-by')?.includes('PHP')) serverInfo.technologies.push('PHP');
    if (response.headers.get('x-aws-cf-id')) serverInfo.technologies.push('AWS CloudFront');

    // Fetch domain age using free RDAP protocol
    try {
      const urlObj = new URL(currentUrl);
      const domain = urlObj.hostname;
      serverInfo.domainAge = await fetchDomainAge(domain);
    } catch (e) {
      // Domain age lookup failed, continue without it
    }

  } catch (e) {
    serverInfo.responseTime = Date.now() - startTime;
  }

  return serverInfo;
}

// EXTRACT DNS INFO
async function extractDNSInfo(url) {
  const dnsInfo = {
    domain: null,
    resolvedIP: null,
    dnsLookupTime: 0
  };

  try {
    const urlObj = new URL(url);
    dnsInfo.domain = urlObj.hostname;

    const startTime = Date.now();
    // Note: Cloudflare Workers don't have direct DNS lookup, but we can infer from fetch
    const response = await fetch(urlObj.hostname ? `https://${urlObj.hostname}` : url, { method: 'HEAD' });
    dnsInfo.dnsLookupTime = Date.now() - startTime;
    
    // Try to get server IP from headers if available
    const viaHeader = response.headers.get('via');
    if (viaHeader) {
      dnsInfo.resolvedIP = viaHeader;
    }
  } catch (e) {
    // Silently handle DNS errors
  }

  return dnsInfo;
}

// GENERATE SECURITY RECOMMENDATIONS
function generateSecurityRecommendations(details) {
  const recommendations = [];

  try {
    if (details.metadata && !details.metadata.title) {
      recommendations.push('Add a proper page title tag for accessibility');
    }

    if (details.server && details.server.securityHeaders) {
      if (!details.server.securityHeaders['Content-Security-Policy']?.includes('✓')) {
        recommendations.push('Implement Content-Security-Policy header to prevent XSS attacks');
      }

      if (!details.server.securityHeaders['X-Frame-Options']?.includes('✓')) {
        recommendations.push('Add X-Frame-Options header to prevent clickjacking');
      }

      if (!details.server.securityHeaders['Strict-Transport-Security']?.includes('✓')) {
        recommendations.push('Enable HSTS (Strict-Transport-Security) for HTTPS enforcement');
      }
    }

    if (details.metadata?.hasForm && details.components?.protocol === 'http:') {
      recommendations.push('⚠️ CRITICAL: Forms over HTTP are vulnerable to interception. Use HTTPS.');
    }

    if (details.server?.responseTime > 3000) {
      recommendations.push('Server response time is slow. Optimize or use a CDN.');
    }

    if (details.server?.statusCode >= 400) {
      recommendations.push(`Server returned status ${details.server.statusCode}. Check URL validity.`);
    }
  } catch (e) {
    // If recommendation generation fails, return empty array
  }

  return recommendations.slice(0, 5); // Return top 5 recommendations
}

// MAIN ANALYSIS
async function analyzeUrl(url, env) {
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
    try {
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
    } catch (e) {
      // Skip this check if it errors out
    }
  }

  // 2. HTTPS/SSL ASYNC CHECKS
  try {
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
  } catch (e) {
    // Skip if HTTPS redirect check fails
  }

  try {
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
  } catch (e) {
    // Skip if HSTS check fails
  }

  // 3. SECURITY HEADERS
  try {
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
  } catch (e) {
    // Skip if security headers check fails
  }

  // 4. REDIRECT CHAIN ANALYSIS
  try {
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
  } catch (e) {
    // Skip if redirect chain check fails
  }

  // 5. GATHER DETAILED INFORMATION
  let urlComponents = null;
  let pageMetadata = null;
  let serverInfo = null;
  let dnsInfo = null;

  try {
    urlComponents = analyzeURLComponents(url);
  } catch (e) {
    // If URL component analysis fails, use defaults
    urlComponents = {
      protocol: 'unknown',
      domain: 'unknown',
      port: 'unknown',
      pathDepth: 0,
      pathLength: 0,
      queryParamCount: 0,
      hasFragment: false,
      domainParts: 0
    };
  }

  try {
    pageMetadata = await extractPageMetadata(url);
  } catch (e) {
    pageMetadata = {
      title: null,
      description: null,
      contentType: null,
      favicon: null,
      language: null,
      charset: null,
      hasForm: false
    };
  }

  try {
    serverInfo = await extractServerInfo(url, env);
  } catch (e) {
    serverInfo = {
      server: null,
      poweredBy: null,
      xFrameOptions: null,
      xContentTypeOptions: null,
      contentSecurityPolicy: null,
      xUaCompatible: null,
      cacheControl: null,
      contentEncoding: null,
      expires: null,
      etag: null,
      responseTime: 0,
      statusCode: null,
      statusMessage: null,
      technologies: [],
      securityHeaders: {
        'Content-Security-Policy': '✗ Missing',
        'X-Frame-Options': '✗ Missing',
        'X-Content-Type-Options': '✗ Missing',
        'Strict-Transport-Security': '✗ Missing',
        'Referrer-Policy': '✗ Missing',
        'Permissions-Policy': '✗ Missing'
      },
      redirects: [],
      contentLength: null,
      lastModified: null,
      age: null,
      finalUrl: url,
      sslInfo: null,
      domainAge: null
    };
  }

  try {
    dnsInfo = await extractDNSInfo(url);
  } catch (e) {
    dnsInfo = {
      domain: null,
      resolvedIP: null,
      dnsLookupTime: 0
    };
  }

  const details = {
    url: url,
    components: urlComponents,
    metadata: pageMetadata,
    server: serverInfo,
    dns: dnsInfo
  };

  const recommendations = generateSecurityRecommendations(details);

  return {
    score: totalScore,
    riskLevel: getRiskLevel(totalScore),
    findings: findings,
    details: details,
    recommendations: recommendations
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

        // Basic URL format validation (more permissive)
        const urlString = url.trim();
        if (urlString.length === 0) {
          return new Response(
            JSON.stringify({
              error: 'URL cannot be empty',
              code: 'EMPTY_URL'
            }),
            { status: 400, headers: corsHeaders }
          );
        }

        // Check if URL has protocol
        if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
          return new Response(
            JSON.stringify({
              error: 'URL must start with http:// or https://',
              code: 'MISSING_PROTOCOL'
            }),
            { status: 400, headers: corsHeaders }
          );
        }

        // Analyze the URL with error handling
        try {
          const result = await analyzeUrl(urlString, env);

          return new Response(
            JSON.stringify({
              success: true,
              data: result
            }),
            { status: 200, headers: corsHeaders }
          );
        } catch (analysisError) {
          // Analysis failed, but return partial results if possible
          return new Response(
            JSON.stringify({
              error: 'Analysis encountered an error',
              code: 'ANALYSIS_ERROR',
              message: analysisError.message,
              url: urlString
            }),
            { status: 500, headers: corsHeaders }
          );
        }
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
