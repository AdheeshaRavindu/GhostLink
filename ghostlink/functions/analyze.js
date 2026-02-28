// URL Analysis Functions
// Analyze URLs for security threats

const SUSPICIOUS_KEYWORDS = ['login', 'verify', 'secure', 'update', 'bank', 'free'];

/**
 * Check if the URL uses an IP address instead of a domain
 * @param {string} url
 * @returns {object} { found: boolean, points: number }
 */
function checkIPAddress(url) {
  const ipPattern = /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/;
  if (ipPattern.test(url)) {
    return { found: true, points: 40 };
  }
  return { found: false, points: 0 };
}

/**
 * Check if HTTPS is missing
 * @param {string} url
 * @returns {object} { found: boolean, points: number }
 */
function checkNoHTTPS(url) {
  if (url.startsWith('http://')) {
    return { found: true, points: 20 };
  }
  return { found: false, points: 0 };
}

/**
 * Check for '@' symbol in URL (credential phishing indicator)
 * @param {string} url
 * @returns {object} { found: boolean, points: number }
 */
function checkAtSymbol(url) {
  if (url.includes('@')) {
    return { found: true, points: 30 };
  }
  return { found: false, points: 0 };
}

/**
 * Check for more than 3 subdomains
 * @param {string} url
 * @returns {object} { found: boolean, points: number }
 */
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
    // Invalid URL
  }
  return { found: false, points: 0 };
}

/**
 * Check for suspicious keywords in URL
 * @param {string} url
 * @returns {object} { found: boolean, points: number }
 */
function checkSuspiciousKeywords(url) {
  const lowerUrl = url.toLowerCase();
  const found = SUSPICIOUS_KEYWORDS.some(keyword => lowerUrl.includes(keyword));
  
  if (found) {
    return { found: true, points: 10 };
  }
  return { found: false, points: 0 };
}

/**
 * Check if domain length exceeds 40 characters
 * @param {string} url
 * @returns {object} { found: boolean, points: number }
 */
function checkDomainLength(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    
    if (hostname.length > 40) {
      return { found: true, points: 10, length: hostname.length };
    }
  } catch (e) {
    // Invalid URL
  }
  return { found: false, points: 0 };
}

/**
 * Determine risk level based on score
 * @param {number} score
 * @returns {string} "Low" | "Medium" | "High"
 */
function getRiskLevel(score) {
  if (score <= 30) return 'Low';
  if (score <= 70) return 'Medium';
  return 'High';
}

/**
 * Analyze URL for security threats
 * @param {string} url
 * @returns {object} { score: number, riskLevel: string, findings: array }
 */
function analyzeUrl(url) {
  const findings = [];
  let totalScore = 0;

  // Check IP address
  const ipCheck = checkIPAddress(url);
  if (ipCheck.found) {
    totalScore += ipCheck.points;
    findings.push({
      type: 'IP Address',
      description: 'URL uses IP address instead of domain name',
      points: ipCheck.points
    });
  }

  // Check HTTPS
  const httpsCheck = checkNoHTTPS(url);
  if (httpsCheck.found) {
    totalScore += httpsCheck.points;
    findings.push({
      type: 'No HTTPS',
      description: 'URL does not use HTTPS encryption',
      points: httpsCheck.points
    });
  }

  // Check @ symbol
  const atCheck = checkAtSymbol(url);
  if (atCheck.found) {
    totalScore += atCheck.points;
    findings.push({
      type: 'At Symbol',
      description: 'URL contains @ symbol (possible credential phishing)',
      points: atCheck.points
    });
  }

  // Check subdomains
  const subdomainCheck = checkSubdomains(url);
  if (subdomainCheck.found) {
    totalScore += subdomainCheck.points;
    findings.push({
      type: 'Excessive Subdomains',
      description: `URL has ${subdomainCheck.count} subdomains (more than 3)`,
      points: subdomainCheck.points
    });
  }

  // Check suspicious keywords
  const keywordCheck = checkSuspiciousKeywords(url);
  if (keywordCheck.found) {
    totalScore += keywordCheck.points;
    findings.push({
      type: 'Suspicious Keywords',
      description: 'URL contains suspicious keywords',
      points: keywordCheck.points
    });
  }

  // Check domain length
  const lengthCheck = checkDomainLength(url);
  if (lengthCheck.found) {
    totalScore += lengthCheck.points;
    findings.push({
      type: 'Domain Length',
      description: `Domain name is ${lengthCheck.length} characters (exceeds 40)`,
      points: lengthCheck.points
    });
  }

  return {
    score: totalScore,
    riskLevel: getRiskLevel(totalScore),
    findings: findings
  };
}

export { analyzeUrl };
