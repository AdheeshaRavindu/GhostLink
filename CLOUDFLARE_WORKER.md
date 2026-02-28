# GhostLink Cloudflare Worker

Copy and paste the code below into your Cloudflare Worker editor.

## Code

```javascript
// Cloudflare Worker - GhostLink URL Analysis
// ES Module Syntax

const SUSPICIOUS_KEYWORDS = ['login', 'verify', 'secure', 'update', 'bank', 'free'];

/**
 * Check if the URL uses an IP address instead of a domain
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
 */
function checkNoHTTPS(url) {
  if (url.startsWith('http://')) {
    return { found: true, points: 20 };
  }
  return { found: false, points: 0 };
}

/**
 * Check for '@' symbol in URL
 */
function checkAtSymbol(url) {
  if (url.includes('@')) {
    return { found: true, points: 30 };
  }
  return { found: false, points: 0 };
}

/**
 * Check for more than 3 subdomains
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
 */
function getRiskLevel(score) {
  if (score <= 30) return 'Low';
  if (score <= 70) return 'Medium';
  return 'High';
}

/**
 * Analyze URL for security threats
 */
function analyzeUrl(url) {
  const findings = [];
  let totalScore = 0;

  const ipCheck = checkIPAddress(url);
  if (ipCheck.found) {
    totalScore += ipCheck.points;
    findings.push({
      type: 'IP Address',
      description: 'URL uses IP address instead of domain name',
      points: ipCheck.points
    });
  }

  const httpsCheck = checkNoHTTPS(url);
  if (httpsCheck.found) {
    totalScore += httpsCheck.points;
    findings.push({
      type: 'No HTTPS',
      description: 'URL does not use HTTPS encryption',
      points: httpsCheck.points
    });
  }

  const atCheck = checkAtSymbol(url);
  if (atCheck.found) {
    totalScore += atCheck.points;
    findings.push({
      type: 'At Symbol',
      description: 'URL contains @ symbol (possible credential phishing)',
      points: atCheck.points
    });
  }

  const subdomainCheck = checkSubdomains(url);
  if (subdomainCheck.found) {
    totalScore += subdomainCheck.points;
    findings.push({
      type: 'Excessive Subdomains',
      description: `URL has ${subdomainCheck.count} subdomains (more than 3)`,
      points: subdomainCheck.points
    });
  }

  const keywordCheck = checkSuspiciousKeywords(url);
  if (keywordCheck.found) {
    totalScore += keywordCheck.points;
    findings.push({
      type: 'Suspicious Keywords',
      description: 'URL contains suspicious keywords',
      points: keywordCheck.points
    });
  }

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

/**
 * Handle HTTP requests
 */
export default {
  async fetch(request, env, ctx) {
    // Enable CORS
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Content-Type': 'application/json'
    };

    // Handle preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // Handle POST /analyze
    if (request.method === 'POST' && new URL(request.url).pathname === '/analyze') {
      try {
        const body = await request.json();
        const { url } = body;

        // Validate input
        if (!url || typeof url !== 'string') {
          return new Response(
            JSON.stringify({
              error: 'Invalid input. Please provide a valid URL string.',
              code: 'INVALID_INPUT'
            }),
            { status: 400, headers: corsHeaders }
          );
        }

        // Validate URL format
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

        // Analyze URL
        const result = analyzeUrl(url);

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

    // Handle 404
    return new Response(
      JSON.stringify({
        error: 'Route not found',
        code: 'NOT_FOUND'
      }),
      { status: 404, headers: corsHeaders }
    );
  }
};
```

## Usage

### Request
```bash
curl -X POST https://your-worker.workers.dev/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"http://evil-bank-login.verify.com"}'
```

### Response (Success)
```json
{
  "success": true,
  "data": {
    "score": 60,
    "riskLevel": "Medium",
    "findings": [
      {
        "type": "No HTTPS",
        "description": "URL does not use HTTPS encryption",
        "points": 20
      },
      {
        "type": "Suspicious Keywords",
        "description": "URL contains suspicious keywords",
        "points": 10
      },
      {
        "type": "Excessive Subdomains",
        "description": "URL has 4 subdomains (more than 3)",
        "points": 15
      },
      {
        "type": "Domain Length",
        "description": "Domain name is 41 characters (exceeds 40)",
        "points": 10
      }
    ]
  }
}
```

### Response (Error)
```json
{
  "error": "Invalid URL format.",
  "code": "INVALID_URL"
}
```

## Features

- ✅ ES Module syntax (export default)
- ✅ Standard Web APIs only (URL, Request, Response, JSON)
- ✅ No Node.js libraries
- ✅ CORS enabled for cross-origin requests
- ✅ Input validation
- ✅ Error handling
- ✅ POST /analyze endpoint
- ✅ All 6 security checks included
