# GhostLink - URL Security Intelligence Scanner

A lightweight, serverless URL security scanner that combines advanced threat detection, domain intelligence, and security header analysis to assess potential threats before users interact with links.

🔗 **[Live Demo](https://ghostlink-2zt.pages.dev/)**

## Features

🎣 **Phishing Detection**
- IP address detection (direct IP URLs)
- @ symbol detection (credential phishing)
- Excessive subdomain analysis
- Suspicious keyword detection
- Domain length analysis
- URL entropy/randomness scoring

🔒 **HTTPS & SSL Analysis**
- HTTPS encryption verification
- HTTP to HTTPS redirect validation
- HSTS header detection
- Complete security headers audit (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)

🌐 **Domain Intelligence**
- Suspicious TLD detection
- Punycode/homograph attack detection
- Registrable domain extraction
- TLD classification (ccTLD vs gTLD)
- Subdomain profile analysis
- Domain entropy calculation
- Numeric and hyphenated label detection

🔀 **Redirect Chain Analysis**
- Multi-stage redirect detection
- Suspicious redirect tracking

📊 **Server Information**
- Response time measurement
- Technology detection
- Status code analysis
- Content type validation

🛡️ **User-Focused Recommendations**
- Risk-level assessment (Low, Medium, High)
- Actionable safety guidance
- Specific threat warnings
- Best practices for safe browsing

## How It Works

GhostLink analyzes URLs across six security dimensions and assigns a composite risk score (0-100):
- **Phishing Risk**: Detects common phishing techniques
- **HTTPS & SSL**: Validates secure transport
- **Security Headers**: Audits HTTP security configurations
- **Domain Intelligence**: Analyzes domain structure and patterns
- **Reputation**: Evaluates URL composition and characteristics
- **Redirect Chain**: Detects suspicious redirects

Each category is weighted based on security impact, providing a comprehensive threat assessment.

## Technology Stack

- **Frontend**: Vanilla JavaScript, HTML5, CSS3
- **Backend**: Cloudflare Workers (Serverless)
- **Architecture**: Fully serverless, no database required
- **Security**: All analysis performed without storing URLs

## Usage

1. Visit the GhostLink scanner
2. Enter any URL (must include http:// or https://)
3. Click "Analyze"
4. Review the security assessment and recommendations

## Live Features

- Real-time URL analysis
- Instant threat detection
- Interactive security headers breakdown
- Domain structure visualization
- Server information discovery
- DNS lookup integration

## Privacy

GhostLink does **not** store analyzed URLs. All analysis is performed on-demand without logging or data persistence.

## License

See LICENSE file for details.

---

**Made with ❤️ by Adheesha**
