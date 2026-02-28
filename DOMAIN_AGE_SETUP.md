# Domain Age Feature Setup Guide

## Overview
The domain age feature uses **RDAP (Registration Data Access Protocol)** - a free, standardized protocol to fetch domain registration information and calculate how old a domain is. This helps identify potentially malicious domains (newly registered domains are often suspicious).

**✅ Completely FREE - No API key required!**

## How It Works
- When analyzing a URL, the worker extracts the domain name
- Queries the free RDAP protocol via `rdap.org` (public bootstrap service)
- RDAP returns domain registration date in JSON format
- Age is calculated and displayed as "X years old" or "X days old"
- Domains under 1 year show ⚠️ warning (potentially suspicious)
- Domains over 1 year show ✓ checkmark (established)

## Setup Instructions

### Just Deploy - No Configuration Needed!
```powershell
# Add all changes
git add -A

# Commit with message
git commit -m "Add: Domain age feature using free RDAP protocol"

# Push to deploy (auto-deploys to Cloudflare Workers)
git push origin main
```

That's it! Domain age will automatically work with no API keys or configuration.

## What is RDAP?
RDAP (Registration Data Access Protocol) is the modern, standardized replacement for WHOIS:
- **Free & Open:** No API keys, no rate limits (reasonable use)
- **Standardized:** JSON responses, not raw text
- **Reliable:** Maintained by domain registries worldwide
- **Official:** IETF standard (RFC 7480-7484)

## What is RDAP?
RDAP (Registration Data Access Protocol) is the modern, standardized replacement for WHOIS:
- **Free & Open:** No API keys, no rate limits (reasonable use)
- **Standardized:** JSON responses, not raw text
- **Reliable:** Maintained by domain registries worldwide
- **Official:** IETF standard (RFC 7480-7484)

## Coverage
RDAP works for most common TLDs:
- ✅ `.com`, `.net`, `.org`, `.info`, `.biz`
- ✅ Country codes: `.uk`, `.au`, `.de`, `.fr`, `.ca`, etc.
- ✅ New gTLDs: `.app`, `.dev`, `.cloud`, `.io`, etc.

Some registries may not support RDAP yet - in those cases, domain age simply won't appear.

## Rate Limiting
RDAP is free but registries may implement rate limiting:
- Typical limits: 100-1000 requests per minute
- 5-second timeout prevents hanging
- Failed lookups are silently skipped

## Testing
After deployment, test with these domains:
- **Old domain:** `google.com` (should show many years)
- **Medium age:** `github.com` (established)
- **Check coverage:** Try various TLDs

## Troubleshooting
**Domain age not showing:**
- Domain's TLD may not support RDAP yet
- Registry may be temporarily unavailable
- Domain registration date may be privacy-protected
- Check Cloudflare Worker logs for errors

**RDAP vs WHOIS:**
- RDAP is the modern standard (recommended)
- Some old registries still only support legacy WHOIS text protocol
- Coverage improves as registries migrate to RDAP
