# Setup Instructions

## Prerequisites

- Git
- Cloudflare account (free tier works)
- Text editor or IDE

## Local Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/AdheeshaRavindu/GhostLink.git
   cd GhostLink
   ```

2. **Open locally**
   - Simply open `index.html` in your browser
   - Or use a local server:
   ```bash
   # Python 3
   python -m http.server 8000

   # Node.js
   npx serve
   ```

## Cloudflare Workers Setup

1. **Create a Cloudflare Worker**
   - Go to [Cloudflare Dashboard](https://dash.cloudflare.com/)
   - Navigate to Workers & Pages
   - Click "Create Application" → "Create Worker"
   - Name your worker (e.g., `ghostlink-analyzer`)

2. **Deploy the Worker**
   - Copy the contents of `ghostlink/worker-production.js`
   - Paste it into the Cloudflare Worker editor
   - Click "Save and Deploy"
   - Copy your worker URL (e.g., `https://your-worker.your-subdomain.workers.dev/analyze`)

3. **Update Frontend Configuration**
   - Open `script.js`
   - Update the `WORKER_URL` constant with your worker URL:
   ```javascript
   const WORKER_URL = 'https://your-worker.your-subdomain.workers.dev/analyze';
   ```

## Cloudflare Pages Deployment

1. **Connect Repository**
   - Go to Cloudflare Dashboard → Workers & Pages
   - Click "Create Application" → "Pages" → "Connect to Git"
   - Select your GhostLink repository

2. **Configure Build Settings**
   - Framework preset: None
   - Build command: (leave empty)
   - Build output directory: `/`
   - Root directory: `/`

3. **Deploy**
   - Click "Save and Deploy"
   - Your site will be live at `https://your-project.pages.dev`

## Alternative: Deploy to Other Platforms

### GitHub Pages
```bash
# Enable GitHub Pages in repository settings
# Select main branch as source
# Your site will be at: https://username.github.io/GhostLink
```

### Netlify
- Drag and drop the project folder to Netlify
- Or connect via Git
- Add `_headers` file for security headers (already included)

### Vercel
```bash
npm i -g vercel
vercel --prod
```

## Configuration

### Update Worker URL
Edit `script.js` line 4:
```javascript
const WORKER_URL = 'YOUR_WORKER_URL/analyze';
```

### Customize Branding
- Update title in `index.html`
- Modify colors in `style.css`
- Change footer text in `index.html`

## Testing

Test with sample URLs:
- Safe: `https://github.com`
- HTTP: `http://example.com`
- IP: `http://192.168.1.1`
- Suspicious: `https://login.secure.account.verification.microsoft-login.com.suspicious-domain.co`

## Troubleshooting

### CORS Issues
Ensure your Cloudflare Worker has CORS headers:
```javascript
headers: {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type'
}
```

### Worker Not Responding
- Check worker URL is correct in `script.js`
- Verify worker is deployed and active in Cloudflare Dashboard
- Check browser console for error messages

### Security Headers Not Applied
- Ensure `_headers` file is in root directory
- Redeploy to Cloudflare Pages
- Check deployment logs for errors

## License

See [LICENSE](LICENSE) file for details.
