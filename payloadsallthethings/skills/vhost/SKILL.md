---
name: vhost
description: Virtual host enumeration and Host header attacks. Use when testing virtual host configurations.
---

# Virtual Host Enumeration

## Description
Virtual hosts allow web servers to host multiple domains on a single IP address. The server routes requests based on the `Host` header. Enumerating virtual hosts can reveal hidden subdomains, development environments, admin panels, and other sensitive functionality.

## How Virtual Hosts Work

```
Client Request:
GET / HTTP/1.1
Host: site-a.com
-> Served site-a.com content

GET / HTTP/1.1
Host: site-b.com
-> Served site-b.com content

Same IP, different content based on Host header
```

## Enumeration Techniques

### 1. Manual Testing

```bash
# Test different Host headers
curl -H "Host: dev.target.com" http://target-ip/
curl -H "Host: admin.target.com" http://target-ip/
curl -H "Host: staging.target.com" http://target-ip/
curl -H "Host: internal.target.com" http://target-ip/
```

### 2. Response Comparison

```bash
# Default response
curl -s http://target-ip/ | md5sum

# Test vhost
curl -s -H "Host: test.target.com" http://target-ip/ | md5sum

# Different hash = different vhost found!
```

### 3. Certificate Analysis

```bash
# Extract domains from SSL certificate
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"

# Using sslyze
sslyze --certinfo target.com
```

## Tools

### Gobuster
```bash
# VHost enumeration
gobuster vhost -u https://target.com -w /path/to/wordlist.txt

# With threads
gobuster vhost -u https://target.com -w wordlist.txt -t 50

# Custom port
gobuster vhost -u http://target.com:8080 -w wordlist.txt

# With output
gobuster vhost -u https://target.com -w wordlist.txt -o vhosts.txt
```

### ffuf
```bash
# VHost fuzzing
ffuf -w wordlist.txt -u http://target.com -H "Host: FUZZ.target.com" -fs 0

# Filter by response size
ffuf -w wordlist.txt -u http://target.com -H "Host: FUZZ.target.com" -fs 1234

# Filter by status code
ffuf -w wordlist.txt -u http://target.com -H "Host: FUZZ.target.com" -fc 404

# Match specific size
ffuf -w wordlist.txt -u http://target.com -H "Host: FUZZ.target.com" -ms 5678
```

### VhostScan
```bash
# https://github.com/codingo/VHostScan

# Basic scan
python VHostScan.py -t target.com

# With wordlist
python VHostScan.py -t target.com -w wordlist.txt

# Specify base host
python VHostScan.py -t target.com -b basehost.com
```

### wfuzz
```bash
# VHost enumeration
wfuzz -w wordlist.txt -H "Host: FUZZ.target.com" --hc 404 http://target-ip/

# Filter by response length
wfuzz -w wordlist.txt -H "Host: FUZZ.target.com" --hh 1234 http://target-ip/
```

### hakoriginfinder
```bash
# Find origin servers behind CDN/WAF
# https://github.com/hakluke/hakoriginfinder

cat domains.txt | hakoriginfinder
```

## Common Virtual Host Names

```
admin
dev
staging
test
beta
api
internal
intranet
portal
backend
cms
blog
shop
mail
webmail
secure
private
hidden
secret
old
new
temp
demo
lab
qa
uat
prod
www
m (mobile)
app
dashboard
panel
manage
management
console
```

## DNS History Analysis

```bash
# Check DNS history for previous IPs
# Use services like:
# - SecurityTrails
# - ViewDNS
# - DNSDumpster

# Then spray current domains against old IPs
for ip in $(cat old_ips.txt); do
    for domain in $(cat domains.txt); do
        curl -s -H "Host: $domain" "http://$ip/" | md5sum
    done
done
```

## Bypassing Security Controls

### WAF Bypass via Origin
```bash
# If WAF protects public-facing server
# Find origin IP and access directly
curl -H "Host: target.com" http://origin-ip/

# May bypass WAF rules
```

### CDN Bypass
```bash
# Access origin server directly
# May have different security controls

# Find origin via:
# - DNS history
# - Certificate transparency
# - Shodan/Censys
# - Error messages
```

## Detection Indicators

### Different VHost Found When:
```
- Different response body
- Different response size
- Different status code
- Different headers
- Different title
- Custom error page
- Different redirect
```

### Filtering Strategies
```bash
# Filter default response size
ffuf -w wordlist.txt -u http://target.com -H "Host: FUZZ.target.com" -fs 1234

# Filter by word count
ffuf -w wordlist.txt -u http://target.com -H "Host: FUZZ.target.com" -fw 100

# Filter by line count
ffuf -w wordlist.txt -u http://target.com -H "Host: FUZZ.target.com" -fl 50
```

## Wordlists

### SecLists
```
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

### Custom Wordlist Generation
```bash
# From certificate transparency
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# From subdomain enumeration tools
subfinder -d target.com -silent | cut -d. -f1 | sort -u > custom_vhosts.txt
```

## Testing Checklist

- [ ] Identify target IP address
- [ ] Extract domains from SSL certificate
- [ ] Check DNS history for the IP
- [ ] Enumerate vhosts with wordlist
- [ ] Compare responses for differences
- [ ] Test common vhost names
- [ ] Check for development/staging environments
- [ ] Look for admin/internal interfaces
- [ ] Document all discovered vhosts

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Virtual%20Hosts
- https://github.com/codingo/VHostScan
- https://portswigger.net/web-security/host-header
