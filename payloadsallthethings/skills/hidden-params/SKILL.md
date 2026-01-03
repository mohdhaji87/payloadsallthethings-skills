---
name: hidden-params
description: Hidden parameter discovery and exploitation techniques. Use for parameter fuzzing and enumeration.
---

# Hidden Parameters Discovery

## Description
Hidden parameters are URL or form parameters that are not visible in the application's user interface but are processed by the backend. Discovering these parameters can reveal additional functionality, debug features, administrative capabilities, or security vulnerabilities.

## Discovery Techniques

### 1. Wordlist-Based Bruteforcing

Send requests with common parameter names and analyze responses for differences.

```bash
# Using Arjun
arjun -u "https://target.com/page"

# With custom wordlist
arjun -u "https://target.com/page" -w custom_params.txt

# POST request
arjun -u "https://target.com/api" -m POST
```

### 2. JavaScript Analysis

Extract parameters from client-side JavaScript files:

```bash
# Download and search JS files
curl -s "https://target.com/app.js" | grep -oE "[a-zA-Z0-9_]+\s*[:=]\s*['\"]" | sort -u

# Look for AJAX calls
grep -oE "data:\s*{[^}]+" app.js
grep -oE "params\s*[:=]\s*{[^}]+" app.js
```

### 3. HTML Analysis

```bash
# Search for hidden inputs
grep -oE '<input[^>]+type=["\']hidden["\'][^>]*>' page.html

# Search for data attributes
grep -oE 'data-[a-zA-Z0-9_-]+' page.html

# Search for form action parameters
grep -oE 'action=["\'][^"\']+["\']' page.html
```

### 4. Wayback Machine Analysis

```bash
# Get historical URLs
waybackurls target.com | grep "?" | sort -u

# Extract unique parameters
waybackurls target.com | grep "?" | cut -d'?' -f2 | tr '&' '\n' | cut -d'=' -f1 | sort -u
```

### 5. Response Comparison

```bash
# Compare responses with/without parameter
# Look for differences in:
# - Response size
# - Response time
# - Status codes
# - Content changes
```

## Tools

### Arjun
```bash
# https://github.com/s0md3v/Arjun

# Basic discovery
arjun -u "https://target.com/page"

# With headers
arjun -u "https://target.com/page" -H "Cookie: session=abc"

# JSON mode
arjun -u "https://target.com/api" -m JSON

# Multiple URLs
arjun -i urls.txt

# Output to file
arjun -u "https://target.com/page" -o params.json
```

### Param Miner (Burp Extension)
```
1. Install from BApp Store
2. Right-click on request > Extensions > Param Miner
3. Select "Guess params"
4. Review discovered parameters in Scanner results
```

### x8
```bash
# https://github.com/Sh1Yo/x8

# Basic scan
x8 -u "https://target.com/" -w params.txt

# With wordlist
x8 -u "https://target.com/" -w /path/to/wordlist.txt

# POST request
x8 -u "https://target.com/" -X POST -w params.txt
```

### ParamSpider
```bash
# https://github.com/devanshbatham/ParamSpider

# Extract parameters from web archives
python paramspider.py --domain target.com

# With output file
python paramspider.py --domain target.com --output params.txt
```

### waybackurls
```bash
# https://github.com/tomnomnom/waybackurls

# Get all archived URLs
waybackurls target.com

# Filter for parameters
waybackurls target.com | grep "="

# Extract unique parameters
waybackurls target.com | unfurl keys | sort -u
```

## Common Hidden Parameters

### Debug/Development
```
debug
test
dev
development
verbose
trace
log
logging
environment
env
```

### Authentication/Authorization
```
admin
administrator
role
roles
user
userid
user_id
auth
token
access
access_token
api_key
apikey
key
secret
password
```

### Functionality
```
action
cmd
command
exec
execute
func
function
callback
redirect
redirect_uri
url
next
return
returnUrl
goto
target
```

### Display/Formatting
```
format
output
type
template
view
render
display
show
hide
include
exclude
```

### Filtering/Sorting
```
filter
sort
order
orderby
sort_by
direction
asc
desc
limit
offset
page
per_page
count
```

### File Operations
```
file
filename
path
filepath
dir
directory
folder
upload
download
read
write
```

### SQL/Database
```
id
table
column
field
select
where
query
search
db
database
```

## Wordlists

### Arjun Built-in
```
~/.config/arjun/small.txt   # 1,000 params
~/.config/arjun/medium.txt  # 5,000 params
~/.config/arjun/large.txt   # 25,000 params
```

### SecLists
```
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
/usr/share/seclists/Discovery/Web-Content/api-endpoints.txt
```

### Custom Lists
```bash
# Create wordlist from JS files
curl -s "https://target.com/app.js" | grep -oE "[a-zA-Z_][a-zA-Z0-9_]{2,}" | sort -u > custom_params.txt
```

## Testing Workflow

### 1. Passive Discovery
```bash
# Extract from JavaScript
gospider -s "https://target.com" -o output -c 10 -d 3
grep -rhoE "[a-zA-Z_][a-zA-Z0-9_]+" output/*.js | sort -u

# Check web archives
waybackurls target.com | unfurl keys | sort -u
```

### 2. Active Discovery
```bash
# Bruteforce common params
arjun -u "https://target.com/page" -w common_params.txt

# Test with Burp Param Miner
# (Send request to Param Miner)
```

### 3. Parameter Analysis
```bash
# Test each discovered parameter for:
# - SQLi: ?param=1'
# - XSS: ?param=<script>alert(1)</script>
# - IDOR: ?param=1, ?param=2
# - Boolean: ?param=true, ?param=false
# - Command injection: ?param=;id
```

## Example Discoveries

### Admin Access
```
# Found parameter: admin=false
https://target.com/panel?admin=true

# Found parameter: role=user
https://target.com/panel?role=admin
```

### Debug Information
```
# Found parameter: debug
https://target.com/api?debug=true
# Returns stack traces, internal paths
```

### Hidden Functionality
```
# Found parameter: action
https://target.com/user?action=delete
https://target.com/user?action=export
```

### API Parameters
```
# Found parameter: include
https://target.com/api/users?include=password
https://target.com/api/users?include=internal
```

## Prevention

```
1. Document all parameters
2. Validate all parameters server-side
3. Don't rely on hidden parameters for security
4. Remove debug parameters in production
5. Implement proper access controls
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Hidden%20Parameters
- https://github.com/s0md3v/Arjun
- https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943
