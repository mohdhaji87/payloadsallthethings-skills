# API Key Leaks

## Description
API keys and tokens are authentication mechanisms for accessing services. Leaking these credentials can lead to unauthorized access, data breaches, and potential security compromises. This skill covers detection, validation, and exploitation of leaked API keys.

## Common Leak Sources
- Hardcoded keys in source code
- Public GitHub repositories
- Docker images and container registries
- Logging/debug information
- Configuration files (.env, config.json, etc.)
- JavaScript files in web applications
- Mobile application binaries (APK/IPA)
- Browser developer tools (localStorage, sessionStorage)
- Error messages and stack traces

## Detection Tools

### Trivy
```bash
# Scan filesystem for secrets
trivy fs --scanners secret /path/to/scan

# Scan Docker image
trivy image --scanners secret image:tag

# Scan git repository
trivy repo https://github.com/target/repo
```

### TruffleHog
```bash
# Scan git repository
trufflehog git https://github.com/target/repo

# Scan filesystem
trufflehog filesystem /path/to/code

# Scan S3 bucket
trufflehog s3 --bucket=bucket-name

# Scan with JSON output
trufflehog git https://github.com/target/repo --json
```

### GitLeaks
```bash
# Scan local repository
gitleaks detect --source=/path/to/repo

# Scan with verbose output
gitleaks detect -v --source=/path/to/repo

# Generate report
gitleaks detect --source=/path/to/repo --report-path=report.json
```

### Nuclei
```bash
# Scan for exposed tokens
nuclei -t /path/to/nuclei-templates/token-spray/ -u https://target.com
```

## API Key Regex Patterns

### AWS
```regex
# AWS Access Key ID
AKIA[0-9A-Z]{16}

# AWS Secret Access Key
[0-9a-zA-Z/+]{40}

# AWS API Gateway
[0-9a-z]+\.execute-api\.[0-9a-z._-]+\.amazonaws\.com
```

### Google
```regex
# Google API Key
AIza[0-9A-Za-z\-_]{35}

# Google OAuth
[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com
```

### GitHub
```regex
# GitHub Personal Access Token
ghp_[0-9a-zA-Z]{36}

# GitHub OAuth Access Token
gho_[0-9a-zA-Z]{36}

# GitHub User-to-Server Token
ghu_[0-9a-zA-Z]{36}

# GitHub Server-to-Server Token
ghs_[0-9a-zA-Z]{36}

# GitHub Refresh Token
ghr_[0-9a-zA-Z]{36}
```

### Slack
```regex
xox[baprs]-([0-9a-zA-Z]{10,48})
```

### Stripe
```regex
# Stripe Secret Key
sk_live_[0-9a-zA-Z]{24}

# Stripe Publishable Key
pk_live_[0-9a-zA-Z]{24}

# Stripe Restricted Key
rk_live_[0-9a-zA-Z]{24}
```

### Private Keys
```regex
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN DSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
```

### Generic Patterns
```regex
api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{16,}
secret[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{16,}
access[_-]?token['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{16,}
password['\"]?\s*[:=]\s*['\"]?[^\s'\"]{8,}
bearer\s+[a-zA-Z0-9\-._~+/]+=*
```

## Key Validation Techniques

### AWS
```bash
# Verify AWS credentials
aws sts get-caller-identity

# List IAM permissions
aws iam get-user
aws iam list-attached-user-policies --user-name USERNAME
```

### Google
```bash
# Test Google API Key
curl "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=API_KEY"
```

### GitHub
```bash
# Verify GitHub token
curl -H "Authorization: token TOKEN" https://api.github.com/user

# Check token scopes
curl -I -H "Authorization: token TOKEN" https://api.github.com/user
```

### Slack
```bash
# Test Slack token
curl -H "Authorization: Bearer TOKEN" https://slack.com/api/auth.test
```

### Telegram Bot
```bash
# Verify Telegram bot token
curl https://api.telegram.org/bot<TOKEN>/getMe
```

### Twilio
```bash
# Test Twilio credentials
curl -X GET "https://api.twilio.com/2010-04-01/Accounts.json" \
  -u "ACCOUNT_SID:AUTH_TOKEN"
```

## Exploitation Workflow

1. **Discovery**: Use automated tools to scan for leaked keys
2. **Validation**: Verify the key is still active and valid
3. **Enumeration**: Determine what permissions/scope the key has
4. **Impact Assessment**: Document what data/actions are accessible
5. **Reporting**: Report the finding with proof of concept

## Prevention with Pre-commit Hooks

### .pre-commit-config.yaml
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/trufflesecurity/trufflehog
    rev: v3.63.0
    hooks:
      - id: trufflehog
```

## Useful Resources
- [KeyHacks](https://github.com/streaak/keyhacks) - Verify API key validity
- [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) - Secret detection regex patterns
- [SignSaboteur](https://github.com/d0ge/sign-saboteur) - Burp Suite extension for JWT/secrets

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/API%20Key%20Leaks
