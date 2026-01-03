# PayloadsAllTheThings Skills Plugin

A comprehensive Claude Code plugin providing 61 security testing skills based on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings).

## Features

- **61 Security Skills** covering all major vulnerability categories
- **18,000+ lines** of payloads, techniques, and exploitation methods
- **Real-world payloads** from PayloadsAllTheThings repository
- **Organized by category** for easy reference during pentests
- **Tool recommendations** for each vulnerability type
- **Prevention guidelines** for secure development

## Installation

### Method 1: Clone and Install
```bash
# Clone the repository
git clone https://github.com/mohdhaji87/payloadsallthethings-skills.git

# Navigate to the directory
cd payloadsallthethings-skills

# Install as Claude Code plugin
claude mcp add payloadsallthethings-skills .
```


### Method 2: Manual Installation
1. Download/clone this repository
2. Copy to your Claude Code plugins directory:
   ```bash
   cp -r payloadsallthethings-skills ~/.claude/plugins/
   ```
3. Restart Claude Code

## Included Skills (61 Total)

### Injection Attacks
| Skill | Description |
|-------|-------------|
| `sqli` | SQL Injection (Union, Error, Blind, Time-based) |
| `xss` | Cross-Site Scripting (Reflected, Stored, DOM) |
| `command-injection` | OS Command Injection |
| `xxe` | XML External Entity Injection |
| `ssti` | Server-Side Template Injection |
| `ldap` | LDAP Injection |
| `xpath` | XPath Injection |
| `xslt` | XSLT Injection |
| `nosql` | NoSQL Injection (MongoDB, CouchDB) |
| `graphql` | GraphQL Injection |
| `crlf` | CRLF Injection |
| `csv-injection` | CSV/Spreadsheet Injection |
| `latex` | LaTeX Injection |
| `ssi` | Server-Side Include Injection |

### Authentication & Session
| Skill | Description |
|-------|-------------|
| `jwt` | JSON Web Token Attacks |
| `oauth` | OAuth Misconfiguration |
| `saml` | SAML Injection |
| `account-takeover` | Account Takeover Techniques |
| `csrf` | Cross-Site Request Forgery |
| `brute-force` | Brute Force & Rate Limit Bypass |

### Server-Side Vulnerabilities
| Skill | Description |
|-------|-------------|
| `ssrf` | Server-Side Request Forgery |
| `lfi-rfi` | Local/Remote File Inclusion |
| `path-traversal` | Directory Traversal |
| `file-upload` | Insecure File Upload |
| `deserialization` | Insecure Deserialization |
| `request-smuggling` | HTTP Request Smuggling |
| `race-condition` | Race Condition Attacks |

### Client-Side Vulnerabilities
| Skill | Description |
|-------|-------------|
| `cors` | CORS Misconfiguration |
| `clickjacking` | Clickjacking / UI Redressing |
| `dom-clobbering` | DOM Clobbering |
| `prototype-pollution` | JavaScript Prototype Pollution |
| `open-redirect` | Open Redirect |
| `tabnabbing` | Reverse Tabnabbing |
| `websocket` | WebSocket Hijacking |

### Access Control
| Skill | Description |
|-------|-------------|
| `idor` | Insecure Direct Object Reference |
| `mass-assignment` | Mass Assignment |
| `business-logic` | Business Logic Errors |
| `hidden-params` | Hidden Parameter Discovery |

### Infrastructure
| Skill | Description |
|-------|-------------|
| `dns-rebinding` | DNS Rebinding |
| `reverse-proxy` | Reverse Proxy Misconfigurations |
| `vhost` | Virtual Host Enumeration |
| `web-cache` | Web Cache Deception/Poisoning |
| `scm-exposure` | Source Code Management Exposure |
| `java-rmi` | Java RMI Exploitation |

### Specialized
| Skill | Description |
|-------|-------------|
| `api-key-leaks` | API Key Detection & Validation |
| `prompt-injection` | LLM/AI Prompt Injection |
| `type-juggling` | PHP Type Juggling |
| `regex` | Regular Expression Attacks |
| `zip-slip` | Zip Slip Path Traversal |
| `dependency-confusion` | Supply Chain Attacks |

## Usage

Once installed, you can invoke skills directly in Claude Code:

```bash
# Get SQL injection payloads
/sqli

# Get XSS techniques
/xss

# Get SSRF bypass methods
/ssrf

# Get JWT attack techniques
/jwt
```

Or ask Claude Code directly:
```
"Show me SQL injection payloads for MySQL"
"How do I bypass CORS restrictions?"
"What are the JWT none algorithm attacks?"
```

## Skill File Structure

Each skill file contains:
- **Description** - What the vulnerability is
- **Detection** - How to identify the vulnerability
- **Payloads** - Real exploitation payloads
- **Bypass Techniques** - WAF/filter evasion
- **Tools** - Recommended security tools
- **Prevention** - Secure coding practices
- **Testing Checklist** - Step-by-step verification
- **References** - Links to resources

## Legal Disclaimer

This plugin is intended for:
- Authorized penetration testing
- Security research and education
- CTF competitions
- Bug bounty programs (within scope)

**Do NOT use these techniques against systems without explicit authorization.**

## Credits

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) by swisskyrepo
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP](https://owasp.org)

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create your feature branch
3. Add/update skill files
4. Submit a pull request

## Support

- Issues: [GitHub Issues](https://github.com/mohdhaji87/payloadsallthethings-skills/issues)
- Discussions: [GitHub Discussions](https://github.com/mohdhaji87/payloadsallthethings-skills/discussions)
