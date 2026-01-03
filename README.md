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

### Method 1: Add Marketplace (Recommended)

```bash
# Add the marketplace to Claude Code
claude plugins marketplace add https://github.com/mohdhaji87/payloadsallthethings-skills.git

# Discover and install the plugin
claude plugins discover

# Or install directly
claude plugins install payloadsallthethings@payloadsallthethings-skills
```

### Method 2: Using /plugins Command

1. Open Claude Code
2. Run `/plugins marketplace add https://github.com/mohdhaji87/payloadsallthethings-skills.git`
3. Run `/plugins discover` to browse and install

### Method 3: Manual Installation

```bash
# Clone the repository
git clone https://github.com/mohdhaji87/payloadsallthethings-skills.git

# Add as a local marketplace
claude plugins marketplace add /path/to/payloadsallthethings-skills
```

## Enabling the Plugin

After installation, enable the plugin:

```bash
# Via command line
claude plugins enable payloadsallthethings@payloadsallthethings-skills

# Or in Claude Code
/plugins enable payloadsallthethings@payloadsallthethings-skills
```

## Included Skills (61 Total)

### Injection Attacks
| Skill | Trigger | Description |
|-------|---------|-------------|
| `sqli` | SQL Injection | Union, Error, Blind, Time-based for all databases |
| `xss` | Cross-Site Scripting | Reflected, Stored, DOM with filter bypasses |
| `command-injection` | OS Command Injection | Space bypass, filter evasion, blind detection |
| `xxe` | XML External Entity | File read, SSRF, DoS techniques |
| `ssti` | Template Injection | Jinja2, Twig, Freemarker, Velocity RCE |
| `ldap` | LDAP Injection | Auth bypass, data extraction |
| `xpath` | XPath Injection | Auth bypass, data extraction |
| `xslt` | XSLT Injection | File read, SSRF, RCE |
| `nosql` | NoSQL Injection | MongoDB, CouchDB operator injection |
| `graphql` | GraphQL Injection | Introspection, batching, auth bypass |
| `crlf` | CRLF Injection | Header manipulation, response splitting |
| `csv-injection` | CSV Injection | Formula payloads for spreadsheets |
| `latex` | LaTeX Injection | File read, command execution |
| `ssi` | SSI Injection | Server-Side Include attacks |

### Authentication & Session
| Skill | Description |
|-------|-------------|
| `jwt` | JWT attacks - none algorithm, key confusion, brute force |
| `oauth` | OAuth misconfiguration - redirect_uri, state bypass |
| `saml` | SAML injection and signature bypass |
| `account-takeover` | Password reset poisoning, OAuth flaws |
| `csrf` | Cross-Site Request Forgery with token bypass |
| `brute-force` | Brute force and rate limit bypass |

### Server-Side Vulnerabilities
| Skill | Description |
|-------|-------------|
| `ssrf` | Server-Side Request Forgery with cloud metadata |
| `lfi-rfi` | Local/Remote File Inclusion with PHP wrappers |
| `path-traversal` | Directory traversal with encoding bypasses |
| `file-upload` | File upload bypass - extension, content-type, magic bytes |
| `deserialization` | Insecure deserialization for Java, PHP, Python, .NET |
| `request-smuggling` | HTTP request smuggling - CL.TE, TE.CL, HTTP/2 |
| `race-condition` | Race condition with HTTP/2 single-packet attacks |

### Client-Side Vulnerabilities
| Skill | Description |
|-------|-------------|
| `cors` | CORS misconfiguration exploitation |
| `clickjacking` | Clickjacking with frame busting bypass |
| `dom-clobbering` | DOM clobbering for variable overwriting |
| `prototype-pollution` | JavaScript prototype pollution |
| `open-redirect` | Open redirect bypass techniques |
| `tabnabbing` | Reverse tabnabbing exploitation |
| `websocket` | WebSocket hijacking |

### Access Control
| Skill | Description |
|-------|-------------|
| `idor` | Insecure Direct Object Reference |
| `mass-assignment` | Mass assignment privilege escalation |
| `business-logic` | Business logic vulnerabilities |
| `hidden-params` | Hidden parameter discovery |

### Infrastructure
| Skill | Description |
|-------|-------------|
| `dns-rebinding` | DNS rebinding for SOP bypass |
| `reverse-proxy` | Reverse proxy misconfiguration |
| `vhost` | Virtual host enumeration |
| `web-cache` | Web cache deception/poisoning |
| `scm-exposure` | .git, .svn, .hg exposure |
| `java-rmi` | Java RMI exploitation |

### Specialized
| Skill | Description |
|-------|-------------|
| `api-key-leaks` | API key detection and validation |
| `prompt-injection` | LLM prompt injection and jailbreaks |
| `type-juggling` | PHP type juggling bypass |
| `regex` | ReDoS and regex attacks |
| `zip-slip` | Zip Slip path traversal |
| `dependency-confusion` | Supply chain attacks |
| `dos` | Denial of Service techniques |

## Usage

Once installed and enabled, skills are automatically available. You can:

### Ask Claude directly:
```
"Show me SQL injection payloads for MySQL"
"How do I bypass CORS restrictions?"
"What are the JWT none algorithm attacks?"
"Give me XSS payloads that bypass CSP"
```

### Invoke skills by name:
```
/sqli - SQL Injection payloads
/xss - XSS techniques
/ssrf - SSRF bypass methods
/jwt - JWT attack techniques
```

## Skill File Structure

Each skill contains:
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
3. Add/update skill files in `payloadsallthethings/skills/`
4. Submit a pull request

## Support

- Issues: [GitHub Issues](https://github.com/mohdhaji87/payloadsallthethings-skills/issues)
- Discussions: [GitHub Discussions](https://github.com/mohdhaji87/payloadsallthethings-skills/discussions)
- Repository: [https://github.com/mohdhaji87/payloadsallthethings-skills](https://github.com/mohdhaji87/payloadsallthethings-skills)
