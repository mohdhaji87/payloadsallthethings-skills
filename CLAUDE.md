# PayloadsAllTheThings Skills - Claude Code Instructions

## Plugin Overview
This plugin provides 61 comprehensive security testing skills based on PayloadsAllTheThings. Each skill contains payloads, techniques, bypass methods, and tools for authorized penetration testing.

## How to Use Skills

### Direct Skill Invocation
Users can invoke skills using slash commands:
- `/sqli` - SQL Injection payloads
- `/xss` - Cross-Site Scripting techniques
- `/ssrf` - Server-Side Request Forgery
- `/jwt` - JSON Web Token attacks

### Contextual Assistance
When users ask about security testing, reference the appropriate skill file:
- "How to test for SQL injection?" → Read `skills/47-sql-injection.md`
- "CORS bypass techniques?" → Read `skills/05-cors-misconfiguration.md`
- "JWT none algorithm attack?" → Read `skills/31-json-web-token.md`

## Skill Categories

### Injection (14 skills)
- SQL, XSS, Command, XXE, SSTI, LDAP, XPath, XSLT, NoSQL, GraphQL, CRLF, CSV, LaTeX, SSI

### Authentication (6 skills)
- JWT, OAuth, SAML, Account Takeover, CSRF, Brute Force

### Server-Side (7 skills)
- SSRF, LFI/RFI, Path Traversal, File Upload, Deserialization, Request Smuggling, Race Condition

### Client-Side (7 skills)
- CORS, Clickjacking, DOM Clobbering, Prototype Pollution, Open Redirect, Tabnabbing, WebSocket

### Access Control (4 skills)
- IDOR, Mass Assignment, Business Logic, Hidden Parameters

### Infrastructure (6 skills)
- DNS Rebinding, Reverse Proxy, Virtual Hosts, Web Cache, SCM Exposure, Java RMI

### Specialized (7 skills)
- API Keys, Prompt Injection, Type Juggling, Regex, Zip Slip, Dependency Confusion, DoS

## Important Guidelines

1. **Authorization Required**: Always remind users these techniques require explicit authorization
2. **Educational Context**: Skills are for learning, CTFs, bug bounties, and authorized testing
3. **Responsible Disclosure**: Encourage proper vulnerability reporting
4. **Legal Compliance**: Users must comply with local laws and regulations

## File Structure
```
skills/
├── 01-api-key-leaks.md
├── 02-account-takeover.md
├── ...
└── 61-zip-slip.md
```

## Payload Formatting
When presenting payloads, use code blocks with appropriate syntax highlighting:
- SQL: ```sql
- Python: ```python
- Bash: ```bash
- HTTP requests: ```http
- XML: ```xml
- JSON: ```json
