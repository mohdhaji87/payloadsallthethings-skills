# PayloadsAllTheThings Skills Index

Quick reference guide to all 61 security testing skills.

## Injection Attacks (14 skills)

| # | Skill | File | Trigger |
|---|-------|------|---------|
| 47 | SQL Injection | [sql-injection.md](47-sql-injection.md) | `/sqli` |
| 59 | XSS Injection | [xss-injection.md](59-xss-injection.md) | `/xss` |
| 11 | Command Injection | [command-injection.md](11-command-injection.md) | `/cmdi` |
| 60 | XXE Injection | [xxe-injection.md](60-xxe-injection.md) | `/xxe` |
| 50 | SSTI | [server-side-template-injection.md](50-server-side-template-injection.md) | `/ssti` |
| 33 | LDAP Injection | [ldap-injection.md](33-ldap-injection.md) | `/ldap` |
| 57 | XPath Injection | [xpath-injection.md](57-xpath-injection.md) | `/xpath` |
| 58 | XSLT Injection | [xslt-injection.md](58-xslt-injection.md) | `/xslt` |
| 36 | NoSQL Injection | [nosql-injection.md](36-nosql-injection.md) | `/nosql` |
| 22 | GraphQL Injection | [graphql-injection.md](22-graphql-injection.md) | `/graphql` |
| 06 | CRLF Injection | [crlf-injection.md](06-crlf-injection.md) | `/crlf` |
| 07 | CSV Injection | [csv-injection.md](07-csv-injection.md) | `/csv` |
| 34 | LaTeX Injection | [latex-injection.md](34-latex-injection.md) | `/latex` |
| 48 | SSI Injection | [server-side-include-injection.md](48-server-side-include-injection.md) | `/ssi` |

## Authentication & Session (6 skills)

| # | Skill | File | Trigger |
|---|-------|------|---------|
| 31 | JWT Attacks | [json-web-token.md](31-json-web-token.md) | `/jwt` |
| 37 | OAuth Misconfiguration | [oauth-misconfiguration.md](37-oauth-misconfiguration.md) | `/oauth` |
| 46 | SAML Injection | [saml-injection.md](46-saml-injection.md) | `/saml` |
| 02 | Account Takeover | [account-takeover.md](02-account-takeover.md) | `/ato` |
| 12 | CSRF | [cross-site-request-forgery.md](12-cross-site-request-forgery.md) | `/csrf` |
| 03 | Brute Force | [brute-force-rate-limit.md](03-brute-force-rate-limit.md) | `/brute` |

## Server-Side Vulnerabilities (7 skills)

| # | Skill | File | Trigger |
|---|-------|------|---------|
| 49 | SSRF | [server-side-request-forgery.md](49-server-side-request-forgery.md) | `/ssrf` |
| 20 | LFI/RFI | [file-inclusion.md](20-file-inclusion.md) | `/lfi` |
| 17 | Path Traversal | [directory-traversal.md](17-directory-traversal.md) | `/traversal` |
| 53 | File Upload | [upload-insecure-files.md](53-upload-insecure-files.md) | `/upload` |
| 26 | Deserialization | [insecure-deserialization.md](26-insecure-deserialization.md) | `/deserial` |
| 44 | Request Smuggling | [request-smuggling.md](44-request-smuggling.md) | `/smuggle` |
| 42 | Race Condition | [race-condition.md](42-race-condition.md) | `/race` |

## Client-Side Vulnerabilities (7 skills)

| # | Skill | File | Trigger |
|---|-------|------|---------|
| 05 | CORS | [cors-misconfiguration.md](05-cors-misconfiguration.md) | `/cors` |
| 09 | Clickjacking | [clickjacking.md](09-clickjacking.md) | `/clickjack` |
| 14 | DOM Clobbering | [dom-clobbering.md](14-dom-clobbering.md) | `/domclob` |
| 41 | Prototype Pollution | [prototype-pollution.md](41-prototype-pollution.md) | `/prototype` |
| 39 | Open Redirect | [open-redirect.md](39-open-redirect.md) | `/redirect` |
| 51 | Tabnabbing | [tabnabbing.md](51-tabnabbing.md) | `/tabnab` |
| 56 | WebSocket | [web-sockets.md](56-web-sockets.md) | `/websocket` |

## Access Control (4 skills)

| # | Skill | File | Trigger |
|---|-------|------|---------|
| 27 | IDOR | [insecure-direct-object-references.md](27-insecure-direct-object-references.md) | `/idor` |
| 35 | Mass Assignment | [mass-assignment.md](35-mass-assignment.md) | `/mass` |
| 04 | Business Logic | [business-logic-errors.md](04-business-logic-errors.md) | `/logic` |
| 25 | Hidden Parameters | [hidden-parameters.md](25-hidden-parameters.md) | `/hidden` |

## Infrastructure (6 skills)

| # | Skill | File | Trigger |
|---|-------|------|---------|
| 13 | DNS Rebinding | [dns-rebinding.md](13-dns-rebinding.md) | `/dnsrebind` |
| 45 | Reverse Proxy | [reverse-proxy-misconfigurations.md](45-reverse-proxy-misconfigurations.md) | `/proxy` |
| 54 | Virtual Hosts | [virtual-hosts.md](54-virtual-hosts.md) | `/vhost` |
| 55 | Web Cache | [web-cache-deception.md](55-web-cache-deception.md) | `/cache` |
| 30 | SCM Exposure | [insecure-source-code-management.md](30-insecure-source-code-management.md) | `/scm` |
| 32 | Java RMI | [java-rmi.md](32-java-rmi.md) | `/rmi` |

## Specialized (17 skills)

| # | Skill | File | Trigger |
|---|-------|------|---------|
| 01 | API Key Leaks | [api-key-leaks.md](01-api-key-leaks.md) | `/apikeys` |
| 40 | Prompt Injection | [prompt-injection.md](40-prompt-injection.md) | `/prompt` |
| 52 | Type Juggling | [type-juggling.md](52-type-juggling.md) | `/juggle` |
| 43 | Regex DoS | [regular-expression.md](43-regular-expression.md) | `/regex` |
| 61 | Zip Slip | [zip-slip.md](61-zip-slip.md) | `/zipslip` |
| 16 | Dependency Confusion | [dependency-confusion.md](16-dependency-confusion.md) | `/depconf` |
| 15 | DoS | [denial-of-service.md](15-denial-of-service.md) | `/dos` |
| 08 | CVE Exploits | [cve-exploits.md](08-cve-exploits.md) | `/cve` |
| 10 | Client Path Traversal | [client-side-path-traversal.md](10-client-side-path-traversal.md) | `/clientpath` |
| 18 | Encoding | [encoding-transformations.md](18-encoding-transformations.md) | `/encode` |
| 19 | External Variable | [external-variable-modification.md](19-external-variable-modification.md) | `/extvar` |
| 21 | GWT | [google-web-toolkit.md](21-google-web-toolkit.md) | `/gwt` |
| 23 | HPP | [http-parameter-pollution.md](23-http-parameter-pollution.md) | `/hpp` |
| 24 | Headless Browser | [headless-browser.md](24-headless-browser.md) | `/headless` |
| 28 | Management Interface | [insecure-management-interface.md](28-insecure-management-interface.md) | `/mgmt` |
| 29 | Randomness | [insecure-randomness.md](29-insecure-randomness.md) | `/random` |
| 38 | ORM Leak | [orm-leak.md](38-orm-leak.md) | `/orm` |

---

## Quick Reference by Attack Type

### Data Extraction
- SQL Injection → Database data
- XXE → File read, SSRF
- LFI/RFI → File read, RCE
- SSRF → Internal services, metadata

### Remote Code Execution
- Command Injection → OS commands
- SSTI → Template engine RCE
- Deserialization → Gadget chain RCE
- File Upload → Webshell upload

### Authentication Bypass
- JWT → Token manipulation
- OAuth → Flow exploitation
- SAML → Signature bypass
- Type Juggling → Comparison bypass

### Client-Side Attacks
- XSS → Script execution
- CORS → Cross-origin data theft
- Clickjacking → UI manipulation
- Prototype Pollution → Object tampering

---

*Based on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)*
