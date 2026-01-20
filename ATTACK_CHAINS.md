# Attack Chain Combinations - Web Security Demo

## Overview
This project demonstrates how multiple vulnerabilities can be chained together for more powerful attacks. Each vulnerability alone is dangerous, but combining them creates devastating attack scenarios.

---

## Attack Chain 1: SQL Injection → Command Injection → Path Traversal

### Objective
Complete system compromise from unauthenticated attacker to reading any file on the server.

### Steps
1. **SQL Injection** (`/sql_login_vuln`)
   - Payload: `admin@example.com' OR '1'='1`
   - Result: Bypass authentication, gain admin access

2. **Command Injection** (`/cmd_search_vuln`)
   - Payload: `flag & dir /s /b secret` (Windows) or `flag; find . -name "*secret*"` (Unix)
   - Result: Discover sensitive file locations

3. **Path Traversal** (`/view_vuln`)
   - Payload: `?file=../../secret/flag.txt`
   - Result: Read discovered sensitive files

### Impact
- Full account takeover without credentials
- Discovery of all files on system
- Ability to read any accessible file
- Potential data exfiltration

### Defense
Breaking ANY link in the chain stops the attack:
- Parameterized SQL queries prevent initial access
- Input sanitization prevents file discovery
- Path validation prevents unauthorized file access

---

## Attack Chain 2: XSS → Session Hijacking → CSRF Bypass

### Objective
Bypass CSRF protection and perform unauthorized actions using XSS.

### Steps
1. **XSS Injection** (`/xss_vuln`)
   - Inject JavaScript payload in user input
   - Execute arbitrary code in victim's browser

2. **Session/Token Theft**
   - Steal session cookie: `document.cookie`
   - Fetch CSRF-protected page and extract token from DOM
   - Send stolen data to attacker-controlled server

3. **CSRF Attack with Valid Token** (`/change_password_secure`)
   - Submit form with stolen CSRF token
   - Server validates token (it's legitimate!)
   - Password changed successfully

### Impact
- Complete session hijacking
- CSRF protection completely bypassed
- Account takeover
- Can perform any action as the victim

### Defense
- **Fix XSS** - Properly escape all output (breaks entire chain)
- Content Security Policy (CSP)
- HttpOnly cookies
- SameSite cookie attribute

---

## Attack Chain 3: Command Injection → Path Traversal (Reconnaissance + Exploitation)

### Objective
Use command injection for reconnaissance, then exploit with path traversal.

### Steps
1. **Reconnaissance via Command Injection** (`/cmd_search_vuln`)
   - Payload: `test & dir /s /b` (list all files)
   - Discover: Database files, config files, secrets
   - Map out directory structure

2. **Targeted Exploitation** (`/attack_chain_3`)
   - Use path traversal to read discovered files
   - Examples:
     - `../../users.db` - User credentials
     - `../../secret/flag.txt` - Secret data
     - `../../app.py` - Source code (reveals more vulnerabilities)

### Impact
- Complete file system mapping
- Discovery of all sensitive data locations
- Ability to read configuration files, databases, source code
- Can find credentials, API keys, business logic

### Defense
- Sanitize command inputs (alphanumeric only)
- Use language-native file operations instead of shell commands
- Validate and restrict file paths
- Principle of least privilege for file access

---

## Additional Possible Chains (Not Implemented)

### 4. Phishing (XSS) → Credential Theft → SQL Injection
1. XSS redirects to fake login page
2. Victim enters real credentials
3. Use stolen credentials for SQL injection exploration

### 5. Path Traversal → Database Read → Credential Reuse
1. Read database file via path traversal
2. Extract password hashes
3. Crack weak passwords
4. Reuse on other systems

### 6. CSRF → XSS → Full Compromise
1. CSRF creates new admin account
2. XSS payload in admin profile
3. Admin views profile, XSS executes with elevated privileges

---

## Key Takeaways

### For Attackers (Educational)
- **Persistence**: One vulnerability often leads to discovering others
- **Reconnaissance**: Always gather information before exploitation
- **Chaining**: Combine multiple small issues for major impact
- **Automation**: Many chains can be automated for mass exploitation

### For Defenders
- **Defense in Depth**: Multiple security layers prevent complete compromise
- **Fix Critical First**: Prioritize vulnerabilities that enable chains
- **Input Validation**: Most chains involve user input at some point
- **Monitoring**: Detect reconnaissance activities early
- **Security Testing**: Test for chains, not just individual vulnerabilities

---

## Testing the Chains

1. **Prerequisites**: Application must be running (`python app.py`)
2. **Start Fresh**: Logout and clear cookies between tests
3. **Follow Steps**: Each chain has a step-by-step guide
4. **Check Terminal**: Watch Flask output for attack indicators
5. **Compare**: Try both vulnerable and secure versions

## Routes Summary

| Route | Purpose | Vulnerable? |
|-------|---------|-------------|
| `/attack_chain_1` | SQL → Cmd → Path guide | Educational |
| `/attack_chain_2` | XSS → CSRF guide | Educational |
| `/attack_chain_3` | Cmd → Path interactive | Vulnerable |
| `/sql_login_vuln` | SQL injection login | ✅ Yes |
| `/cmd_search_vuln` | Command injection | ✅ Yes |
| `/view_vuln` | Path traversal | ✅ Yes |
| `/xss_vuln` | XSS vulnerability | ✅ Yes |
| `/change_password_vuln` | CSRF vulnerable | ✅ Yes |
| `/csrf_attack` | CSRF exploit page | Malicious |
