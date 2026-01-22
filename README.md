# 🛡️ Web Security Vulnerabilities Demo

An interactive, gamified educational platform for learning web application security concepts through hands-on attack chain puzzles.

---

## ⚠️ SECURITY WARNING

**This application is INTENTIONALLY VULNERABLE for educational purposes!**

- 🚫 **NEVER** deploy this to a public server or production environment
- 🚫 **NEVER** use with real credentials or sensitive data
- ✅ Only run in isolated local environments or containers
- ✅ Use for learning and teaching purposes only

---

## 🎯 Purpose & Educational Goals

This demo teaches web security by allowing learners to:

1. **Experience vulnerabilities firsthand** - See how attacks work from the attacker's perspective
2. **Understand attack chains** - Learn how multiple vulnerabilities combine for deeper exploitation
3. **Compare vulnerable vs secure code** - Side-by-side demonstrations of bad and good practices
4. **Practice in a safe environment** - No risk of damaging real systems

### 🎓 Learning Outcomes

After completing the challenges, you will understand:

- ✅ SQL Injection and parameterized queries
- ✅ Cross-Site Scripting (XSS) and output encoding
- ✅ Cross-Site Request Forgery (CSRF) and token validation
- ✅ Command Injection and input sanitization
- ✅ Path Traversal and secure file handling
- ✅ Session hijacking and cookie security
- ✅ How attackers chain vulnerabilities together

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- pip (Python package manager)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/WEB-Project.git
cd WEB-Project

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

### Access

Open your browser and navigate to:
```
http://localhost:5000
```

### Default Credentials

| Email | Password |
|-------|----------|
| demo@example.com | password123 |
| admin@example.com | admin123 |
| user@example.com | user123 |

---

## 🎮 Features

### Attack Chain Puzzles

Interactive story-driven challenges that teach real attack patterns:

| Chain | Name | Vulnerabilities |
|-------|------|-----------------|
| 1 | **The Database Heist** | SQL Injection → Command Injection → Path Traversal |
| 2 | **The Identity Thief** | XSS → Session Hijacking → CSRF |
| 3 | **The Server Explorer** | Command Injection → Reconnaissance → Data Exfiltration |

### Gamification System

- 📊 **Progress Tracking** - Track completion across all chains
- 🏆 **Scoring System** - Earn points for completing challenges
- 🥇 **Achievements** - Unlock badges for special accomplishments
- ⏱️ **Timer Challenge** - Speed bonus for fast completions
- 💡 **Progressive Hints** - Get help when stuck (affects score)
- 💾 **Progress Backup** - LocalStorage backup with recovery option

### 🌙 Dark/Light Theme Toggle

Switch between dark and light themes with preference saved to localStorage.

### 📝 Security Quiz Mode

Test your knowledge with a randomized quiz:
- 10 questions covering all 5 vulnerability types
- 5 random questions per session
- Explanations after submission
- "Quiz Master" achievement for perfect score

### 🎓 Interactive Defense Guide

Learn secure coding through hands-on practice:
- **Live Attack Demos** - Try attacks against vulnerable vs secure systems
- **Coding Challenges** - Fix vulnerable code snippets
- **XP Progress Tracking** - Earn 50 XP per topic mastered
- **Side-by-Side Comparison** - See the difference between vulnerable and secure code

### 🎬 Animated Attack Flows

Visual step-by-step animations showing how each attack chain works, integrated into the hint system.

### Scoring Table

| Action | Points |
|--------|--------|
| Stage Complete | +100 |
| Chain Complete Bonus | +200 |
| No Hints Used | +50 |
| Speed Bonus (<5 min) | +75 |

### Achievements

| Badge | Name | Description |
|-------|------|-------------|
| 🩸 | First Blood | Complete your first stage |
| 🗄️ | Database Heist Master | Complete Chain 1 |
| 👤 | Identity Thief Master | Complete Chain 2 |
| 💻 | Server Explorer Master | Complete Chain 3 |
| ⚡ | Speed Runner | Complete a chain in under 5 minutes |
| 🎓 | No Training Wheels | Complete a stage without hints |
| 🏆 | Security Expert | Complete all 3 chains |
| 📝 | Quiz Master | Score 100% on the security quiz |
| 🛡️ | Defense Learner | Complete all Interactive Defense Guide sections |

---

## 📚 Individual Demos

Beyond the attack chains, the app includes standalone vulnerability demos:

### Injection Attacks
- `/sql_login_vuln` - SQL Injection login bypass
- `/sql_login_secure` - Secure parameterized queries
- `/cmd_search_vuln` - Command injection in file search
- `/cmd_search_secure` - Safe file search implementation

### Cross-Site Attacks
- `/xss_vuln` - Reflected XSS demonstration
- `/xss_secure` - Properly escaped output
- `/csrf_attack` - CSRF attack page
- `/change_password_vuln` - Vulnerable to CSRF
- `/change_password_secure` - CSRF token protected

### File System Attacks
- `/view_vuln` - Path traversal vulnerability
- `/view_secure` - Secure file serving

### Social Engineering
- `/fake_signup` - Phishing page demonstration
- `/steal` - Credential exfiltration endpoint

### Learning Resources
- `/defense_guide` - Interactive Defense Guide with live demos
- `/quiz` - Security Quiz with 10 questions
- `/achievements` - View progress and unlocked achievements

---

## 🏗️ Project Structure

```
WEB-Project/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── Dockerfile            # Container configuration
├── users.db              # SQLite database (auto-created)
├── README.md             # This file
├── ATTACK_CHAINS.md      # Attack chain documentation
├── public/
│   └── files/            # Public file directory
├── secret/
│   ├── flag.txt          # CTF-style flag file
│   └── another_secret.txt
└── templates/
    ├── index.html        # Home page
    ├── login.html        # Login page
    ├── achievements.html # Achievements page
    ├── defense_guide.html # Security guide
    ├── attack_chain_*.html # Chain hub pages
    ├── chain*_stage*.html  # Individual stage pages
    └── ...               # Other templates
```

---

## 🔒 Defense Implementation Guide

The app includes a comprehensive **Interactive Defense Guide** at `/defense_guide` covering:

- **SQL Injection** - Parameterized queries, ORM usage
- **XSS** - Output encoding, Content Security Policy
- **CSRF** - Token validation, SameSite cookies
- **Command Injection** - Input sanitization, safe subprocess
- **Path Traversal** - Path validation, allowlisting

Each section includes:
- 🎮 **Interactive Attack Demo** - Try attacks against vulnerable vs secure systems
- ❌ Vulnerable code example
- ✅ Secure code example
- 🧩 **Coding Challenge** - Fix the vulnerable code yourself
- 📊 **XP Progress Tracking** - Earn points for mastering each topic
- 🔗 OWASP references

---

## 🐳 Docker Deployment

```bash
# Build the image
docker build -t web-security-demo .

# Run the container
docker run -p 5000:5000 web-security-demo
```

---

## 🛠️ Development

### Adding New Vulnerabilities

1. Create vulnerable route in `app.py`
2. Create secure comparison route
3. Create template with side-by-side demonstration
4. Add to index.html navigation
5. Update gamification if applicable

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_SECRET_KEY` | dev-only-change-me | Session secret key |
| `DEMO_LOGIN_EMAIL` | demo@example.com | Demo login email |
| `DEMO_LOGIN_PASSWORD` | password123 | Demo login password |

---

## 📖 Further Learning

### OWASP Resources
- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Practice Platforms
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)

### Security Tools
- [Burp Suite](https://portswigger.net/burp)
- [OWASP ZAP](https://www.zaproxy.org/)
- [sqlmap](https://sqlmap.org/)

---

## 📜 License

This project is for educational purposes only. Use responsibly.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add your vulnerability demo
4. Submit a pull request

**Note:** All contributed vulnerabilities should include both vulnerable AND secure implementations for educational comparison.

---

## ⚡ Quick Reference

### Attack Payloads (for learning)

**SQL Injection:**
```sql
' OR '1'='1' --
admin'--
' UNION SELECT * FROM users --
```

**XSS:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
```

**Command Injection:**
```bash
; ls -la
| cat /etc/passwd
& whoami
```

**Path Traversal:**
```
../../../etc/passwd
..\..\..\..\windows\system32\config\sam
```

---

**Happy Learning! 🎓🔐**
