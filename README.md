# 🛡️ Web Security Vulnerabilities Demo & CTF Platform
By: Dan Shani & Yogev Solomon

A gamified, educational web application built with **Python (Flask)** designed to demonstrate common web vulnerabilities, how to exploit them, and how to write secure code.

This project features three narrative-driven **Attack Chains** (multi-stage CTF challenges) and a suite of isolated **Vulnerability Labs** comparing insecure vs. secure code implementations.

---

## 🚀 Features

*   **Interactive Attack Chains**: Story-driven missions where you must chain vulnerabilities together to hack a target.
*   **Live Vulnerability Demos**: Hands-on examples of the OWASP Top 10 (SQLi, XSS, CSRF, RCE, Path Traversal).
*   **Secure vs. Insecure Code**: Side-by-side comparison of vulnerable Python code and the patched, secure versions.
*   **Gamification**: Earn points, unlock achievements, and track progress via session-based scoring.
*   **Built-in Tools**: Includes specific endpoints that act as "targets" for your attacks.

---

## 🛠️ Installation & Usage

### Option 1: Running Locally (Python)

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/danshani/WEB-Project.git
    cd WEB-Project
    ```

2.  **Install dependencies:**
    It is recommended to use a virtual environment.
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the application:**
    ```bash
    python app.py
    ```

4.  **Access the platform:**
    Open your browser and navigate to:
    ```
    http://localhost:5000
    ```

### Option 2: Docker

1.  **Build the image:**
    ```bash
    docker build -t web-security-demo .
    ```

2.  **Run the container:**
    ```bash
    docker run -p 5000:5000 web-security-demo
    ```

---

## 🎯 Attack Chains (The Missions)

The core usage of this platform is to solve the three Multi-Stage Attack Chains.

### 🔗 Chain 1: The Database Heist
**Objective:** Break into MegaCorp's admin panel and steal their secrets.
1.  **Stage 1 (SQL Injection):** Bypass the admin login screen using SQL injection techniques.
2.  **Stage 2 (Command Injection):** Once inside, exploit a "network tool" to run shell commands on the server.
3.  **Stage 3 (Path Traversal):** Escape the web directory to read sensitive files located in `/secret/`.

### 🔗 Chain 2: The Identity Thief
**Objective:** Steal a user's session and hijack their account.
1.  **Stage 1 (Reflected XSS):** Inject malicious JavaScript into a vulnerable search parameter.
2.  **Stage 2 (Session Hijacking):** Use the XSS payload to steal the victim's `session_cookie`.
3.  **Stage 3 (CSRF):** Create a malicious form that secretly changes the victim's password without them knowing.

### 🔗 Chain 3: The Server Explorer
**Objective:** Map the server infrastructure and exfiltrate data.
1.  **Stage 1 (Reconnaissance):** Hijack a ping tool to scan the internal network.
2.  **Stage 2 (Mapping):** Map the filesystem structure using command chaining.
3.  **Stage 3 (Exfiltration):** Send secret data out to an external server (simulated).

---

## 🧪 Vulnerability Labs

Apart from the story mode, you can explore individual vulnerabilities via the Dashboard.

| Vulnerability | Vulnerable Endpoint | Secure Endpoint | Description |
| :--- | :--- | :--- | :--- |
| **Path Traversal** | `/view_vuln` | `/view_secure` | Demonstrates accessing files outside the web root (e.g., `../../secret/flag.txt`). |
| **SQL Injection** | `/sql_login_vuln` | `/sql_login_secure` | Shows bypassing authentication (e.g., `' OR '1'='1`) vs Parameterized Queries. |
| **Command Injection** | `/cmd_search_vuln` | `/cmd_search_secure` | Demonstrates RCE via `subprocess.check_output(shell=True)` vs `os.walk`. |
| **CSRF** | `/change_password_vuln` | `/change_password_secure` | Hijacking state-changing actions vs CSRF Token protection. |
| **XSS** | `/xss_vuln` | `/xss_secure` | Executing scripts in the browser vs Context-aware Auto-escaping. |

---

## 📂 Project Structure

├── app.py # Main Flask logic and route definitions
├── ATTACK_CHAINS.md # Detailed walkthroughs of solutions
├── Dockerfile # Container configuration
├── requirements.txt # Python dependencies
├── secret/ # Restricted folder containing flags
│ ├── another_secret.txt
│ └── flag.txt
├── templates/ # HTML frontend files
│ ├── index.html # Main Dashboard
│ ├── chain1_*.html # Database Heist Views
│ ├── chain2_*.html # Identity Thief Views
│ └── chain3_*.html # Server Explorer Views
└── tests/ # Unit tests


---

## ⚠️ Disclaimer

**This application is DELIBERATELY VULNERABLE.** 

It contains severe security flaws for educational purposes. 
*   **DO NOT** run this application on a public server or an insecure network. 
*   **DO NOT** use the code examples in `*_vuln` routes in production applications.

---

## 🤝 Contributing

Contributions are welcome! If you have ideas for new attack chains or improved visualizations, please open a PR.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request
