import os
from functools import wraps
import sqlite3
import subprocess
import secrets

from flask import (
    Flask,
    abort,
    flash,
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


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("user_email"):
            return redirect(url_for("login", next=request.full_path))
        return view_func(*args, **kwargs)

    return wrapper


@app.route("/")
def index():
    if not session.get("user_email"):
        return redirect(url_for("login"))
    return render_template("index.html", user_email=session.get("user_email"))


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
            output = subprocess.check_output(
                cmd,
                shell=True,  # VULNERABLE: shell=True with user input
                cwd=BASE_DIR,
                stderr=subprocess.STDOUT,
                timeout=5,
            )
            results = output.decode("utf-8", errors="ignore")
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
            output = subprocess.check_output(
                cmd, shell=True, cwd=BASE_DIR, timeout=5
            )
            cmd_result = output.decode("utf-8", errors="ignore")
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
            output = subprocess.check_output(
                cmd, shell=True, cwd=BASE_DIR, timeout=5
            )
            cmd_result = output.decode("utf-8", errors="ignore")
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


if __name__ == "__main__":
    # For demo purposes only; in production use a real WSGI server
    app.run(host="0.0.0.0", port=5000, debug=True)
