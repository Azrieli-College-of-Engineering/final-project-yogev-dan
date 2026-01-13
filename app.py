import os
from flask import Flask, render_template, request, send_file, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Base directory of the project
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Public directory where legitimate files are stored
PUBLIC_DIR = os.path.join(BASE_DIR, "public", "files")

# Ensure public directory exists
os.makedirs(PUBLIC_DIR, exist_ok=True)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/view_vuln")
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

    # send_file will happily serve anything this path points to
    return send_file(file_path)


@app.route("/view_secure")
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


if __name__ == "__main__":
    # For demo purposes only; in production use a real WSGI server
    app.run(host="0.0.0.0", port=5000, debug=True)
