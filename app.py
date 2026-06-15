"""
=============================================================================
  DELIBERATELY VULNERABLE — SECURITY TRAINING FIXTURE — DO NOT DEPLOY
=============================================================================
This file intentionally contains textbook vulnerabilities so that a
defensive scanner (Codex Security) has something to DETECT, VALIDATE, and
PATCH. It is a practice target only. Never run this in production or expose
it to untrusted networks.

Each vulnerability is tagged [VULN-N] with its CWE and the secure fix, so you
can compare the scanner's proposed patch against the intended remediation.
=============================================================================
"""

import hashlib
import os
import sqlite3
import subprocess

from flask import Flask, request, send_file

app = Flask(__name__)

# [VULN-1] CWE-798: Hard-coded secret.
# A real key in source control is a finding. Secure fix: read from env/secret store.
API_KEY = "sk-live-1234567890abcdef-DO-NOT-COMMIT-REAL-KEYS"


@app.route("/search")
def search():
    # [VULN-2] CWE-89: SQL injection via string formatting.
    # Secure fix: parameterized query -> cur.execute("... WHERE name = ?", (q,))
    q = request.args.get("q", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % q)
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    # [VULN-3] CWE-78: OS command injection via shell=True + user input.
    # Secure fix: subprocess.run(["ping", "-c", "1", host]) with shell=False + validation.
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return out


@app.route("/download")
def download():
    # [VULN-4] CWE-22: Path traversal — user controls the file path.
    # Secure fix: resolve against a fixed base dir and reject paths that escape it.
    name = request.args.get("file", "")
    return send_file(os.path.join("/var/data/", name))


def store_password(password: str) -> str:
    # [VULN-5] CWE-327/916: Weak, unsalted hash for passwords.
    # Secure fix: use a slow KDF such as bcrypt/argon2 with a per-user salt.
    return hashlib.md5(password.encode()).hexdigest()


if __name__ == "__main__":
    # [VULN-6] CWE-489: Debug mode on -> remote code execution via Werkzeug console.
    # Secure fix: debug=False in any non-local environment.
    app.run(debug=True, host="0.0.0.0")
