# Secured Website — Ethical Hacking Lab

A deliberately self-contained web application for **authorized security practice**. Run it locally only.

## Features
- Modern responsive security-dashboard UI
- Registration and login
- Session-based authentication
- Profile page
- Search endpoint
- Notes/comments
- JSON API
- Security headers
- CSRF protection
- Password hashing
- SQLite database
- Built-in lab guide with safe challenge targets

## Run locally

```bash
python -m venv .venv
# Windows
.venv\\Scripts\\activate
# Linux/macOS
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

Default demo account is created automatically:
- username: `demo`
- password: `DemoPass!2026`

Change it before exposing the application anywhere.

## Practice areas

Use the app as a target you own. Suggested exercises:
1. Recon: identify routes, methods, cookies and headers.
2. Authentication: inspect login/session behavior.
3. Input handling: test search and note fields with harmless payloads.
4. Access control: verify that users cannot read or modify another user's data.
5. CSRF: inspect form protections.
6. Session security: inspect cookie attributes and session lifecycle.
7. API testing: enumerate documented API endpoints.
8. Security headers: inspect CSP, HSTS (when HTTPS is used), X-Content-Type-Options, Referrer-Policy and frame protections.

This project is intentionally designed to be **defensive by default**. It does not contain intentionally exploitable remote-code-execution, command-injection, credential-stealing, or malware functionality.

## Scope

Only test this application on systems you own or have explicit permission to assess.
