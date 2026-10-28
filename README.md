> **Project Status: Educational Prototype (v1.0)**
>
> OneKey University Portal is an academic project demonstrating authentication, multi-factor authentication, and simulated Single Sign-On (SSO) flows.
>
> The built-in OAuth 2.0 and SAML implementations are for educational purposes only and are not production-ready.
>
> Google Sign-In requires separate OAuth credentials. HTTPS uses a local development certificate.
>
> Future development will focus on stronger security controls, full Google Sign-In integration, and production-ready HTTPS configuration.

# OneKey University Portal

**An educational university portal demonstrating centralized sign-in and access to multiple campus services.**

OneKey brings together an E-Learning portal, Digital Library, Student Registration, and Faculty Portal behind a shared login experience. It was built as a hands-on project to explore authentication, multi-factor authentication (MFA), audit logging, and the concepts behind single sign-on (SSO).

> **Security notice:** This is an educational prototype, **not a production-ready identity provider or university information system**. The built-in SAML and OAuth 2.0 flows are protocol **simulations**, not secure, standards-compliant implementations. They are disabled by default and should be enabled only for local demonstrations using dummy data.

## Features

- Local username/password sign-in with bcrypt password hashing
- Time-based one-time passwords (TOTP) for MFA, compatible with authenticator apps
- CAPTCHA and basic failed-login tracking
- Central dashboard and security event/audit logs
- E-Learning, Digital Library, Student Registration, and Faculty Portal interfaces
- Local educational demonstrations of SAML SSO and OAuth 2.0 authorization flows
- Optional Google sign-in integration through OpenID Connect, when configured
- SQLite database with seeded demonstration records
- HTTPS for local development (temporary certificate or local certificate files)

## Tech stack

**Backend:** Python, Flask, SQLite  
**Authentication:** Flask-Bcrypt, PyOTP, Authlib, Python sessions  
**Frontend:** HTML, CSS and JavaScript rendered by Flask  
**Configuration:** Environment variables, optionally loaded from `.env` using `python-dotenv`

## Getting started (local development only)

### 1. Install dependencies

Requires Python and the packages listed in `requirements.txt`.

```powershell
python -m pip install -r requirements.txt
```

### 2. Configure environment variables

Create a local file named `.env` in the project folder. **Never commit it.**

```dotenv
APP_SECRET_KEY=REPLACE_WITH_A_NEW_RANDOM_SECRET
DEMO_ADMIN_PASSWORD=REPLACE_WITH_A_STRONG_UNIQUE_PASSWORD
DEMO_STUDENT_PASSWORD=REPLACE_WITH_A_DIFFERENT_STRONG_PASSWORD
DEMO_FACULTY_PASSWORD=REPLACE_WITH_ANOTHER_STRONG_PASSWORD
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
ENABLE_PROTOCOL_DEMOS=false
```

Generate a Flask secret locally with:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Replace the placeholders with real **local** secrets. The Google settings are optional for the Google login feature. An existing SQLite database retains its existing user password hashes; editing `.env` will not reset existing accounts.

### 3. Run the app

```powershell
python app.py
```

Open **https://localhost:5050/login**.

The local HTTPS certificate may display a browser trust warning if a temporary development certificate is used. Do not use Flask's development server for internet-facing deployment.

### 4. Explore the SSO simulations (optional)

For a **local-only** educational demonstration, set `ENABLE_PROTOCOL_DEMOS=true` in your local `.env` and restart the app. Keep it set to `false` otherwise. These endpoints are **not suitable for real authentication**, even if they work during a demonstration.

## Project structure

```text
OneKey-University-Portal/
├── app.py                 # Flask application and demonstration interfaces
├── requirements.txt       # Python dependencies
├── README.md              # Project overview and local setup
├── .gitignore             # Excludes secrets, databases and local artifacts
└── .env                   # Local credentials — NOT committed
```

Additional setup notes may be present for Google integration and local HTTPS certificates.

## Security scope and limitations

The project is intended to **demonstrate** security concepts, not to assert production-grade protection.

- Custom SAML assertions are not cryptographically signed/verified.
- The built-in OAuth 2.0 simulation does not provide full production-grade token validation, client authentication, or PKCE.
- CSRF protection, XSS review, and comprehensive authorization testing remain future work.
- Demonstration accounts and locally generated data must not be reused with real student data.
- Keep `.env`, database files, TLS private keys, and user information out of version control.

## Suggested demo checklist

1. Sign in with a locally configured demo account.
2. Complete CAPTCHA and authenticator-based MFA.
3. Open the dashboard and inspect recorded authentication events.
4. Explore the E-Learning and Digital Library interfaces.
5. If needed, enable the protocol simulations **locally only**, then disable them again.

## Screenshots

Screenshots can be added under a `screenshots/` folder after checking that they contain no passwords, OTPs, secret keys, QR codes, or personal information.

## Purpose

Created as a student learning project to practice authentication workflows, web application development, and security-aware system design.
