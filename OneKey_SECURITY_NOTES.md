# OneKey Security Review — Educational Prototype

This project demonstrates authentication concepts and is **not production-ready**.

## Applied in reviewed code
- Removed static seeded demo passwords in favor of required environment variables.
- Kept Flask secret in environment variables.
- Disabled Flask debugger.
- Disabled custom OAuth/SAML simulation endpoints by default and limited opt-in use to localhost.
- Added an exact redirect URI check to the demonstration authorization endpoint.
- Kept the pending MFA secret server-side rather than in Flask's client-side session cookie.
- Restricted post-login redirect to a relative path.

## Known limitations / future work
- Custom SAML flow does not cryptographically sign or verify assertions. It must not be used for real authentication.
- Custom OAuth simulation does not implement a standards-compliant token validation system, PKCE, or robust client authentication. Its tokens are not secure bearer credentials.
- Forms require CSRF protection, and HTML templating needs an XSS review, especially interpolated values in render_template_string.
- Review role-based access control for all sensitive routes and actions, rate limiting, account enumeration, and audit logging.
- Demo users are seeded only when absent; changing environment variables does not reset existing database passwords.
- HTTPS uses local certificates for development. Do not expose the Flask development server to the Internet.
- Do not commit `.env`, SQLite DB files (including -wal/-shm), private keys, or personal data.

## Run locally
1. Install dependencies from the project's `requirements.txt`.
2. Create `.env` from `OneKey_env.example.txt` and replace all placeholder values with unique secrets.
3. Generate a Flask secret using `python -c "import secrets; print(secrets.token_hex(32))"`.
4. Run `python app.py` after renaming the reviewed code file to `app.py`.
5. For protocol flow demonstrations *only*, set `ENABLE_PROTOCOL_DEMOS=true` and run strictly on localhost.

This file reflects a static code review and Python syntax validation; full runtime and security tests have not been performed.
