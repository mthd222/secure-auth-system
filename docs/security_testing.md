# Security Testing and Phase 2 Documentation

## Manual Security Tests

| Test | Steps | Expected Result | Status |
|---|---|---|---|
| SQL Injection | Enter `' OR '1'='1` in the login fields | Login fails because parameterized queries treat the value as input | Ready for screenshot |
| Weak Password | Register or reset with `123`, `password`, or `admin` | Password validation rejects the input | Ready for screenshot |
| Brute Force | Enter a wrong password 5 times for the same email | Account is temporarily locked for 15 minutes | Ready for screenshot |
| Session Timeout | Login successfully, then wait 10 minutes | Session expires and dashboard access redirects to login | Ready for screenshot |
| Password Reset | Use Forgot Password with a registered email, then set a new password | Password hash is updated in the database | Ready for screenshot |
| OTP Failure | Login with correct password but wrong OTP | Dashboard access is blocked | Ready for screenshot |
| OTP Success | Login with correct password and correct terminal demo OTP or Google Authenticator TOTP | Session is created and dashboard opens | Ready for screenshot |

## Session Hijacking Analysis

### Risk

Session hijacking occurs when an attacker steals or predicts a valid user session cookie and uses it to impersonate the user.

### Mitigations Implemented

- `SESSION_COOKIE_HTTPONLY=True` prevents JavaScript from reading the session cookie.
- `SESSION_COOKIE_SAMESITE='Lax'` reduces cross-site request risks.
- `permanent_session_lifetime=10 minutes` limits the lifetime of stolen sessions.
- CSRF tokens protect state-changing form submissions.
- Logout uses POST with CSRF protection.
- The session is created only after password authentication and OTP verification.

### Production Recommendation

Enable HTTPS and set:

```python
app.config['SESSION_COOKIE_SECURE'] = True
```

This prevents browsers from sending session cookies over plain HTTP.

## OWASP ZAP Testing Plan

Target:

```text
http://127.0.0.1:5000
```

Recommended scan sequence:

1. Start the Flask app locally.
2. Open OWASP ZAP.
3. Set the target URL to `http://127.0.0.1:5000`.
4. Run Spider Scan.
5. Run Passive Scan.
6. Run Active Scan.
7. Export the report and add screenshots to the project.

## Expected ZAP Findings

| Finding | Current Mitigation |
|---|---|
| Missing X-Frame-Options | Added `X-Frame-Options: DENY` |
| Missing X-Content-Type-Options | Added `X-Content-Type-Options: nosniff` |
| Missing Content Security Policy | Added `Content-Security-Policy: default-src 'self'` |
| Missing Referrer-Policy | Added `Referrer-Policy: strict-origin` |
| Missing HSTS | Enable only when deployed on HTTPS |

## Security Header Implementation

The Flask app adds security headers in `app.py`:

```python
@app.after_request
def security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```
