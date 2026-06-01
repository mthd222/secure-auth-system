# Secure Login and Authentication System

A Flask and SQLite authentication system built for a cybersecurity internship project. The application demonstrates password hashing, CSRF protection, SQL injection prevention, brute-force lockout, secure session handling, password reset, OTP verification, two-factor authentication, security headers, and login activity logging.

---

## Project Overview

The goal of this project is to protect user accounts from common web authentication attacks while keeping the implementation simple enough to study and test.

Implemented cybersecurity concepts:

- Secure user registration and login
- Password hashing with Werkzeug
- CSRF protection with Flask-WTF
- Parameterized SQLite queries
- Account lockout after repeated failed logins
- Secure session timeout
- OTP verification after password authentication
- Google Authenticator-compatible TOTP support
- Password reset with password policy enforcement
- Login activity logging
- Security response headers
- Session hijacking mitigation documentation

---

## Features

### Authentication

- User registration
- Login with password plus OTP
- Secure logout through POST and CSRF protection
- Session timeout after 10 minutes
- Forgot password and reset password flow
- Password-protected 2FA reset flow

### Security

- Password hashing
- Strong password validation
- Email validation
- SQL injection prevention
- CSRF protection
- Brute-force attempt tracking
- Temporary account lock after 5 failed attempts
- Demo email OTP for academic testing
- Google Authenticator-compatible TOTP
- HTTPOnly and SameSite session cookies
- Security headers:
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Content-Security-Policy

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend development |
| Flask | Web framework |
| SQLite | Local database |
| HTML5 | Page structure |
| CSS3 | Styling |
| JavaScript | Password visibility toggle |
| Flask-WTF | CSRF protection |
| Werkzeug | Password hashing |
| python-dotenv | Environment variables |

---

## Project Structure

```text
secure-auth-system/
|-- app.py
|-- requirements.txt
|-- README.md
|-- database.db
|-- database/
|   |-- db_setup.py
|-- docs/
|   |-- security_testing.md
|-- security/
|   |-- hashing.py
|   |-- totp.py
|   |-- validators.py
|-- static/
|   |-- css/
|   |   |-- style.css
|   |-- js/
|       |-- script.js
|-- templates/
|   |-- dashboard.html
|   |-- forgot_password.html
|   |-- login.html
|   |-- register.html
|   |-- reset_password.html
|   |-- reset_2fa.html
|   |-- setup_2fa.html
|   |-- verify_otp.html
```

---

## Installation

Create and activate a virtual environment:

```bash
python -m venv venv
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create `.env` in the project root:

```env
SECRET_KEY=replace-with-a-strong-random-secret
FLASK_DEBUG=0
```

Set up the database:

```bash
python database/db_setup.py
```

Run the application:

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

## Phase 2 Security Modules

### Password Reset

Flow:

```text
Forgot Password -> Enter Email -> Verify Account Exists -> Set New Password -> Hash Password -> Update Database
```

Pages:

- `forgot_password.html`
- `reset_password.html`

### OTP Verification and 2FA

Login now requires two steps:

```text
Email + Password -> OTP Challenge -> Session Creation -> Dashboard
```

The OTP page supports:

- Demo email OTP printed in the Flask terminal for academic testing
- Google Authenticator-compatible TOTP using the displayed setup key or setup URI
- A dedicated 2FA setup page after registration
- A password-protected 2FA reset page if the authenticator app has an old key

### Session Hijacking Mitigations

Implemented mitigations:

- `SESSION_COOKIE_HTTPONLY`
- `SESSION_COOKIE_SAMESITE='Lax'`
- 10-minute session timeout
- CSRF-protected logout
- Session is created only after OTP verification

More detail is documented in [docs/security_testing.md](docs/security_testing.md).

---

## Security Testing Checklist

| Test Case | Input | Expected Result |
|---|---|---|
| SQL injection | `' OR '1'='1` | Login blocked |
| Weak password | `123`, `password`, `admin` | Validation failed |
| Brute force | 5 wrong passwords | Account locked |
| Password reset | Valid registered email | New password stored as hash |
| OTP verification | Wrong OTP | Dashboard blocked |
| OTP verification | Correct demo OTP or TOTP | Dashboard allowed |
| Session timeout | Wait 10 minutes | Session expires |
| ZAP scan | `http://127.0.0.1:5000` | Findings documented |

Recommended screenshots:

- Login page
- Registration page
- Forgot password page
- Reset password page
- OTP verification page
- Dashboard
- SQL injection blocked
- Weak password blocked
- Brute-force account lock
- Login logs table
- ZAP scan results

---

## OWASP ZAP Testing

Target:

```text
http://127.0.0.1:5000
```

Run:

- Spider scan
- Passive scan
- Active scan

Expected findings and notes are documented in [docs/security_testing.md](docs/security_testing.md).

---

## Author

Milan Tej H D

Cyber Security Intern

---

## License

This project is developed for educational and cybersecurity learning purposes.
