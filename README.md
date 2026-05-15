# Secure Login and Authentication System

## Project Overview

This project is a secure authentication system developed using Flask and SQLite.

The system provides:
- Secure Registration
- Secure Login
- Password Hashing
- Session Management
- CSRF Protection
- SQL Injection Prevention
- Brute Force Protection
- Login Logging

---

## Technologies Used

- Python Flask
- SQLite
- HTML/CSS/JavaScript
- Flask-WTF
- Werkzeug

---

## Security Features

### Password Hashing
Passwords are hashed using Werkzeug.

### SQL Injection Prevention
Parameterized queries are used.

### Session Management
Flask sessions are used securely.

### Brute Force Protection
Accounts lock after multiple failed attempts.

### CSRF Protection
Implemented using Flask-WTF.

---

## Project Structure

```text
secure-auth-system/
```

---

## How to Run

```bash
pip install -r requirements.txt
python app.py
```

---

## Future Enhancements

- OTP Authentication
- Email Verification
- JWT Authentication
- OAuth Login

---

## Author

Milan