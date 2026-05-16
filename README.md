# 🔐 Secure Login and Authentication System

A secure authentication system developed using Flask and SQLite that implements modern cybersecurity mechanisms including password hashing, session management, brute-force protection, CSRF protection, login logging, secure cookie handling, and input validation.

---

# 📌 Project Overview

This project focuses on designing and implementing a secure login and authentication system that protects user accounts and sensitive data from unauthorized access.

The application demonstrates practical cybersecurity concepts such as:

- Secure user authentication
- Password hashing
- Session security
- SQL Injection prevention
- CSRF protection
- Brute-force attack mitigation
- Secure cookie configuration
- Login activity logging

The project was developed as part of a cybersecurity internship assignment.

---

# 🚀 Features

## ✅ Authentication Features

- User Registration
- Secure Login
- Secure Logout
- Session Management
- Session Timeout

---

## ✅ Security Features

- Password Hashing using Werkzeug
- SQL Injection Prevention
- CSRF Protection
- Brute Force Protection
- Login Attempt Tracking
- Temporary Account Lock
- Secure Cookie Configuration
- Input Validation
- Input Sanitization
- Email Validation
- Login Logging

---

## ✅ UI Features

- Responsive Authentication Pages
- Modern Glassmorphism UI
- Password Visibility Toggle
- Smooth Animations
- User-Friendly Interface

---

# 🛠 Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend Development |
| Flask | Web Framework |
| SQLite | Database |
| HTML5 | Frontend Structure |
| CSS3 | Styling |
| JavaScript | Frontend Logic |
| Flask-WTF | CSRF Protection |
| Werkzeug | Password Hashing |
| python-dotenv | Environment Variable Management |
| GitHub | Version Control |

---

# 📂 Project Structure

```text
secure-auth-system/
│
├── app.py
├── requirements.txt
├── .env
├── database.db
│
├── templates/
│   ├── login.html
│   ├── register.html
│   └── dashboard.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── script.js
│
├── security/
│   ├── hashing.py
│   └── validators.py
│
├── database/
│   └── db_setup.py
│
├── docs/
├── images/
└── README.md
```

---

# ⚙️ Installation Guide

## Step 1 — Clone Repository

```bash
git clone <repository-url>
cd secure-auth-system
```

---

## Step 2 — Create Virtual Environment

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux / Kali / Ubuntu

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 🔑 Environment Variables

Create a `.env` file in the project root directory.

```env
SECRET_KEY=MyVeryStrongSecretKey123
```

---

# 🗄 Database Setup

Run the following command:

```bash
python database/db_setup.py
```

This creates:

- users table
- login_logs table
- failed_attempts table

---

# ▶️ Run Application

```bash
python app.py
```

Open browser:

```text
http://127.0.0.1:5000
```

---

# 🔐 Security Mechanisms Implemented

## Password Hashing

Passwords are securely hashed using Werkzeug security utilities.

Benefits:
- Prevents plain-text password storage
- Protects credentials during database compromise

---

## SQL Injection Prevention

Parameterized queries are used throughout the application.

Example:

```python
cursor.execute(
    "SELECT * FROM users WHERE email=?",
    (email,)
)
```

---

## CSRF Protection

CSRF protection is implemented using Flask-WTF.

Benefits:
- Prevents forged requests
- Secures form submissions

---

## Brute Force Protection

The system:
- Tracks failed login attempts
- Locks account after 5 failed attempts
- Automatically unlocks after 15 minutes

---

## Session Security

Implemented controls:
- Session timeout
- Secure cookies
- HTTPONLY cookies
- SAMESITE cookie policy

---

# 🧪 Testing Performed

| Test Case | Result |
|---|---|
| Valid Registration | ✅ PASS |
| Duplicate Email | ✅ PASS |
| Weak Password | ✅ PASS |
| Valid Login | ✅ PASS |
| Invalid Login | ✅ PASS |
| Logout | ✅ PASS |
| SQL Injection Test | ✅ BLOCKED |
| Brute Force Test | ✅ BLOCKED |
| Session Timeout | ✅ PASS |
| Password Hashing Verification | ✅ PASS |

---

# 📸 Screenshots

Insert screenshots inside the `images/` folder.

Recommended screenshots:

- Login Page
- Registration Page
- Dashboard
- Database Tables
- Hashed Passwords
- Brute Force Protection
- Login Logs
- Session Timeout
- Project Structure
- Architecture Diagram

---

# 🔮 Future Enhancements

Future improvements may include:

- Two-Factor Authentication (2FA)
- Email Verification
- JWT Authentication
- OAuth Login
- CAPTCHA Integration
- Password Reset System
- Docker Deployment
- MySQL/PostgreSQL Integration

---

# 📚 References

- Flask Documentation  
  https://flask.palletsprojects.com/

- OWASP Authentication Cheat Sheet  
  https://owasp.org/www-project-authentication-cheat-sheet/

- SQLite Documentation  
  https://www.sqlite.org/docs.html

- Werkzeug Security Documentation  
  https://werkzeug.palletsprojects.com/

- Python Documentation  
  https://docs.python.org/3/

---

# 👨‍💻 Author

## Milan
Cyber Security Intern

---

# 📄 License

This project is developed for educational and cybersecurity learning purposes.