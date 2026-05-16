from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
import os
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv
from security.hashing import hash_password, verify_password
from security.validators import validate_password
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta,datetime
import html

app = Flask(__name__)

load_dotenv()

csrf = CSRFProtect(app)

app.secret_key = os.getenv(
    "SECRET_KEY",
    "fallback_secret_key"
)

app.permanent_session_lifetime = timedelta(minutes=10)
# ---------------- SECURE SESSION COOKIES ----------------

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

DATABASE = "database.db"

# ---------------- HOME ----------------

@app.route('/')
def home():

    if 'user' in session:
        return redirect('/dashboard')

    return render_template("login.html")

# ---------------- REGISTER ----------------

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        # ---------------- INPUT SANITIZATION ----------------

        username = html.escape(
            request.form['username'].strip()
        )

        email = request.form['email'].strip().lower()

        password = request.form['password']

        # ---------------- EMAIL VALIDATION ----------------

        try:

            valid_email = validate_email(email)

            email = valid_email.email

        except EmailNotValidError:

            flash("Invalid email address")

            return redirect('/register')

        # Validate Password
        valid, message = validate_password(password)

        if not valid:
            flash(message)
            return redirect('/register')

        hashed_password = hash_password(password)

        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            cursor.execute(
                '''
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
                ''',
                (username, email, hashed_password)
            )

            conn.commit()
            conn.close()

            flash("Registration Successful")
            return redirect('/')

        except sqlite3.IntegrityError:

            conn.close()

            flash("Email already exists")
            return redirect('/register')

    return render_template("register.html")

# ---------------- LOGIN ----------------


# ---------------- LOGIN ----------------

@app.route('/login', methods=['POST'])
def login():

    email = request.form['email'].strip().lower()
    password = request.form['password']

    ip = request.remote_addr

    # ---------------- DATABASE CONNECTION ----------------

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # ---------------- CHECK FAILED ATTEMPTS ----------------

    cursor.execute(
        '''
        SELECT attempts, last_attempt
        FROM failed_attempts
        WHERE email=?
        ''',
        (email,)
    )

    record = cursor.fetchone()

    if record:

        attempts = record[0]
        last_attempt = record[1]

        last_attempt_time = datetime.strptime(
            last_attempt,
            '%Y-%m-%d %H:%M:%S'
        )

        time_difference = (
            datetime.now() - last_attempt_time
        ).seconds

        # ---------------- ACCOUNT LOCK ----------------

        if attempts >= 5 and time_difference < 900:

            conn.close()

            flash(
                "Account locked. Try again after 15 minutes."
            )

            return redirect('/')

        # ---------------- AUTO RESET AFTER 15 MINUTES ----------------

        elif attempts >= 5 and time_difference >= 900:

            cursor.execute(
                '''
                DELETE FROM failed_attempts
                WHERE email=?
                ''',
                (email,)
            )

            conn.commit()

    # ---------------- CHECK USER ----------------

    cursor.execute(
        '''
        SELECT * FROM users
        WHERE email=?
        ''',
        (email,)
    )

    user = cursor.fetchone()

    # ---------------- VERIFY PASSWORD ----------------

    if user:

        stored_password = user[3]

        if verify_password(stored_password, password):

            # Create secure session
            session.permanent = True
            session['user'] = user[1]

            # Log successful login
            cursor.execute(
                '''
                INSERT INTO login_logs
                (email, status, ip_address)
                VALUES (?, ?, ?)
                ''',
                (email, "SUCCESS", ip)
            )

            # Reset failed attempts
            cursor.execute(
                '''
                DELETE FROM failed_attempts
                WHERE email=?
                ''',
                (email,)
            )

            conn.commit()
            conn.close()

            flash("Login Successful")

            return redirect('/dashboard')

    # ---------------- FAILED LOGIN ----------------

    # Log failed login
    cursor.execute(
        '''
        INSERT INTO login_logs
        (email, status, ip_address)
        VALUES (?, ?, ?)
        ''',
        (email, "FAILED", ip)
    )

    # Check existing failed attempts
    cursor.execute(
        '''
        SELECT * FROM failed_attempts
        WHERE email=?
        ''',
        (email,)
    )

    existing = cursor.fetchone()

    if existing:

        cursor.execute(
            '''
            UPDATE failed_attempts
            SET attempts = attempts + 1,
            last_attempt = CURRENT_TIMESTAMP
            WHERE email=?
            ''',
            (email,)
        )

    else:

        cursor.execute(
            '''
            INSERT INTO failed_attempts
            (email, attempts, last_attempt)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ''',
            (email, 1)
        )

    conn.commit()
    conn.close()

    flash("Invalid Email or Password")

    return redirect('/')

# ---------------- DASHBOARD ----------------

@app.route('/dashboard')
def dashboard():

    if 'user' not in session:
        return redirect('/')

    return render_template(
        'dashboard.html',
        username=session['user']
    )

# ---------------- LOGOUT ----------------

@app.route('/logout')
def logout():

    session.pop('user', None)

    flash("Logged Out Successfully")

    return redirect('/')

# ---------------- MAIN ----------------

if __name__ == '__main__':
    app.run(debug=True)