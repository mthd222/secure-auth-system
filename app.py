from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
import os
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv
from security.hashing import hash_password, verify_password
from security.totp import generate_totp, generate_totp_secret, get_totp_uri, verify_totp
from security.validators import validate_password
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta,datetime
import base64
import io
import qrcode
import secrets
import html

app = Flask(__name__)

load_dotenv()

csrf = CSRFProtect(app)

app.secret_key = os.getenv(
    "SECRET_KEY",
    secrets.token_hex(32)
)

app.permanent_session_lifetime = timedelta(minutes=10)
# ---------------- SECURE SESSION COOKIES ----------------

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

DATABASE = "database.db"


def get_db_connection():
    return sqlite3.connect(DATABASE)


def normalize_otp_code(code):
    return ''.join(character for character in code if character.isdigit())


def generate_qr_code_data_uri(value):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4
    )
    qr.add_data(value)
    qr.make(fit=True)

    image = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded_image = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded_image}"


def initialize_database():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        otp_secret TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS login_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        status TEXT,
        ip_address TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS failed_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        attempts INTEGER DEFAULT 0,
        last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]

    if 'otp_secret' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN otp_secret TEXT")

    conn.commit()
    conn.close()


initialize_database()


@app.after_request
def security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; img-src 'self' data:"
    )
    return response

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

            valid_email = validate_email(email, check_deliverability=False)

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
        otp_secret = generate_totp_secret()

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                '''
                INSERT INTO users (username, email, password_hash, otp_secret)
                VALUES (?, ?, ?, ?)
                ''',
                (username, email, hashed_password, otp_secret)
            )

            conn.commit()
            conn.close()

            session['setup_email'] = email
            session['setup_otp_secret'] = otp_secret

            flash("Registration successful. Set up two-factor authentication.")
            return redirect('/setup-2fa')

        except sqlite3.IntegrityError:

            conn.close()

            flash("Email already exists")
            return redirect('/register')

    return render_template("register.html")


# ---------------- 2FA SETUP ----------------

@app.route('/setup-2fa', methods=['GET', 'POST'])
def setup_2fa():

    if 'setup_email' not in session or 'setup_otp_secret' not in session:
        return redirect('/')

    email = session['setup_email']
    otp_secret = session['setup_otp_secret']
    provisioning_uri = get_totp_uri(email, otp_secret)
    qr_code = generate_qr_code_data_uri(provisioning_uri)

    if request.method == 'POST':
        otp_code = normalize_otp_code(request.form['otp'])

        if verify_totp(otp_secret, otp_code):
            session.pop('setup_email', None)
            session.pop('setup_otp_secret', None)
            session.pop('setup_pending_user', None)

            flash("Two-factor authentication setup verified. Login now.")
            return redirect('/')

        print(
            f"2FA setup failed for {email}. Server codes: "
            f"previous={generate_totp(otp_secret, offset=-1)} "
            f"current={generate_totp(otp_secret)} "
            f"next={generate_totp(otp_secret, offset=1)}",
            flush=True
        )

        flash("Invalid 2FA code. Delete old entries and scan this QR again.")
        return redirect('/setup-2fa')

    return render_template(
        'setup_2fa.html',
        email=email,
        otp_secret=otp_secret,
        provisioning_uri=provisioning_uri,
        qr_code=qr_code
    )

# ---------------- LOGIN ----------------


# ---------------- LOGIN ----------------

@app.route('/login', methods=['POST'])
def login():

    email = request.form['email'].strip().lower()
    password = request.form['password']

    ip = request.remote_addr

    # ---------------- DATABASE CONNECTION ----------------

    conn = get_db_connection()
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

        last_attempt_time = datetime.strptime(last_attempt, '%Y-%m-%d %H:%M:%S')
        time_difference = (datetime.now() - last_attempt_time).total_seconds()

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
        SELECT id, username, email, password_hash, otp_secret FROM users
        WHERE email=?
        ''',
        (email,)
    )

    user = cursor.fetchone()

    # ---------------- VERIFY PASSWORD ----------------

    if user:

        stored_password = user[3]

        if verify_password(stored_password, password):

            email_otp = f"{secrets.randbelow(1000000):06d}"
            otp_secret = user[4]

            session.clear()
            session.permanent = True

            if not otp_secret:
                otp_secret = generate_totp_secret()
                session['setup_email'] = user[2]
                session['setup_otp_secret'] = otp_secret
                session['setup_pending_user'] = user[1]

                cursor.execute(
                    '''
                    UPDATE users
                    SET otp_secret=?
                    WHERE email=?
                    ''',
                    (otp_secret, user[2])
                )

                conn.commit()
                conn.close()

                flash("Set up two-factor authentication before continuing.")
                return redirect('/setup-2fa')

            session['pending_user'] = user[1]
            session['pending_email'] = user[2]
            session['pending_otp_secret'] = otp_secret
            session['email_otp'] = email_otp
            session['email_otp_created_at'] = datetime.now().isoformat()

            cursor.execute(
                '''
                INSERT INTO login_logs
                (email, status, ip_address)
                VALUES (?, ?, ?)
                ''',
                (email, "OTP_PENDING", ip)
            )

            conn.commit()
            conn.close()

            flash("Password verified. Enter your OTP to continue.")
            print(f"Demo email OTP for {email}: {email_otp}", flush=True)
            print(
                f"Google Authenticator debug for {email}: "
                f"previous={generate_totp(otp_secret, offset=-1)} "
                f"current={generate_totp(otp_secret)} "
                f"next={generate_totp(otp_secret, offset=1)} "
                f"time_remaining={30 - (int(datetime.now().timestamp()) % 30)}s",
                flush=True
            )

            return redirect('/verify-otp')

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


# ---------------- OTP VERIFICATION ----------------

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():

    if 'pending_user' not in session:
        return redirect('/')

    email = session['pending_email']
    otp_secret = session['pending_otp_secret']
    provisioning_uri = get_totp_uri(email, otp_secret)

    if request.method == 'POST':

        otp_code = normalize_otp_code(request.form['otp'])
        email_otp = session.get('email_otp')
        created_at = session.get('email_otp_created_at')
        email_otp_valid = False

        if email_otp and created_at:
            otp_age = datetime.now() - datetime.fromisoformat(created_at)
            email_otp_valid = (
                otp_age.total_seconds() <= 300 and
                secrets.compare_digest(email_otp, otp_code)
            )

        if email_otp_valid or verify_totp(otp_secret, otp_code):
            username = session['pending_user']

            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                '''
                UPDATE users
                SET otp_secret=?
                WHERE email=? AND (otp_secret IS NULL OR otp_secret='')
                ''',
                (otp_secret, email)
            )

            cursor.execute(
                '''
                INSERT INTO login_logs
                (email, status, ip_address)
                VALUES (?, ?, ?)
                ''',
                (email, "SUCCESS", request.remote_addr)
            )

            cursor.execute(
                '''
                DELETE FROM failed_attempts
                WHERE email=?
                ''',
                (email,)
            )

            conn.commit()
            conn.close()

            session.clear()
            session.permanent = True
            session['user'] = username

            flash("Two-factor verification successful")
            return redirect('/dashboard')

        flash("Invalid or expired OTP")
        return redirect('/verify-otp')

    return render_template(
        'verify_otp.html',
        otp_secret=otp_secret,
        provisioning_uri=provisioning_uri
    )


@app.route('/verify-reset-otp', methods=['GET', 'POST'])
def verify_reset_otp():

    if 'reset_pending_email' not in session:
        return redirect('/forgot-password')

    email = session['reset_pending_email']
    otp_secret = session.get('reset_pending_otp_secret')
    provisioning_uri = None

    if otp_secret:
        provisioning_uri = get_totp_uri(email, otp_secret)

    if request.method == 'POST':

        otp_code = normalize_otp_code(request.form['otp'])
        email_otp = session.get('reset_email_otp')
        created_at = session.get('reset_email_otp_created_at')
        email_otp_valid = False

        if email_otp and created_at:
            otp_age = datetime.now() - datetime.fromisoformat(created_at)
            email_otp_valid = (
                otp_age.total_seconds() <= 300 and
                secrets.compare_digest(email_otp, otp_code)
            )

        if email_otp_valid or (otp_secret and verify_totp(otp_secret, otp_code)):
            # Mark the reset as verified and allow password change
            session.pop('reset_email_otp', None)
            session.pop('reset_email_otp_created_at', None)
            session['reset_email'] = session.pop('reset_pending_email')
            session.pop('reset_pending_otp_secret', None)

            flash("OTP verified. Set a new password.")
            return redirect('/reset-password')

        flash("Invalid or expired OTP")
        return redirect('/verify-reset-otp')

    return render_template(
        'verify_reset_otp.html',
        otp_secret=otp_secret,
        provisioning_uri=provisioning_uri
    )


# ---------------- RESET 2FA ----------------

@app.route('/reset-2fa', methods=['GET', 'POST'])
def reset_2fa():

    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']

        try:
            valid_email = validate_email(email, check_deliverability=False)
            email = valid_email.email
        except EmailNotValidError:
            flash("Invalid email address")
            return redirect('/reset-2fa')

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT username, email, password_hash FROM users
            WHERE email=?
            ''',
            (email,)
        )

        user = cursor.fetchone()

        if not user or not verify_password(user[2], password):
            conn.close()
            flash("Invalid email or password")
            return redirect('/reset-2fa')

        otp_secret = generate_totp_secret()

        cursor.execute(
            '''
            UPDATE users
            SET otp_secret=?
            WHERE email=?
            ''',
            (otp_secret, email)
        )

        conn.commit()
        conn.close()

        session.clear()
        session['setup_email'] = user[1]
        session['setup_otp_secret'] = otp_secret

        flash("Two-factor authentication was reset. Add the new key.")
        return redirect('/setup-2fa')

    return render_template('reset_2fa.html')


# ---------------- PASSWORD RESET ----------------

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():

    if request.method == 'POST':
        email = request.form['email'].strip().lower()

        try:
            valid_email = validate_email(email, check_deliverability=False)
            email = valid_email.email
        except EmailNotValidError:
            flash("Invalid email address")
            return redirect('/forgot-password')

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT email, otp_secret FROM users
            WHERE email=?
            ''',
            (email,)
        )

        user = cursor.fetchone()

        if user:
            # Prepare OTP for reset: allow either email OTP (demo) or TOTP if configured
            email_otp = f"{secrets.randbelow(1000000):06d}"
            otp_secret = user[1]

            session.clear()
            session['reset_pending_email'] = email
            session['reset_pending_otp_secret'] = otp_secret
            session['reset_email_otp'] = email_otp
            session['reset_email_otp_created_at'] = datetime.now().isoformat()

            conn.close()

            flash("Account verified. Enter OTP to continue password reset.")
            print(f"Demo password-reset email OTP for {email}: {email_otp}", flush=True)
            return redirect('/verify-reset-otp')

        conn.close()

        flash("No account found for that email")
        return redirect('/forgot-password')

    return render_template('forgot_password.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():

    if 'reset_email' not in session:
        return redirect('/forgot-password')

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match")
            return redirect('/reset-password')

        valid, message = validate_password(password)

        if not valid:
            flash(message)
            return redirect('/reset-password')

        email = session['reset_email']
        hashed_password = hash_password(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            UPDATE users
            SET password_hash=?
            WHERE email=?
            ''',
            (hashed_password, email)
        )

        cursor.execute(
            '''
            DELETE FROM failed_attempts
            WHERE email=?
            ''',
            (email,)
        )

        conn.commit()
        conn.close()

        session.pop('reset_email', None)

        flash("Password reset successful. Login with your new password.")
        return redirect('/')

    return render_template('reset_password.html')

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

@app.route('/logout', methods=['POST'])
def logout():

    session.clear()

    flash("Logged Out Successfully")

    return redirect('/')

# ---------------- MAIN ----------------

if __name__ == '__main__':
    app.run(debug=os.getenv("FLASK_DEBUG") == "1")
