from flask import Flask, render_template, request, redirect, session, flash
import sqlite3

from security.hashing import hash_password, verify_password
from security.validators import validate_password
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta

app = Flask(__name__)
csrf = CSRFProtect(app)

app.secret_key = "supersecretkey"
app.permanent_session_lifetime = timedelta(minutes=10)

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

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

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
            flash("Email already exists")
            return redirect('/register')

    return render_template("register.html")

# ---------------- LOGIN ----------------

@app.route('/login', methods=['POST'])
def login():

    email = request.form['email']
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT attempts FROM failed_attempts WHERE email=?",
        (email,)
    )

    record = cursor.fetchone()

    if record and record[0] >= 5:
        flash("Account temporarily locked due to multiple failed attempts")
        return redirect('/')
    password = request.form['password']

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE email=?",
        (email,)
    )

    user = cursor.fetchone()

    conn.close()

    ip = request.remote_addr

    if user:

        stored_password = user[3]

        if verify_password(stored_password, password):

            session.permanent = True
            session['user'] = user[1]
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            cursor.execute(
                '''
                INSERT INTO login_logs (email, status, ip_address)
                VALUES (?, ?, ?)
                ''',
                (email, "SUCCESS", ip)
            )

            conn.commit()
            conn.close()

            cursor.execute(
                "DELETE FROM failed_attempts WHERE email=?",
                (email,)
            )

            conn.commit()
            flash("Login Successful")

            return redirect('/dashboard')

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        '''
        INSERT INTO login_logs (email, status, ip_address)
        VALUES (?, ?, ?)
        ''',
        (email, "FAILED", ip)
    )

    conn.commit()
    conn.close()

    cursor.execute(
        "SELECT * FROM failed_attempts WHERE email=?",
        (email,)
    )

    existing = cursor.fetchone()

    if existing:

        cursor.execute(
            '''
            UPDATE failed_attempts
            SET attempts = attempts + 1
            WHERE email=?
            ''',
            (email,)
        )

    else:

        cursor.execute(
            '''
            INSERT INTO failed_attempts (email, attempts)
            VALUES (?, ?)
            ''',
            (email, 1)
        )

    conn.commit()
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