import sqlite3

conn = sqlite3.connect('database.db')

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

conn.commit()

cursor.execute("PRAGMA table_info(users)")
columns = [column[1] for column in cursor.fetchall()]

if 'otp_secret' not in columns:
    cursor.execute("ALTER TABLE users ADD COLUMN otp_secret TEXT")
    conn.commit()

conn.close()

print("Database Created Successfully")
