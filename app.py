"""
Secure Login System
--------------------
A beginner-friendly Flask web app that demonstrates:
  1. User registration & login with bcrypt password hashing
  2. Protection from SQL injection using parameterized queries
  3. Session management with a logout feature
  4. Optional Two-Factor Authentication (2FA) using TOTP (like Google Authenticator)

Every section below has comments explaining WHAT it does and WHY.
For a line-by-line breakdown of libraries and concepts, see README.md.
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
import re
import os
import pyotp
from functools import wraps

# ---------------------------------------------------------------------------
# APP SETUP
# ---------------------------------------------------------------------------

app = Flask(__name__)

# The secret_key is used by Flask to cryptographically SIGN the session cookie.
# Without it, users could tamper with their own session data (e.g. fake being
# logged in as someone else). os.urandom(24) generates 24 random bytes each
# time the app starts. In a real production app, set this from an environment
# variable so it stays the same across restarts (otherwise everyone gets
# logged out every time you restart the server).
app.secret_key = os.urandom(24)

DB_NAME = "users.db"


# ---------------------------------------------------------------------------
# DATABASE HELPERS
# ---------------------------------------------------------------------------

def init_db():
    """Create the users table if it doesn't already exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT
        )
    ''')
    conn.commit()
    conn.close()


def get_db_connection():
    """Open a new database connection for a single request."""
    conn = sqlite3.connect(DB_NAME)
    # row_factory lets us access columns by name, e.g. user['username']
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# INPUT VALIDATION
# ---------------------------------------------------------------------------

def is_valid_username(username):
    """Only allow letters, numbers, and underscores, 3-20 characters long."""
    return bool(re.match(r'^[A-Za-z0-9_]{3,20}$', username))


def is_valid_password(password):
    """Require a minimum length. You could add more rules (uppercase, digits, etc.)."""
    return len(password) >= 8


# ---------------------------------------------------------------------------
# LOGIN-REQUIRED DECORATOR
# ---------------------------------------------------------------------------

def login_required(f):
    """
    A decorator we can put above any route to block access unless the
    user is logged in (i.e. has 'user_id' stored in their session).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in first.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------------

@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # --- Basic input validation ---
        if not is_valid_username(username):
            flash("Username must be 3-20 characters: letters, numbers, underscores only.")
            return redirect(url_for('register'))
        if not is_valid_password(password):
            flash("Password must be at least 8 characters long.")
            return redirect(url_for('register'))

        # --- Hash the password with bcrypt ---
        # bcrypt.gensalt() creates a random "salt" so that even two users
        # with the same password get different hashes. This protects against
        # rainbow-table attacks. We NEVER store the plain password.
        password_bytes = password.encode('utf-8')
        hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

        # --- Generate a 2FA secret (optional feature) ---
        # pyotp.random_base32() creates a secret key the user can load into
        # an authenticator app (Google Authenticator, Authy, etc.)
        totp_secret = pyotp.random_base32()

        conn = get_db_connection()
        try:
            # Using "?" placeholders (parameterized query) instead of
            # inserting the username/password directly into the SQL string
            # is what prevents SQL injection attacks.
            conn.execute(
                "INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)",
                (username, hashed.decode('utf-8'), totp_secret)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            # This fires if the username already exists (UNIQUE constraint).
            flash("That username is already taken.")
            return redirect(url_for('register'))
        finally:
            conn.close()

        flash(f"Registration successful! Optional 2FA key (save in an authenticator app): {totp_secret}")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db_connection()
        # Again: "?" placeholder, NOT string formatting/concatenation.
        # This is safe from SQL injection even if someone types
        # something like:  admin' OR '1'='1
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if user is None:
            flash("Invalid username or password.")
            return redirect(url_for('login'))

        stored_hash = user['password_hash'].encode('utf-8')

        # bcrypt.checkpw re-hashes the entered password with the same salt
        # that's embedded in stored_hash and compares the results.
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            # Don't fully log them in yet -- send them to the 2FA step first.
            session['pending_user_id'] = user['id']
            session['pending_username'] = user['username']
            return redirect(url_for('verify_2fa'))
        else:
            flash("Invalid username or password.")
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """
    Optional 2FA step. The user can either enter the 6-digit code from
    their authenticator app, or click "skip" since this feature is optional.
    """
    if 'pending_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if request.form.get('skip'):
            session['user_id'] = session.pop('pending_user_id')
            session['username'] = session.pop('pending_username')
            flash("Logged in (2FA skipped).")
            return redirect(url_for('dashboard'))

        code = request.form.get('code', '').strip()

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?", (session['pending_user_id'],)
        ).fetchone()
        conn.close()

        totp = pyotp.TOTP(user['totp_secret'])
        if totp.verify(code):
            session['user_id'] = session.pop('pending_user_id')
            session['username'] = session.pop('pending_username')
            flash("Login successful!")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid 2FA code. Try again.")
            return redirect(url_for('verify_2fa'))

    return render_template('verify_2fa.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session.get('username'))


@app.route('/logout')
def logout():
    # session.clear() wipes all session data, effectively logging the user out.
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))


# ---------------------------------------------------------------------------
# RUN THE APP
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
