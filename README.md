# Secure Login System 

This is a small web app built with **Python + Flask**. It lets people register an
account, log in, and protect their login with a 6-digit 2FA code.

## 1. How to run it

```bash
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

A file called `users.db` will be created automatically the first time you run
the app — that's your database, no separate database server needed.

---

## 2. The libraries used, and why

| Library | What it's for |
|---|---|
| **Flask** | A lightweight Python "web framework." It handles turning URLs (like `/login`) into Python functions, reading form data, and returning HTML pages. It's the backbone of the whole app. |
| **sqlite3** | Comes built into Python. It's a tiny, file-based database (no separate install needed). We use it to store usernames and password hashes. |
| **bcrypt** | A password-hashing library. It turns a password like `"mypassword123"` into a scrambled, one-way string that can't be reversed back into the original password. |
| **re** (built into Python) | Short for "regular expressions." We use it to check that a username only contains allowed characters. |
| **pyotp** | Generates and checks Time-based One-Time Passwords (TOTP) — the same kind of 6-digit codes you see in Google Authenticator or Authy. This powers the 2FA feature. |
| **functools.wraps** | A small built-in helper used when writing a "decorator" so Flask doesn't get confused about function names. |

---

## 3. Why passwords are hashed, not stored directly

```python
password_bytes = password.encode('utf-8')
hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
```

- `password.encode('utf-8')` converts the text password into raw bytes, since
  bcrypt works on bytes, not strings.
- `bcrypt.gensalt()` creates a random "salt" — extra random data mixed into the
  hash so that two users with the same password still get *different* stored
  hashes. This defeats precomputed "rainbow table" attacks.
- `bcrypt.hashpw(...)` does the actual one-way hashing.

Later, to check a login attempt:

```python
bcrypt.checkpw(password.encode('utf-8'), stored_hash)
```

This re-runs the same hashing process using the salt stored inside
`stored_hash`, and compares the result. If it matches, the password was correct
— all without ever storing or comparing plain-text passwords.

---

## 4. Session management & logout

- `app.secret_key` lets Flask cryptographically sign the session cookie sent to
  the browser, so users can't tamper with it (e.g. change `user_id` to someone
  else's).
- On successful login, we store `session['user_id']` and `session['username']`
  — this is how Flask "remembers" that a specific browser is logged in on
  future requests.
- The `@login_required` decorator (a function that wraps another function)
  checks for `user_id` in the session before allowing access to pages like the
  dashboard.
- `/logout` calls `session.clear()`, wiping all session data — instantly
  logging the user out.

---

## 5. Two-Factor Authentication (2FA)

- When a user registers, we generate a random secret with
  `pyotp.random_base32()` and store it alongside their account.
- In a real app, you'd show this secret as a QR code for the user to scan into
  Google Authenticator/Authy. Here, for simplicity, it's shown as plain text
  in a flash message after registering.
- At login, after the password is verified, the user is asked for a 6-digit
  code. `pyotp.TOTP(secret).verify(code)` checks whether the code matches what
  the authenticator app would currently be showing.

---

## 6. Input validation

```python
def is_valid_username(username):
    return bool(re.match(r'^[A-Za-z0-9_]{3,20}$', username))

def is_valid_password(password):
    return len(password) >= 8
```

- The username regex `^[A-Za-z0-9_]{3,20}$` only allows letters, digits, and
  underscores, between 3–20 characters — blocking stray symbols or SQL-ish
  characters from ever reaching the database.
- The password just needs a minimum length here; feel free to add rules for
  requiring numbers, symbols, etc.

---

## 7. Project structure

```
secure_login_system/
├── app.py                 # All the Python/Flask logic (this is the "backend")
├── requirements.txt       # Libraries to install
├── users.db                # Created automatically — the database file
└── templates/              # HTML pages (the "frontend")
    ├── base.html            # Shared layout + styling
    ├── register.html
    ├── login.html
    ├── verify_2fa.html
    └── dashboard.html
```

Flask automatically looks inside a folder named `templates/` for HTML files,
so that folder name must stay exactly as-is.

---
