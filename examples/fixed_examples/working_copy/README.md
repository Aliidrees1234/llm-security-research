# SHIELD Examples

Demonstrates the complete SHIELD pipeline on a real vulnerable Flask app.

## The Vulnerable App

`vulnerable_flask.py` contains 6 vulnerabilities — the same patterns
found in the empirical study across 60 LLM-generated files (March 2026):

| Line | Rule | CWE | Severity | Vulnerability |
|------|------|-----|----------|--------------|
| 22 | B105 | CWE-259 | Low | Hardcoded secret key |
| 34 | CUSTOM_SQL_FSTRING | CWE-89 | High | SQL injection via f-string |
| 43 | B324 | CWE-327 | High | MD5 weak hash |
| 50 | B602 | CWE-78 | High | shell=True RCE |
| 57 | B311 | CWE-330 | Low | Insecure random |
| 62 | B201 | CWE-94 | High | debug=True |

## Run SHIELD

### Step 1 — Scan (see all findings)
```bash
shield scan ./examples
```

### Step 2 — Fix (auto-remediate)
```bash
shield fix ./examples --output ./examples/fixed --report ./examples/report.html
```

### Step 3 — Open report
```bash
# Windows
start examples/report.html

# Mac/Linux
open examples/report.html
```

### Step 4 — Full pipeline (build secured prompt first)
```bash
shield secure "Write a Flask login endpoint with SQLite" --claude
```

## Expected Results

Before SHIELD:
High: 4
Low: 2
Grade: F
I/100L: ~8.0

After SHIELD:
High: 0
Low: 2
Grade: A
I/100L: ~3.0

## What SHIELD Fixed Automatically

| Rule | Before | After |
|------|--------|-------|
| B201 | app.run(debug=True) | app.run(debug=False, host='127.0.0.1') |
| B602 | shell=True | shell=False + ALLOWED_COMMANDS |
| B324 | hashlib.md5() | hashlib.sha256(usedforsecurity=False) |
| B105 | secret_key = 'literal' | os.environ.get('FLASK_SECRET_KEY') |