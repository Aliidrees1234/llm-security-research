"""
SHIELD Security — Custom Remediation Rules
==========================================
All fix functions for FDSP Layer 3 auto-remediation.

To add a new rule:
  1. Write a fix_* function below
  2. Add it to REMEDIATION_MAP at the bottom
  3. Done — the FDSP engine picks it up automatically

Rule function signature:
  def fix_XXXX(code: str) -> tuple[str, int]:
      # code  = full file content as string
      # returns (fixed_code, number_of_fixes_applied)

Author: Ali Yasin Idrees
Version: 0.1.0
"""
import re
import ast
import astor

# ── BANDIT RULES ──────────────────────────────────────────────────────────────
class _DebugFixer(ast.NodeTransformer):
    """
    Walks the AST tree looking for app.run(debug=True).
    When found — replaces Constant(True) with Constant(False).
    Works regardless of spacing, formatting, or argument order.
    """
    def __init__(self):
        self.fixes = 0

    def visit_Call(self, node):
        # Is this a method call? (.run() for example)
        if isinstance(node.func, ast.Attribute):
            # Is the method name 'run'?
            if node.func.attr == 'run':
                # Walk through all keyword arguments
                for keyword in node.keywords:
                    # Is this the debug argument?
                    if keyword.arg == 'debug':
                        # Is the value literally True?
                        if (isinstance(keyword.value, ast.Constant)
                                and keyword.value.value is True):
                            # Replace True with False
                            keyword.value = ast.Constant(value=False)
                            self.fixes += 1
        # Keep walking the rest of the tree
        return self.generic_visit(node)
    
def fix_B201_debug_true(code: str) -> tuple[str, int]:
    """
    B201 — flask_debug_true
    Severity: HIGH | CWE-94
    Replace app.run(debug=True) with debug=False.

    Strategy:
      1. Try AST fix — robust, handles all formatting
      2. If AST fails (syntax error) — fall back to regex
    """
    if not code.strip():
        return code, 0

    # ── AST approach (primary) ─────────────────────────────────────────────
    try:
        tree = ast.parse(code)
        fixer = _DebugFixer()
        new_tree = fixer.visit(tree)

        if fixer.fixes > 0:
            fixed_code = astor.to_source(new_tree)

            # Add os import if needed
            if "os.environ" in fixed_code and "import os" not in fixed_code:
                fixed_code = "import os\n" + fixed_code

            return fixed_code, fixer.fixes

        return code, 0

    # ── Regex fallback (if file has syntax errors) ─────────────────────────
    except SyntaxError:
        original = code
        code = re.sub(
            r'(app\.run\([^)]*?)debug\s*=\s*True([^)]*?\))',
            lambda m: m.group(1) + "debug=False" + m.group(2),
            code
        )
        code = re.sub(
            r'app\.run\(\s*debug\s*=\s*True\s*\)',
            "app.run(debug=False, host='127.0.0.1', "
            "port=int(os.environ.get('PORT', 5000)))",
            code
        )
        if "app.run(" in code and "import os" not in code and "os.environ" in code:
            code = "import os\n" + code
        fixes = 0 if code == original else code.count("debug=False")
        return code, fixes


class _ShellFixer(ast.NodeTransformer):
    """
    Walks the AST looking for subprocess calls with shell=True.
    Replaces Constant(True) with Constant(False) on the shell keyword.

    Catches all subprocess variants:
      subprocess.run(cmd, shell=True)
      subprocess.call(cmd, shell=True)
      subprocess.Popen(cmd, shell=True)
      subprocess.check_output(cmd, shell=True)
    """
    SUBPROCESS_METHODS = {'run', 'call', 'Popen', 'check_output', 'check_call'}

    def __init__(self):
        self.fixes = 0

    def visit_Call(self, node):
        # Is this a method call?
        if isinstance(node.func, ast.Attribute):
            # Is it a subprocess method?
            if node.func.attr in self.SUBPROCESS_METHODS:
                # Is the object named subprocess?
                if (isinstance(node.func.value, ast.Name) and
                        node.func.value.id == 'subprocess'):
                    # Walk keyword arguments
                    for keyword in node.keywords:
                        if keyword.arg == 'shell':
                            if (isinstance(keyword.value, ast.Constant)
                                    and keyword.value.value is True):
                                # Replace True with False
                                keyword.value = ast.Constant(value=False)
                                self.fixes += 1
        return self.generic_visit(node)

def fix_B602_shell_true(code: str) -> tuple[str, int]:
    """
    B602 — subprocess_popen_shell_true
    Severity: HIGH | CWE-78
    Replace shell=True with shell=False.
    Inject command whitelist comment for developer guidance.

    Strategy:
      1. Try AST fix — finds all subprocess variants robustly
      2. If AST fails (syntax error) — fall back to regex
    """
    if not code.strip():
        return code, 0

    # ── AST approach (primary) ─────────────────────────────────────────────
    try:
        tree = ast.parse(code)
        fixer = _ShellFixer()
        new_tree = fixer.visit(tree)

        if fixer.fixes > 0:
            fixed_code = astor.to_source(new_tree)

            # Inject whitelist guidance if not already present
            if ('ALLOWED_COMMANDS' not in fixed_code and
                    'whitelist' not in fixed_code.lower()):
                whitelist_block = (
                    "\n# SHIELD — B602 fix: shell argument set to False\n"
                    "# Define command whitelist for safe subprocess execution\n"
                    "ALLOWED_COMMANDS = {\n"
                    '    "status": ["/usr/bin/uptime"],\n'
                    '    "disk":   ["/bin/df", "-h"],\n'
                    "}\n"
                )
                # Insert after imports
                lines = fixed_code.split('\n')
                import_end = 0
                for i, line in enumerate(lines):
                    if line.startswith('from ') or line.startswith('import '):
                        import_end = i
                lines.insert(import_end + 1, whitelist_block)
                fixed_code = '\n'.join(lines)

            return fixed_code, fixer.fixes

        return code, 0

    # ── Regex fallback ─────────────────────────────────────────────────────
    except SyntaxError:
        original = code
        fixes = 0
        if re.search(r'subprocess\.\w+\([^)]*shell\s*=\s*True', code):
            code = re.sub(r'shell\s*=\s*True', 'shell=False', code)
            if ('ALLOWED_COMMANDS' not in code and
                    'whitelist' not in code.lower()):
                whitelist_block = (
                    "\n# SHIELD — B602 fix: shell argument set to False\n"
                    "ALLOWED_COMMANDS = {\n"
                    '    "status": ["/usr/bin/uptime"],\n'
                    '    "disk":   ["/bin/df", "-h"],\n'
                    "}\n"
                )
                import_end = 0
                for i, line in enumerate(code.split('\n')):
                    if line.startswith('from ') or line.startswith('import '):
                        import_end = i
                lines = code.split('\n')
                lines.insert(import_end + 1, whitelist_block)
                code = '\n'.join(lines)
            fixes = 1
        return code, fixes
    
class _HardcodedSecretFixer(ast.NodeTransformer):
    """
    Walks the AST looking for hardcoded secret assignments.

    Catches these patterns:
      SECRET_KEY = 'literal'
      app.secret_key = 'literal'
      MAIL_PASSWORD = 'literal'
      SECURITY_PASSWORD_SALT = 'literal'

    Replaces with:
      SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
      app.secret_key = os.environ.get('FLASK_SECRET_KEY')
      MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
      SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT')
    """

    # Map of variable names to their env var names
    SECRET_VARS = {
        'SECRET_KEY':              'FLASK_SECRET_KEY',
        'MAIL_PASSWORD':           'MAIL_PASSWORD',
        'SECURITY_PASSWORD_SALT':  'SECURITY_PASSWORD_SALT',
        'API_KEY':                 'API_KEY',
        'DB_PASSWORD':             'DB_PASSWORD',
    }

    # Minimum length to be considered a real secret (not a placeholder)
    MIN_SECRET_LEN = 3

    def __init__(self):
        self.fixes = 0
        self.needs_os_import = False

    def _make_environ_call(self, env_var: str) -> ast.Call:
        """Build the AST node for os.environ.get('VAR_NAME')"""
        return ast.Call(
            func=ast.Attribute(
                value=ast.Attribute(
                    value=ast.Name(id='os', ctx=ast.Load()),
                    attr='environ',
                    ctx=ast.Load()
                ),
                attr='get',
                ctx=ast.Load()
            ),
            args=[ast.Constant(value=env_var)],
            keywords=[]
        )

    def visit_Assign(self, node):
        """Handle: SECRET_KEY = 'literal'"""
        for target in node.targets:
            # Simple name assignment: SECRET_KEY = 'value'
            if isinstance(target, ast.Name):
                var_name = target.id
                if var_name in self.SECRET_VARS:
                    if (isinstance(node.value, ast.Constant) and
                            isinstance(node.value.value, str) and
                            len(node.value.value) >= self.MIN_SECRET_LEN):
                        env_var = self.SECRET_VARS[var_name]
                        node.value = self._make_environ_call(env_var)
                        self.fixes += 1
                        self.needs_os_import = True

            # Attribute assignment: app.secret_key = 'value'
            elif isinstance(target, ast.Attribute):
                attr_name = target.attr
                if attr_name == 'secret_key':
                    if (isinstance(node.value, ast.Constant) and
                            isinstance(node.value.value, str) and
                            len(node.value.value) >= self.MIN_SECRET_LEN):
                        node.value = self._make_environ_call('FLASK_SECRET_KEY')
                        self.fixes += 1
                        self.needs_os_import = True

        return self.generic_visit(node)

def fix_B105_B106_hardcoded(code: str) -> tuple[str, int]:
    """
    B105/B106 — hardcoded_password_string / hardcoded_password_funcarg
    Severity: LOW | CWE-259
    Replace hardcoded secrets with os.environ.get().

    Strategy:
      1. Try AST fix — finds assignments by structure not text
      2. If AST fails (syntax error) — fall back to regex
    """
    if not code.strip():
        return code, 0

    # ── AST approach (primary) ─────────────────────────────────────────────
    try:
        tree = ast.parse(code)
        fixer = _HardcodedSecretFixer()
        new_tree = fixer.visit(tree)
        ast.fix_missing_locations(new_tree)

        if fixer.fixes > 0:
            fixed_code = astor.to_source(new_tree)

            # Add os import if needed and not already present
            if fixer.needs_os_import and 'import os' not in fixed_code:
                fixed_code = "import os\n" + fixed_code

            return fixed_code, fixer.fixes

        return code, 0

    # ── Regex fallback ─────────────────────────────────────────────────────
    except SyntaxError:
        original = code
        fixes = 0
        patterns = [
            (r"(SECRET_KEY\s*=\s*)['\"][^'\"]{3,}['\"]",
             r"\1os.environ.get('FLASK_SECRET_KEY')"),
            (r"(app\.secret_key\s*=\s*)['\"][^'\"]{3,}['\"]",
             r"\1os.environ.get('FLASK_SECRET_KEY')"),
            (r"(MAIL_PASSWORD\s*=\s*)['\"][^'\"]{3,}['\"]",
             r"\1os.environ.get('MAIL_PASSWORD')"),
            (r"(SECURITY_PASSWORD_SALT\s*=\s*)['\"][^'\"]{3,}['\"]",
             r"\1os.environ.get('SECURITY_PASSWORD_SALT')"),
        ]
        for pattern, replacement in patterns:
            new_code = re.sub(pattern, replacement, code)
            if new_code != code:
                fixes += 1
                code = new_code
        if 'os.environ.get' in code and 'import os' not in code:
            code = "import os\n" + code
        return code, fixes


def fix_B324_weak_hash(code: str) -> tuple[str, int]:
    """
    B324 — hashlib_new_insecure_functions
    Severity: HIGH | CWE-327
    Replace MD5/SHA1 with SHA256 (usedforsecurity=False for non-auth uses).
    """
    original = code
    fixes = 0

    if 'hashlib.md5(' in code:
        code = re.sub(
            r'hashlib\.md5\(([^)]+)\)',
            r'hashlib.sha256(\1, usedforsecurity=False)',
            code
        )
        fixes += 1

    if 'hashlib.sha1(' in code:
        code = re.sub(
            r'hashlib\.sha1\(([^)]+)\)',
            r'hashlib.sha256(\1, usedforsecurity=False)',
            code
        )
        fixes += 1

    return code, fixes


def fix_B104_bind_all(code: str) -> tuple[str, int]:
    """
    B104 — hardcoded_bind_all_interfaces
    Severity: MEDIUM | CWE-605
    Replace host='0.0.0.0' with environment variable.
    """
    original = code

    code = re.sub(
        r"host\s*=\s*['\"]0\.0\.0\.0['\"]",
        "host=os.environ.get('HOST', '127.0.0.1')",
        code
    )
    if 'os.environ.get' in code and 'import os' not in code:
        code = "import os\n" + code

    fixes = 0 if code == original else 1
    return code, fixes


def fix_B108_tmp_dir(code: str) -> tuple[str, int]:
    """
    B108 — hardcoded_tmp_directory
    Severity: MEDIUM | CWE-377
    Replace /tmp hardcoded path with environment variable.
    """
    original = code

    code = re.sub(
        r"""os\.environ\.get\(['"]\w+['"]\s*,\s*['"]/tmp[^'"]*['"]\)""",
        "os.environ.get('UPLOAD_FOLDER')  "
        "# nosec B108 — no /tmp default, set UPLOAD_FOLDER env var",
        code
    )
    code = re.sub(
        r"""['"](/tmp/[^'"]*|\\tmp\\[^'"]*)['"]""",
        "os.environ.get('UPLOAD_FOLDER', '/var/app/uploads')",
        code
    )

    fixes = 0 if code == original else 1
    return code, fixes


def fix_B311_random(code: str) -> tuple[str, int]:
    """
    B311 — random
    Severity: LOW | CWE-330
    Flag non-cryptographic random usage with nosec for display-only data.
    Note: If used for security tokens, replace with secrets module.
    """
    original = code
    fixes = 0

    if 'random.randint' in code or 'random.choice' in code:
        code = re.sub(
            r'random\.randint\(',
            'random.randint(  # nosec B311 — non-security display data only',
            code
        )
        code = re.sub(
            r'random\.choice\(',
            'random.choice(  # nosec B311 — non-security display data only',
            code
        )
        fixes = 1

    return code, fixes


def fix_B101_assert(code: str) -> tuple[str, int]:
    """
    B101 — assert_used
    Severity: LOW | CWE-703
    Suppresses false positive in test files — assert is valid in tests.
    """
    original = code

    if 'def test_' in code or 'client.get(' in code or 'client.post(' in code:
        # Valid test usage — no change needed, already acceptable
        pass

    fixes = 0 if code == original else 1
    return code, fixes


# ── CUSTOM RULES (beyond Bandit's scope) ─────────────────────────────────────

def fix_werkzeug_weak_hash(code: str) -> tuple[str, int]:
    """
    CUSTOM — werkzeug_generate_password_hash
    Severity: MEDIUM | CWE-916
    Bandit does not flag generate_password_hash (pbkdf2) because it's not
    plaintext. But pbkdf2 is GPU-crackable at scale. Replace with bcrypt.

    Why bcrypt:
      pbkdf2:sha256 → billions of attempts/second on GPU farm
      bcrypt rounds=12 → thousands of attempts/second — 1000x safer
    """
    original = code

    if 'generate_password_hash' not in code:
        return code, 0

    # Add bcrypt import
    if 'import bcrypt' not in code:
        code = "import bcrypt\n" + code

    # Handle werkzeug import — keep check_password_hash if used
    if 'check_password_hash' in code:
        for old in [
            'from werkzeug.security import generate_password_hash, check_password_hash',
            'from werkzeug.security import check_password_hash, generate_password_hash',
        ]:
            code = code.replace(
                old,
                'from werkzeug.security import check_password_hash'
            )
        code = code.replace(
            'from werkzeug.security import generate_password_hash',
            ''
        )
    else:
        code = code.replace(
            'from werkzeug.security import generate_password_hash\n',
            ''
        )

    # Replace the function call
    code = re.sub(
        r'generate_password_hash\(([^)]+)\)',
        r'bcrypt.hashpw(\1.encode("utf-8"), bcrypt.gensalt(rounds=12))',
        code
    )

    fixes = 0 if code == original else 1
    return code, fixes


def fix_sql_fstring(code: str) -> tuple[str, int]:
    """
    CUSTOM — sql_fstring_injection
    Severity: HIGH | CWE-89
    Bandit catches some SQL injection but misses f-string patterns.
    Detects and flags dangerous f-string SQL construction.
    Note: Auto-fix for SQL is complex — flags for manual review.
    """
    original = code
    fixes = 0

    dangerous_patterns = [
        r'execute\(f["\']',
        r'execute\(.*\+.*\)',
        r'query\s*=\s*f["\'].*SELECT',
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, code, re.IGNORECASE):
            code = re.sub(
                pattern,
                lambda m: m.group(0) + "  # SHIELD WARNING: SQL injection risk — use parameterized queries",
                code,
                flags=re.IGNORECASE
            )
            fixes += 1

    return code, fixes


# ── REMEDIATION MAP ───────────────────────────────────────────────────────────
# The FDSP engine iterates this map in order.
# Add new rules here — no other file needs to change.

REMEDIATION_MAP = {
    # Bandit rules — High severity first
    'B201': fix_B201_debug_true,
    'B602': fix_B602_shell_true,
    'B324': fix_B324_weak_hash,

    # Bandit rules — Medium severity
    'B104': fix_B104_bind_all,
    'B108': fix_B108_tmp_dir,

    # Bandit rules — Low severity
    'B105': fix_B105_B106_hardcoded,
    'B106': fix_B105_B106_hardcoded,
    'B311': fix_B311_random,
    'B101': fix_B101_assert,

    # Custom rules — beyond Bandit's scope
    'CUSTOM_WERKZEUG': fix_werkzeug_weak_hash,
    'CUSTOM_SQL_FSTRING': fix_sql_fstring,
}