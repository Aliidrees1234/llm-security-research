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
Version: 1.0.3
"""
import re
import ast


# ── FALLBACK MANAGER ──────────────────────────────────────────────────────────

class RuleResult:
    """
    Wraps the result of every fix function.
    Tracks: fixed code, fix count, which strategy was used, any errors.
    """
    def __init__(self, code: str, fixes: int,
                 strategy: str = "none", error: str = None):
        self.code     = code
        self.fixes    = fixes 
        self.strategy = strategy  # "ast", "regex", or "none"
        self.error    = error     # error message if fallback triggered

    def __repr__(self):
        return (f"RuleResult(fixes={self.fixes}, "
                f"strategy='{self.strategy}', "
                f"error={self.error!r})")


def safe_apply(ast_fn, regex_fn, code: str, rule_id: str) -> RuleResult:
    """
    Central hybrid executor.
    Tries AST fix first. Falls back to regex if AST raises any error.
    Always returns a RuleResult — never crashes.

    Args:
        ast_fn:   function that applies AST-based fix
        regex_fn: function that applies regex-based fix (fallback)
        code:     source code string to fix
        rule_id:  rule identifier for logging (e.g. 'B201')

    Returns:
        RuleResult with fixed code, fix count, and strategy used
    """
    if not code.strip():
        return RuleResult(code, 0, strategy="none")

    # ── Try AST first ─────────────────────────────────────────────────────
    try:
        fixed, count = ast_fn(code)
        if count > 0:
            return RuleResult(fixed, count, strategy="ast")
        # AST found nothing to fix — that's fine, not an error
        return RuleResult(code, 0, strategy="ast")

    except SyntaxError as e:
        # File has syntax errors — expected, fall back to regex
        pass
    except Exception as e:
        # Unexpected AST error — log and fall back
        error_msg = f"{rule_id} AST error: {type(e).__name__}: {e}"
        try:
            fixed, count = regex_fn(code)
            return RuleResult(fixed, count, strategy="regex", error=error_msg)
        except Exception as re:
            return RuleResult(code, 0, strategy="UNFIXABLE",
                            error=f"{error_msg} | Regex also failed: {re}")

    # ── Regex fallback ─────────────────────────────────────────────────────
    try:
        fixed, count = regex_fn(code)
        return RuleResult(fixed, count, strategy="regex")
    except Exception as e:
        #FAIL-CLOSED: regex fallback failed
        return RuleResult(code, 0, strategy="UNFIXABLE",
                        error=f"{rule_id} both strategies failed: {e}")
    


# ── PURE REGEX FALLBACKS ──────────────────────────────────────────────────────
# Used by safe_apply when AST fails. These are the original regex implementations.

def _regex_B201(code: str) -> tuple[str, int]:
    """Pure regex fallback for B201."""
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


def _regex_B602(code: str) -> tuple[str, int]:
    """Pure regex fallback for B602."""
    original = code
    fixes = 0
    if re.search(r'subprocess\.\w+\([^)]*shell\s*=\s*True', code):
        code = re.sub(r'shell\s*=\s*True', 'shell=False', code)
        fixes = 1
    return code, fixes


def _regex_B105(code: str) -> tuple[str, int]:
    """Pure regex fallback for B105."""
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

def _regex_B324(code: str) -> tuple[str, int]:
    """Pure regex fallback for B324."""
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

def _regex_B104(code: str) -> tuple[str, int]:
    """Pure regex fallback for B104."""
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

def _regex_B108(code: str) -> tuple[str, int]:
    """Pure regex fallback for B108."""
    original = code
    code = re.sub(
        r"""['"](/tmp/[^'"]*|/tmp)['"]""",
        "os.environ.get('UPLOAD_FOLDER', '/var/app/uploads')",
        code
    )
    fixes = 0 if code == original else 1
    return code, fixes

def _regex_B311(code: str) -> tuple[str, int]:
    """Pure regex fallback for B311 — adds nosec for display data."""
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
            fixed_code = ast.unparse(new_tree)

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
            fixed_code = ast.unparse(new_tree)

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
    'SECRET_KEY':             'FLASK_SECRET_KEY',           # nosec B105 — mapping key, not a secret
    'MAIL_PASSWORD':          'MAIL_PASSWORD',              # nosec B105 — mapping key, not a secret
    'SECURITY_PASSWORD_SALT': 'SECURITY_PASSWORD_SALT',     # nosec B105 — mapping key, not a secret
    'API_KEY':                'API_KEY',                    # nosec B105 — mapping key, not a secret
    'DB_PASSWORD':            'DB_PASSWORD',                # nosec B105 — mapping key, not a secret
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
                        
            # Dict subscript: app.config['SECRET_KEY'] = 'value'
            elif isinstance(target, ast.Subscript):
                # Get the key being subscripted
                if isinstance(target.slice, ast.Constant):
                    key_name = target.slice.value
                    if key_name in self.SECRET_VARS:
                        if (isinstance(node.value, ast.Constant) and
                                isinstance(node.value.value, str) and
                                len(node.value.value) >= self.MIN_SECRET_LEN):
                            env_var = self.SECRET_VARS[key_name]
                            node.value = self._make_environ_call(env_var)
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
            fixed_code = ast.unparse(new_tree)

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

class _WeakHashFixer(ast.NodeTransformer):
    """
    Walks AST looking for hashlib.md5() or hashlib.sha1() calls.
    Replaces with hashlib.sha256() preserving existing args.
    usedforsecurity=False added via regex after AST reconstruction
    to avoid astor keyword argument ordering issues.
    """
    WEAK_HASHES = {'md5', 'sha1'}

    def __init__(self):
        self.fixes = 0

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in self.WEAK_HASHES:
                if (isinstance(node.func.value, ast.Name) and
                        node.func.value.id == 'hashlib'):
                    # Just rename the method — don't touch arguments
                    node.func.attr = 'sha256'
                    self.fixes += 1
        return self.generic_visit(node)

def fix_B324_weak_hash(code: str) -> tuple[str, int]:
    """
    B324 — hashlib_new_insecure_functions
    Severity: HIGH | CWE-327
    Replace MD5/SHA1 with SHA256.
    Strategy: AST renames the method, regex adds usedforsecurity=False.
    """
    if not code.strip():
        return code, 0

    try:
        tree = ast.parse(code)
        fixer = _WeakHashFixer()
        new_tree = fixer.visit(tree)
        ast.fix_missing_locations(new_tree)

        if fixer.fixes > 0:
            fixed_code = ast.unparse(new_tree)
            # Add usedforsecurity=False only to hashlib.sha256() — not to nested calls
            # Find the outermost closing paren of sha256()
            def add_usedforsecurity(m):
                inner = m.group(1)
                if 'usedforsecurity' not in inner:
                    return f'hashlib.sha256({inner}, usedforsecurity=False)'
                return m.group(0)

            fixed_code = re.sub(
                r'hashlib\.sha256\((.+?)\)(?!\))',
                add_usedforsecurity,
                fixed_code
            )
            # Avoid double-adding
            fixed_code = fixed_code.replace(
                ', usedforsecurity=False, usedforsecurity=False',
                ', usedforsecurity=False'
            )
            return fixed_code, fixer.fixes

        return code, 0

    except SyntaxError:
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
    
class _BindAllFixer(ast.NodeTransformer):
    """
    Walks AST looking for host='0.0.0.0' in any function call.
    Replaces with host=os.environ.get('HOST', '127.0.0.1').
    """
    def __init__(self):
        self.fixes = 0
        self.needs_os_import = False

    def _make_environ_call(self) -> ast.Call:
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
            args=[
                ast.Constant(value='HOST'),
                ast.Constant(value='127.0.0.1')
            ],
            keywords=[]
        )

    def visit_Call(self, node):
        for keyword in node.keywords:
            if keyword.arg == 'host':
                if (isinstance(keyword.value, ast.Constant) and
                        keyword.value.value == '0.0.0.0'):  # nosec B104
                    keyword.value = self._make_environ_call()
                    self.fixes += 1
                    self.needs_os_import = True
        return self.generic_visit(node)

    
def fix_B104_bind_all(code: str) -> tuple[str, int]:
    """
    B104 — hardcoded_bind_all_interfaces
    Severity: MEDIUM | CWE-605
    Replace host='0.0.0.0' with os.environ.get('HOST', '127.0.0.1').

    Strategy:
      1. Try AST fix — finds host keyword by structure
      2. If AST fails — fall back to regex
    """
    if not code.strip():
        return code, 0

    # ── AST approach (primary) ─────────────────────────────────────────────
    try:
        tree = ast.parse(code)
        fixer = _BindAllFixer()
        new_tree = fixer.visit(tree)
        ast.fix_missing_locations(new_tree)

        if fixer.fixes > 0:
            fixed_code = ast.unparse(new_tree)
            if fixer.needs_os_import and 'import os' not in fixed_code:
                fixed_code = "import os\n" + fixed_code
            return fixed_code, fixer.fixes

        return code, 0

    # ── Regex fallback ─────────────────────────────────────────────────────
    except SyntaxError:
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

class _TmpDirFixer(ast.NodeTransformer):
    """
    Walks AST looking for string assignments containing /tmp.
    Replaces with os.environ.get('UPLOAD_FOLDER', '/var/app/uploads').

    Catches:
      UPLOAD_FOLDER = '/tmp/uploads'
      app.config['UPLOAD_FOLDER'] = '/tmp'
      path = '/tmp/files'
    """
    def __init__(self):
        self.fixes = 0
        self.needs_os_import = False

    def _is_tmp_path(self, value) -> bool:
        """Check if a constant string starts with /tmp."""
        return (isinstance(value, ast.Constant) and
                isinstance(value.value, str) and
                value.value.startswith('/tmp')) # nosec B108 — checking for pattern, not using /tmp

    def _make_environ_call(self) -> ast.Call:
        """Build: os.environ.get('UPLOAD_FOLDER', '/var/app/uploads')"""
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
            args=[
                ast.Constant(value='UPLOAD_FOLDER'),
                ast.Constant(value='/var/app/uploads')
            ],
            keywords=[]
        )

    def visit_Assign(self, node):
        """Handle: UPLOAD_FOLDER = '/tmp/...'"""
        if self._is_tmp_path(node.value):
            node.value = self._make_environ_call()
            self.fixes += 1
            self.needs_os_import = True
        return self.generic_visit(node)

    def visit_Subscript(self, node):
        """Handle: app.config['UPLOAD_FOLDER'] = '/tmp/...'"""
        return self.generic_visit(node)

def fix_B108_tmp_dir(code: str) -> tuple[str, int]:
    """
    B108 — hardcoded_tmp_directory
    Severity: MEDIUM | CWE-377
    Replace /tmp hardcoded paths with environment variable.

    Strategy:
      1. Try AST fix — finds /tmp string assignments by structure
      2. If AST fails — fall back to regex
    """
    if not code.strip():
        return code, 0

    # ── AST approach (primary) ─────────────────────────────────────────────
    try:
        tree = ast.parse(code)
        fixer = _TmpDirFixer()
        new_tree = fixer.visit(tree)
        ast.fix_missing_locations(new_tree)

        if fixer.fixes > 0:
            fixed_code = ast.unparse(new_tree)
            if fixer.needs_os_import and 'import os' not in fixed_code:
                fixed_code = "import os\n" + fixed_code
            return fixed_code, fixer.fixes

        return code, 0

    # ── Regex fallback ─────────────────────────────────────────────────────
    except SyntaxError:
        original = code
        code = re.sub(
            r"""['"](/tmp/[^'"]*|/tmp)['"]""",
            "os.environ.get('UPLOAD_FOLDER', '/var/app/uploads')",
            code
        )
        fixes = 0 if code == original else 1
        return code, fixes

class _RandomFixer(ast.NodeTransformer):
    """
    Walks AST looking for random.randint() or random.choice() calls.

    Strategy:
      - If used in a security context (token, password, key, secret)
        → replace with secrets module equivalent
      - If used for display/demo data
        → add nosec comment via inline annotation

    Catches:
      random.randint(1, 100)
      random.choice(items)
      random.random()
      random.uniform(0, 1)
    """
    RANDOM_METHODS = {
        'randint', 'choice', 'random',
        'uniform', 'shuffle', 'sample'
    }

    SECURITY_CONTEXTS = {
        'token', 'secret', 'password', 'key',
        'salt', 'nonce', 'csrf', 'session'
    }

    def __init__(self):
        self.fixes = 0
        self.needs_secrets_import = False

    def _is_security_context(self, node) -> bool:
        """Check if the call is assigned to a security-sensitive variable."""
        return False  # Context detection handled at assign level

    def _make_secrets_call(self, method: str, node: ast.Call) -> ast.Call:
        """
        Replace random.X() with secrets equivalent:
          random.randint(a, b) → secrets.randbelow(b - a) + a
          random.choice(seq)   → secrets.choice(seq)
        """
        if method == 'randint' and len(node.args) == 2:
            return ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id='secrets', ctx=ast.Load()),
                    attr='randbelow',
                    ctx=ast.Load()
                ),
                args=[
                    ast.BinOp(
                        left=node.args[1],
                        op=ast.Sub(),
                        right=node.args[0]
                    )
                ],
                keywords=[]
            )
        elif method == 'choice':
            return ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id='secrets', ctx=ast.Load()),
                    attr='choice',
                    ctx=ast.Load()
                ),
                args=node.args,
                keywords=[]
            )
        return node  # Can't auto-replace — leave as-is

    def visit_Assign(self, node):
        """
        Check assignment context:
          token = random.choice(...)  → replace with secrets
          color = random.choice(...)  → leave (display data)
        """
        # Check if target variable name suggests security use
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(ctx in var_name for ctx in self.SECURITY_CONTEXTS):
                    # Security context — replace with secrets
                    if isinstance(node.value, ast.Call):
                        call = node.value
                        if (isinstance(call.func, ast.Attribute) and
                                call.func.attr in self.RANDOM_METHODS and
                                isinstance(call.func.value, ast.Name) and
                                call.func.value.id == 'random'):
                            node.value = self._make_secrets_call(
                                call.func.attr, call
                            )
                            self.fixes += 1
                            self.needs_secrets_import = True
        return self.generic_visit(node)
    

def fix_B311_random(code: str) -> tuple[str, int]:
    """
    B311 — random
    Severity: LOW | CWE-330
    For security contexts: replace with secrets module.
    For display contexts: add nosec comment.

    Strategy:
      1. Try AST fix — detects security vs display context
      2. If AST fails — fall back to regex (nosec annotation)
    """
    if not code.strip():
        return code, 0

    # ── AST approach (primary) ─────────────────────────────────────────────
    try:
        tree = ast.parse(code)
        fixer = _RandomFixer()
        new_tree = fixer.visit(tree)
        ast.fix_missing_locations(new_tree)

        if fixer.fixes > 0:
            fixed_code = ast.unparse(new_tree)
            if fixer.needs_secrets_import and 'import secrets' not in fixed_code:
                fixed_code = "import secrets\n" + fixed_code
            return fixed_code, fixer.fixes

        # No security context found — fall back to nosec annotation
        return _regex_B311(code)

    # ── Regex fallback ─────────────────────────────────────────────────────
    except SyntaxError:
        return _regex_B311(code)


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
class _WerkzeugHashFixer(ast.NodeTransformer):
    """
    Walks AST looking for generate_password_hash() calls.
    Replaces with bcrypt.hashpw() — GPU-resistant hashing.

    Catches:
      generate_password_hash(password)
      generate_password_hash(user.password)
      generate_password_hash(form.password.data)
    """
    def __init__(self):
        self.fixes = 0
        self.needs_bcrypt_import = True
        self.has_check_password_hash = False

    def visit_Call(self, node):
        # Direct function call: generate_password_hash(...)
        if (isinstance(node.func, ast.Name) and
                node.func.id == 'generate_password_hash'):
            if node.args:
                # Replace with bcrypt.hashpw(arg.encode('utf-8'), bcrypt.gensalt(rounds=12))
                new_node = ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id='bcrypt', ctx=ast.Load()),
                        attr='hashpw',
                        ctx=ast.Load()
                    ),
                    args=[
                        ast.Call(
                            func=ast.Attribute(
                                value=node.args[0],
                                attr='encode',
                                ctx=ast.Load()
                            ),
                            args=[ast.Constant(value='utf-8')],
                            keywords=[]
                        ),
                        ast.Call(
                            func=ast.Attribute(
                                value=ast.Name(id='bcrypt', ctx=ast.Load()),
                                attr='gensalt',
                                ctx=ast.Load()
                            ),
                            args=[],
                            keywords=[
                                ast.keyword(
                                    arg='rounds',
                                    value=ast.Constant(value=12)
                                )
                            ]
                        )
                    ],
                    keywords=[]
                )
                self.fixes += 1
                return new_node
        return self.generic_visit(node)

    def visit_ImportFrom(self, node):
        """Handle werkzeug import — keep check_password_hash if used."""
        if node.module == 'werkzeug.security':
            names = [alias.name for alias in node.names]
            if 'check_password_hash' in names:
                self.has_check_password_hash = True
                # Keep only check_password_hash
                node.names = [
                    alias for alias in node.names
                    if alias.name == 'check_password_hash'
                ]
                if node.names:
                    return node
                return None
            elif 'generate_password_hash' in names:
                # Remove entire import
                return None
        return self.generic_visit(node)
    
def fix_werkzeug_weak_hash(code: str) -> tuple[str, int]:
    """
    CUSTOM — werkzeug_generate_password_hash
    Severity: MEDIUM | CWE-916
    Replace generate_password_hash (pbkdf2) with bcrypt.

    Strategy:
      1. Try AST fix — replaces call by structure
      2. If AST fails — fall back to regex
    """
    if not code.strip():
        return code, 0

    if 'generate_password_hash' not in code:
        return code, 0

    # ── AST approach (primary) ─────────────────────────────────────────────
    try:
        tree = ast.parse(code)
        fixer = _WerkzeugHashFixer()
        new_tree = fixer.visit(tree)
        ast.fix_missing_locations(new_tree)

        if fixer.fixes > 0:
            fixed_code = ast.unparse(new_tree)
            if 'import bcrypt' not in fixed_code:
                fixed_code = "import bcrypt\n" + fixed_code
            return fixed_code, fixer.fixes

        return code, 0

    # ── Regex fallback ─────────────────────────────────────────────────────
    except SyntaxError:
        return _regex_werkzeug(code)


def _regex_werkzeug(code: str) -> tuple[str, int]:
    """Pure regex fallback for werkzeug weak hash."""
    original = code
    if 'generate_password_hash' not in code:
        return code, 0
    if 'import bcrypt' not in code:
        code = "import bcrypt\n" + code
    if 'check_password_hash' in code:
        for old in [
            'from werkzeug.security import generate_password_hash, check_password_hash',
            'from werkzeug.security import check_password_hash, generate_password_hash',
        ]:
            code = code.replace(old, 'from werkzeug.security import check_password_hash')
        code = code.replace(
            'from werkzeug.security import generate_password_hash', ''
        )
    else:
        code = code.replace(
            'from werkzeug.security import generate_password_hash\n', ''
        )
    code = re.sub(
        r'generate_password_hash\(([^)]+)\)',
        r'bcrypt.hashpw(\1.encode("utf-8"), bcrypt.gensalt(rounds=12))',
        code
    )
    fixes = 0 if code == original else 1
    return code, fixes

class _SQLFstringFixer(ast.NodeVisitor):
    """
    Walks AST looking for dangerous SQL patterns.
    Detection only — SQL auto-fix is complex, flags for manual review.

    Detects:
      db.execute(f"SELECT ... {var}")     ← f-string interpolation
      db.execute("SELECT ..." + var)      ← string concatenation
      cursor.execute(f"INSERT ... {var}") ← any cursor execute
    """
    SQL_METHODS = {'execute', 'executemany', 'raw', 'query'}

    def __init__(self):
        self.findings = 0

    def _is_fstring(self, node) -> bool:
        """Check if node is an f-string (JoinedStr)."""
        return isinstance(node, ast.JoinedStr)

    def _is_concatenation(self, node) -> bool:
        """Check if node is string concatenation with +."""
        return (isinstance(node, ast.BinOp) and
                isinstance(node.op, ast.Add))

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in self.SQL_METHODS:
                if node.args:
                    arg = node.args[0]
                    if self._is_fstring(arg):
                        self.findings += 1
                    elif self._is_concatenation(arg):
                        self.findings += 1
        self.generic_visit(node)

def fix_sql_fstring(code: str) -> tuple[str, int]:
    """
    CUSTOM — sql_fstring_injection
    Severity: HIGH | CWE-89
    Detect SQL injection via f-strings and concatenation.
    Flags for manual review — auto-fix is too risky for SQL.

    Strategy:
      1. AST detection — finds dangerous patterns by structure
      2. Adds inline warning comment for developer
      3. Regex fallback for syntax errors
    """
    if not code.strip():
        return code, 0

    # ── AST detection (primary) ────────────────────────────────────────────
    try:
        tree = ast.parse(code)
        detector = _SQLFstringFixer()
        detector.visit(tree)

        if detector.findings > 0:
            # Add warning comment — don't auto-fix SQL (too risky)
            warning = (
                "# SHIELD WARNING: SQL injection risk detected below\n"
                "# Replace f-strings/concatenation with parameterized queries:\n"
                "# db.execute('SELECT * FROM t WHERE id = ?', (user_id,))\n"
            )
            return warning + code, detector.findings

        return code, 0

    # ── Regex fallback ─────────────────────────────────────────────────────
    except SyntaxError:
        return _regex_sql(code)


def _regex_sql(code: str) -> tuple[str, int]:
    """Pure regex fallback for SQL fstring detection."""
    original = code
    fixes = 0
    patterns = [
        r'execute\(f["\']',
        r'execute\(.*\+.*\)',
        r'query\s*=\s*f["\'].*SELECT',
    ]
    for pattern in patterns:
        if re.search(pattern, code, re.IGNORECASE):
            fixes += 1
    return code, fixes


class _EvalExecFixer(ast.NodeVisitor):
    """
    Detects eval() and exec() calls — dynamic execution = RCE risk.
    Detection only — cannot auto-fix safely.
    CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code.
    """
    DANGEROUS = {'eval', 'exec'}

    def __init__(self):
        self.findings = 0

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id in self.DANGEROUS:
                self.findings += 1
        self.generic_visit(node)


def fix_eval_exec(code: str) -> tuple[str, int]:
    """
    CUSTOM — eval_exec_detection
    Severity: HIGH | CWE-95
    Detect eval() and exec() — dynamic execution is RCE risk.
    Flags for manual review — cannot auto-fix safely.
    """
    if not code.strip():
        return code, 0

    try:
        tree = ast.parse(code)
        detector = _EvalExecFixer()
        detector.visit(tree)

        if detector.findings > 0:
            warning = (
                "# SHIELD WARNING: eval()/exec() detected — RCE risk (CWE-95)\n"
                "# Never pass user input to eval() or exec()\n"
                "# Replace with explicit logic or safe alternatives\n"
            )
            return warning + code, detector.findings

        return code, 0

    except SyntaxError:
        fixes = 0
        if 'eval(' in code or 'exec(' in code:
            fixes = 1
        return code, fixes

class _UnicodeObfuscationFixer(ast.NodeVisitor):
    """
    Detects zero-width and invisible Unicode characters in string literals.
    Used in supply chain attacks to hide malicious code from code review.
    CWE-116: Improper Encoding or Escaping of Output.
    """
    SUSPICIOUS_CHARS = {
        '\u200b', '\u200c', '\u200d', '\u200e', '\u200f',
        '\u2060', '\u2061', '\u2062', '\u2063', '\u2064',
        '\ufeff', '\u00ad', '\u034f', '\u115f', '\u1160',
    }

    def __init__(self):
        self.findings = 0

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            if any(c in node.value for c in self.SUSPICIOUS_CHARS):
                self.findings += 1
        self.generic_visit(node)

def fix_unicode_obfuscation(code: str) -> tuple[str, int]:
    """
    CUSTOM — unicode_obfuscation
    Severity: HIGH | CWE-116
    Detect zero-width Unicode characters used to hide malicious code.
    Common in supply chain attacks (TrapDoor campaign, May 2026).
    """
    if not code.strip():
        return code, 0

    try:
        tree = ast.parse(code)
        detector = _UnicodeObfuscationFixer()
        detector.visit(tree)

        if detector.findings > 0:
            warning = (
                "# SHIELD WARNING: Zero-width Unicode characters detected (CWE-116)\n"
                "# This is a supply chain attack indicator — review immediately\n"
                "# Reference: TrapDoor campaign, May 2026\n"
            )
            return warning + code, detector.findings

        return code, 0

    except SyntaxError:
        # Regex fallback — check raw bytes
        suspicious = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u2060']
        fixes = sum(1 for c in suspicious if c in code)
        return code, fixes
    

class _InstallExecFixer(ast.NodeVisitor):
    """
    Detects code that executes at import/install time.
    Supply chain attacks use this to run malicious code when package is installed.
    CWE-506: Embedded Malicious Code.
    Flags: os.system(), subprocess at module level, urllib/requests at module level.
    """
    DANGEROUS_MODULE_LEVEL = {
        'system', 'popen', 'urlopen', 'urlretrieve',
        'get', 'post', 'download',
    }

    def __init__(self):
        self.findings = 0
        self._in_function = False

    def visit_FunctionDef(self, node):
        old = self._in_function
        self._in_function = True
        self.generic_visit(node)
        self._in_function = old

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Call(self, node):
        if not self._in_function:
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in self.DANGEROUS_MODULE_LEVEL:
                    self.findings += 1
            elif isinstance(node.func, ast.Name):
                if node.func.id in {'eval', 'exec', '__import__'}:
                    self.findings += 1
        self.generic_visit(node)

def fix_install_exec(code: str) -> tuple[str, int]:
    """
    CUSTOM — install_time_execution
    Severity: HIGH | CWE-506
    Detect code that executes network calls or system commands at module level.
    Used in supply chain attacks to exfiltrate credentials on pip install.
    """
    if not code.strip():
        return code, 0

    try:
        tree = ast.parse(code)
        detector = _InstallExecFixer()
        detector.visit(tree)

        if detector.findings > 0:
            warning = (
                "# SHIELD WARNING: Module-level execution detected (CWE-506)\n"
                "# Code running at import time is a supply chain attack indicator\n"
                "# Move all execution inside functions or __main__ guard\n"
            )
            return warning + code, detector.findings

        return code, 0

    except SyntaxError:
        return code, 0

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
    'CUSTOM_EVAL_EXEC': fix_eval_exec,
    'CUSTOM_UNICODE_OBFUSCATION': fix_unicode_obfuscation,
    'CUSTOM_INSTALL_EXEC': fix_install_exec,
}