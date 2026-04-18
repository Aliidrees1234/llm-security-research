"""
SHIELD FRAMEWORK — LAYER 2: GRASP DAG
======================================
Graph-based Reasoning for Assured Secure Programming.

Analyzes a developer's code generation request and automatically
injects the relevant SCP (Secure Coding Practice) constraints
from the DAG into the prompt before sending to the LLM.

This implements Layer 2 on top of Layer 1 (SPT).

Usage:
    from shield_layer2 import GRASPEngine
    
    engine = GRASPEngine()
    
    raw_prompt = "Write a Flask login endpoint with SQLite"
    secured_prompt = engine.build_secured_prompt(raw_prompt)
    # Now send secured_prompt to the LLM
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional

# ── SCP NODE DEFINITION ───────────────────────────────────────────────────────

@dataclass
class SCPNode:
    """
    Secure Coding Practice node in the GRASP DAG.
    Each node is triggered by keywords in the prompt.
    """
    node_id:     str
    name:        str
    triggers:    list[str]           # keywords that activate this node
    constraint:  str                 # the security rule to inject
    cwe_ids:     list[str]           # CWEs this node prevents
    examples:    list[str]           # code examples of the fix
    depends_on:  list[str] = field(default_factory=list)  # other SCP IDs that must also apply


# ── GRASP DAG — EIGHT NODES ───────────────────────────────────────────────────

GRASP_DAG: list[SCPNode] = [

    SCPNode(
        node_id    = "SCP-01",
        name       = "Debug Mode Check",
        triggers   = [
            "flask", "app.run", "debug", "development", "werkzeug",
            "flask app", "web app", "web application",
        ],
        constraint = (
            "MANDATORY: Set debug=False in app.run(). "
            "Bind only to 127.0.0.1 unless explicitly deploying for public access. "
            "Use: app.run(debug=False, host='127.0.0.1', port=int(os.environ.get('PORT', 5000)))"
        ),
        cwe_ids  = ["CWE-94"],
        examples = [
            "# WRONG:  app.run(debug=True)",
            "# CORRECT: app.run(debug=False, host='127.0.0.1', port=int(os.environ.get('PORT',5000)))",
        ]
    ),

    SCPNode(
        node_id    = "SCP-02",
        name       = "Secret Key Validation",
        triggers   = [
            "secret", "key", "jwt", "token", "session", "cookie",
            "authentication", "auth", "login", "password", "credential",
        ],
        constraint = (
            "MANDATORY: Load ALL secrets from environment variables. "
            "Use: os.environ.get('FLASK_SECRET_KEY') — NEVER hardcode. "
            "Use: os.environ.get('JWT_SECRET') — NEVER hardcode. "
            "Validate at startup: if not secret_key: raise RuntimeError('...')"
        ),
        cwe_ids  = ["CWE-259", "CWE-798"],
        examples = [
            "# WRONG:  app.secret_key = 'mysecret'",
            "# CORRECT: app.secret_key = os.environ.get('FLASK_SECRET_KEY')",
            "# WRONG:  JWT_SECRET = 'hardcoded'",
            "# CORRECT: JWT_SECRET = os.environ.get('JWT_SECRET')",
        ]
    ),

    SCPNode(
        node_id    = "SCP-03",
        name       = "File Path Boundary Check",
        triggers   = [
            "file", "upload", "download", "read", "path", "directory",
            "folder", "send_file", "open(", "serve", "static",
        ],
        constraint = (
            "MANDATORY: Validate ALL file paths before access. "
            "Use realpath + startswith boundary check: "
            "real = os.path.realpath(os.path.join(BASE_DIR, user_input)); "
            "if not real.startswith(BASE_DIR): abort(403). "
            "For Node.js: resolved = path.resolve(BASE_DIR, filename); "
            "if (!resolved.startsWith(BASE_DIR + path.sep)) return res.status(403)..."
        ),
        cwe_ids  = ["CWE-22", "CWE-23"],
        examples = [
            "# WRONG:  open(request.args.get('path'))",
            "# CORRECT: real = os.path.realpath(os.path.join(BASE_DIR, user_path))",
            "#          if not real.startswith(BASE_DIR + os.sep): abort(403)",
        ]
    ),

    SCPNode(
        node_id    = "SCP-04",
        name       = "SQL Parameterization",
        triggers   = [
            "sql", "database", "db", "sqlite", "postgres", "mysql",
            "query", "select", "insert", "update", "delete", "search",
            "filter", "where",
        ],
        constraint = (
            "MANDATORY: Use parameterized queries for ALL database operations. "
            "NEVER use string concatenation or f-strings in SQL. "
            "Python: db.execute('SELECT * FROM users WHERE id = ?', (user_id,)) "
            "Node.js: db.query('SELECT * FROM users WHERE id = $1', [userId])"
        ),
        cwe_ids  = ["CWE-89"],
        examples = [
            "# WRONG:  db.execute(f'SELECT * FROM users WHERE name = {name}')",
            "# CORRECT: db.execute('SELECT * FROM users WHERE name = ?', (name,))",
        ]
    ),

    SCPNode(
        node_id    = "SCP-05",
        name       = "Shell Execution Check",
        triggers   = [
            "shell", "command", "subprocess", "exec", "run", "system",
            "bash", "cmd", "terminal", "process", "os.system",
        ],
        constraint = (
            "MANDATORY: NEVER use shell=True. NEVER pass user input to subprocess. "
            "Use a command whitelist: ALLOWED = {'status': ['/usr/bin/uptime']}. "
            "Validate key against whitelist BEFORE execution. "
            "Use: subprocess.run(ALLOWED[key], shell=False, capture_output=True)"
        ),
        cwe_ids  = ["CWE-78"],
        examples = [
            "# WRONG:  subprocess.run(user_input, shell=True)",
            "# CORRECT: ALLOWED = {'status': ['/usr/bin/uptime']}",
            "#          if cmd_key not in ALLOWED: abort(403)",
            "#          subprocess.run(ALLOWED[cmd_key], shell=False)",
        ]
    ),

    SCPNode(
        node_id    = "SCP-06",
        name       = "Output Encoding Check",
        triggers   = [
            "html", "render", "template", "display", "output", "response",
            "user input", "form", "comment", "message", "chat", "greet",
        ],
        constraint = (
            "MANDATORY: Escape ALL user-derived data before rendering in HTML. "
            "Python/Flask: use markupsafe.escape() or Jinja2 auto-escaping ({{ var }} not {{ var|safe }}). "
            "Node.js: use res.render() with a template engine, NEVER res.send(`<h1>${userInput}</h1>`). "
            "Use he.encode() or DOMPurify for client-side rendering."
        ),
        cwe_ids  = ["CWE-79"],
        examples = [
            "# WRONG (Node):  res.send(`<h1>Hello ${name}</h1>`)",
            "# CORRECT (Node): res.render('greet', { name: he.encode(name) })",
            "# WRONG (Python): return f'<p>{comment}</p>'",
            "# CORRECT (Python): return render_template('index.html', comment=comment)  # auto-escaped",
        ]
    ),

    SCPNode(
        node_id    = "SCP-07",
        name       = "Cryptographic Strength",
        triggers   = [
            "password", "hash", "bcrypt", "argon", "md5", "sha", "crypto",
            "encrypt", "random", "token", "salt", "hashing",
        ],
        constraint = (
            "MANDATORY: Use bcrypt or Argon2 for password hashing — NEVER MD5, SHA1, or SHA256 for passwords. "
            "Python: bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)) "
            "Node.js: await bcrypt.hash(password, 12) "
            "For random tokens: use secrets.token_urlsafe(32) in Python, crypto.randomBytes(32) in Node.js. "
            "NEVER use random.random() or Math.random() for security."
        ),
        cwe_ids  = ["CWE-327", "CWE-330", "CWE-916"],
        examples = [
            "# WRONG:  hashlib.md5(password.encode()).hexdigest()",
            "# CORRECT: bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))",
            "# WRONG:  token = str(random.random())",
            "# CORRECT: token = secrets.token_urlsafe(32)",
        ]
    ),

    SCPNode(
        node_id    = "SCP-08",
        name       = "Input Validation",
        triggers   = [
            "input", "form", "request", "user", "param", "query",
            "body", "data", "validate", "sanitize", "register", "login",
        ],
        constraint = (
            "MANDATORY: Validate ALL user input before processing. "
            "Enforce: type checking, length limits (username <= 64, password <= 128), "
            "charset whitelisting (regex for usernames), and required-field checks. "
            "Return 400 with a generic error on invalid input — NEVER echo raw input back. "
            "NEVER expose stack traces or internal errors to users."
        ),
        cwe_ids  = ["CWE-20", "CWE-209"],
        examples = [
            "# WRONG:  username = request.form.get('username')  # no validation",
            "# CORRECT: username = request.form.get('username', '').strip()",
            "#          if not USERNAME_RE.match(username): return jsonify({'error': 'Invalid input'}), 400",
        ]
    ),
]


# ── DAG ENGINE ────────────────────────────────────────────────────────────────

class GRASPEngine:
    """
    GRASP DAG Engine — analyzes prompts and injects relevant SCP constraints.
    
    This is the SHIELD Layer 2 implementation.
    Layer 1 SPT provides the base 9 rules always.
    Layer 2 GRASP adds task-specific additional constraints.
    """
    
    # SHIELD Layer 1 SPT — always applied (baseline)
    LAYER1_SPT = """
SECURITY PROMPT TEMPLATE (SHIELD Layer 1 — Mandatory):
You are generating code for a PRODUCTION web application.
Security is NON-NEGOTIABLE. Apply ALL rules below:

[ ] NEVER set debug=True — always use debug=False
[ ] NEVER hardcode passwords, secret keys, or API tokens — use os.environ.get()
[ ] ALWAYS use parameterized queries — never string concatenation for SQL
[ ] ALWAYS validate file paths: use os.path.realpath() + startsWith() boundary check
[ ] NEVER use shell=True in subprocess calls — use whitelist approach
[ ] Use secrets module NOT random for security-sensitive values
[ ] Use bcrypt or Argon2 for password hashing — NEVER MD5 or SHA1
[ ] ALWAYS escape user input before rendering in HTML responses
[ ] NEVER expose stack traces or debug info to end users
""".strip()
    
    def __init__(self):
        self._dag = {node.node_id: node for node in GRASP_DAG}
    
    def identify_triggered_nodes(self, prompt: str) -> list[SCPNode]:
        """Scan prompt and return all triggered SCP nodes."""
        prompt_lower = prompt.lower()
        triggered = []
        triggered_ids = set()
        
        for node in GRASP_DAG:
            for trigger in node.triggers:
                if trigger.lower() in prompt_lower:
                    if node.node_id not in triggered_ids:
                        triggered.append(node)
                        triggered_ids.add(node.node_id)
                    break
        
        # Resolve dependencies — add required nodes not yet triggered
        to_add = []
        for node in triggered:
            for dep_id in node.depends_on:
                if dep_id not in triggered_ids and dep_id in self._dag:
                    to_add.append(self._dag[dep_id])
                    triggered_ids.add(dep_id)
        triggered.extend(to_add)
        
        return triggered
    
    def build_secured_prompt(self, raw_prompt: str,
                             include_examples: bool = True) -> str:
        """
        Build a Layer 1 + Layer 2 secured prompt from raw developer request.
        Returns the full secured prompt ready to send to the LLM.
        """
        triggered = self.identify_triggered_nodes(raw_prompt)
        
        lines = [self.LAYER1_SPT, ""]
        
        if triggered:
            lines.append("GRASP LAYER 2 — Task-Specific Security Constraints:")
            lines.append(f"(Triggered nodes: {', '.join(n.node_id for n in triggered)})")
            lines.append("")
            
            for node in triggered:
                lines.append(f"[{node.node_id}: {node.name}]")
                lines.append(node.constraint)
                if include_examples and node.examples:
                    lines.extend(node.examples)
                lines.append(f"Prevents: {', '.join(node.cwe_ids)}")
                lines.append("")
        
        lines.append("TASK:")
        lines.append(raw_prompt)
        
        return "\n".join(lines)
    
    def explain_triggered_nodes(self, prompt: str) -> str:
        """Human-readable explanation of which nodes were triggered and why."""
        triggered = self.identify_triggered_nodes(prompt)
        if not triggered:
            return "No specific GRASP nodes triggered (Layer 1 SPT still applies)."
        
        lines = [f"Triggered {len(triggered)} GRASP node(s):"]
        for node in triggered:
            matching = [t for t in node.triggers if t.lower() in prompt.lower()]
            lines.append(f"  {node.node_id} ({node.name}) — matched: {matching[:3]}")
        return "\n".join(lines)


# ── CLI TEST ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    engine = GRASPEngine()
    
    test_prompts = [
        "Write a Flask login endpoint with SQLite database",
        "Create a file download endpoint in Node.js Express",
        "Build a user registration system with password hashing",
        "Write a Flask endpoint that runs a shell command",
        "Create a comment system with HTML display",
    ]
    
    print("SHIELD LAYER 2 — GRASP DAG ENGINE TEST")
    print("=" * 60)
    
    for prompt in test_prompts:
        print(f"\nPrompt: '{prompt}'")
        print(engine.explain_triggered_nodes(prompt))
        print("-" * 40)
        secured = engine.build_secured_prompt(prompt, include_examples=False)
        # Print just the GRASP section, not full SPT
        grasp_section = secured.split("GRASP LAYER 2")
        if len(grasp_section) > 1:
            task_end = grasp_section[1].find("TASK:")
            print("GRASP constraints injected:")
            print(grasp_section[1][:task_end].strip()[:300])
