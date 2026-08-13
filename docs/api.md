# SHIELD Developer API

Use SHIELD programmatically in your own Python projects.

## Scanner

```python
from shield.layer3_fdsp import fdsp_loop

results = fdsp_loop(
    corpus_dir="./my_project",
    output_dir="./fixed",
    max_k=3,
    inplace=False
)

print(results['summary']['final_high'])    # High findings remaining
print(results['summary']['final_I100L'])   # I/100L score
print(results['total_fixes'])              # Rules applied
```

## Reporter

```python
from shield.reporter import (
    ScanResult, Finding,
    generate_report,
    save_json_report,
    generate_comparison_report
)

# Create a scan result
result = ScanResult("./my_project", loc=500)
result.add_finding(Finding(
    rule_id="B201",
    severity="HIGH",
    cwe="94",
    message="debug=True detected",
    filename="app.py",
    line=46,
    code="app.run(debug=True)"
))

# Generate HTML report
generate_report(result, "report.html")

# Save JSON
save_json_report(result, "report.json")

# Security grade
print(result.grade)   # A+, A, B, C, D, F
print(result.i100l)   # vulnerability density
```

## Prompt Builder

```python
from shield.layer2_grasp import GRASPEngine

engine = GRASPEngine()
secured_prompt = engine.build_secured_prompt(
    "Write a Flask login endpoint with SQLite"
)
# Send secured_prompt to your LLM instead of the raw task
```

## Runtime Monitor (Flask integration)

```python
from flask import Flask
from shield.layer5_runtime import ShieldMiddleware, CanaryManager

app = Flask(__name__)

# WAF + prompt injection blocking
shield = ShieldMiddleware(app, block_injections=True)

# Canary documents for RAG poisoning detection
canary = CanaryManager()
doc = canary.generate_document("Q4 Financial Report")
# Insert doc into your knowledge base

# Later — check LLM responses
triggered, details = canary.is_triggered(llm_response)
if triggered:
    alert_security_team()
```

## Individual Rules

```python
from shield.rules.custom_rules import (
    fix_B201_debug_true,
    fix_B602_shell_true,
    fix_B105_B106_hardcoded,
    fix_B324_weak_hash,
    REMEDIATION_MAP
)

code = "app.run(debug=True)"
fixed, count = fix_B201_debug_true(code)
print(fixed)   # app.run(debug=False, ...)
print(count)   # 1

# Apply all rules at once
from shield.layer3_fdsp import apply_all_fixes
fixed_code, summary = apply_all_fixes(code)
```