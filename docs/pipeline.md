# SHIELD Pipeline — How It Works

## The Complete Flow
Developer writes a task description
↓
shield secure "Write a Flask login endpoint" --claude
↓
Layer 2 (GRASP) builds a secured prompt

Detects relevant SCP nodes from task keywords
Injects mandatory security constraints
Copies to clipboard automatically
↓
Developer pastes into LLM (Claude/ChatGPT/Gemini)
↓
LLM generates code with security constraints applied
↓
Developer saves code to file: output.py
↓
shield fix ./output.py --output ./fixed --report report.html
↓
Layer 3 (FDSP) scans and fixes automatically
K=0: Baseline scan — record all findings
K=1: Apply all fix functions — rescan
K=2: Apply remaining fixes — rescan
K=3: Final attempt — rescan
↓
Post-fix syntax validation (ast.parse)
Pass → write fixed file
Fail → mark UNFIXABLE, flag for manual review
↓
HTML report generated — grade, I/100L, findings, recommendations
↓
Layer 4 (CI/CD Gate) blocks deployment if High findings remain

## Layer 2 — GRASP DAG

GRASP (Guided Remediation and Security Prompting) analyzes
your task description and activates relevant SCP nodes:

| Keyword detected | SCP node activated |
|-----------------|-------------------|
| flask, django | SCP-01 (debug mode) |
| secret, key, token | SCP-02 (secret key) |
| sqlite, mysql, db | SCP-04 (SQL parameterization) |
| upload, file, path | SCP-03 (path validation) |
| user, input, form | SCP-08 (input validation) |
| password, hash, bcrypt | SCP-05 (password hashing) |
| subprocess, shell, cmd | SCP-06 (command injection) |
| random, token, session | SCP-07 (secure random) |

## Layer 3 — FDSP Engine

FDSP (Feedback-Driven Security Patching) applies fixes
using a hybrid AST + regex approach:

For each file:

1- Parse with ast.parse()
2- Apply AST fixer (robust — handles all formatting)
3- If SyntaxError → fall back to regex
4- If both fail → mark UNFIXABLE
5- Validate fixed code with ast.parse()
6- Write only if validation passes

## Cost Per Fix

Both AST and Regex layers run entirely locally.
Zero API calls. Zero token cost. Unlimited volume.

**CPMF = $0.00** — a structural advantage over
LLM-dependent remediation approaches.