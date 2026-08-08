"""
SHIELD Security — Report Generator
====================================
Generates HTML scan reports from Bandit and Semgrep results.

Usage:
  from shield.reporter import generate_report
  generate_report(findings, output_path="shield_report.html")

Author: Ali Yasin Idrees
Version: 1.0.0
"""

import json
from datetime import datetime
from pathlib import Path
from unittest import result


# ── DATA STRUCTURES ───────────────────────────────────────────────────────────

class Finding:
    """Represents a single security finding."""

    def __init__(self, rule_id: str, severity: str, cwe: str,
                 message: str, filename: str, line: int,
                 code: str = "", source: str = "bandit"):
        self.rule_id  = rule_id
        self.severity = severity.upper()
        self.cwe      = cwe
        self.message  = message
        self.filename = filename
        self.line     = line
        self.code     = code
        self.source   = source

    def to_dict(self) -> dict:
        return {
            "rule_id":  self.rule_id,
            "severity": self.severity,
            "cwe":      self.cwe,
            "message":  self.message,
            "filename": self.filename,
            "line":     self.line,
            "code":     self.code,
            "source":   self.source,
        }


class ScanResult:
    """Complete scan result for one corpus."""

    def __init__(self, corpus_path: str, loc: int = 0):
        self.corpus_path = corpus_path
        self.loc         = loc
        self.findings:   list[Finding] = []
        self.timestamp   = datetime.now().isoformat()
        self.languages   = []

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    @property
    def high(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "HIGH"]

    @property
    def medium(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "MEDIUM"]

    @property
    def low(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "LOW"]

    @property
    def i100l(self) -> float:
        if self.loc == 0:
            return 0.0
        return round(len(self.findings) / self.loc * 100, 2)

    @property
    def grade(self) -> str:
        """Security grade based on I/100L and High findings."""
        if len(self.high) > 0:
            return "F"
        if self.i100l == 0:
            return "A+"
        if self.i100l < 1.0:
            return "A"
        if self.i100l < 2.0:
            return "B"
        if self.i100l < 4.0:
            return "C"
        if self.i100l < 6.0:
            return "D"
        return "F"

    @property
    def grade_color(self) -> str:
        colors = {
            "A+": "#1B5E20", "A": "#2E7D32",
            "B": "#F57F17", "C": "#E65100",
            "D": "#B71C1C", "F": "#7B1FA2"
        }
        return colors.get(self.grade, "#000000")


# ── RECOMMENDATION MAP ────────────────────────────────────────────────────────

RECOMMENDATIONS = {
    "B201": "Replace app.run(debug=True) with app.run(debug=False). "
            "Never expose the Werkzeug debugger in production.",
    "B602": "Replace shell=True with shell=False. "
            "Use a command whitelist to prevent OS command injection.",
    "B105": "Replace hardcoded secrets with os.environ.get('VAR_NAME'). "
            "Store all credentials in environment variables.",
    "B106": "Replace hardcoded passwords with os.environ.get('VAR_NAME').",
    "B324": "Replace hashlib.md5/sha1 with hashlib.sha256(usedforsecurity=False) "
            "for non-security use, or bcrypt/Argon2 for passwords.",
    "B104": "Replace host='0.0.0.0' with os.environ.get('HOST', '127.0.0.1'). "
            "Binding to all interfaces exposes the app externally.",
    "B108": "Replace /tmp hardcoded path with os.environ.get('UPLOAD_FOLDER'). "
            "Never use /tmp as a default upload directory.",
    "B311": "Replace random with the secrets module for security-sensitive values. "
            "random is not cryptographically secure.",
    "B101": "Assert statements are removed in optimized Python (-O flag). "
            "Use proper error handling instead.",
    "B404": "Review subprocess usage — ensure commands are hardcoded, "
            "not derived from user input.",
    "B603": "Ensure subprocess input is hardcoded or whitelisted, "
            "never passed from user-controlled data.",
    "CUSTOM_WERKZEUG": "Replace generate_password_hash (pbkdf2) with bcrypt. "
                       "pbkdf2 is vulnerable to GPU-accelerated cracking.",
    "CUSTOM_SQL_FSTRING": "Replace f-string SQL with parameterized queries: "
                          "db.execute('SELECT * FROM t WHERE id = ?', (user_id,))",
}


# ── HTML TEMPLATE ─────────────────────────────────────────────────────────────

def _severity_color(severity: str) -> str:
    return {
        "HIGH":   "#B71C1C",
        "MEDIUM": "#E65100",
        "LOW":    "#F57F17",
    }.get(severity.upper(), "#000000")


def _severity_bg(severity: str) -> str:
    return {
        "HIGH":   "#FFEBEE",
        "MEDIUM": "#FFF3E0",
        "LOW":    "#FFFDE7",
    }.get(severity.upper(), "#FFFFFF")


def _build_finding_html(finding: Finding, index: int) -> str:
    color   = _severity_color(finding.severity)
    bg      = _severity_bg(finding.severity)
    rec     = RECOMMENDATIONS.get(finding.rule_id, "Review and fix manually.")
    code_html = f"<pre>{finding.code.strip()}</pre>" if finding.code else ""

    return f"""
    <div class="finding" style="border-left: 4px solid {color}; background: {bg};">
        <div class="finding-header">
            <span class="badge" style="background:{color};">{finding.severity}</span>
            <span class="rule-id">[{finding.rule_id}]</span>
            <span class="message">{finding.message}</span>
        </div>
        <div class="finding-meta">
            <span>📄 {finding.filename}</span>
            <span>📍 Line {finding.line}</span>
            <span>🔗 CWE-{finding.cwe}</span>
            <span>🔧 {finding.source.upper()}</span>
        </div>
        {code_html}
        <div class="recommendation">
            💡 <strong>Recommendation:</strong> {rec}
        </div>
    </div>
    """


def _build_html(result: ScanResult) -> str:
    """Build the complete HTML report."""

    # Build findings HTML
    findings_html = ""
    for i, finding in enumerate(
        sorted(result.findings,
               key=lambda f: ["HIGH","MEDIUM","LOW"].index(f.severity)
               if f.severity in ["HIGH","MEDIUM","LOW"] else 3)
    ):
        findings_html += _build_finding_html(finding, i)

    if not findings_html:
        findings_html = """
        <div style="text-align:center; padding:60px; color:#2E7D32;">
            <h2>✅ Zero Findings</h2>
            <p>No security issues detected in this scan.</p>
        </div>
        """

    grade_color = result.grade_color

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SHIELD Security Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #F5F5F5;
            color: #1A1A1A;
            line-height: 1.6;
        }}
        .header {{
            background: #0D0D0D;
            color: white;
            padding: 32px 48px;
            border-bottom: 4px solid #444;
        }}
        .header h1 {{
            font-size: 28px;
            letter-spacing: 2px;
            text-transform: uppercase;
        }}
        .header p {{
            color: #999;
            margin-top: 4px;
            font-size: 14px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px;
            padding: 32px 48px;
            background: white;
            border-bottom: 1px solid #E0E0E0;
        }}
        .stat-card {{
            background: #F9F9F9;
            border: 1px solid #E0E0E0;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .stat-number {{
            font-size: 36px;
            font-weight: bold;
            line-height: 1;
        }}
        .stat-label {{
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
            margin-top: 4px;
        }}
        .grade-card {{
            background: #0D0D0D;
            color: white;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .grade-number {{
            font-size: 48px;
            font-weight: bold;
            color: {grade_color};
        }}
        .findings-section {{
            padding: 32px 48px;
        }}
        .findings-section h2 {{
            font-size: 20px;
            margin-bottom: 20px;
            padding-bottom: 8px;
            border-bottom: 2px solid #E0E0E0;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .finding {{
            margin-bottom: 16px;
            border-radius: 6px;
            padding: 16px 20px;
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 8px;
        }}
        .badge {{
            color: white;
            padding: 2px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .rule-id {{
            font-weight: bold;
            font-family: monospace;
            font-size: 13px;
        }}
        .message {{
            font-size: 14px;
            flex: 1;
        }}
        .finding-meta {{
            display: flex;
            gap: 20px;
            font-size: 12px;
            color: #555;
            margin-bottom: 8px;
        }}
        pre {{
            background: #1A1A1A;
            color: #E0E0E0;
            padding: 12px;
            border-radius: 4px;
            font-size: 12px;
            overflow-x: auto;
            margin: 8px 0;
        }}
        .recommendation {{
            font-size: 13px;
            color: #333;
            margin-top: 8px;
            padding-top: 8px;
            border-top: 1px solid rgba(0,0,0,0.1);
        }}
        .footer {{
            text-align: center;
            padding: 24px;
            color: #999;
            font-size: 12px;
            border-top: 1px solid #E0E0E0;
            background: white;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>⚡ SHIELD Security Report</h1>
        <p>
            {result.corpus_path} &nbsp;·&nbsp;
            {datetime.now().strftime('%B %d, %Y at %H:%M')} &nbsp;·&nbsp;
            Ali Yasin Idrees
        </p>
    </div>

    <div class="summary">
        <div class="grade-card">
            <div class="grade-number">{result.grade}</div>
            <div class="stat-label" style="color:#999;">Security Grade</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" style="color:#B71C1C;">{len(result.high)}</div>
            <div class="stat-label">High Severity</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" style="color:#E65100;">{len(result.medium)}</div>
            <div class="stat-label">Medium Severity</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" style="color:#F57F17;">{len(result.low)}</div>
            <div class="stat-label">Low Severity</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{result.loc}</div>
            <div class="stat-label">Lines of Code</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{result.i100l}</div>
            <div class="stat-label">I/100L Score</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{len(result.findings)}</div>
            <div class="stat-label">Total Findings</div>
        </div>
    </div>

    <div class="findings-section">
        <h2>Findings ({len(result.findings)})</h2>
        {findings_html}
    </div>

    <div class="footer">
        Generated by SHIELD Security v0.3.0 &nbsp;·&nbsp;
        Ali Yasin Idrees &nbsp;·&nbsp;
        github.com/Aliidrees1234/llm-security-research
    </div>
</body>
</html>"""


# ── PUBLIC API ────────────────────────────────────────────────────────────────

def generate_report(result: ScanResult, output_path: str = "shield_report.html") -> str:
    """
    Generate HTML report from scan result.
    Returns the output path.
    """
    html = _build_html(result)
    Path(output_path).write_text(html, encoding='utf-8')
    return output_path


def parse_bandit_to_result(bandit_json: dict,
                           corpus_path: str,
                           loc: int = 0) -> ScanResult:
    """
    Parse Bandit JSON output into a ScanResult.
    """
    result = ScanResult(corpus_path, loc)

    for issue in bandit_json.get('results', []):
        finding = Finding(
            rule_id  = issue.get('test_id', 'UNKNOWN'),
            severity = issue.get('issue_severity', 'LOW'),
            cwe      = str(issue.get('issue_cwe', {}).get('id', 'N/A')),
            message  = issue.get('issue_text', ''),
            filename = issue.get('filename', ''),
            line     = issue.get('line_number', 0),
            code     = issue.get('code', ''),
            source   = 'bandit'
        )
        result.add_finding(finding)

    return result


def parse_semgrep_to_result(semgrep_json: dict,
                            result: ScanResult) -> ScanResult:
    """
    Parse Semgrep JSON output and add findings to existing ScanResult.
    """
    for issue in semgrep_json.get('results', []):
        finding = Finding(
            rule_id  = issue.get('check_id', 'SEMGREP').split('.')[-1],
            severity = 'HIGH',
            cwe      = 'N/A',
            message  = issue.get('extra', {}).get('message', '')[:100],
            filename = issue.get('path', ''),
            line     = issue.get('start', {}).get('line', 0),
            code     = issue.get('extra', {}).get('lines', ''),
            source   = 'semgrep'
        )
        result.add_finding(finding)

    return result

def save_json_report(result: ScanResult, output_path: str = "shield_report.json") -> str:
    """
    Save scan results as JSON file.
    Returns the output path.
    """
    data = {
        "shield_version": "0.3.0",
        "timestamp":      result.timestamp,
        "corpus":         result.corpus_path,
        "loc":            result.loc,
        "languages":      result.languages,
        "grade":          result.grade,
        "i100l":          result.i100l,
        "summary": {
            "high":   len(result.high),
            "medium": len(result.medium),
            "low":    len(result.low),
            "total":  len(result.findings),
        },
        "findings": [f.to_dict() for f in result.findings],
    }
    Path(output_path).write_text(
        __import__('json').dumps(data, indent=2),
        encoding='utf-8'
    )
    return output_path


def generate_comparison_report(before: ScanResult,
                                after: ScanResult,
                                output_path: str = "shield_comparison.html") -> str:
    """
    Generate a before/after comparison HTML report.
    Shows what SHIELD fixed and what remains.
    """
    fixed_count   = len(before.findings) - len(after.findings)
    high_fixed    = len(before.high) - len(after.high)
    i100l_change  = round(before.i100l - after.i100l, 2)
    reduction_pct = round(
        (len(before.findings) - len(after.findings)) /
        max(len(before.findings), 1) * 100
    )

    before_grade_color = before.grade_color
    after_grade_color  = after.grade_color

    html = f"""<!DOCTYPE html>
    
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SHIELD — Before/After Comparison</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #F5F5F5;
            color: #1A1A1A;
            line-height: 1.6;
        }}
        .header {{
            background: #0D0D0D;
            color: white;
            padding: 32px 48px;
            border-bottom: 4px solid #444;
        }}
        .header h1 {{ font-size: 28px; letter-spacing: 2px; text-transform: uppercase; }}
        .header p  {{ color: #999; margin-top: 4px; font-size: 14px; }}
        .comparison-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            padding: 32px 48px;
        }}
        .panel {{
            background: white;
            border-radius: 8px;
            padding: 24px;
            border: 1px solid #E0E0E0;
        }}
        .panel h2 {{
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 2px solid #E0E0E0;
        }}
        .grade-big {{
            font-size: 72px;
            font-weight: bold;
            text-align: center;
            line-height: 1;
            margin: 16px 0;
        }}
        .stat-row {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #F0F0F0;
            font-size: 14px;
        }}
        .stat-row:last-child {{ border-bottom: none; }}
        .improvement {{
            background: white;
            border-radius: 8px;
            padding: 24px 48px;
            margin: 0 48px 32px;
            border: 1px solid #E0E0E0;
        }}
        .improvement h2 {{
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 16px;
        }}
        .improvement-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
        }}
        .imp-card {{
            text-align: center;
            padding: 16px;
            background: #F9F9F9;
            border-radius: 8px;
            border: 1px solid #E0E0E0;
        }}
        .imp-number {{
            font-size: 32px;
            font-weight: bold;
            color: #1B5E20;
        }}
        .imp-label {{
            font-size: 11px;
            color: #666;
            text-transform: uppercase;
            margin-top: 4px;
        }}
        .footer {{
            text-align: center;
            padding: 24px;
            color: #999;
            font-size: 12px;
            border-top: 1px solid #E0E0E0;
            background: white;
        }}
        .red   {{ color: #B71C1C; }}
        .green {{ color: #1B5E20; }}
        .ora   {{ color: #E65100; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>⚡ SHIELD — Before / After Comparison</h1>
        <p>{result.corpus_path if hasattr(result, 'corpus_path') else before.corpus_path}
           &nbsp;·&nbsp; Ali Yasin Idrees</p>
    </div>

    <div class="comparison-grid">
        <div class="panel">
            <h2>⚠️ Before SHIELD</h2>
            <div class="grade-big" style="color:{before_grade_color};">{before.grade}</div>
            <div class="stat-row"><span>High Severity</span><span class="red">{len(before.high)}</span></div>
            <div class="stat-row"><span>Medium Severity</span><span class="ora">{len(before.medium)}</span></div>
            <div class="stat-row"><span>Low Severity</span><span>{len(before.low)}</span></div>
            <div class="stat-row"><span>Total Findings</span><span>{len(before.findings)}</span></div>
            <div class="stat-row"><span>I/100L Score</span><span>{before.i100l}</span></div>
            <div class="stat-row"><span>Lines of Code</span><span>{before.loc}</span></div>
        </div>

        <div class="panel">
            <h2>✅ After SHIELD</h2>
            <div class="grade-big" style="color:{after_grade_color};">{after.grade}</div>
            <div class="stat-row"><span>High Severity</span><span class="green">{len(after.high)}</span></div>
            <div class="stat-row"><span>Medium Severity</span><span class="green">{len(after.medium)}</span></div>
            <div class="stat-row"><span>Low Severity</span><span>{len(after.low)}</span></div>
            <div class="stat-row"><span>Total Findings</span><span>{len(after.findings)}</span></div>
            <div class="stat-row"><span>I/100L Score</span><span class="green">{after.i100l}</span></div>
            <div class="stat-row"><span>Lines of Code</span><span>{after.loc}</span></div>
        </div>
    </div>

    <div class="improvement">
        <h2>📈 Improvement Summary</h2>
        <div class="improvement-grid">
            <div class="imp-card">
                <div class="imp-number">{high_fixed}</div>
                <div class="imp-label">High Findings Fixed</div>
            </div>
            <div class="imp-card">
                <div class="imp-number">{fixed_count}</div>
                <div class="imp-label">Total Findings Fixed</div>
            </div>
            <div class="imp-card">
                <div class="imp-number">{reduction_pct}%</div>
                <div class="imp-label">Reduction</div>
            </div>
            <div class="imp-card">
                <div class="imp-number">{i100l_change}</div>
                <div class="imp-label">I/100L Improvement</div>
            </div>
        </div>
    </div>

    <div class="footer">
        Generated by SHIELD Security v0.3.0 &nbsp;·&nbsp;
        Ali Yasin Idrees &nbsp;·&nbsp;
        github.com/Aliidrees1234/llm-security-research
    </div>
</body>
</html>"""

    Path(output_path).write_text(html, encoding='utf-8')
    return output_path