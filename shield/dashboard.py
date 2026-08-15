"""
SHIELD Security — Local Dashboard
===================================
Starts a local web server showing scan history,
security grades, and vulnerability trends.

Usage:
  shield dashboard
  shield dashboard --port 8080

Author: Ali Yasin Idrees
Version: 1.0.0
"""

import json
import threading
import webbrowser
from pathlib import Path
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler


# ── Scan History Loader ───────────────────────────────────────────────────────

def load_scan_history(search_paths: list[str] = None) -> list[dict]:
    """
    Find all shield JSON reports in common locations.
    Returns list of scan results sorted by date.
    """
    if search_paths is None:
        search_paths = ['.', './shield_results', './fixed', './research/results']

    reports = []
    seen = set()

    for base in search_paths:
        base_path = Path(base)
        if not base_path.exists():
            continue
        for json_file in base_path.rglob('*.json'):
            if json_file in seen:
                continue
            seen.add(json_file)
            try:
                data = json.loads(json_file.read_text(encoding='utf-8'))
                # Only load SHIELD scan reports
                if 'shield_version' in data or 'grade' in data:
                    data['_source_file'] = str(json_file)
                    reports.append(data)
            except Exception: # nosec B110 — intentional: skip malformed JSON files silently
                pass

    # Sort by timestamp
    reports.sort(
        key=lambda r: r.get('timestamp', ''),
        reverse=True
    )
    return reports


# ── Grade Color ───────────────────────────────────────────────────────────────

def grade_color(grade: str) -> str:
    return {
        'A+': '#1B5E20', 'A': '#2E7D32',
        'B':  '#F57F17', 'C': '#E65100',
        'D':  '#B71C1C', 'F': '#7B1FA2'
    }.get(grade, '#444444')


# ── HTML Dashboard ────────────────────────────────────────────────────────────

def build_dashboard_html(reports: list[dict]) -> str:
    """Build the complete dashboard HTML."""

    # Build scan cards
    cards_html = ""
    if not reports:
        cards_html = """
        <div class="empty">
            <h2>No scan reports found</h2>
            <p>Run a scan first:</p>
            <code>shield scan ./my_project --report report.html</code>
        </div>
        """
    else:
        for r in reports:
            grade    = r.get('grade', '?')
            i100l    = r.get('i100l', 0)
            corpus   = r.get('corpus', r.get('_source_file', 'Unknown'))
            ts       = r.get('timestamp', '')[:19].replace('T', ' ')
            summary  = r.get('summary', {})
            high     = summary.get('high', 0)
            medium   = summary.get('medium', 0)
            low      = summary.get('low', 0)
            total    = summary.get('total', 0)
            loc      = r.get('loc', 0)
            color    = grade_color(grade)
            findings = r.get('findings', [])

            # Top 3 rules fired
            from collections import Counter
            rule_counts = Counter(f.get('rule_id', '') for f in findings)
            top_rules = rule_counts.most_common(3)
            rules_html = ' '.join(
                f'<span class="tag">{rule} ×{count}</span>'
                for rule, count in top_rules
            )

            cards_html += f"""
            <div class="card">
                <div class="card-header">
                    <div class="grade-circle" style="background:{color};">{grade}</div>
                    <div class="card-info">
                        <div class="corpus">{Path(corpus).name}</div>
                        <div class="timestamp">{ts}</div>
                        <div class="corpus-full">{corpus}</div>
                    </div>
                </div>
                <div class="stats">
                    <div class="stat">
                        <div class="stat-num" style="color:#B71C1C;">{high}</div>
                        <div class="stat-label">High</div>
                    </div>
                    <div class="stat">
                        <div class="stat-num" style="color:#E65100;">{medium}</div>
                        <div class="stat-label">Medium</div>
                    </div>
                    <div class="stat">
                        <div class="stat-num" style="color:#F57F17;">{low}</div>
                        <div class="stat-label">Low</div>
                    </div>
                    <div class="stat">
                        <div class="stat-num">{loc}</div>
                        <div class="stat-label">LOC</div>
                    </div>
                    <div class="stat">
                        <div class="stat-num">{i100l}</div>
                        <div class="stat-label">I/100L</div>
                    </div>
                    <div class="stat">
                        <div class="stat-num">{total}</div>
                        <div class="stat-label">Total</div>
                    </div>
                </div>
                {f'<div class="rules">{rules_html}</div>' if rules_html else ''}
            </div>
            """

    # Build chart data
    chart_labels = []
    chart_high   = []
    chart_i100l  = []

    for r in reversed(reports[-10:]):
        label = Path(r.get('corpus', 'scan')).name[:15]
        chart_labels.append(f'"{label}"')
        chart_high.append(r.get('summary', {}).get('high', 0))
        chart_i100l.append(r.get('i100l', 0))

    labels_js = '[' + ','.join(chart_labels) + ']'
    high_js   = str(chart_high)
    i100l_js  = str(chart_i100l)

    total_scans  = len(reports)
    avg_i100l    = round(sum(r.get('i100l', 0) for r in reports) / max(len(reports), 1), 2)
    total_high   = sum(r.get('summary', {}).get('high', 0) for r in reports)
    clean_scans  = sum(1 for r in reports if r.get('grade', '') in ('A+', 'A'))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SHIELD Security Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #0D0D0D;
            color: #E0E0E0;
            min-height: 100vh;
        }}
        .header {{
            background: #1A1A1A;
            border-bottom: 2px solid #333;
            padding: 20px 40px;
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        .header h1 {{
            font-size: 24px;
            letter-spacing: 3px;
            text-transform: uppercase;
            color: white;
        }}
        .header p {{
            color: #666;
            font-size: 13px;
            margin-top: 2px;
        }}
        .bolt {{ font-size: 28px; }}
        .overview {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            padding: 24px 40px;
        }}
        .ov-card {{
            background: #1A1A1A;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .ov-num {{
            font-size: 36px;
            font-weight: bold;
            color: white;
        }}
        .ov-label {{
            font-size: 11px;
            color: #666;
            text-transform: uppercase;
            margin-top: 4px;
            letter-spacing: 1px;
        }}
        .charts {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            padding: 0 40px 24px;
        }}
        .chart-card {{
            background: #1A1A1A;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 20px;
        }}
        .chart-card h3 {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #666;
            margin-bottom: 16px;
        }}
        .section-title {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: #666;
            padding: 0 40px 12px;
        }}
        .cards {{
            padding: 0 40px 40px;
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
            gap: 16px;
        }}
        .card {{
            background: #1A1A1A;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 20px;
        }}
        .card:hover {{
            border-color: #555;
        }}
        .card-header {{
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 16px;
        }}
        .grade-circle {{
            width: 52px;
            height: 52px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            font-weight: bold;
            color: white;
            flex-shrink: 0;
        }}
        .corpus {{
            font-weight: bold;
            font-size: 15px;
            color: white;
        }}
        .corpus-full {{
            font-size: 10px;
            color: #444;
            margin-top: 2px;
            word-break: break-all;
        }}
        .timestamp {{
            font-size: 12px;
            color: #666;
            margin-top: 2px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 8px;
            margin-bottom: 12px;
        }}
        .stat {{
            text-align: center;
            background: #111;
            border-radius: 6px;
            padding: 8px 4px;
        }}
        .stat-num {{
            font-size: 18px;
            font-weight: bold;
        }}
        .stat-label {{
            font-size: 9px;
            color: #555;
            text-transform: uppercase;
            margin-top: 2px;
        }}
        .rules {{
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }}
        .tag {{
            background: #222;
            border: 1px solid #444;
            border-radius: 4px;
            padding: 2px 8px;
            font-size: 10px;
            color: #888;
            font-family: monospace;
        }}
        .empty {{
            text-align: center;
            padding: 60px;
            color: #444;
        }}
        .empty h2 {{ margin-bottom: 12px; color: #666; }}
        .empty code {{
            background: #1A1A1A;
            padding: 8px 16px;
            border-radius: 4px;
            font-size: 14px;
            color: #888;
        }}
        .refresh {{
            margin-left: auto;
            background: #222;
            border: 1px solid #444;
            color: #888;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
        }}
        .refresh:hover {{ border-color: #666; color: white; }}
    </style>
</head>
<body>

<div class="header">
    <span class="bolt">⚡</span>
    <div>
        <h1>SHIELD Security Dashboard</h1>
        <p>Ali Yasin Idrees · v1.0.2 · {datetime.now().strftime('%B %d, %Y %H:%M')}</p>
    </div>
    <button class="refresh" onclick="location.reload()">↻ Refresh</button>
</div>

<div class="overview">
    <div class="ov-card">
        <div class="ov-num">{total_scans}</div>
        <div class="ov-label">Total Scans</div>
    </div>
    <div class="ov-card">
        <div class="ov-num" style="color:#B71C1C;">{total_high}</div>
        <div class="ov-label">Total High Findings</div>
    </div>
    <div class="ov-card">
        <div class="ov-num" style="color:#F57F17;">{avg_i100l}</div>
        <div class="ov-label">Avg I/100L</div>
    </div>
    <div class="ov-card">
        <div class="ov-num" style="color:#1B5E20;">{clean_scans}</div>
        <div class="ov-label">Clean Scans (A/A+)</div>
    </div>
</div>

<div class="charts">
    <div class="chart-card">
        <h3>High Findings Per Scan</h3>
        <canvas id="highChart" height="120"></canvas>
    </div>
    <div class="chart-card">
        <h3>I/100L Vulnerability Density</h3>
        <canvas id="i100lChart" height="120"></canvas>
    </div>
</div>

<div class="section-title">Scan History ({total_scans} reports)</div>
<div class="cards">
    {cards_html}
</div>

<script>
const labels = {labels_js};
const highData = {high_js};
const i100lData = {i100l_js};

const chartDefaults = {{
    responsive: true,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
        x: {{ ticks: {{ color: '#666', font: {{ size: 10 }} }}, grid: {{ color: '#222' }} }},
        y: {{ ticks: {{ color: '#666' }}, grid: {{ color: '#222' }} }}
    }}
}};

new Chart(document.getElementById('highChart'), {{
    type: 'bar',
    data: {{
        labels,
        datasets: [{{
            data: highData,
            backgroundColor: '#B71C1C',
            borderRadius: 4
        }}]
    }},
    options: chartDefaults
}});

new Chart(document.getElementById('i100lChart'), {{
    type: 'line',
    data: {{
        labels,
        datasets: [{{
            data: i100lData,
            borderColor: '#F57F17',
            backgroundColor: 'rgba(245,127,23,0.1)',
            tension: 0.3,
            fill: true,
            pointBackgroundColor: '#F57F17'
        }}]
    }},
    options: chartDefaults
}});
</script>

</body>
</html>"""


# ── HTTP Server ───────────────────────────────────────────────────────────────

class DashboardHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        try:
            reports = load_scan_history()
            html    = build_dashboard_html(reports)
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(html.encode('utf-8'))
        except (ConnectionAbortedError, BrokenPipeError):
            pass  # nosec B110 — browser closed connection early, normal on Windows

    def log_message(self, format, *args):
        pass


def start_dashboard(port: int = 5555, open_browser: bool = True):
    """Start the dashboard server."""
    server = HTTPServer(('127.0.0.1', port), DashboardHandler)

    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(
            f'http://127.0.0.1:{port}'
        )).start()

    print(f"  SHIELD Dashboard running at http://127.0.0.1:{port}")
    print(f"  Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Dashboard stopped.")
        server.shutdown()