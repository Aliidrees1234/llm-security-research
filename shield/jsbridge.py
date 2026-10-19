"""
SHIELD <-> shield-js bridge
============================
Lets the Python SHIELD CLI use the shield-js engine for JavaScript and
TypeScript files (scan + auto-fix), and merge the results into the same
ScanResult / report as the Python findings.

shield-js is located, in this order:
  1. SHIELD_JS_PATH  - path to the shield-js repo folder (or to its src/cli.js)
  2. `shield-js` on PATH  (run `npm link` inside the shield-js folder)

Author: Ali Yasin Idrees
"""

import json
import os
import shutil
import subprocess  # nosec B404
from pathlib import Path

from shield.reporter import Finding

JS_LANGUAGES = ('javascript', 'typescript')
TIMEOUT_SECONDS = 180


class JsBridgeError(RuntimeError):
    """shield-js is missing, crashed, or returned something unreadable."""


def find_shield_js():
    """Return the argv prefix that runs shield-js, or None if it is not installed."""
    node = shutil.which('node')

    configured = os.environ.get('SHIELD_JS_PATH')
    if configured and node:
        p = Path(configured)
        cli = p if p.is_file() else p / 'src' / 'cli.js'
        if cli.is_file():
            return [node, str(cli)]

    exe = shutil.which('shield-js')
    return [exe] if exe else None


def wants_js(languages):
    """True if the detected language list contains JavaScript or TypeScript."""
    return any(lang in JS_LANGUAGES for lang in languages)


def run_shield_js(args):
    """Run shield-js and return its parsed JSON output.

    shield-js exits 0 (clean) or 1 (findings) for normal runs; anything else,
    or unreadable output, is a failure and raises JsBridgeError.
    """
    cmd = find_shield_js()
    if not cmd:
        raise JsBridgeError(
            'shield-js not found. Run `npm link` inside the shield-js folder, '
            'or set SHIELD_JS_PATH to that folder.'
        )
    try:
        # Fixed executable; the arguments are file paths and flags only.
        res = subprocess.run(  # nosec B603
            cmd + [str(a) for a in args],
            capture_output=True, text=True,
            encoding='utf-8', errors='replace',
            timeout=TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise JsBridgeError(f'shield-js timed out after {TIMEOUT_SECONDS}s') from exc
    except OSError as exc:
        raise JsBridgeError(f'could not start shield-js: {exc}') from exc

    if res.returncode not in (0, 1):
        detail = (res.stderr or res.stdout).strip().splitlines()
        raise JsBridgeError(detail[0] if detail else f'shield-js exited with code {res.returncode}')
    try:
        return json.loads(res.stdout)
    except ValueError as exc:
        raise JsBridgeError('shield-js returned invalid JSON') from exc


def _to_finding(item):
    return Finding(
        rule_id=item['ruleId'],
        severity=item['severity'],
        cwe=str(item.get('cwe', 'N/A')).replace('CWE-', ''),
        message=item['message'],
        filename=item['file'],
        line=item.get('line', 0),
        code='',
        source='shield-js',
    )


def scan_js(target):
    """Scan JS/TS files under `target`. Returns findings, parse errors and totals."""
    data = run_shield_js(['scan', target, '--json'])
    return {
        'findings': [_to_finding(f) for f in data.get('findings', [])],
        'errors': data.get('errors', []),
        'files': data.get('files', 0),
        'loc': data.get('loc', 0),
    }


def fix_js(target, output, inplace=False, exclude=None):
    """Fix JS/TS files under `target`. Returns shield-js's fix report as a dict.

    `exclude` lists directories to skip, e.g. the Python fix output folder, so
    copies of already-fixed files are never scanned again.
    """
    args = ['fix', target, '--json']
    if inplace:
        args.append('--inplace')
    else:
        args += ['--output', output]
    for directory in exclude or []:
        args += ['--exclude', directory]
    return run_shield_js(args)


def _key(finding):
    return (os.path.normcase(os.path.abspath(finding.filename)), finding.line)


def merge_findings(result, js_findings):
    """Add shield-js findings to a ScanResult, skipping ones another scanner
    already reported on the same file and line. Returns the findings added."""
    seen = {_key(f) for f in result.findings}
    added = []
    for finding in js_findings:
        key = _key(finding)
        if key in seen:
            continue
        seen.add(key)
        result.add_finding(finding)
        added.append(finding)
    return added
