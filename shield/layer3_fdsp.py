"""
SHIELD Layer 3 — FDSP Auto-Remediation Engine
=============================================
Feedback-Driven Security Patching (FDSP) for Python/Flask code.

Pipeline:
  K=0 : Scan original file  → record baseline
  K=1 : Apply auto-fixes    → re-scan → record
  K=2 : Apply remaining     → re-scan → record
  K=3 : Final attempt       → re-scan → record final

Usage:
  python fdsp_layer3.py --corpus snippets/chatgpt   --output results/chatgpt_layer3
  python fdsp_layer3.py --corpus snippets/claude    --output results/claude_layer3
  python fdsp_layer3.py --corpus snippets/gemini    --output results/gemini_layer3

Requirements:
  pip install bandit
"""

import os
import re
import sys
import json
import shutil
import argparse
import subprocess  # nosec B404 — used to run Bandit with hardcoded arguments only
import tempfile
from pathlib import Path
from datetime import datetime
from shield.rules.custom_rules import REMEDIATION_MAP

def apply_all_fixes(code: str) -> tuple[str, dict]:
    """
    Apply all remediation functions to code.
    Uses safe_apply for AST rules — never crashes on bad input.
    Returns fixed code + fix summary.
    """
    from shield.rules.custom_rules import (
        REMEDIATION_MAP, safe_apply,
        _regex_B201, _regex_B602, _regex_B105,
        fix_B201_debug_true, fix_B602_shell_true, fix_B105_B106_hardcoded,
    )

    summary = {}

    # AST rules — use safe_apply with regex fallback
    ast_rules = {
        'B201': (fix_B201_debug_true, _regex_B201),
        'B602': (fix_B602_shell_true, _regex_B602),
        'B105': (fix_B105_B106_hardcoded, _regex_B105),
        'B106': (fix_B105_B106_hardcoded, _regex_B105),
    }

    for rule_id, (ast_fn, regex_fn) in ast_rules.items():
        result = safe_apply(ast_fn, regex_fn, code, rule_id)
        if result.fixes > 0:
            summary[rule_id] = result.fixes
            summary[f'{rule_id}_strategy'] = result.strategy
            code = result.code
        if result.error:
            summary[f'{rule_id}_error'] = result.error

    # Remaining rules — direct call (regex only, no AST yet)
    remaining = {k: v for k, v in REMEDIATION_MAP.items()
                 if k not in ast_rules}

    for rule_id, fix_fn in remaining.items():
        try:
            fixed, count = fix_fn(code)
            if count > 0:
                summary[rule_id] = count
                code = fixed
        except Exception as e:
            summary[f'{rule_id}_error'] = str(e)

    return code, summary

# ── BANDIT RUNNER ─────────────────────────────────────────────────────────────

def run_bandit(directory: str) -> dict:
    """Run Bandit on directory, return parsed JSON results."""
    cmd = [
        sys.executable, '-m', 'bandit',
        '-r', directory,
        '-f', 'json',
        '-q'
    ]
    try:
        result = subprocess.run( # nosec B603 — cmd is a hardcoded Bandit invocation
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        # Bandit returns exit code 1 when issues found — that's fine
        output = result.stdout or result.stderr
        
        # Find JSON in output
        json_start = output.find('{')
        if json_start >= 0:
            return json.loads(output[json_start:])
        return {"results": [], "metrics": {}}
    except Exception as e:
        print(f"    Bandit error: {e}")
        return {"results": [], "metrics": {}}

def parse_metrics(bandit_data: dict) -> dict:
    """Extract H/M/L totals from Bandit output."""
    results = bandit_data.get('results', [])
    metrics = {'High': 0, 'Medium': 0, 'Low': 0, 'Total': 0, 'Skipped': 0}
    
    sev_map = {'HIGH': 'High', 'MEDIUM': 'Medium', 'LOW': 'Low'}
    for issue in results:
        sev = sev_map.get(issue.get('issue_severity', '').upper(), 'Low')
        metrics[sev] += 1
        metrics['Total'] += 1
    
    # Count skipped files
    errors = bandit_data.get('errors', [])
    metrics['Skipped'] = len(errors)
    
    return metrics

def count_lines(directory: str) -> int:
    """Count total Python lines in directory."""
    total = 0
    for f in Path(directory).rglob('*.py'):
        try:
            total += len(f.read_text(encoding='utf-8', errors='ignore').splitlines())
        except: # nosec B110 — intentional: skip unreadable files silently
            pass
    return total

# ── FDSP MAIN LOOP ────────────────────────────────────────────────────────────

def fdsp_loop(corpus_dir: str, output_dir: str, max_k: int = 3, inplace: bool = False) -> dict:
    """
    Run FDSP loop on corpus:
      K=0: baseline scan
      K=1..max_k: apply fixes, rescan
    Returns full results dict.
    """
    corpus_path = Path(corpus_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    corpus_name = corpus_path.name
    print(f"\n{'='*60}")
    print(f"FDSP LAYER 3 — Corpus: {corpus_name}")
    print(f"{'='*60}")
    
    results = {
        'corpus': corpus_name,
        'timestamp': datetime.now().isoformat(),
        'iterations': {}
    }
    
    # Work in a temp directory so we don't modify originals
    if inplace:
        work_dir = corpus_path
        print("  ⚠️  INPLACE MODE — original files will be modified")
    else:
        work_dir = output_path / 'working_copy'
        if work_dir.exists():
            shutil.rmtree(work_dir)
        shutil.copytree(corpus_path, work_dir)
    
    # ── K=0: Baseline ─────────────────────────────────────────────────────────
    print(f"\n  K=0 — Baseline scan...")
    bandit_data = run_bandit(str(work_dir))
    metrics_k0 = parse_metrics(bandit_data)
    loc_k0 = count_lines(str(work_dir))
    i100l_k0 = round(metrics_k0['Total'] / loc_k0 * 100, 2) if loc_k0 > 0 else 0
    
    results['iterations']['K0'] = {
        'label': 'Baseline (no FDSP)',
        **metrics_k0,
        'LOC': loc_k0,
        'I100L': i100l_k0,
        'fixes_applied': {},
    }
    print(f"    H:{metrics_k0['High']}  M:{metrics_k0['Medium']}  L:{metrics_k0['Low']}  Total:{metrics_k0['Total']}  LOC:{loc_k0}  I/100L:{i100l_k0}")
    if metrics_k0['Skipped']:
        print(f"    Files skipped (syntax error): {metrics_k0['Skipped']}")
    
    # Save baseline bandit report
    baseline_report_path = output_path / 'bandit_K0_baseline.json'
    with open(baseline_report_path, 'w') as f:
        json.dump(bandit_data, f, indent=2)
    
    # ── K=1..3: Fix and rescan ────────────────────────────────────────────────
    total_fixes_all_k = {}
    
    for k in range(1, max_k + 1):
        print(f"\n  K={k} — Applying remediations...")
        
        py_files = list(work_dir.rglob('*.py'))
        iter_fixes = {}
        
        for py_file in sorted(py_files):
            try:
                original_code = py_file.read_text(encoding='utf-8', errors='ignore')
                fixed_code, fix_summary = apply_all_fixes(original_code)
                
                if fix_summary:
                    py_file.write_text(fixed_code, encoding='utf-8')
                    print(f"    Fixed {py_file.name}: {fix_summary}")
                    for rule, count in fix_summary.items():
                        iter_fixes[rule] = iter_fixes.get(rule, 0) + count
                        total_fixes_all_k[rule] = total_fixes_all_k.get(rule, 0) + count
                        
            except Exception as e:
                print(f"    Could not process {py_file.name}: {e}")
        
        # Re-scan
        print(f"    Re-scanning after K={k} fixes...")
        bandit_data_k = run_bandit(str(work_dir))
        metrics_k = parse_metrics(bandit_data_k)
        loc_k = count_lines(str(work_dir))
        i100l_k = round(metrics_k['Total'] / loc_k * 100, 2) if loc_k > 0 else 0
        
        results['iterations'][f'K{k}'] = {
            'label': f'After K={k} FDSP iteration',
            **metrics_k,
            'LOC': loc_k,
            'I100L': i100l_k,
            'fixes_applied': iter_fixes,
        }
        print(f"    H:{metrics_k['High']}  M:{metrics_k['Medium']}  L:{metrics_k['Low']}  Total:{metrics_k['Total']}  LOC:{loc_k}  I/100L:{i100l_k}")
        
        # Save report for this K
        report_path = output_path / f'bandit_K{k}.json'
        with open(report_path, 'w') as f:
            json.dump(bandit_data_k, f, indent=2)
        
        # Early stop if no High remaining
        if metrics_k['High'] == 0:
            print(f"    ✅ Zero High-severity findings reached at K={k} — stopping early.")
            if k < max_k:
                for remaining_k in range(k + 1, max_k + 1):
                    results['iterations'][f'K{remaining_k}'] = {
                        'label': f'K={remaining_k} — not needed (zero High at K={k})',
                        **metrics_k,
                        'LOC': loc_k,
                        'I100L': i100l_k,
                        'fixes_applied': {},
                    }
            break
    
    results['total_fixes'] = total_fixes_all_k
    results['summary'] = {
        'baseline_high':  results['iterations']['K0']['High'],
        'final_high':     results['iterations'][f'K{min(max_k, k)}']['High'],
        'high_reduction': results['iterations']['K0']['High'] - results['iterations'][f'K{min(max_k, k)}']['High'],
        'baseline_total': results['iterations']['K0']['Total'],
        'final_total':    results['iterations'][f'K{min(max_k, k)}']['Total'],
        'baseline_I100L': results['iterations']['K0']['I100L'],
        'final_I100L':    results['iterations'][f'K{min(max_k, k)}']['I100L'],
    }
    
    return results

# ── REPORT GENERATOR ──────────────────────────────────────────────────────────

def print_summary_table(all_results: list):
    """Print a formatted summary table for all corpora."""
    print("\n")
    print("=" * 80)
    print("  SHIELD LAYER 3 FDSP — FINAL SUMMARY")
    print("=" * 80)
    
    header = f"{'Corpus':<25} {'K0 H':>6} {'K1 H':>6} {'K2 H':>6} {'K3 H':>6} {'K0 I/100L':>10} {'K3 I/100L':>10} {'Red%':>6}"
    print(header)
    print("-" * 80)
    
    for r in all_results:
        corpus = r['corpus']
        iters  = r['iterations']
        k0_h   = iters.get('K0', {}).get('High', '?')
        k1_h   = iters.get('K1', {}).get('High', '?')
        k2_h   = iters.get('K2', {}).get('High', '?')
        k3_h   = iters.get('K3', {}).get('High', '?')
        k0_i   = iters.get('K0', {}).get('I100L', '?')
        k3_i   = iters.get('K3', {}).get('I100L', '?')
        
        # Reduction %
        try:
            red = round((k0_h - k3_h) / k0_h * 100) if k0_h > 0 else 100
        except:
            red = '?'
        
        print(f"{corpus:<25} {str(k0_h):>6} {str(k1_h):>6} {str(k2_h):>6} {str(k3_h):>6} {str(k0_i):>10} {str(k3_i):>10} {str(red)+'%':>6}")
    
    print("=" * 80)

# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SHIELD Layer 3 — FDSP Auto-Remediation Engine"
    )
    parser.add_argument(
        '--corpora',
        nargs='+',
        default=['snippets/chatgpt', 'snippets/claude', 'snippets/gemini'],
        help="Corpus directories to process"
    )
    parser.add_argument(
        '--output',
        default='results/layer3_fdsp',
        help="Output directory for results"
    )
    parser.add_argument(
        '--k',
        type=int,
        default=3,
        help="Maximum FDSP iterations (default: 3)"
    )
    args = parser.parse_args()
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║        SHIELD FRAMEWORK — LAYER 3 FDSP VALIDATION           ║
║        Feedback-Driven Security Patching Engine              ║
║        Bandit 1.9.4 · Python SAST · K=3 iterations          ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    all_results = []
    master_output = Path(args.output)
    master_output.mkdir(parents=True, exist_ok=True)
    
    for corpus_dir in args.corpora:
        if not Path(corpus_dir).exists():
            print(f"⚠ Corpus not found: {corpus_dir} — skipping")
            continue
        
        corpus_name = Path(corpus_dir).name
        corpus_output = master_output / corpus_name
        
        r = fdsp_loop(corpus_dir, str(corpus_output), max_k=args.k)
        all_results.append(r)
        
        # Save per-corpus JSON
        result_file = corpus_output / 'fdsp_results.json'
        with open(result_file, 'w') as f:
            json.dump(r, f, indent=2)
        print(f"\n  Results saved: {result_file}")
    
    # Print summary
    print_summary_table(all_results)
    
    # Save master results
    master_file = master_output / 'fdsp_master_results.json'
    with open(master_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"\nMaster results saved: {master_file}")
    print("\nNow paste the summary table numbers into the research paper!\n")

if __name__ == '__main__':
    main()
