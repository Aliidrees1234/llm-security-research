"""
SHIELD Security — CLI Entry Point
===================================
Secure Hybrid Integration and Enforcement Layer
for LLM-assisted Development

Author: Ali Yasin Idrees
Version: 0.3.0

Commands:
  shield scan <path>              Scan for vulnerabilities
  shield fix <path>               Scan and auto-fix
  shield fix <path> --inplace     Fix original files directly
  shield version                  Show version
"""

import sys
import argparse
from pathlib import Path
from colorama import init, Fore, Style

# Initialize colorama for Windows color support
init(autoreset=True)

# ── BANNER ────────────────────────────────────────────────────────────────────

BANNER = f"""
{Fore.WHITE}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   {Fore.WHITE}███████╗██╗  ██╗██╗███████╗██╗     ██████╗{Fore.WHITE}               ║
║   {Fore.WHITE}██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗{Fore.WHITE}              ║
║   {Fore.WHITE}███████╗███████║██║█████╗  ██║     ██║  ██║{Fore.WHITE}              ║
║   {Fore.WHITE}╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║{Fore.WHITE}              ║
║   {Fore.WHITE}███████║██║  ██║██║███████╗███████╗██████╔╝{Fore.WHITE}              ║
║   {Fore.WHITE}╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝{Fore.WHITE}               ║
║                                                              ║
║   {Fore.WHITE}Security Layer for LLM-assisted Development{Fore.WHITE}              ║
║   {Fore.WHITE}v0.3.0  ·  Ali Yasin Idrees  ·  2026{Fore.WHITE}                    ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""

# ── HELPERS ───────────────────────────────────────────────────────────────────

def print_banner():
    import sys
    if sys.stdout.isatty():
        print(BANNER)

def success(msg): print(f"{Fore.GREEN}  ✅  {msg}{Style.RESET_ALL}")
def warning(msg): print(f"{Fore.YELLOW}  ⚠️   {msg}{Style.RESET_ALL}")
def error(msg):   print(f"{Fore.RED}  ❌  {msg}{Style.RESET_ALL}")
def info(msg):    print(f"{Fore.WHITE}  →   {msg}{Style.RESET_ALL}")
def section(msg): print(f"\n{Fore.WHITE}{'─'*60}\n  {msg}\n{'─'*60}{Style.RESET_ALL}")

# ── LANGUAGE DETECTION ────────────────────────────────────────────────────────

def detect_languages(path: str) -> list[str]:
    """Auto-detect programming languages in directory."""
    extensions = {
        '.py':   'python',
        '.js':   'javascript',
        '.ts':   'typescript',
        '.java': 'java',
        '.php':  'php',
        '.go':   'go',
        '.rb':   'ruby',
    }
    found = set()
    for f in Path(path).rglob('*'):
        if f.suffix in extensions:
            found.add(extensions[f.suffix])
    return sorted(list(found))

# ── SCAN COMMAND ──────────────────────────────────────────────────────────────

def cmd_scan(args):
    """shield scan <path> [--report report.html] [--json]"""
    import subprocess # nosec B404 — subprocess used to run Bandit/Semgrep with hardcoded commands only
    import json as jsonlib
    from shield.reporter import (
        ScanResult, Finding,
        generate_report,
        parse_bandit_to_result,
        parse_semgrep_to_result
    )

    if sys.stdout.isatty():
        print_banner()

    section(f"SCANNING  {args.path}")

    path = Path(args.path)
    if not path.exists():
        error(f"Path not found: {args.path}")
        sys.exit(1)

    languages = detect_languages(args.path)
    if not languages:
        warning("No supported language files found.")
        sys.exit(0)

    info(f"Languages detected: {', '.join(languages)}")

    # Count lines of code
    loc = sum(
        len(f.read_text(encoding='utf-8', errors='ignore').splitlines())
        for f in path.rglob('*.py')
    )

    # Create scan result
    result = ScanResult(str(args.path), loc=loc)
    result.languages = languages

    total_high   = 0
    total_medium = 0
    total_low    = 0

    # ── Python scan via Bandit ─────────────────────────────────────────────
    if 'python' in languages:
        section("Python — Bandit 1.9.4")
        cmd = [
            sys.executable, '-m', 'bandit',
            '-r', str(path),
            '-f', 'json', '-q'
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)  # nosec B603
        output = res.stdout or res.stderr
        json_start = output.find('{')

        if json_start >= 0:
            data = jsonlib.loads(output[json_start:])
            result = parse_bandit_to_result(data, str(args.path), loc)
            result.languages = languages

            high   = result.high
            medium = result.medium
            low    = result.low

            total_high   += len(high)
            total_medium += len(medium)
            total_low    += len(low)

            if high:
                for f in high:
                    error(f"[{f.rule_id}] {f.message}")
                    info(f"    File: {f.filename}")
                    info(f"    Line: {f.line}")
                    info(f"    CWE:  {f.cwe}")
                    if f.code:
                        info(f"    Code: {f.code.strip()[:80]}")
                    print()

            if medium:
                for f in medium:
                    warning(f"[{f.rule_id}] {f.message}")
                    info(f"    File: {f.filename}")
                    info(f"    Line: {f.line}")
                    print()

            if low:
                print(f"\n{Fore.CYAN}  ── Low Severity Findings ──{Style.RESET_ALL}")
                for f in low:
                    print(f"{Fore.CYAN}  ℹ️  [{f.rule_id}] {f.message}{Style.RESET_ALL}")
                    info(f"    File: {f.filename}")
                    info(f"    Line: {f.line}")
                    info(f"    CWE:  {f.cwe}")
                    if f.code:
                        info(f"    Code: {f.code.strip()[:80]}")
                    print()

            if not high and not medium and not low:
                success("Zero findings — completely clean")
            elif not high and not medium:
                success("No High or Medium findings detected")

            info(f"Python total — High: {len(high)}  "
                 f"Medium: {len(medium)}  Low: {len(low)}")

    # ── JavaScript scan via Semgrep ────────────────────────────────────────
    if 'javascript' in languages or 'typescript' in languages:
        section("JavaScript / TypeScript — Semgrep p/nodejs")
        try:
            cmd = ['semgrep', '--config=p/nodejs', '--json', str(path)]
            res = subprocess.run(  # nosec B603
                cmd, capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            output = res.stdout
            json_start = output.find('{')

            if json_start >= 0:
                data = jsonlib.loads(output[json_start:])
                result = parse_semgrep_to_result(data, result)
                findings = [f for f in result.findings if f.source == 'semgrep']
                total_high += len(findings)

                if findings:
                    for f in findings:
                        error(f"[SEMGREP] {f.rule_id}")
                        info(f"    File: {f.filename} — Line {f.line}")
                else:
                    success("No findings in JavaScript/TypeScript files")

                info(f"JS/TS total — Blocking: {len(findings)}")

        except FileNotFoundError:
            warning("Semgrep not installed — skipping JS/TS scan")

    # ── Final verdict ──────────────────────────────────────────────────────
    section("SHIELD SCAN RESULT")

    if total_high > 0:
        print(f"  {Fore.RED}High:   {total_high}  ← must fix before deployment{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}High:   {total_high}{Style.RESET_ALL}")

    if total_medium > 0:
        print(f"  {Fore.YELLOW}Medium: {total_medium}  ← review recommended{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}Medium: {total_medium}{Style.RESET_ALL}")

    if total_low > 0:
        print(f"  {Fore.CYAN}Low:    {total_low}  ← best practice violations{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}Low:    {total_low}{Style.RESET_ALL}")

    # ── Grade ──────────────────────────────────────────────────────────────
    print()
    grade_display = {
        "A+": Fore.GREEN, "A": Fore.GREEN,
        "B": Fore.YELLOW, "C": Fore.YELLOW,
        "D": Fore.RED, "F": Fore.RED
    }.get(result.grade, Fore.WHITE)
    print(f"  {grade_display}Security Grade: {result.grade}  "
          f"·  I/100L: {result.i100l}{Style.RESET_ALL}")

    # ── JSON output ────────────────────────────────────────────────────────
    if hasattr(args, 'json') and args.json:
        print(jsonlib.dumps(
            [f.to_dict() for f in result.findings], indent=2
        ))

    # ── HTML Report ────────────────────────────────────────────────────────
    if hasattr(args, 'report') and args.report:
        report_path = generate_report(result, args.report)
        print()
        success(f"Report saved: {report_path}")
        info("Open in browser to view full results")

    print()
    if total_high > 0:
        error(f"BLOCKED — {total_high} High-severity finding(s) detected")
        error("Run 'shield fix <path>' to auto-remediate")
        sys.exit(1)
    elif total_medium > 0:
        warning(f"WARNING — {total_medium} Medium finding(s) — review recommended")
        sys.exit(0)
    else:
        success("CLEAN — No High or Medium findings detected")
        sys.exit(0)

# ── FIX COMMAND ───────────────────────────────────────────────────────────────

def cmd_fix(args):
    """shield fix <path>"""
    from shield.reporter import (
        ScanResult, Finding,
        generate_report,
        parse_bandit_to_result
    )
    import json as jsonlib
    import subprocess # nosec B404 — subprocess used to run Bandit with hardcoded commands only

    if sys.stdout.isatty():
        print_banner()

    section(f"FIXING  {args.path}")

    path = Path(args.path)
    if not path.exists():
        error(f"Path not found: {args.path}")
        sys.exit(1)

    if args.inplace:
        warning("INPLACE MODE — original files will be modified directly")
    else:
        info(f"Safe mode — fixed files will be saved to: {args.output}")

    try:
        from shield.layer3_fdsp import fdsp_loop
        results = fdsp_loop(
            corpus_dir=str(path),
            output_dir=args.output,
            max_k=args.k,
            inplace=args.inplace
        )

        section("FIX COMPLETE")
        summary = results.get('summary', {})

        baseline_high  = summary.get('baseline_high', 0)
        final_high     = summary.get('final_high', 0)
        baseline_i100l = summary.get('baseline_I100L', 0)
        final_i100l    = summary.get('final_I100L', 0)
        total_fixes    = sum(results.get('total_fixes', {}).values())

        info(f"Baseline High:    {baseline_high}")
        info(f"Final High:       {final_high}")
        info(f"Baseline I/100L:  {baseline_i100l}")
        info(f"Final I/100L:     {final_i100l}")
        info(f"Auto-fixes applied: {total_fixes}")
        print()

        # Fixes breakdown
        if results.get('total_fixes'):
            section("FIXES APPLIED")
            for rule, count in results['total_fixes'].items():
                if not rule.endswith('_strategy') and not rule.endswith('_error'):
                    success(f"[{rule}] {count} fix(es) applied")

        # Grade improvement
        if final_high == 0:
            success("Zero High-severity findings remaining")
            if baseline_high > 0:
                reduction = round((baseline_high - final_high) / baseline_high * 100)
                success(f"High-severity reduction: {reduction}%")
        else:
            warning(f"{final_high} High finding(s) remain — manual review needed")

        # Generate fix report
        if hasattr(args, 'report') and args.report:
            # Scan the fixed output for the report
            fixed_path = Path(args.output) / 'working_copy'
            if fixed_path.exists():
                cmd = [
                    sys.executable, '-m', 'bandit',
                    '-r', str(fixed_path),
                    '-f', 'json', '-q'
                ]
                res = subprocess.run(  # nosec B603
                    cmd, capture_output=True, text=True
                )
                output = res.stdout or res.stderr
                json_start = output.find('{')
                if json_start >= 0:
                    data = jsonlib.loads(output[json_start:])
                    loc = sum(
                        len(f.read_text(encoding='utf-8', errors='ignore').splitlines())
                        for f in fixed_path.rglob('*.py')
                    )
                    result = parse_bandit_to_result(data, str(args.path), loc)
                    report_path = generate_report(result, args.report)
                    print()
                    success(f"Fix report saved: {report_path}")

        # Save JSON results
        if hasattr(args, 'output_json') and args.output_json:
            json_path = Path(args.output_json)
            json_path.write_text(
                jsonlib.dumps(results, indent=2),
                encoding='utf-8'
            )
            success(f"JSON results saved: {args.output_json}")

    except Exception as e:
        error(f"Fix failed: {e}")
        sys.exit(1)
# ── VERSION COMMAND ───────────────────────────────────────────────────────────

def cmd_version(args):
    print_banner()
    info("SHIELD Security v0.2.0")
    info("Author: Ali Yasin Idrees")
    info("GitHub: github.com/Aliidrees1234/llm-security-research")
    info("Research: LLM Security in Web Applications — 2026")
    info("Engine: Full AST engine — 11 rules — 89 tests")

# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="shield",
        description="SHIELD Security — Automated security layer for LLM-assisted development",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  shield scan ./my_project
  shield fix ./my_project
  shield fix ./my_project --inplace
  shield fix ./my_project --output ./fixed --k 3
  shield version
        """
    )

    subparsers = parser.add_subparsers(dest="command")

   # ── scan ──────────────────────────────────────────────────────────────────
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a directory for security vulnerabilities"
    )
    scan_parser.add_argument(
        "path",
        help="Directory to scan"
    )
    scan_parser.add_argument(
        "--report",
        default=None,
        help="Generate HTML report (e.g. --report report.html)"
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output results as JSON"
    )

    # ── fix ───────────────────────────────────────────────────────────────
    fix_parser = subparsers.add_parser(
        "fix",
        help="Scan and automatically fix security vulnerabilities"
    )
    fix_parser.add_argument(
        "path",
        help="Directory to fix"
    )
    fix_parser.add_argument(
        "--inplace",
        action="store_true",
        default=False,
        help="Fix original files directly (WARNING: modifies your files)"
    )
    fix_parser.add_argument(
        "--output",
        default="shield_results",
        help="Output directory for fixed files (default: shield_results)"
    )
    fix_parser.add_argument(
        "--k",
        type=int,
        default=3,
        help="Maximum FDSP iterations (default: 3)"
    )
    fix_parser.add_argument(
        "--report",
        default=None,
        help="Generate HTML report of fixed code (e.g. --report fixed_report.html)"
    )
    fix_parser.add_argument(
        "--output-json",
        default=None,
        dest="output_json",
        help="Save fix results as JSON (e.g. --output-json results.json)"
    )

    # ── version ───────────────────────────────────────────────────────────
    subparsers.add_parser(
        "version",
        help="Show SHIELD version and author info"
    )

    # ── parse and dispatch ─────────────────────────────────────────────────
    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "fix":
        cmd_fix(args)
    elif args.command == "version":
        cmd_version(args)
    else:
        print_banner()
        parser.print_help()

if __name__ == "__main__":
    main()