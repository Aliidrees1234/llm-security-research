"""
SHIELD Security — CLI Entry Point
===================================
Secure Hybrid Integration and Enforcement Layer
for LLM-assisted Development

Author: Ali Yasin Idrees
Version: 0.1.0

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
║   {Fore.WHITE}v0.1.0  ·  Ali Yasin Idrees  ·  2026{Fore.WHITE}                    ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""

# ── HELPERS ───────────────────────────────────────────────────────────────────

def print_banner():
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
    """shield scan <path>"""
    import subprocess  # nosec B404 — subprocess used to run Bandit/Semgrep with hardcoded commands only
    import json

    print_banner()
    section(f"SCANNING  {args.path}")

    path = Path(args.path)
    if not path.exists():
        error(f"Path not found: {args.path}")
        sys.exit(1)

    # Detect languages
    languages = detect_languages(args.path)
    if not languages:
        warning("No supported language files found.")
        sys.exit(0)

    info(f"Languages detected: {', '.join(languages)}")

    total_high = 0
    total_medium = 0
    total_low = 0

    # ── Python scan via Bandit ─────────────────────────────────────────────
    if 'python' in languages:
        section("Python — Bandit 1.9.4")
        cmd = [
            sys.executable, '-m', 'bandit',
            '-r', str(path),
            '-f', 'json', '-q'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)  # nosec B603 — cmd is hardcoded, no user input
        output = result.stdout or result.stderr
        json_start = output.find('{')

        if json_start >= 0:
            data = json.loads(output[json_start:])
            results = data.get('results', [])
            high   = [r for r in results if r['issue_severity'] == 'HIGH']
            medium = [r for r in results if r['issue_severity'] == 'MEDIUM']
            low    = [r for r in results if r['issue_severity'] == 'LOW']

            total_high   += len(high)
            total_medium += len(medium)
            total_low    += len(low)

            if high:
                for r in high:
                    error(f"[{r['test_id']}] {r['issue_text']}")
                    info(f"    File: {r['filename']}")
                    info(f"    Line: {r['line_number']}")
                    info(f"    CWE:  {r.get('issue_cwe', {}).get('id', 'N/A')}")
                    info(f"    Code: {r.get('code', '').strip()}")
                    print()

            if medium:
                for r in medium:
                    warning(f"[{r['test_id']}] {r['issue_text']}")
                    info(f"    File: {r['filename']}")
                    info(f"    Line: {r['line_number']}")
                    info(f"    CWE:  {r.get('issue_cwe', {}).get('id', 'N/A')}")
                    info(f"    Code: {r.get('code', '').strip()}")
                    print()

            if low:
                print(f"\n{Fore.CYAN}  ── Low Severity Findings ──{Style.RESET_ALL}")
                for r in low:
                    print(f"{Fore.CYAN}  ℹ️  [{r['test_id']}] {r['issue_text']}{Style.RESET_ALL}")
                    info(f"    File: {r['filename']}")
                    info(f"    Line: {r['line_number']}")
                    info(f"    CWE:  {r.get('issue_cwe', {}).get('id', 'N/A')}")
                    info(f"    Code: {r.get('code', '').strip()}")
                    print()

            if not high and not medium and not low:
                success("Zero findings — completely clean")
            elif not high and not medium:
                success("No High or Medium findings detected")

            info(f"Python total — High: {len(high)}  Medium: {len(medium)}  Low: {len(low)}")

    # ── JavaScript scan via Semgrep ────────────────────────────────────────
    if 'javascript' in languages or 'typescript' in languages:
        section("JavaScript / TypeScript — Semgrep p/nodejs")
        try:
            cmd = [
                'semgrep', '--config=p/nodejs',
                '--json', str(path)
            ]
            result = subprocess.run( # nosec B603 — cmd is hardcoded semgrep command
                cmd, capture_output=True, text=True, timeout=60
            )
            output = result.stdout
            json_start = output.find('{')

            if json_start >= 0:
                data = json.loads(output[json_start:])
                findings = data.get('results', [])
                total_high += len(findings)

                if findings:
                    for f in findings:
                        error(f"[SEMGREP] {f['check_id']}")
                        info(f"  File: {f['path']} — Line {f['start']['line']}")
                else:
                    success("No findings in JavaScript/TypeScript files")

                info(f"JS/TS total — Blocking: {len(findings)}")

        except FileNotFoundError:
            warning("Semgrep not installed — skipping JS/TS scan")
            info("Install with: pip install semgrep")

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

    # Import and run FDSP engine
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
        info(f"Baseline High:  {summary.get('baseline_high', '?')}")
        info(f"Final High:     {summary.get('final_high', '?')}")
        info(f"Baseline I/100L: {summary.get('baseline_I100L', '?')}")
        info(f"Final I/100L:    {summary.get('final_I100L', '?')}")

        total_fixes = sum(results.get('total_fixes', {}).values())
        info(f"Total auto-fixes applied: {total_fixes}")

        if summary.get('final_high', 1) == 0:
            success("Zero High-severity findings remaining")
        else:
            warning(f"{summary.get('final_high')} High finding(s) remain — manual review needed")

    except Exception as e:
        error(f"Fix failed: {e}")
        sys.exit(1)

# ── VERSION COMMAND ───────────────────────────────────────────────────────────

def cmd_version(args):
    print_banner()
    info("SHIELD Security v0.1.0")
    info("Author: Ali Yasin Idrees")
    info("GitHub: github.com/Aliidrees1234/llm-security-research")
    info("Research: LLM Security in Web Applications — 2026")

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

    # ── scan ──────────────────────────────────────────────────────────────
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a directory for security vulnerabilities"
    )
    scan_parser.add_argument(
        "path",
        help="Directory to scan"
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