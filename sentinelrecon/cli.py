"""SentinelRecon CLI - Adaptive Reconnaissance & Vulnerability Correlation Engine."""

import argparse
import dataclasses
import json
import os
import sys

from sentinelrecon import __version__
from sentinelrecon.core.analyzer import Analyzer
from sentinelrecon.core.planner import ReconPlanner
from sentinelrecon.core.session import SessionManager
from sentinelrecon.core.target_parser import TargetParser
from sentinelrecon.execution.backend import RealExecutionBackend
from sentinelrecon.reporters.html import HTMLReporter
from sentinelrecon.reporters.json_ext import JSONReporter
from sentinelrecon.reporters.terminal import TerminalReporter
from sentinelrecon.tools.registry import ToolRegistry


def print_tools():
    registry = ToolRegistry()
    print("SentinelRecon Capabilities & Provider Status\n")
    print("-" * 65)
    print(f"  {'Capability':<30} {'Provider':<20} {'Status'}")
    print("-" * 65)

    for tool in registry.tools.values():
        status = "[OK] Installed" if registry.is_installed(tool.name) else "[!] Missing"
        cap = tool.capability_name or tool.name
        prov = tool.provider_name or tool.name
        print(f"  {cap:<30} {prov:<20} {status}")
    print()


def _handle_output(target, format_choice, output_file):
    if format_choice == "terminal":
        TerminalReporter().report(target)
    elif format_choice == "json":
        output_file = output_file or "report.json"
        JSONReporter().report(target, output_file)
        print(f"[+] JSON report saved to {output_file}")
    elif format_choice == "html":
        output_file = output_file or "report.html"
        HTMLReporter().report(target, output_file)
        print(f"[+] HTML report saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="SentinelRecon - Adaptive Reconnaissance & Vulnerability Correlation Engine"
    )
    parser.add_argument("--version", action="version", version=f"SentinelRecon v{__version__}")
    parser.add_argument("target", nargs="?", default=None, help="Target IP, hostname, or URL")
    parser.add_argument("-u", "--url", help="Target URL or IP (alternative to positional argument)")
    parser.add_argument("--mode", choices=["standard", "low-impact"], default=None, help="Reconnaissance mode (standard vs low-impact)")
    parser.add_argument("--plan", action="store_true", help="Display autonomous execution plan without executing tools")
    parser.add_argument("--execute", action="store_true", help="Execute the planned tools")

    # Optional backward compatibility for legacy profile flag
    parser.add_argument("-p", "--profile", "--depth", dest="profile", choices=["common", "medium", "deep", "COMMON", "MEDIUM", "DEEP", "autonomous", "AUTONOMOUS"], default="AUTONOMOUS", help=argparse.SUPPRESS)

    known_commands = ["import", "analyze", "sessions", "show", "report", "waf", "tools"]
    has_command = any(arg in known_commands for arg in sys.argv[1:])

    if has_command:
        subparsers = parser.add_subparsers(dest="command", help="Available commands")
        import_parser = subparsers.add_parser("import", help="Import and analyze a directory of scan results")
        import_parser.add_argument("directory")
        import_parser.add_argument("--format", choices=["terminal", "json", "html"], default="terminal")
        import_parser.add_argument("--output")

        analyze_parser = subparsers.add_parser("analyze", help="Analyze a single file")
        analyze_parser.add_argument("file")
        analyze_parser.add_argument("--format", choices=["terminal", "json", "html"], default="terminal")
        analyze_parser.add_argument("--output")

        subparsers.add_parser("sessions", help="List all analysis sessions")

        show_parser = subparsers.add_parser("show", help="Show an analysis session")
        show_parser.add_argument("session_id")

        report_parser = subparsers.add_parser("report", help="Generate a report for a session")
        report_parser.add_argument("session_id")
        report_parser.add_argument("--format", choices=["terminal", "json", "html"], default="terminal")
        report_parser.add_argument("--output")

        waf_parser = subparsers.add_parser("waf", help="Show WAF/CDN analysis for a session")
        waf_parser.add_argument("session_id")

        subparsers.add_parser("tools", help="List capability providers and tool availability")

    args, unknown = parser.parse_known_args()
    session_manager = SessionManager()

    if has_command and getattr(args, "command", None):
        if args.command == "import":
            if not os.path.isdir(args.directory):
                print(f"[!] Error: Directory {args.directory} does not exist.")
                sys.exit(1)
            target = Analyzer().analyze_directory(args.directory)
            session = session_manager.create_session(target)
            print(f"[*] Created session: {session.id}")
            _handle_output(target, args.format, getattr(args, "output", None))
            sys.exit(0)
        elif args.command == "analyze":
            if not os.path.isfile(args.file):
                print(f"[!] Error: File {args.file} does not exist.")
                sys.exit(1)
            target = Analyzer().analyze_file(args.file)
            session = session_manager.create_session(target)
            print(f"[*] Created session: {session.id}")
            _handle_output(target, args.format, getattr(args, "output", None))
            sys.exit(0)
        elif args.command == "sessions":
            sessions = session_manager.list_sessions()
            if not sessions:
                print("No sessions found.")
            else:
                print("\nAvailable Sessions:")
                print("-" * 40)
                for s in sessions:
                    print(f"  {s}")
            sys.exit(0)
        elif args.command == "show":
            try:
                session = (
                    session_manager.get_latest_session()
                    if args.session_id == "current"
                    else session_manager.get_session(args.session_id)
                )
                if not session:
                    print(f"[!] Error: Session {args.session_id} not found.")
                    sys.exit(1)
                _handle_output(session.target, "terminal", None)
            except Exception as e:
                print(f"[!] Error: {str(e)}")
                sys.exit(1)
            sys.exit(0)
        elif args.command == "report":
            try:
                session = (
                    session_manager.get_latest_session()
                    if args.session_id == "current"
                    else session_manager.get_session(args.session_id)
                )
                if not session:
                    print(f"[!] Error: Session {args.session_id} not found.")
                    sys.exit(1)
                _handle_output(session.target, args.format, getattr(args, "output", None))
            except Exception as e:
                print(f"[!] Error: {str(e)}")
                sys.exit(1)
            sys.exit(0)
        elif args.command == "waf":
            try:
                session = (
                    session_manager.get_latest_session()
                    if args.session_id == "current"
                    else session_manager.get_session(args.session_id)
                )
                if not session:
                    print(f"[!] Error: Session {args.session_id} not found.")
                    sys.exit(1)
                TerminalReporter().report_waf(session.target)
            except Exception as e:
                print(f"[!] Error: {str(e)}")
                sys.exit(1)
            sys.exit(0)
        elif args.command == "tools":
            print_tools()
            sys.exit(0)

    target_str = args.target or args.url or (unknown[0] if (unknown and not unknown[0].startswith("-")) else None)
    if target_str:
        mode = "WAF-Aware Low-Impact Recon" if (args.mode and args.mode.lower() == "low-impact") else "Standard Recon"
        recon_target = TargetParser.parse(target_str)
        recon_target.mode = mode
        recon_target.discovery_profile = "AUTONOMOUS"
        recon_target.source = "cli"

        planner = ReconPlanner()
        plan = planner.plan(recon_target)

        if args.plan:
            print("SentinelRecon Execution Plan")
            print("-" * 40)
            print(f"Target:   {recon_target.url or recon_target.input}")
            print(f"Mode:     {recon_target.mode}")
            print(f"Modules:  {', '.join(plan.modules)}")
            sys.exit(0)

        backend = RealExecutionBackend()
        result = backend.execute(plan)

        if result:
            TerminalReporter().report(result)
            json_path = os.path.join(plan.output_directory, "report.json")
            JSONReporter().report(result, json_path)
            html_path = os.path.join(plan.output_directory, "report.html")
            HTMLReporter().report(result, html_path)
            print("\nReports generated:")
            print("  JSON: report.json")
            print("  HTML: report.html")
        sys.exit(0)

    from sentinelrecon.interactive import interactive_menu

    recon_target = interactive_menu()
    planner = ReconPlanner()
    plan = planner.plan(recon_target)
    backend = RealExecutionBackend()
    result = backend.execute(plan)
    if result:
        TerminalReporter().report(result)
        json_path = os.path.join(plan.output_directory, "report.json")
        JSONReporter().report(result, json_path)
        html_path = os.path.join(plan.output_directory, "report.html")
        HTMLReporter().report(result, html_path)
        print("\nReports generated:")
        print("  JSON: report.json")
        print("  HTML: report.html")
    sys.exit(0)


if __name__ == "__main__":
    main()
