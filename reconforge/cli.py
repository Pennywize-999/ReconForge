import argparse
import sys
import os
import subprocess

from reconforge import __version__
from reconforge.core.analyzer import Analyzer
from reconforge.core.session import SessionManager
from reconforge.reporters.terminal import TerminalReporter
from reconforge.reporters.json_ext import JSONReporter
from reconforge.reporters.html import HTMLReporter
from reconforge.core.target_parser import parse_target
from reconforge.core.planner import ReconPlanner
from reconforge.execution.backend import PlanningOnlyBackend
from reconforge.tools.registry import ToolRegistry

def interactive_menu():
    try:
        try:
            print("â•­â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â•®")
            print(f"â”‚       RECONFORGE v{__version__:<14}â”‚")
            print("â•°â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â•¯\n")
        except UnicodeEncodeError:
            print("-" * 32)
            print(f"       RECONFORGE v{__version__}")
            print("-" * 32 + "\n")

        print("Select reconnaissance mode:\n")
        print("1. Standard Recon")
        print("2. WAF-Aware Low-Impact Recon\n")

        while True:
            mode_opt = input("Select option [1-2]: ").strip()
            if mode_opt == "1":
                mode = "Standard Recon"
                break
            elif mode_opt == "2":
                mode = "WAF-Aware Low-Impact Recon"
                break
            else:
                print("[!] Invalid option. Please select 1 or 2.")

        print("\nSelect target type:\n")
        print("1. IP Address")
        print("2. URL\n")

        while True:
            target_opt = input("Select option [1-2]: ").strip()
            if target_opt in ["1", "2"]:
                break
            else:
                print("[!] Invalid option. Please select 1 or 2.")

        if target_opt == "1":
            target_input = input("\nEnter IP address: ").strip()
            target = parse_target(target_input, mode=mode, source="interactive")

        elif target_opt == "2":
            target_input = input("\nEnter URL: ").strip()

            print("\nSelect port mode:\n")
            print("1. Default Port")
            print("2. Custom Port\n")

            while True:
                port_opt = input("Select option [1-2]: ").strip()
                if port_opt in ["1", "2"]:
                    break
                else:
                    print("[!] Invalid option. Please select 1 or 2.")

            if port_opt == "2":
                while True:
                    port_str = input("\nEnter port: ").strip()
                    if port_str.isdigit() and 1 <= int(port_str) <= 65535:
                        port = int(port_str)
                        break
                    else:
                        print("[!] Invalid port. Please enter 1-65535.")

                target = parse_target(target_input, mode=mode, source="interactive")
                target.port = port
                target.url = f"{target.scheme}://{target.hostname or target.ip}:{port}"
            else:
                target = parse_target(target_input, mode=mode, source="interactive")
                if not target.port:
                    if target.scheme == "https":
                        target.port = 443
                    else:
                        target.port = 80
                        if not target.scheme:
                            target.scheme = "http"
                        target.url = f"{target.scheme}://{target.hostname or target.ip}:{target.port}"

                print(f"[*] Using default port: {target.port}")

        return target
    except KeyboardInterrupt:
        print("\n\n[!] ReconForge interactive menu cancelled by user. Exiting.")
        sys.exit(0)
    except EOFError:
        print("\n\n[!] Input stream closed. Exiting.")
        sys.exit(1)


def print_tools():
    registry = ToolRegistry()
    print("ReconForge Tool Availability\n")
    categories = registry.get_tools_by_category()

    for category, tools in categories.items():
        print(f"{category}")
        for tool in tools:
            status = "[+]" if registry.is_installed(tool.name) else "[-]"
            print(f"  {status} {tool.name}")
        print()


def main():
    parser = argparse.ArgumentParser(description="ReconForge Offline Reconnaissance Analyzer")
    parser.add_argument("--version", action="version", version=f"ReconForge v{__version__}")
    parser.add_argument("--test", action="store_true", help="Run local tests")
    parser.add_argument("-u", "--url", help="URL target")
    parser.add_argument("--mode", choices=["standard", "low-impact"], help="Reconnaissance mode")
    parser.add_argument("--plan", action="store_true", help="Only plan the execution")
    parser.add_argument("--execute", action="store_true", help="Execute the planned tools")

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
        subparsers.add_parser("tools", help="List external tools availability")

    args, unknown = parser.parse_known_args()

    if args.test:
        print("[*] Running ReconForge test suite...")
        try:
            subprocess.run(["python", "-m", "pytest", "tests/"], check=True)
        except subprocess.CalledProcessError:
            print("[!] Tests failed.")
            sys.exit(1)
        except FileNotFoundError:
            print("[!] pytest not found. Please ensure it is installed (pip install pytest).")
            sys.exit(1)
        sys.exit(0)

    session_manager = SessionManager()

    if has_command:
        if args.command == "import":
            if not os.path.isdir(args.directory):
                print(f"[!] Error: Directory {args.directory} does not exist.")
                sys.exit(1)
            target = Analyzer().analyze_directory(args.directory)
            session = session_manager.create_session(target)
            print(f"[*] Created session: {session.id}")
            _handle_output(target, args.format, getattr(args, 'output', None))
            sys.exit(0)
        elif args.command == "analyze":
            if not os.path.isfile(args.file):
                print(f"[!] Error: File {args.file} does not exist.")
                sys.exit(1)
            target = Analyzer().analyze_file(args.file)
            session = session_manager.create_session(target)
            print(f"[*] Created session: {session.id}")
            _handle_output(target, args.format, getattr(args, 'output', None))
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
                session = session_manager.get_current() if args.session_id == "current" else session_manager.load_session(args.session_id)
                _handle_output(session.target, "terminal", None)
            except Exception as e:
                print(f"[!] Error: {str(e)}")
                sys.exit(1)
            sys.exit(0)
        elif args.command == "report":
            try:
                session = session_manager.get_current() if args.session_id == "current" else session_manager.load_session(args.session_id)
                _handle_output(session.target, args.format, getattr(args, 'output', None))
            except Exception as e:
                print(f"[!] Error: {str(e)}")
                sys.exit(1)
            sys.exit(0)
        elif args.command == "waf":
            try:
                session = session_manager.get_current() if args.session_id == "current" else session_manager.load_session(args.session_id)
                TerminalReporter().report_waf(session.target)
            except Exception as e:
                print(f"[!] Error: {str(e)}")
                sys.exit(1)
            sys.exit(0)
        elif args.command == "tools":
            print_tools()
            sys.exit(0)

    target_str = args.url or (unknown[0] if unknown else None)
    if target_str:
        mode = "WAF-Aware Low-Impact Recon" if args.mode == "low-impact" else "Standard Recon"
        recon_target = parse_target(target_str, mode=mode, source="cli")
        planner = ReconPlanner()
        plan = planner.plan(recon_target)
        session = session_manager.create_session(recon_target)
        plan.output_directory = session_manager.get_session_dir(session.id)
        plan_file = os.path.join(plan.output_directory, "plan.json")
        with open(plan_file, "w", encoding="utf-8") as f:
            import json
            import dataclasses
            json.dump(dataclasses.asdict(plan), f, indent=2)

        if getattr(args, "execute", False):
            from reconforge.execution.backend import RealExecutionBackend
            backend = RealExecutionBackend()
        else:
            backend = PlanningOnlyBackend()
        result = backend.execute(plan)

        if getattr(args, "execute", False) and result:
            reporter = TerminalReporter()
            reporter.report(result)
            json_path = os.path.join(plan.output_directory, "report.json")
            JSONReporter().report(result, json_path)
            html_path = os.path.join(plan.output_directory, "report.html")
            HTMLReporter().report(result, html_path)
            print("\nEVIDENCE & REPORTS")
            print(f"  {json_path}")
            print(f"  {html_path}")
        sys.exit(0)

    if not has_command and not unknown and not args.url:
        recon_target = interactive_menu()
        planner = ReconPlanner()
        plan = planner.plan(recon_target)
        backend = PlanningOnlyBackend()
        result = backend.execute(plan)
        if result:
            TerminalReporter().report(result)
        sys.exit(0)

    parser.print_help()


def _handle_output(target, format, output_file):
    if format == "terminal":
        TerminalReporter().report(target)
    elif format == "json":
        output_file = output_file or "report.json"
        JSONReporter().report(target, output_file)
        print(f"[+] JSON report saved to {output_file}")
    elif format == "html":
        output_file = output_file or "report.html"
        HTMLReporter().report(target, output_file)
        print(f"[+] HTML report saved to {output_file}")


# Replace only the interactive path while retaining the existing command-line API.
from reconforge.interactive import install_cli_overrides
install_cli_overrides(sys.modules[__name__])

if __name__ == "__main__":
    main()
