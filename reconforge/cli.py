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
        from rich.console import Console
        from rich.panel import Panel
        console = Console()
        console.print(Panel("╔══════════════════════════════════════╗\n║            RECONFORGE                ║\n║      Fast Adaptive Recon Engine      ║\n╚══════════════════════════════════════╝", expand=False, style="bold blue"))
        print()

        target_input = input("Target:\n> ").strip()
        if not target_input:
            print("[!] Target cannot be empty.")
            sys.exit(1)

        print("\nRecon Mode:\n")
        print("1. Standard Recon")
        print("2. WAF-Aware Low-Impact Recon\n")

        while True:
            mode_opt = input("Select mode: ").strip()
            if mode_opt == "1":
                mode = "Standard Recon"
                break
            elif mode_opt == "2":
                mode = "WAF-Aware Low-Impact Recon"
                break
            else:
                print("[!] Invalid option. Please select 1 or 2.")

        print("\nRecon Depth:\n")
        print("1. Common")
        print("2. Medium")
        print("3. Deep\n")

        while True:
            depth_opt = input("Select depth: ").strip()
            if depth_opt == "1":
                depth = "Common"
                break
            elif depth_opt == "2":
                depth = "Medium"
                break
            elif depth_opt == "3":
                depth = "Deep"
                break
            else:
                print("[!] Invalid option. Please select 1, 2, or 3.")

        target = parse_target(target_input, mode=mode, depth=depth, source="interactive")
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

    # Global arguments
    parser.add_argument("-u", "--url", help="URL target")
    parser.add_argument("--mode", choices=["standard", "low-impact"], help="Reconnaissance mode")
    parser.add_argument("--depth", choices=["common", "medium", "deep"], default="common", help="Reconnaissance depth")
    parser.add_argument("--plan", action="store_true", help="Only plan the execution")
    parser.add_argument("--execute", action="store_true", help="Execute the planned tools")


    # We will only add subparsers if the command is actually one of the subparser commands
    # Otherwise argparse will throw an invalid choice error on IPs like 10.0.0.1
    known_commands = ["import", "analyze", "sessions", "show", "report", "waf", "tools"]
    has_command = any(arg in known_commands for arg in sys.argv[1:])

    if has_command:
        subparsers = parser.add_subparsers(dest="command", help="Available commands")


    if has_command:
        # Import command
        import_parser = subparsers.add_parser("import", help="Import and analyze a directory of scan results")
        import_parser.add_argument("directory", help="Directory containing reconnaissance files")
        import_parser.add_argument("--format", choices=["terminal", "json", "html"], default="terminal", help="Output format")
        import_parser.add_argument("--output", help="Output file (for json/html formats)")

        # Analyze command
        analyze_parser = subparsers.add_parser("analyze", help="Analyze a single file")
        analyze_parser.add_argument("file", help="File to analyze")
        analyze_parser.add_argument("--format", choices=["terminal", "json", "html"], default="terminal", help="Output format")
        analyze_parser.add_argument("--output", help="Output file (for json/html formats)")

        # Sessions command
        subparsers.add_parser("sessions", help="List all analysis sessions")

        # Show command
        show_parser = subparsers.add_parser("show", help="Show an analysis session")
        show_parser.add_argument("session_id", help="Session ID or 'current'")

        # Report command
        report_parser = subparsers.add_parser("report", help="Generate a report for a session")
        report_parser.add_argument("session_id", help="Session ID or 'current'")
        report_parser.add_argument("--format", choices=["terminal", "json", "html"], default="terminal", help="Output format")
        report_parser.add_argument("--output", help="Output file (for json/html formats)")

        # WAF command
        waf_parser = subparsers.add_parser("waf", help="Show WAF/CDN analysis for a session")
        waf_parser.add_argument("session_id", help="Session ID or 'current'")

        # Tools command
        subparsers.add_parser("tools", help="List external tools availability")

    # If the user passes only global args but no command, parser.parse_args handles it.
    # However, if they pass a command, we don't treat the first arg as a 'target' unless it's not a command.
    # The way argparse handles optional positional args alongside subparsers can be tricky.
    # Since subparsers are optional in our setup (because of `target` being optional positional),
    # let's manually parse known args first.

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

            analyzer = Analyzer()
            target = analyzer.analyze_directory(args.directory)
            session = session_manager.create_session(target)
            print(f"[*] Created session: {session.id}")
            _handle_output(target, args.format, getattr(args, 'output', None))
            sys.exit(0)

        elif args.command == "analyze":
            if not os.path.isfile(args.file):
                print(f"[!] Error: File {args.file} does not exist.")
                sys.exit(1)

            analyzer = Analyzer()
            target = analyzer.analyze_file(args.file)
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
                print()
            sys.exit(0)

        elif args.command == "show":
            try:
                if args.session_id == "current":
                    session = session_manager.get_current()
                else:
                    session = session_manager.load_session(args.session_id)
                _handle_output(session.target, "terminal", None)
            except Exception as e:
                print(f"[!] Error: {str(e)}")
                sys.exit(1)
            sys.exit(0)

        elif args.command == "report":
            try:
                if args.session_id == "current":
                    session = session_manager.get_current()
                else:
                    session = session_manager.load_session(args.session_id)
                _handle_output(session.target, args.format, getattr(args, 'output', None))
            except Exception as e:
                print(f"[!] Error: {str(e)}")
                sys.exit(1)
            sys.exit(0)

        elif args.command == "waf":
            try:
                if args.session_id == "current":
                    session = session_manager.get_current()
                else:
                    session = session_manager.load_session(args.session_id)

                reporter = TerminalReporter()
                reporter.report_waf(session.target)
            except Exception as e:
                print(f"[!] Error: {str(e)}")
                sys.exit(1)
            sys.exit(0)

        elif args.command == "tools":
            print_tools()
            sys.exit(0)

    target_str = args.url
    if not target_str and unknown:
        target_str = unknown[0]

    recon_target = None
    if not has_command and not target_str:
        recon_target = interactive_menu()

    if target_str or recon_target:
        if not recon_target:
            mode = "Standard Recon"
            if args.mode == "low-impact":
                mode = "WAF-Aware Low-Impact Recon"

            depth = "Common"
            if getattr(args, "depth", None):
                d_val = args.depth.lower()
                if d_val == "medium":
                    depth = "Medium"
                elif d_val == "deep":
                    depth = "Deep"

            recon_target = parse_target(target_str, mode=mode, depth=depth, source="cli")


        planner = ReconPlanner()
        plan = planner.plan(recon_target)

        session = session_manager.create_session(recon_target)
        plan.output_directory = session_manager.get_session_dir(session.id)

        # Save plan to session
        plan_file = os.path.join(plan.output_directory, "plan.json")
        with open(plan_file, "w") as f:
            import json
            import dataclasses
            from reconforge.core.models import SafeJSONEncoder
            json.dump(plan, f, cls=SafeJSONEncoder, indent=2)

        if getattr(args, "plan", False):
            backend = PlanningOnlyBackend()
        else:
            from reconforge.execution.backend import RealExecutionBackend
            backend = RealExecutionBackend()

        result = backend.execute(plan)

        if not getattr(args, "plan", False) and result:
            from reconforge.reporters.terminal import TerminalReporter
            from reconforge.reporters.json_ext import JSONReporter
            from reconforge.reporters.html import HTMLReporter

            reporter = TerminalReporter()
            reporter.report(result)

            json_rep = JSONReporter()
            json_path = os.path.join(plan.output_directory, "report.json")
            json_rep.report(result, json_path)

            html_rep = HTMLReporter()
            html_path = os.path.join(plan.output_directory, "report.html")
            html_rep.report(result, html_path)

        sys.exit(0)



    parser.print_help()


def _handle_output(target, format, output_file):
    if format == "terminal":
        reporter = TerminalReporter()
        reporter.report(target)
    elif format == "json":
        if not output_file:
            output_file = "report.json"
        reporter = JSONReporter()
        reporter.report(target, output_file)
        print(f"[+] JSON report saved to {output_file}")
    elif format == "html":
        if not output_file:
            output_file = "report.html"
        reporter = HTMLReporter()
        reporter.report(target, output_file)
        print(f"[+] HTML report saved to {output_file}")


if __name__ == "__main__":
    main()
