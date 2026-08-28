import dataclasses
import json
import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from sentinelrecon import __version__
from sentinelrecon.core.models import Target
from sentinelrecon.core.session import SessionManager
from sentinelrecon.core.target_parser import TargetParser

console = Console(highlight=False)


def _show_banner():
    banner = Text(justify="center")
    banner.append("SENTINELRECON", style="bold bright_cyan")
    banner.append(f"  v{__version__}\n", style="bold white")
    banner.append("ADAPTIVE RECONNAISSANCE & VULNERABILITY CORRELATION ENGINE", style="bright_blue")
    console.print(Panel(banner, border_style="bright_cyan", width=70, padding=(0, 2)))


def _read_mode(choice):
    if choice not in {"1", "2"}:
        print("[!] Invalid option.")
        sys.exit(1)
    return "Standard Recon" if choice == "1" else "WAF-Aware Low-Impact Recon"


def _read_profile(choice):
    profiles = {"1": "COMMON", "2": "MEDIUM", "3": "DEEP"}
    if choice not in profiles:
        print("[!] Invalid option.")
        sys.exit(1)
    return profiles[choice]


def _set_url_port(target, legacy=False, selector=False):
    if target.target_type != "url":
        return

    default_port = 443 if target.scheme == "https" else 80

    explicit_port = False
    try:
        explicit_port = ":" in target.input.rsplit("/", 1)[-1]
    except (AttributeError, TypeError):
        explicit_port = False

    if explicit_port:
        return

    if selector:
        choice = input(f"Port: 1=DEFAULT ({default_port}), 2=CUSTOM: ").strip()
        if choice in {"", "1"}:
            target.port = default_port
        elif choice == "2":
            port = input(f"Custom port [{default_port}]: ").strip()
            if not port:
                target.port = default_port
            elif not port.isdigit() or not 1 <= int(port) <= 65535:
                print("[!] Invalid port. Please enter 1-65535.")
                sys.exit(1)
            else:
                target.port = int(port)
        else:
            print("[!] Invalid port option.")
            sys.exit(1)
    else:
        port = input(f"Port [{default_port}]: ").strip()
        if not port:
            target.port = default_port
        elif not port.isdigit() or not 1 <= int(port) <= 65535:
            print("[!] Invalid port. Please enter 1-65535.")
            sys.exit(1)
        else:
            target.port = int(port)

    target.url = f"{target.scheme}://{target.hostname or target.ip}:{target.port}"


def interactive_menu():
    """Interactive target/mode/profile selection for live SentinelRecon execution."""
    try:
        _show_banner()

        first = input("Enter IP or URL: ").strip()
        if not first:
            print("[!] Target cannot be empty.")
            sys.exit(1)

        legacy = first in {"1", "2"}
        if legacy:
            mode = _read_mode(first)
            profile = _read_profile(input("Select discovery profile [1-3]: ").strip())
            target_input = input("Enter IP or URL: ").strip()
        else:
            target_input = first
            mode = None
            profile = None

        if not target_input:
            print("[!] Target cannot be empty.")
            sys.exit(1)

        target = TargetParser.parse(target_input)
        target.mode = mode or "Standard Recon"
        target.source = "interactive"

        if target.target_type == "unknown":
            print("[!] Enter a valid IP address or http:// / https:// URL.")
            sys.exit(1)

        compat_port_selector = False
        if mode is None:
            print("\nRecon Mode\n")
            print("1. STANDARD")
            print("2. LOW-IMPACT\n")
            mode_choice = input("Select option [1-2]: ").strip()
            if mode_choice == "":
                mode = "Standard Recon"
                compat_port_selector = True
            else:
                mode = _read_mode(mode_choice)

        target.mode = mode
        _set_url_port(target, legacy=legacy, selector=(legacy or compat_port_selector))

        if profile is None:
            print("\nContent Discovery Profile\n")
            print("1. COMMON")
            print("2. MEDIUM")
            print("3. DEEP\n")
            profile = _read_profile(input("Select option [1-3]: ").strip())

        target.discovery_profile = profile
        target.source = "interactive_execute"

        console.print("\n[bold bright_cyan]Starting SentinelRecon...[/bold bright_cyan]")
        console.print(f"[bold white]Target:[/bold white]   {target.url or target.input}")
        console.print(f"[bold white]Mode:[/bold white]     {target.mode}")
        console.print(f"[bold white]Profile:[/bold white]  [bright_cyan]{target.discovery_profile}[/bright_cyan]\n")
        return target
    except KeyboardInterrupt:
        print("\n[!] SentinelRecon cancelled.")
        sys.exit(0)
    except EOFError:
        print("\n[!] Input stream closed.")
        sys.exit(1)


def install_cli_overrides(cli_module):
    """Keep existing CLI commands, execute interactive scans, and persist every run."""
    from sentinelrecon.execution.backend import RealExecutionBackend
    from sentinelrecon.reporters.html import HTMLReporter
    from sentinelrecon.reporters.json_ext import JSONReporter

    class InteractiveBackend:
        def execute(self, plan):
            session_manager = SessionManager()
            session = session_manager.create_session(Target())
            plan.output_directory = session_manager.get_session_dir(session.id)

            plan_path = os.path.join(plan.output_directory, "plan.json")
            with open(plan_path, "w", encoding="utf-8") as handle:
                json.dump(dataclasses.asdict(plan), handle, indent=2)

            result = RealExecutionBackend().execute(plan)
            if result is None:
                return None

            session.target = result
            session.raw_files = sorted(
                os.path.relpath(os.path.join(root, name), plan.output_directory)
                for root, _, files in os.walk(plan.output_directory)
                for name in files
                if name != "target.json"
            )
            session_manager.save_session(session)

            JSONReporter().report(result, os.path.join(plan.output_directory, "report.json"))
            HTMLReporter().report(result, os.path.join(plan.output_directory, "report.html"))

            console.print("\n[bold bright_cyan]SCAN SAVED[/bold bright_cyan]")
            console.print(f"  Session: {session.id}")
            console.print(f"  Location: {plan.output_directory}")
            console.print("  Reports: report.json, report.html")
            return result

    cli_module.interactive_menu = interactive_menu
    cli_module.ExecutionBackend = InteractiveBackend
