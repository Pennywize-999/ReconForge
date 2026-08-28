"""Interactive reconnaissance UX for live SentinelRecon execution."""

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


def _read_mode(choice: str) -> str:
    choice = choice.strip()
    if choice not in {"1", "2", "standard", "low-impact"}:
        print("[!] Invalid option. Selecting Standard Recon by default.")
        return "Standard Recon"
    return "Standard Recon" if choice in {"1", "standard"} else "WAF-Aware Low-Impact Recon"


def _set_url_port(target, selector: bool = False):
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
                print("[!] Invalid port. Using default port.")
                target.port = default_port
            else:
                target.port = int(port)
        else:
            target.port = default_port
    else:
        target.port = default_port

    target.url = f"{target.scheme}://{target.hostname or target.ip}:{target.port}"


def interactive_menu():
    """Interactive target and mode selection for live SentinelRecon execution.

    Autonomous discovery replaces manual depth selection.
    """
    try:
        _show_banner()

        first = input("Enter IP, hostname, or URL: ").strip()
        if not first:
            print("[!] Target cannot be empty.")
            sys.exit(1)

        # Legacy compatibility: if user input was a mode selection number '1' or '2'
        legacy_mode = first in {"1", "2"}
        if legacy_mode:
            mode = _read_mode(first)
            target_input = input("Enter IP, hostname, or URL: ").strip()
            if not target_input:
                print("[!] Target cannot be empty.")
                sys.exit(1)
        else:
            target_input = first
            mode = None

        target = TargetParser.parse(target_input)
        if target.target_type == "unknown":
            print("[!] Enter a valid IP address, hostname, or http:// / https:// URL.")
            sys.exit(1)

        if mode is None:
            console.print("\n[bold cyan]Recon Mode:[/bold cyan]\n")
            console.print("  [bold white]1.[/bold white] Standard Recon")
            console.print("  [bold white]2.[/bold white] Low-Impact Recon (WAF/Firewall-Conscious)\n")
            mode_choice = input("Select mode [1-2] (default: 1): ").strip()
            mode = _read_mode(mode_choice if mode_choice else "1")

        target.mode = mode
        target.source = "interactive_execute"
        target.discovery_profile = "AUTONOMOUS"

        _set_url_port(target, selector=True if target.target_type == "url" else False)

        console.print("\n[bold bright_cyan]Starting SentinelRecon...[/bold bright_cyan]")
        console.print(f"[bold white]Target:[/bold white]   {target.url or target.input}")
        console.print(f"[bold white]Mode:[/bold white]     {target.mode}\n")
        return target
    except KeyboardInterrupt:
        print("\n[!] SentinelRecon cancelled.")
        sys.exit(0)
    except EOFError:
        print("\n[!] Input stream closed.")
        sys.exit(1)
