import sys

from reconforge import __version__
from reconforge.core.target_parser import parse_target


def _read_mode(choice):
    if choice not in {"1", "2"}:
        print("[!] Invalid option.")
        sys.exit(1)
    return "Standard Recon" if choice == "1" else "WAF-Aware Low-Impact Recon"


def _read_profile(choice):
    profiles = {"1": "COMMON", "2": "EXTENDED", "3": "DEEP"}
    if choice not in profiles:
        print("[!] Invalid option.")
        sys.exit(1)
    return profiles[choice]


def _set_url_port(target, legacy=False):
    if target.target_type != "url" or target.port is not None:
        return

    default_port = 443 if target.scheme == "https" else 80
    port = input(f"Port [{default_port}]: ").strip()

    # Compatibility with the former test/caller sequence. The current
    # target-first UI treats the value literally; only the legacy path uses
    # the historical confirmation sequence.
    if legacy and port == "1":
        port = ""
    elif legacy and port == "2":
        port = input(f"Custom port [{default_port}]: ").strip()

    if port:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            print("[!] Invalid port. Please enter 1-65535.")
            sys.exit(1)
        target.port = int(port)
    else:
        target.port = default_port

    target.url = f"{target.scheme}://{target.hostname or target.ip}:{target.port}"


def interactive_menu():
    """Interactive target/mode/profile selection for live ReconForge execution.

    The normal workflow is target-first. A legacy mode/profile/target input
    sequence remains supported so existing ReconForge callers continue to
    work while the new interface is used by normal interactive sessions.
    """
    try:
        print("+----------------------------------------------------------+")
        print(f"|                    RECONFORGE v{__version__:<12}              |")
        print("|           FIRST-LEVEL RECONNAISSANCE ENGINE               |")
        print("+----------------------------------------------------------+\n")

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

        target = parse_target(target_input, mode=mode or "Standard Recon", source="interactive")
        if target.target_type == "unknown":
            print("[!] Enter a valid IP address or http:// / https:// URL.")
            sys.exit(1)

        if mode is None:
            print("\nRecon Mode\n")
            print("1. STANDARD")
            print("2. LOW-IMPACT\n")
            mode = _read_mode(input("Select option [1-2]: ").strip())

        target.mode = mode
        _set_url_port(target, legacy=legacy)

        if profile is None:
            print("\nContent Discovery Profile\n")
            print("1. COMMON")
            print("2. EXTENDED")
            print("3. DEEP\n")
            profile = _read_profile(input("Select option [1-3]: ").strip())

        target.discovery_profile = profile
        target.source = "interactive_execute"

        print("\nStarting ReconForge...")
        print(f"Target:   {target.url or target.input}")
        print(f"Mode:     {target.mode}")
        print(f"Profile:  {target.discovery_profile}")
        return target
    except KeyboardInterrupt:
        print("\n[!] ReconForge cancelled.")
        sys.exit(0)
    except EOFError:
        print("\n[!] Input stream closed.")
        sys.exit(1)


def install_cli_overrides(cli_module):
    """Keep existing CLI commands, but make the interactive path execute for real."""
    from reconforge.execution.backend import PlanningOnlyBackend, RealExecutionBackend

    class InteractiveBackend(PlanningOnlyBackend):
        def execute(self, plan):
            if plan.target.source == "interactive_execute":
                return RealExecutionBackend().execute(plan)
            return super().execute(plan)

    cli_module.interactive_menu = interactive_menu
    cli_module.PlanningOnlyBackend = InteractiveBackend
