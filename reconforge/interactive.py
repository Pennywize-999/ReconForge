import sys

from reconforge import __version__
from reconforge.core.target_parser import parse_target


def interactive_menu():
    """Interactive target/mode/profile selection for live ReconForge execution."""
    try:
        print("+----------------------------------------------------------+")
        print(f"|                    RECONFORGE v{__version__:<12}              |")
        print("|           FIRST-LEVEL RECONNAISSANCE ENGINE               |")
        print("+----------------------------------------------------------+\n")

        target_input = input("Enter IP or URL: ").strip()
        if not target_input:
            print("[!] Target cannot be empty.")
            sys.exit(1)

        target = parse_target(target_input, mode="Standard Recon", source="interactive")
        if target.target_type == "unknown":
            print("[!] Enter a valid IP address or http:// / https:// URL.")
            sys.exit(1)

        if target.target_type == "url" and target.port is None:
            default_port = 443 if target.scheme == "https" else 80
            port = input(f"Port [{default_port}]: ").strip()
            if port:
                if not port.isdigit() or not 1 <= int(port) <= 65535:
                    print("[!] Invalid port. Please enter 1-65535.")
                    sys.exit(1)
                target.port = int(port)
            else:
                target.port = default_port
            target.url = f"{target.scheme}://{target.hostname or target.ip}:{target.port}"

        print("\nRecon Mode\n")
        print("1. STANDARD")
        print("2. LOW-IMPACT\n")
        mode_choice = input("Select option [1-2]: ").strip()
        if mode_choice not in {"1", "2"}:
            print("[!] Invalid option.")
            sys.exit(1)
        target.mode = "Standard Recon" if mode_choice == "1" else "WAF-Aware Low-Impact Recon"

        print("\nContent Discovery Profile\n")
        print("1. COMMON")
        print("2. EXTENDED")
        print("3. DEEP\n")
        profile_choice = input("Select option [1-3]: ").strip()
        profiles = {"1": "COMMON", "2": "EXTENDED", "3": "DEEP"}
        if profile_choice not in profiles:
            print("[!] Invalid option.")
            sys.exit(1)
        target.discovery_profile = profiles[profile_choice]
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
