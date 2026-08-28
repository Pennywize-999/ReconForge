"""ReconForge CLI compatibility entrypoint redirecting to SentinelRecon."""

from sentinelrecon.cli import _handle_output, main, print_tools
from sentinelrecon.execution.backend import RealExecutionBackend
from sentinelrecon.interactive import interactive_menu

PlanningOnlyBackend = RealExecutionBackend

__all__ = ["main", "interactive_menu", "print_tools", "_handle_output", "PlanningOnlyBackend"]

if __name__ == "__main__":
    main()
