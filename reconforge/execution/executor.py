import os
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

from reconforge.tools.models import ToolExecutionPlan
from reconforge.core.config import load_config


# Keep potentially slow fingerprinting bounded. A service that does not answer
# must not make the complete ReconForge run appear frozen.
TOOL_TIMEOUTS = {
    "whatweb": 45,
}


@dataclass
class ToolExecutionResult:
    tool: str
    target: str
    arguments: list
    output_file: str
    return_code: Optional[int]
    stdout: str
    stderr: str
    started_at: str
    finished_at: str
    duration: float
    success: bool
    timed_out: bool
    error: str


class ToolExecutor:
    def __init__(self):
        self.config = load_config()

    def execute(self, plan: ToolExecutionPlan) -> ToolExecutionResult:
        if plan.tool == "http_collector":
            from reconforge.tools.collectors import execute_http_collector
            return execute_http_collector(plan, self.config)

        if plan.tool == "tls_collector":
            from reconforge.tools.collectors import execute_tls_collector
            return execute_tls_collector(plan, self.config)

        started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        start_time = time.time()

        command = [plan.tool] + plan.arguments
        timeout = min(self.config.timeout, TOOL_TIMEOUTS.get(plan.tool, self.config.timeout))

        stdout_content = ""
        stderr_content = ""
        return_code = None
        success = False
        timed_out = False
        error_msg = ""

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                # Never allow an external reconnaissance utility to consume
                # the user's terminal input. Some tools can pause when stdin is
                # attached to a TTY, which previously looked like a frozen scan
                # until the user pressed Space/Enter.
                stdin=subprocess.DEVNULL,
            )
            stdout_content = result.stdout or ""
            stderr_content = result.stderr or ""
            return_code = result.returncode
            success = return_code == 0
            if not success:
                error_msg = f"Command failed with exit code {return_code}"

        except subprocess.TimeoutExpired as exc:
            timed_out = True
            error_msg = f"Timed out after {timeout} seconds"
            if exc.stdout:
                stdout_content = exc.stdout.decode("utf-8", errors="ignore") if isinstance(exc.stdout, bytes) else exc.stdout
            if exc.stderr:
                stderr_content = exc.stderr.decode("utf-8", errors="ignore") if isinstance(exc.stderr, bytes) else exc.stderr
        except FileNotFoundError:
            error_msg = f"Executable not found: {plan.tool}"
        except Exception as exc:
            error_msg = str(exc)

        end_time = time.time()
        finished_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        duration = end_time - start_time

        if plan.output_file:
            base, _ = os.path.splitext(plan.output_file)
            log_file = f"{base}_exec.log"
            with open(log_file, "w", encoding="utf-8") as f:
                f.write(f"COMMAND: {' '.join(command)}\n")
                f.write(f"STDOUT:\n{stdout_content}\n")
                f.write(f"STDERR:\n{stderr_content}\n")

        return ToolExecutionResult(
            tool=plan.tool,
            target=plan.target,
            arguments=command,
            output_file=plan.output_file,
            return_code=return_code,
            stdout=stdout_content,
            stderr=stderr_content,
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
            success=success,
            timed_out=timed_out,
            error=error_msg,
        )
