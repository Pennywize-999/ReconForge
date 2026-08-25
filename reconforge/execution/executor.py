import os
import subprocess
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any

from reconforge.tools.models import ToolExecutionPlan
from reconforge.core.config import load_config

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

        if plan.tool == "smb_collector":
            from reconforge.tools.collectors import execute_smb_collector
            return execute_smb_collector(plan, self.config)

        if plan.tool == "dns_collector":
            from reconforge.tools.collectors import execute_dns_collector
            return execute_dns_collector(plan, self.config)


        started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        start_time = time.time()

        command = [plan.tool] + plan.arguments

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
                timeout=self.config.timeout,
                shell=False
            )
            stdout_content = result.stdout
            stderr_content = result.stderr
            return_code = result.returncode
            success = (return_code == 0)
            if not success:
                error_msg = f"Command failed with exit code {return_code}"

        except subprocess.TimeoutExpired as e:
            timed_out = True
            error_msg = f"Timed out after {self.config.timeout} seconds"
            if e.stdout:
                stdout_content = e.stdout.decode('utf-8', errors='ignore') if isinstance(e.stdout, bytes) else e.stdout
            if e.stderr:
                stderr_content = e.stderr.decode('utf-8', errors='ignore') if isinstance(e.stderr, bytes) else e.stderr
        except FileNotFoundError:
            error_msg = f"Executable not found: {plan.tool}"
        except Exception as e:
            error_msg = str(e)

        end_time = time.time()
        finished_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        duration = end_time - start_time

        if plan.output_file and not os.path.exists(plan.output_file) and stdout_content and success:
             # some tools like rustscan or dirb might output directly to stdout if -o is not respected
             # though our adapters use output files. If they failed to write, we can fallback to stdout.
             pass

        # Write exec log
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
            error=error_msg
        )
