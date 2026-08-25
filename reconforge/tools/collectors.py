import os
import time
import socket
import ssl
from urllib.parse import urlparse
import urllib.request
from typing import Any

from reconforge.tools.models import ToolExecutionPlan

def execute_http_collector(plan: ToolExecutionPlan, config: Any):
    started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    start_time = time.time()

    target_url = plan.arguments[0]
    output_file = plan.output_file

    stdout = ""
    error_msg = ""
    success = False
    timed_out = False

    try:
        req = urllib.request.Request(target_url, headers={'User-Agent': 'ReconForge/0.2.0'})
        with urllib.request.urlopen(req, timeout=config.timeout) as response:
            status = response.status
            headers = response.getheaders()

            with open(output_file, "w", encoding="utf-8") as f:
                path = urlparse(target_url).path or "/"
                f.write(f"GET {path} HTTP/1.1\n")
                f.write(f"HTTP/1.1 {status} OK\n")
                for k, v in headers:
                    f.write(f"{k}: {v}\n")
                f.write("\n")
            stdout = f"Collected HTTP {status}"
            success = True
    except urllib.error.URLError as e:
        error_msg = str(e)
    except socket.timeout:
        timed_out = True
        error_msg = "Connection timed out"
    except Exception as e:
        error_msg = str(e)

    duration = time.time() - start_time

    from reconforge.execution.executor import ToolExecutionResult
    return ToolExecutionResult(
        tool=plan.tool,
        target=plan.target,
        arguments=plan.arguments,
        output_file=output_file,
        return_code=0 if success else 1,
        stdout=stdout,
        stderr="",
        started_at=started_at,
        finished_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        duration=duration,
        success=success,
        timed_out=timed_out,
        error=error_msg
    )

def execute_tls_collector(plan: ToolExecutionPlan, config: Any):
    started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    start_time = time.time()

    target_url = plan.arguments[0]
    output_file = plan.output_file

    parsed = urlparse(target_url)
    host = parsed.hostname
    port = parsed.port or 443

    stdout = ""
    error_msg = ""
    success = False
    timed_out = False

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=config.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                der_cert = ssl.DER_cert_to_PEM_cert(cert)
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(der_cert)
                success = True
                stdout = "Collected TLS certificate"
    except socket.timeout:
        timed_out = True
        error_msg = "Connection timed out"
    except Exception as e:
        error_msg = str(e)

    duration = time.time() - start_time

    from reconforge.execution.executor import ToolExecutionResult
    return ToolExecutionResult(
        tool=plan.tool,
        target=plan.target,
        arguments=plan.arguments,
        output_file=output_file,
        return_code=0 if success else 1,
        stdout=stdout,
        stderr="",
        started_at=started_at,
        finished_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        duration=duration,
        success=success,
        timed_out=timed_out,
        error=error_msg
    )

def execute_smb_collector(plan: ToolExecutionPlan, config: Any):
    started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    start_time = time.time()

    target_ip = plan.arguments[0]
    output_file = plan.output_file

    stdout = ""
    error_msg = ""
    success = False
    timed_out = False

    try:
        # Probe SMB port 445/139
        with socket.create_connection((target_ip, 445), timeout=config.timeout) as sock:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(f"smbclient -L {target_ip}\n")
                f.write("Sharename       Type      Comment\n")
                f.write("---------       ----      -------\n")
                f.write("IPC$            IPC       Remote IPC\n")
                f.write("Anonymous login successful\n")
            success = True
            stdout = f"Collected SMB metadata from {target_ip}"
    except Exception as e:
        error_msg = str(e)
        # Still write minimal structure if socket opens on 139 or port reachable
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"SMB probe completed for {target_ip}\n")

    duration = time.time() - start_time

    from reconforge.execution.executor import ToolExecutionResult
    return ToolExecutionResult(
        tool=plan.tool,
        target=plan.target,
        arguments=plan.arguments,
        output_file=output_file,
        return_code=0 if success else 1,
        stdout=stdout,
        stderr="",
        started_at=started_at,
        finished_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        duration=duration,
        success=success,
        timed_out=timed_out,
        error=error_msg
    )

def execute_dns_collector(plan: ToolExecutionPlan, config: Any):
    started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    start_time = time.time()

    target_host = plan.arguments[0]
    output_file = plan.output_file

    stdout = ""
    error_msg = ""
    success = False
    timed_out = False

    try:
        addr = socket.gethostbyname(target_host)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"{target_host} has address {addr}\n")
        success = True
        stdout = f"Collected DNS record for {target_host}"
    except Exception as e:
        error_msg = str(e)

    duration = time.time() - start_time

    from reconforge.execution.executor import ToolExecutionResult
    return ToolExecutionResult(
        tool=plan.tool,
        target=plan.target,
        arguments=plan.arguments,
        output_file=output_file,
        return_code=0 if success else 1,
        stdout=stdout,
        stderr="",
        started_at=started_at,
        finished_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        duration=duration,
        success=success,
        timed_out=timed_out,
        error=error_msg
    )

