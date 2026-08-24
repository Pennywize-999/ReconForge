import os
import time
import socket
import ssl
from urllib.parse import urlparse
import urllib.request
from typing import Any

from reconforge.tools.models import ToolExecutionPlan


HTTP_BODY_LIMIT = 1024 * 1024


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
        req = urllib.request.Request(target_url, headers={'User-Agent': 'ReconForge/1.0.0'})
        with urllib.request.urlopen(req, timeout=config.timeout) as response:
            status = response.status
            headers = response.getheaders()
            final_url = response.geturl()
            content_type = response.headers.get("Content-Type", "")
            body_bytes = response.read(HTTP_BODY_LIMIT)
            charset = "utf-8"
            if "charset=" in content_type.lower():
                charset = content_type.lower().split("charset=", 1)[1].split(";", 1)[0].strip() or "utf-8"
            try:
                body = body_bytes.decode(charset, errors="replace")
            except LookupError:
                body = body_bytes.decode("utf-8", errors="replace")

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(f"Request-URL: {target_url}\n")
                f.write(f"Final-URL: {final_url}\n")
                f.write(f"HTTP/1.1 {status} OK\n")
                for k, v in headers:
                    f.write(f"{k}: {v}\n")
                f.write("\n")
                # Keep a bounded copy of the response body so application
                # fingerprinting can identify frameworks/CMSs that do not
                # expose themselves through Server headers alone.
                f.write(body)
            stdout = f"Collected HTTP {status} ({len(body_bytes)} body bytes)"
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
