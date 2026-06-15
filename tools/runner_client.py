"""
HTTP client for the Go tool execution runner (tools-runner/main.go).

Python builds the argv for each tool (it already knows the quirks —
subfinder takes -d, rustscan takes -a, etc.). Go receives the full
argv and handles:
  - exec.CommandContext: child process dies the instant the campaign
    is killed, no orphaned nmap/nuclei processes left behind
  - goroutine-based semaphores: concurrency limiting without asyncio overhead
  - scope enforcement: second gate at the execution boundary

If the runner is not reachable (not built / not started), every tool
call returns an ERROR string so agents fail gracefully rather than crashing.
"""

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_RUNNER_URL = os.environ.get("RECON_RUNNER_URL", "http://127.0.0.1:7373")
_client: Any = None  # httpx.AsyncClient, created lazily


def _get_client():
    """Lazy singleton — avoids import cost on modules that never run."""
    global _client
    if _client is None:
        import httpx
        _client = httpx.AsyncClient(base_url=_RUNNER_URL, timeout=None)
    return _client


async def run_tool(
    tool: str,
    argv: list[str],
    target: str = "",
    timeout: int = 600,
) -> str:
    """
    Send a tool call to the Go runner.

    Args:
        tool:    Tool name (used by Go for concurrency limiting + logging).
        argv:    Full command array — Python constructs this, Go execs it.
        target:  Host/IP/URL being acted on; empty skips Go's scope check.
        timeout: Seconds before Go kills the subprocess.

    Returns raw stdout from the tool, or "ERROR: ..." / "SCOPE VIOLATION: ...".
    """
    client = _get_client()
    payload = {
        "tool": tool,
        "argv": argv,
        "target": target,
        "timeout": timeout,
    }

    try:
        resp = await client.post(
            "/run",
            json=payload,
            timeout=float(timeout + 30),
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.error("[runner] HTTP error for %s: %s", tool, exc)
        return f"ERROR: runner unavailable ({exc}). Build it: make runner"

    if data.get("scope_violation"):
        from core.stop import stop
        stop.trigger(f"scope_violation:{data['error']}")
        return f"SCOPE VIOLATION: {data['error']} — campaign halted"

    if data.get("error"):
        return f"ERROR: {data['error']}"

    return data.get("output", "")


async def close() -> None:
    """Close the shared HTTP client. Call once at campaign end."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


async def wait_ready(timeout: float = 10.0) -> bool:
    """
    Poll /health until the Go runner responds or timeout expires.
    Returns True if the runner is up.
    """
    import asyncio
    import httpx

    deadline = asyncio.get_event_loop().time() + timeout
    async with httpx.AsyncClient(base_url=_RUNNER_URL) as probe:
        while asyncio.get_event_loop().time() < deadline:
            try:
                r = await probe.get("/health", timeout=1.0)
                if r.status_code == 200:
                    return True
            except Exception:
                pass
            await asyncio.sleep(0.15)
    return False
