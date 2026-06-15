"""
Network scanning tools — nmap, masscan, rustscan.

Argv construction stays in Python (each tool has its own flag conventions).
Actual subprocess execution is delegated to the Go runner which provides
context-propagated cancellation and goroutine-based concurrency limiting.
"""

from tools.registry import tool
from tools.runner_client import run_tool


@tool(
    description=(
        "Run nmap against a target with arbitrary arguments. "
        "Use for host discovery (-sn), port scanning (-sV), "
        "service detection (-sC), OS detection (-O), etc. "
        "Examples: '-sn 10.0.0.0/24' or '-sV -sC -p- -T4 10.0.0.5' "
        "or '-sU --top-ports 100 10.0.0.5'"
    ),
    schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "IP, CIDR, or hostname"},
            "args":   {"type": "string", "description": "nmap flags"},
        },
        "required": ["target"],
    },
)
async def nmap(target: str, args: str = "-sV --top-ports 1000 -T4") -> str:
    argv = ["nmap"] + args.split() + [target]
    return await run_tool("nmap", argv=argv, target=target, timeout=600)


@tool(
    description=(
        "Run masscan for high-speed port discovery across large ranges. "
        "Faster than nmap for initial discovery; use nmap for service detail. "
        "Example: '--ports 0-65535 --rate 1000 10.0.0.0/24'"
    ),
    schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "CIDR range or IP"},
            "args":   {"type": "string", "description": "masscan flags"},
        },
        "required": ["target"],
    },
)
async def masscan(target: str, args: str = "--ports 1-65535 --rate 1000") -> str:
    argv = ["masscan"] + args.split() + [target]
    return await run_tool("masscan", argv=argv, target=target, timeout=600)


@tool(
    description=(
        "Run rustscan for extremely fast initial port discovery. "
        "Fastest option for finding open ports before detailed scanning."
    ),
    schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "IP or CIDR"},
            "args":   {"type": "string", "description": "rustscan flags"},
        },
        "required": ["target"],
    },
)
async def rustscan(target: str, args: str = "-b 500 --timeout 2000") -> str:
    argv = ["rustscan", "-a", target] + args.split()
    return await run_tool("rustscan", argv=argv, target=target, timeout=300)
