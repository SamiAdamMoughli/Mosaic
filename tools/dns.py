"""
DNS enumeration tools — amass, subfinder, dnsx, dig, fierce.

Argv construction stays in Python. Go runner handles execution.
"""

from tools.registry import tool
from tools.runner_client import run_tool


@tool(
    description=(
        "Run amass for comprehensive subdomain enumeration. "
        "Combines passive sources (crt.sh, VirusTotal, Shodan, etc.) "
        "and active DNS resolution. "
        "Examples: 'enum -passive -d example.com' or "
        "'enum -active -d example.com -ip'"
    ),
    schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Root domain e.g. example.com"},
            "args":   {"type": "string", "description": "amass subcommand + flags"},
        },
        "required": ["target"],
    },
)
async def amass(target: str, args: str = "enum -passive") -> str:
    argv = ["amass"] + args.split() + ["-d", target]
    return await run_tool("amass", argv=argv, target=target, timeout=300)


@tool(
    description=(
        "Run subfinder for fast passive subdomain discovery. "
        "Uses 40+ passive sources. Fastest option for initial subdomain recon. "
        "Example args: '-silent' or '-all -recursive'"
    ),
    schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Root domain"},
            "args":   {"type": "string", "description": "subfinder flags"},
        },
        "required": ["target"],
    },
)
async def subfinder(target: str, args: str = "-silent") -> str:
    argv = ["subfinder", "-d", target] + args.split()
    return await run_tool("subfinder", argv=argv, target=target, timeout=120)


@tool(
    description=(
        "Run dnsx to resolve hostnames, probe DNS records, or brute-force "
        "subdomains. Accepts a domain or a path to a host list file. "
        "Examples: '-a -resp -l hosts.txt' or '-d example.com -w wordlist.txt'"
    ),
    schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Domain or path to host list"},
            "args":   {"type": "string", "description": "dnsx flags"},
        },
        "required": ["target"],
    },
)
async def dnsx(target: str, args: str = "-a -resp -silent") -> str:
    if target.endswith(".txt") or ("/" in target and not target.startswith("http")):
        argv = ["dnsx", "-l", target] + args.split()
    else:
        argv = ["dnsx", "-d", target] + args.split()
    return await run_tool("dnsx", argv=argv, target=target, timeout=120)


@tool(
    description=(
        "Run dig to query DNS records. "
        "Use for specific record lookups, zone transfers (AXFR), "
        "or investigating DNS infrastructure. "
        "Examples: 'example.com ANY' or '@ns1.example.com example.com AXFR'"
    ),
    schema={
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Full dig query string"},
        },
        "required": ["query"],
    },
)
async def dig(query: str) -> str:
    argv = ["dig", "+noall", "+answer"] + query.split()
    # No scope check: query is a DNS record type expression, not a single target
    return await run_tool("dig", argv=argv, target="", timeout=15)


@tool(
    description=(
        "Run fierce for DNS reconnaissance — finds non-contiguous IP space, "
        "hostnames, and subdomains via brute force and dictionary attack."
    ),
    schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Root domain"},
            "args":   {"type": "string", "description": "fierce flags"},
        },
        "required": ["target"],
    },
)
async def fierce(target: str, args: str = "") -> str:
    argv = ["fierce", "--domain", target] + (args.split() if args else [])
    return await run_tool("fierce", argv=argv, target=target, timeout=180)
