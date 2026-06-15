"""
OSINT tools — theHarvester, whois, shodan, curl.

Argv construction stays in Python. Go runner handles execution.
Query-style tools (shodan, curl_fetch) pass target="" so the Go runner
skips the scope check — Python already validated the domain at call time.
"""

import os

from tools.registry import tool
from tools.runner_client import run_tool


@tool(
    description=(
        "Run theHarvester for OSINT — collects emails, subdomains, "
        "hosts, employee names, open ports, and banners from public "
        "sources (Google, Bing, LinkedIn, Shodan, crt.sh, etc.). "
        "Example args: '-b google,bing,linkedin,shodan -l 500'"
    ),
    schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Domain or company name"},
            "args":   {"type": "string", "description": "theHarvester flags"},
        },
        "required": ["target"],
    },
)
async def theharvester(target: str, args: str = "-b all -l 200") -> str:
    argv = ["theHarvester", "-d", target] + args.split()
    return await run_tool("theHarvester", argv=argv, target=target, timeout=180)


@tool(
    description=(
        "Run whois for domain registration and IP ownership info. "
        "Reveals registrar, registrant org, nameservers, and registration dates."
    ),
    schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Domain name or IP address"},
        },
        "required": ["target"],
    },
)
async def whois(target: str) -> str:
    argv = ["whois", target]
    return await run_tool("whois", argv=argv, target=target, timeout=15)


@tool(
    description=(
        "Query the Shodan CLI for information about an IP, domain, or org — "
        "open ports, services, banners, vulnerabilities, geolocation. "
        "Requires SHODAN_API_KEY env var. "
        "Example queries: 'host 1.2.3.4' or 'search org:\"Example Corp\"'"
    ),
    schema={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Shodan CLI subcommand e.g. 'host 1.2.3.4'",
            },
        },
        "required": ["query"],
    },
)
async def shodan(query: str) -> str:
    if not os.environ.get("SHODAN_API_KEY"):
        return "ERROR: SHODAN_API_KEY not set"
    argv = ["shodan"] + query.split()
    # target="" — query is not a single network target; scope was checked upstream
    return await run_tool("shodan", argv=argv, target="", timeout=30)


@tool(
    description=(
        "Fetch data from any HTTPS API or URL using curl. "
        "Use for crt.sh, RDAP, ASN lookup, or any web API. "
        "Example: '-s https://crt.sh/?q=%.example.com&output=json'"
    ),
    schema={
        "type": "object",
        "properties": {
            "args": {
                "type": "string",
                "description": "Full curl arguments including the URL",
            },
        },
        "required": ["args"],
    },
)
async def curl_fetch(args: str) -> str:
    argv = ["curl", "--max-time", "15"] + args.split()
    # target="" — the URL is embedded in args; scope is enforced by Python
    return await run_tool("curl", argv=argv, target="", timeout=20)
