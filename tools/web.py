"""
Web reconnaissance tools — httpx, nuclei, katana, ffuf, gowitness, gau.

Argv construction stays in Python. Go runner handles execution.
"""

from tools.registry import tool
from tools.runner_client import run_tool


@tool(
    description=(
        "Run httpx for fast HTTP probing. Identifies status codes, titles, "
        "server banners, TLS info, CDN, and web technology fingerprints. "
        "Example args: '-sc -title -server -td -cdn -json' or "
        "'-follow-redirects -mc 200,301'"
    ),
    schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "URL, host, IP, or file of targets"},
            "args":   {"type": "string", "description": "httpx flags"},
        },
        "required": ["target"],
    },
)
async def httpx(target: str, args: str = "-sc -title -server -td -json") -> str:
    if target.endswith(".txt") or ("/" in target and not target.startswith("http")):
        argv = ["httpx", "-l", target] + args.split()
    else:
        argv = ["httpx", "-u", target] + args.split()
    return await run_tool("httpx", argv=argv, target=target, timeout=120)


@tool(
    description=(
        "Run nuclei for vulnerability and misconfiguration scanning. "
        "Example args: '-t cves/ -severity high,critical' or "
        "'-t exposures/ -t misconfiguration/' or "
        "'-t http/technologies/ -tags wordpress'"
    ),
    schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "URL or file of URLs"},
            "args":   {"type": "string", "description": "nuclei flags including -t templates"},
        },
        "required": ["target"],
    },
)
async def nuclei(target: str, args: str = "-t exposures/ -t misconfiguration/ -json") -> str:
    if target.endswith(".txt"):
        argv = ["nuclei", "-l", target] + args.split()
    else:
        argv = ["nuclei", "-u", target] + args.split()
    return await run_tool("nuclei", argv=argv, target=target, timeout=600)


@tool(
    description=(
        "Run katana for web crawling and endpoint discovery. "
        "Crawls JS files, finds API endpoints, forms, and parameters. "
        "Example args: '-d 3 -jc -ef css,png,jpg'"
    ),
    schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "URL to crawl"},
            "args":   {"type": "string", "description": "katana flags"},
        },
        "required": ["target"],
    },
)
async def katana(target: str, args: str = "-d 3 -jc -silent") -> str:
    argv = ["katana", "-u", target] + args.split()
    return await run_tool("katana", argv=argv, target=target, timeout=300)


@tool(
    description=(
        "Run ffuf for web fuzzing — directory brute-force, parameter fuzzing, "
        "vhost discovery. FUZZ keyword is replaced by wordlist entries. "
        "Example args: '-w /usr/share/wordlists/dirb/common.txt -mc 200,301,403 -t 50'"
    ),
    schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "URL with FUZZ placeholder"},
            "args":   {"type": "string", "description": "ffuf flags including -w wordlist"},
        },
        "required": ["target"],
    },
)
async def ffuf(target: str, args: str = "") -> str:
    argv = ["ffuf", "-u", target] + (args.split() if args else [])
    return await run_tool("ffuf", argv=argv, target=target, timeout=300)


@tool(
    description=(
        "Run gowitness to take screenshots of web targets. "
        "Useful for visually triaging large sets of discovered web services. "
        "Example args: 'scan single -u https://target.com'"
    ),
    schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "URL or file of URLs"},
            "args":   {"type": "string", "description": "gowitness flags"},
        },
        "required": ["target"],
    },
)
async def gowitness(target: str, args: str = "") -> str:
    if target.endswith(".txt"):
        argv = ["gowitness", "file", "-f", target] + (args.split() if args else [])
    else:
        argv = ["gowitness", "scan", "single", "-u", target] + (
            args.split() if args else []
        )
    return await run_tool("gowitness", argv=argv, target=target, timeout=300)


@tool(
    description=(
        "Run gau to pull historical URLs from Wayback Machine, Common Crawl, "
        "and OTX for a domain. Great for discovering forgotten endpoints. "
        "Example args: '--subs --blacklist png,jpg,gif,css'"
    ),
    schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Domain name"},
            "args":   {"type": "string", "description": "gau flags"},
        },
        "required": ["target"],
    },
)
async def gau(target: str, args: str = "--subs") -> str:
    argv = ["gau", target] + (args.split() if args else [])
    return await run_tool("gau", argv=argv, target=target, timeout=120)
