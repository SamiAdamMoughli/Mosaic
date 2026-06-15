"""
Port Scanner — Gemini 2.5 Flash.

Triggered by HOST findings from the network mapper. Runs deep port
scans on individual hosts: full TCP range, UDP top ports, service
version detection, and default script scanning. Writes PORT and
SERVICE findings back to the blackboard.
"""

import logging
import re

from agents.base import BaseAgent
from core.audit import AuditLog
from core.scope import Scope
from llm.client import LLMClient
from memory.models import Finding, FindingType
from memory.store import FindingsStore
from tools.registry import ToolRegistry
import tools.network  # noqa: registers nmap, masscan, rustscan

logger = logging.getLogger(__name__)

PORT_TOOLS = ["nmap", "rustscan"]

_PORT_RE = re.compile(r"(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?")


class PortScannerAgent(BaseAgent):
    """Deep port and service scanning on discovered hosts."""

    role = "port_scanner"

    def __init__(
        self,
        scope: Scope,
        store: FindingsStore,
        audit: AuditLog,
        llm: LLMClient,
    ):
        registry = ToolRegistry(scope, enabled=PORT_TOOLS)
        super().__init__(store, registry, audit, llm)

    def system_prompt(self) -> str:
        return (
            "You are a port scanning specialist on an authorised red team.\n"
            "You receive a single host IP as your target.\n\n"
            "Process:\n"
            "1. Run rustscan first to rapidly identify all open TCP ports.\n"
            "2. Feed those ports into nmap with -sV -sC for service "
            "detection and default scripts.\n"
            "3. Run nmap -sU --top-ports 100 for UDP service discovery.\n"
            "4. For interesting services (databases, management interfaces, "
            "unusual ports), run targeted nmap scripts.\n\n"
            "Nmap script examples:\n"
            "  - SSH: nmap --script ssh-hostkey,ssh-auth-methods\n"
            "  - SMB: nmap --script smb-os-discovery,smb-security-mode\n"
            "  - HTTP: nmap --script http-title,http-headers,http-methods\n"
            "  - SMTP: nmap --script smtp-open-relay,smtp-commands\n\n"
            "Record every open port with service and version. Flag anything "
            "unusual: non-standard ports for known services, management "
            "interfaces, databases exposed without authentication indicators."
        )

    async def _parse_and_store(
        self, tool_name: str, args: dict, result: str
    ) -> None:
        if not result or result.startswith("ERROR"):
            return
        target = args.get("target", "")

        for match in _PORT_RE.finditer(result):
            port, service, version = match.groups()
            await self.store.add(Finding(
                type=FindingType.PORT,
                source_agent=self.role,
                data={
                    "host": target,
                    "port": int(port),
                    "protocol": "tcp",
                    "service": service,
                    "version": (version or "").strip(),
                },
                dedup_key=f"port:{target}:{port}/tcp",
            ))

        # Store full scan output as a service record
        if result:
            await self.store.add(Finding(
                type=FindingType.SERVICE,
                source_agent=self.role,
                data={"host": target, "tool": tool_name, "output": result[:3000]},
            ))
