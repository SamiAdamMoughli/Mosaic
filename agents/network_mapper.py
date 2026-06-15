"""
Network Mapper — Gemini 2.5 Flash.

Maps live hosts and network topology using nmap and masscan.
Fast tool-calling loop: broad sweep first, then targeted follow-up
on interesting segments. Feeds HOST and NETWORK_MAP findings to
the blackboard for the port scanner and orchestrator to act on.
"""

import logging

from agents.base import BaseAgent
from core.audit import AuditLog
from core.scope import Scope
from llm.client import LLMClient
from memory.models import Finding, FindingType
from memory.store import FindingsStore
from tools.registry import ToolRegistry
import tools.network  # noqa: registers nmap, masscan, rustscan

logger = logging.getLogger(__name__)

NETWORK_TOOLS = ["nmap", "masscan", "rustscan"]


class NetworkMapperAgent(BaseAgent):
    """Discovers live hosts and maps network topology."""

    role = "network_mapper"

    def __init__(
        self,
        scope: Scope,
        store: FindingsStore,
        audit: AuditLog,
        llm: LLMClient,
    ):
        registry = ToolRegistry(scope, enabled=NETWORK_TOOLS)
        super().__init__(store, registry, audit, llm)
        self._scope_cidrs = [str(n) for n in scope.networks]

    def system_prompt(self) -> str:
        cidrs = ", ".join(self._scope_cidrs)
        return (
            "You are a network mapping specialist on an authorised red team.\n"
            f"In-scope ranges: {cidrs}\n\n"
            "Mission: discover every live host in scope and understand "
            "the network topology.\n\n"
            "Strategy:\n"
            "1. Use nmap -sn (ping sweep) for host discovery across each CIDR.\n"
            "2. For large ranges (>500 hosts), use masscan first for speed.\n"
            "3. For very large ranges, rustscan finds open ports faster "
            "than nmap — use it for initial triage.\n"
            "4. Run nmap -O (OS detection) on representative hosts to "
            "understand what you're dealing with.\n"
            "5. Note subnet structure — /24s, /16s, VLAN boundaries.\n\n"
            "Be methodical. Cover every CIDR in scope. Report all live "
            "hosts with their IPs. Flag anything unexpected: /8s, "
            "unexpected subnets, or hosts that don't respond to ICMP "
            "but have open TCP ports."
        )

    async def _parse_and_store(
        self, tool_name: str, args: dict, result: str
    ) -> None:
        if not result or result.startswith("ERROR"):
            return
        target = args.get("target", "")

        # Try to extract IPs from nmap output
        if tool_name in ("nmap", "masscan", "rustscan"):
            for line in result.splitlines():
                line = line.strip()
                # nmap "Nmap scan report for X" or masscan "Discovered open port"
                if line.startswith("Nmap scan report for "):
                    ip = line.split()[-1].strip("()")
                    await self.store.add(Finding(
                        type=FindingType.HOST,
                        source_agent=self.role,
                        data={"ip": ip, "source_range": target},
                        dedup_key=f"host:{ip}",
                    ))
                elif line.startswith("Discovered open port"):
                    parts = line.split()
                    if len(parts) >= 6:
                        ip = parts[-1]
                        port = parts[3].split("/")[0]
                        await self.store.add(Finding(
                            type=FindingType.PORT,
                            source_agent=self.role,
                            data={"ip": ip, "port": port, "tool": tool_name},
                            dedup_key=f"port:{ip}:{port}",
                        ))

            # Store full output as network map
            await self.store.add(Finding(
                type=FindingType.NETWORK_MAP,
                source_agent=self.role,
                data={"target": target, "tool": tool_name, "output": result[:3000]},
            ))
