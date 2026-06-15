"""
DNS Enumerator — Gemini 2.5 Flash.

Runs comprehensive DNS reconnaissance: passive subdomain enumeration
via amass + subfinder, active resolution via dnsx, zone transfer
attempts, and brute-force with fierce. Fast tool-calling loop.
"""

import logging

from agents.base import BaseAgent
from core.audit import AuditLog
from core.scope import Scope
from llm.client import LLMClient
from memory.models import Finding, FindingType
from memory.store import FindingsStore
from tools.registry import ToolRegistry
import tools.dns  # noqa: registers amass, subfinder, dnsx, dig, fierce

logger = logging.getLogger(__name__)

DNS_TOOLS = ["amass", "subfinder", "dnsx", "dig", "fierce"]


class DNSAgent(BaseAgent):
    """Enumerates the DNS attack surface: subdomains, records, zone transfers."""

    role = "dns_enumerator"

    def __init__(
        self,
        scope: Scope,
        store: FindingsStore,
        audit: AuditLog,
        llm: LLMClient,
    ):
        registry = ToolRegistry(scope, enabled=DNS_TOOLS)
        super().__init__(store, registry, audit, llm)

    def system_prompt(self) -> str:
        return (
            "You are a DNS enumeration specialist on an authorised red team.\n"
            "Your mission: map the complete DNS footprint of the target.\n\n"
            "Process:\n"
            "1. Run subfinder first — fastest passive subdomain discovery.\n"
            "2. Run amass enum -passive for broader passive coverage.\n"
            "3. Resolve all discovered subdomains with dnsx to find live ones.\n"
            "4. Attempt zone transfer (AXFR) against each discovered nameserver.\n"
            "5. Use dig to investigate interesting DNS records (MX, TXT, SPF, DMARC).\n"
            "6. Run fierce for brute-force discovery of unlisted subdomains.\n\n"
            "Record every live subdomain and IP. Flag anything unusual: "
            "internal hostnames leaking, misconfigured SPF/DMARC, "
            "wildcard DNS, or zone transfers that succeed."
        )

    async def _parse_and_store(
        self, tool_name: str, args: dict, result: str
    ) -> None:
        if not result or result.startswith("ERROR"):
            return
        target = args.get("target", args.get("query", ""))

        if tool_name in ("subfinder", "amass", "fierce", "dnsx"):
            for line in result.splitlines():
                line = line.strip()
                if line and "." in line and not line.startswith("["):
                    await self.store.add(Finding(
                        type=FindingType.SUBDOMAIN,
                        source_agent=self.role,
                        data={"subdomain": line, "tool": tool_name, "root": target},
                        dedup_key=f"subdomain:{line.lower()}",
                    ))

        elif tool_name == "dig":
            await self.store.add(Finding(
                type=FindingType.DNS_RECORD,
                source_agent=self.role,
                data={"query": target, "output": result[:1000]},
            ))

        axfr_attempted = tool_name == "dig" and "AXFR" in args.get("query", "")
        if axfr_attempted and "Transfer failed" not in result:
            await self.store.add(Finding(
                type=FindingType.ZONE_XFER,
                source_agent=self.role,
                data={"nameserver": target, "output": result[:2000]},
            ))
