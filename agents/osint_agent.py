"""
OSINT Collector — Perplexity Sonar Pro.

Uses live web search baked into the model to gather intelligence:
emails, employee names, leaked credentials, org structure, ASN info,
tech stack from job postings, and anything publicly visible.
No tool loops needed — the model searches and reasons natively.
Also invokes theHarvester and whois for structured data.
"""

import logging

from agents.base import BaseAgent
from core.audit import AuditLog
from core.scope import Scope
from llm.client import LLMClient
from memory.models import Finding, FindingType
from memory.store import FindingsStore
from tools.registry import ToolRegistry
import tools.osint  # noqa: registers theharvester, whois, shodan, curl_fetch

logger = logging.getLogger(__name__)

OSINT_TOOLS = ["theharvester", "whois", "shodan", "curl_fetch"]


class OSINTAgent(BaseAgent):
    """Collects open-source intelligence on the target organisation."""

    role = "osint_collector"

    def __init__(
        self,
        scope: Scope,
        store: FindingsStore,
        audit: AuditLog,
        llm: LLMClient,
    ):
        registry = ToolRegistry(scope, enabled=OSINT_TOOLS)
        super().__init__(store, registry, audit, llm)

    def system_prompt(self) -> str:
        return (
            "You are an OSINT specialist on an authorised internal red team.\n"
            "Your mission: gather all publicly available intelligence about "
            "the target organisation and its digital footprint.\n\n"
            "Investigate:\n"
            "- Email addresses and employee names (LinkedIn, GitHub, job ads)\n"
            "- Subdomains and IP ranges visible on the internet\n"
            "- Technology stack revealed by job postings and GitHub repos\n"
            "- Leaked credentials in breach databases (HaveIBeenPwned, etc.)\n"
            "- ASN and IP block ownership via RDAP/ARIN\n"
            "- SSL certificates (crt.sh) to discover shadow IT domains\n"
            "- Cloud asset exposure (S3 buckets, Azure blobs)\n"
            "- Historic content via Wayback Machine\n\n"
            "Use your built-in web search for research, and tools for "
            "structured enumeration. Document every finding with source."
        )

    async def _parse_and_store(
        self, tool_name: str, args: dict, result: str
    ) -> None:
        if not result or result.startswith("ERROR"):
            return
        if tool_name == "theharvester":
            await self.store.add(Finding(
                type=FindingType.ORG_INFO,
                source_agent=self.role,
                data={"tool": "theHarvester", "output": result[:2000]},
            ))
        elif tool_name == "whois":
            await self.store.add(Finding(
                type=FindingType.ORG_INFO,
                source_agent=self.role,
                data={"tool": "whois", "target": args.get("target"), "output": result[:1000]},
            ))
        elif tool_name == "shodan":
            await self.store.add(Finding(
                type=FindingType.EXPOSURE,
                source_agent=self.role,
                data={"tool": "shodan", "query": args.get("query"), "output": result[:2000]},
            ))
