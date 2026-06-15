"""
Service Fingerprinter — GPT-4o-mini.

Triggered by PORT findings for HTTP/HTTPS services. Uses httpx for
fast probing and nuclei for technology and misconfiguration detection.
Interprets banners, headers, and response patterns to build a detailed
picture of what's running before the web recon agent goes deep.
"""

import logging

from agents.base import BaseAgent
from core.audit import AuditLog
from core.scope import Scope
from llm.client import LLMClient
from memory.models import Finding, FindingType
from memory.store import FindingsStore
from tools.registry import ToolRegistry
import tools.web  # noqa: registers httpx, nuclei, katana, ffuf, gowitness, gau
import tools.network  # noqa: registers nmap (for script scans)

logger = logging.getLogger(__name__)

FINGERPRINT_TOOLS = ["httpx", "nuclei", "nmap"]


class ServiceFingerprinterAgent(BaseAgent):
    """Identifies services, technologies, and surface-level misconfigurations."""

    role = "service_fingerprinter"

    def __init__(
        self,
        scope: Scope,
        store: FindingsStore,
        audit: AuditLog,
        llm: LLMClient,
    ):
        registry = ToolRegistry(scope, enabled=FINGERPRINT_TOOLS)
        super().__init__(store, registry, audit, llm)

    def system_prompt(self) -> str:
        return (
            "You are a service fingerprinting specialist on an authorised red team.\n"
            "You are given a host and port to fingerprint.\n\n"
            "Process:\n"
            "1. Run httpx with full fingerprinting flags to identify:\n"
            "   server, title, status code, content-length, tech stack, CDN.\n"
            "   Use: -sc -title -server -td -cdn -json\n"
            "2. Run nuclei with technology detection templates:\n"
            "   -t http/technologies/ -t http/exposures/ -json\n"
            "3. If the service looks like a specific product (Grafana, "
            "Jenkins, GitLab, etc.), run nmap with targeted scripts.\n"
            "4. Check for default credentials indicators, exposed admin "
            "panels, version disclosures in headers or error pages.\n\n"
            "Output a clear summary: what is running, what version, "
            "and any immediate red flags (unauthenticated endpoints, "
            "default creds patterns, version-specific CVE candidates)."
        )

    async def _parse_and_store(
        self, tool_name: str, args: dict, result: str
    ) -> None:
        if not result or result.startswith("ERROR"):
            return
        target = args.get("target", "")

        if tool_name == "httpx":
            await self.store.add(Finding(
                type=FindingType.WEB_TECH,
                source_agent=self.role,
                data={"target": target, "httpx_output": result[:2000]},
            ))

        elif tool_name == "nuclei":
            if result and result != "no findings":
                await self.store.add(Finding(
                    type=FindingType.WEB_FINDING,
                    source_agent=self.role,
                    data={"target": target, "nuclei_output": result[:2000]},
                ))
