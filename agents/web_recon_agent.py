"""
Web Recon Agent — Claude Sonnet 4.6.

Deep web reconnaissance: crawls the app with katana, brute-forces
directories with ffuf, pulls historical URLs via gau, screenshots
with gowitness, and runs the full nuclei template suite. Builds a
complete picture of the web attack surface.
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

logger = logging.getLogger(__name__)

WEB_TOOLS = ["httpx", "nuclei", "katana", "ffuf", "gowitness", "gau"]


class WebReconAgent(BaseAgent):
    """Deep web reconnaissance — crawling, fuzzing, historical URL analysis."""

    role = "web_recon"

    def __init__(
        self,
        scope: Scope,
        store: FindingsStore,
        audit: AuditLog,
        llm: LLMClient,
    ):
        registry = ToolRegistry(scope, enabled=WEB_TOOLS)
        super().__init__(store, registry, audit, llm)

    def system_prompt(self) -> str:
        return (
            "You are a web reconnaissance specialist on an authorised red team.\n"
            "You have a specific web target to investigate thoroughly.\n\n"
            "Work through these phases:\n\n"
            "PHASE 1 — Surface mapping:\n"
            "  - gau: pull all historical URLs from Wayback/CommonCrawl\n"
            "  - katana: crawl live app including JS files (-d 4 -jc -aff)\n"
            "  - Analyse endpoint patterns from both sources\n\n"
            "PHASE 2 — Directory and file discovery:\n"
            "  - ffuf: brute-force directories with a large wordlist\n"
            "  - Target interesting paths: /api/, /admin/, /backup/, "
            "/.git/, /config/, /swagger/, /.env\n"
            "  - Run ffuf with -mc 200,301,302,403 and note 403s "
            "(they exist but are blocked)\n\n"
            "PHASE 3 — Vulnerability scan:\n"
            "  - nuclei: run full template suite\n"
            "    -t cves/ -t exposures/ -t misconfiguration/ "
            "-t http/technologies/ -severity low,medium,high,critical\n\n"
            "PHASE 4 — Visual recon:\n"
            "  - gowitness: screenshot the target for the report\n\n"
            "Document all endpoints found, interesting parameters, "
            "authentication mechanisms, API patterns, and any nuclei findings."
        )

    async def _parse_and_store(
        self, tool_name: str, args: dict, result: str
    ) -> None:
        if not result or result.startswith("ERROR"):
            return
        target = args.get("target", "")

        if tool_name == "gau":
            urls = [l.strip() for l in result.splitlines() if l.strip()]
            await self.store.add(Finding(
                type=FindingType.ENDPOINT,
                source_agent=self.role,
                data={"target": target, "source": "gau", "urls": urls[:500]},
            ))

        elif tool_name == "katana":
            endpoints = [l.strip() for l in result.splitlines() if l.strip()]
            await self.store.add(Finding(
                type=FindingType.ENDPOINT,
                source_agent=self.role,
                data={"target": target, "source": "katana", "endpoints": endpoints[:500]},
            ))

        elif tool_name == "ffuf":
            await self.store.add(Finding(
                type=FindingType.ENDPOINT,
                source_agent=self.role,
                data={"target": target, "source": "ffuf", "output": result[:3000]},
            ))

        elif tool_name == "nuclei":
            if result.strip():
                await self.store.add(Finding(
                    type=FindingType.WEB_FINDING,
                    source_agent=self.role,
                    data={"target": target, "nuclei_output": result[:3000]},
                ))
