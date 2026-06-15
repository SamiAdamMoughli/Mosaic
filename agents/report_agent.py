"""
Report Synthesiser — Gemini 2.5 Pro.

Runs at campaign end. Pulls all findings from the blackboard, holds
the full context in its 1M-token window, and produces a structured
recon report: attack surface summary, notable findings, prioritised
targets, and recommendations.
"""

import logging

from agents.base import BaseAgent
from core.audit import AuditLog
from core.scope import Scope
from llm.client import LLMClient
from memory.models import Finding, FindingType
from memory.store import FindingsStore
from tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class ReportAgent(BaseAgent):
    """Synthesises all blackboard findings into a structured recon report."""

    role = "report_synthesiser"

    def __init__(
        self,
        scope: Scope,
        store: FindingsStore,
        audit: AuditLog,
        llm: LLMClient,
    ):
        registry = ToolRegistry(scope, enabled=[])
        super().__init__(store, registry, audit, llm)
        self._scope = scope

    def system_prompt(self) -> str:
        return (
            "You are a senior red team analyst producing the final recon report.\n"
            "You have been given the complete findings from an automated "
            "reconnaissance campaign.\n\n"
            "Produce a structured report with these sections:\n\n"
            "## Executive Summary\n"
            "3-5 sentences. What was in scope, what was found, top risk.\n\n"
            "## Attack Surface Overview\n"
            "- Total live hosts, open ports, web services discovered\n"
            "- DNS footprint: subdomain count, notable exposures\n"
            "- OSINT highlights: emails, leaked data, tech stack clues\n\n"
            "## Notable Findings\n"
            "List each significant finding with:\n"
            "  - What it is\n"
            "  - Why it matters (attack potential)\n"
            "  - Source agent and evidence\n\n"
            "## Prioritised Targets\n"
            "Rank the most interesting targets for follow-on testing, "
            "with rationale for each.\n\n"
            "## Recommendations\n"
            "Quick wins the defender should address immediately.\n\n"
            "Be specific — include IPs, hostnames, ports, and URLs. "
            "No vague statements."
        )

    async def generate(self) -> str:
        """Pull all findings and generate the report."""
        all_findings = await self.store.query()
        summary = await self.store.get_summary()

        findings_text = "\n".join(str(f) for f in all_findings)
        summary_text = str(summary)

        prompt = (
            f"Campaign findings summary by type: {summary_text}\n\n"
            f"All findings ({len(all_findings)} total):\n\n"
            f"{findings_text}\n\n"
            "Generate the full recon report now."
        )

        from memory.models import Task
        task = Task(goal=prompt)
        await self.assign(task)
        # Run one iteration and capture the report from the store
        await self._react(task)

        # Return the most recent SUMMARY finding
        summaries = await self.store.query(types=[FindingType.SUMMARY])
        if summaries:
            return summaries[-1].data.get("report", "")
        return ""

    async def _on_complete(self, summary: str, task: "Task") -> None:  # type: ignore[override]
        if summary:
            await self.store.add(Finding(
                type=FindingType.SUMMARY,
                source_agent=self.role,
                data={"report": summary},
            ))
            logger.info("[report] report written to findings store")
