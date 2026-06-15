"""
Strategic Orchestrator — o3.

Plans the campaign, decides which agents to activate at each phase,
and reacts to findings by spawning the right specialist. Processes
findings in batches so one LLM call covers many discoveries at once,
enabling true parallel team operation.

Hierarchy:
  Orchestrator
    ├── OSINTAgent         (Perplexity Sonar Pro)
    ├── DNSAgent           (Gemini 2.5 Flash)
    ├── NetworkMapperAgent (Gemini 2.5 Flash)
    ├── PortScannerAgent   (Gemini 2.5 Flash)  ← spawned per host
    ├── ServiceFingerprinterAgent (GPT-4o-mini) ← spawned per HTTP service
    ├── WebReconAgent      (Claude Sonnet 4.6)  ← spawned per web app
    └── ReportAgent        (Gemini 2.5 Pro)
"""

import asyncio
import logging

from core.audit import AuditLog
from core.scope import Scope
from core.stop import stop
from llm.client import LLMClient
from memory.models import Finding, FindingType, Task
from memory.store import FindingsStore
from tools.registry import ToolRegistry
from agents.base import BaseAgent

logger = logging.getLogger(__name__)

# Collect findings for up to this many seconds before making a batch decision
BATCH_WINDOW = 2.0
BATCH_MAX = 30

# Max port scanner agents running concurrently. Each holds an nmap slot in the
# Go runner (capped at 3 there), so 10 here = at most 3 actual nmap processes.
# Without this, a /16 could queue thousands of tasks.
PORT_SCANNER_CAP = 10


class OrchestratorAgent(BaseAgent):
    """Plans and coordinates the full recon team."""

    role = "orchestrator"

    def __init__(
        self,
        scope: Scope,
        store: FindingsStore,
        audit: AuditLog,
        llm: LLMClient,
        agent_factory,
    ):
        registry = ToolRegistry(scope, enabled=[])
        super().__init__(store, registry, audit, llm)
        self.scope = scope
        self.agent_factory = agent_factory
        self.active_agents: dict[str, BaseAgent] = {}
        self._port_sem = asyncio.Semaphore(PORT_SCANNER_CAP)
        # HOST / PORT / SUBDOMAIN pass through ValidationAgent first.
        self._validated_queue = store.subscribe_confirmed({
            FindingType.HOST,
            FindingType.PORT,
            FindingType.SUBDOMAIN,
        })
        # Rich findings are auto-confirmed by the store; bypass validation.
        self._direct_queue = store.subscribe_confirmed({
            FindingType.SERVICE,
            FindingType.WEB_TECH,
            FindingType.WEB_FINDING,
        })

    def system_prompt(self) -> str:
        nets = [str(n) for n in self.scope.networks]
        domains = [str(d) for d in self.scope.domains]
        return (
            "You are the strategic orchestrator of an authorised red team recon campaign.\n"
            f"In-scope networks: {nets}\n"
            f"In-scope domains: {domains}\n\n"
            "You coordinate a specialist team:\n"
            "  osint      — OSINT collection (emails, org info, leaks)\n"
            "  dns        — DNS enumeration (subdomains, records, zone transfers)\n"
            "  network    — Network mapping (host discovery, topology)\n"
            "  port       — Port scanning (assigned per host)\n"
            "  fingerprint— Service fingerprinting (per HTTP/S service)\n"
            "  web        — Deep web recon (crawl, fuzz, nuclei)\n\n"
            "When given new findings, decide which agents to spawn next.\n"
            "Respond with one SPAWN line per agent to launch:\n"
            "  SPAWN: <type> | GOAL: <specific goal>\n"
            "Or WAIT if nothing new is needed.\n\n"
            "Rules:\n"
            "- Don't spawn duplicate agents for the same target.\n"
            "- Spawn port scanner for every new HOST discovered.\n"
            "- Spawn fingerprinter for every HTTP/HTTPS PORT found.\n"
            "- Spawn web recon for HTTP services after fingerprinting confirms "
            "  an interesting application.\n"
            "- Let DNS and OSINT run in parallel at campaign start."
        )

    async def run_campaign(self, goal: str):
        """Entry point — runs the full campaign until done or stopped."""
        logger.info(f"[orchestrator] campaign start: {goal}")
        await self.audit.record("orchestrator", "campaign_start", {"goal": goal})

        await asyncio.gather(
            self._initial_wave(goal),
            self._reactive_loop(),
        )

        logger.info("[orchestrator] all agents done, generating report")
        await self._generate_report()

        summary = await self.store.get_summary()
        logger.info(f"[orchestrator] campaign complete: {summary}")
        await self.audit.record("orchestrator", "campaign_complete", {"summary": summary})

    async def _initial_wave(self, goal: str):
        """Ask the LLM for the first wave of agents to spawn in parallel."""
        scope_desc = (
            f"Networks: {[str(n) for n in self.scope.networks]}, "
            f"Domains: {self.scope.domains}"
        )
        prompt = (
            f"Campaign goal: {goal}\nScope: {scope_desc}\n\n"
            "Plan the first wave of parallel recon agents to launch simultaneously. "
            "Use SPAWN lines for each agent."
        )
        response = await self.llm.think(
            system=self.system_prompt(),
            messages=[{"role": "user", "content": prompt}],
            tools=[],
        )
        await self.audit.record_decision("orchestrator", response.text)
        logger.info(f"[orchestrator] initial plan:\n{response.text}")
        await self._spawn_from_text(response.text, context={"phase": "initial"})

    async def _reactive_loop(self):
        """Drain findings in batches, make one LLM call per batch."""
        # One extra drain after active_agents hits 0 so ValidationAgent has
        # time to confirm the last batch (it uses the same 3-second window).
        grace = 0
        while not stop.is_set():
            batch = await self._drain_batch()

            if not batch:
                if not self.active_agents:
                    if grace == 0:
                        grace = 1
                        continue  # one more drain to catch late confirmations
                    logger.info("[orchestrator] all agents idle")
                    break
                continue

            grace = 0  # reset if we received new findings
            logger.info(f"[orchestrator] processing batch of {len(batch)} findings")
            await self._react_to_batch(batch)

    async def _drain_batch(self) -> list[Finding]:
        """Collect up to BATCH_MAX findings within BATCH_WINDOW seconds from both queues."""
        batch: list[Finding] = []
        deadline = asyncio.get_event_loop().time() + BATCH_WINDOW

        while len(batch) < BATCH_MAX:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            timeout = max(0.1, remaining)
            # Race both queues; take whichever fires first
            done, pending = await asyncio.wait(
                [
                    asyncio.ensure_future(self._validated_queue.get()),
                    asyncio.ensure_future(self._direct_queue.get()),
                ],
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            if not done:
                break
            for task in done:
                try:
                    batch.append(task.result())
                except Exception:
                    pass
        return batch

    async def _react_to_batch(self, batch: list[Finding]):
        """Single LLM call covering all findings in the batch."""
        if stop.is_set():
            return

        running = list(self.active_agents.keys())
        findings_text = "\n".join(str(f) for f in batch)

        prompt = (
            f"New findings ({len(batch)}):\n{findings_text}\n\n"
            f"Currently running agents: {running}\n\n"
            "Which new agents should I spawn? Use SPAWN lines or WAIT."
        )
        response = await self.llm.think(
            system=self.system_prompt(),
            messages=[{"role": "user", "content": prompt}],
            tools=[],
        )
        await self.audit.record_decision("orchestrator", response.text)

        context = {"triggered_by": [str(f.type) for f in batch]}
        await self._spawn_from_text(response.text, context=context)

    async def _spawn_from_text(self, text: str, context: dict):
        """Parse SPAWN lines from LLM response and launch agents in parallel."""
        spawns = []
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("SPAWN:"):
                continue
            parts = line.split("|")
            agent_type = parts[0].replace("SPAWN:", "").strip()
            goal = parts[1].replace("GOAL:", "").strip() if len(parts) > 1 else ""
            spawns.append((agent_type, goal))

        await asyncio.gather(*[
            self._spawn_agent(agent_type, goal, context)
            for agent_type, goal in spawns
        ])

    async def _spawn_agent(self, agent_type: str, goal: str, context: dict):
        """Instantiate an agent, register it, and run it as a background task."""
        key = f"{agent_type}:{goal[:50]}"
        if key in self.active_agents:
            logger.debug(f"[orchestrator] skipping duplicate: {key}")
            return

        agent = self.agent_factory(agent_type)
        if agent is None:
            logger.warning(f"[orchestrator] unknown agent type: {agent_type}")
            return

        self.active_agents[key] = agent
        task = Task(goal=goal, context=context)
        await self.audit.record(
            "orchestrator", "spawn_agent",
            {"type": agent_type, "goal": goal}
        )
        logger.info(f"[orchestrator] spawning {agent_type} → {goal}")

        async def _run_and_cleanup():
            if agent_type == "port":
                async with self._port_sem:
                    await agent.assign(task)
                    await agent.run()
            else:
                await agent.assign(task)
                await agent.run()
            self.active_agents.pop(key, None)
            logger.info(f"[orchestrator] agent done: {key}")

        asyncio.create_task(_run_and_cleanup())

    async def _generate_report(self):
        """Instantiate the report agent and run it."""
        report_agent = self.agent_factory("report")
        if report_agent is None:
            return
        report = await report_agent.generate()
        if report:
            logger.info("[orchestrator] report generated (%d chars)", len(report))
