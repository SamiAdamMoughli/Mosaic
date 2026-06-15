"""
Append-only structured audit log. Every tool call and agent decision is recorded
before execution so the blue team has a full timeline even if the campaign is killed.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    async def record(self, agent: str, action: str, details: dict):
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent": agent,
            "action": action,
            **details,
        }
        async with self._lock:
            with self.path.open("a") as f:
                f.write(json.dumps(entry) + "\n")
        logger.debug(f"[AUDIT] {agent} → {action}")

    async def record_tool_call(self, agent: str, tool: str, args: dict):
        await self.record(agent, "tool_call", {"tool": tool, "args": args})

    async def record_tool_result(self, agent: str, tool: str, result: str):
        await self.record(agent, "tool_result", {"tool": tool, "result": result[:500]})

    async def record_decision(self, agent: str, reasoning: str):
        await self.record(agent, "decision", {"reasoning": reasoning[:1000]})

    async def record_finding(self, agent: str, finding_type: str, data: dict):
        await self.record(agent, "finding", {"finding_type": finding_type, "data": data})

    async def record_stop(self, reason: str):
        await self.record("system", "stop", {"reason": reason})
