"""
Base agent. All specialist agents inherit this.

The ReAct loop:
  1. Build context from shared memory
  2. Ask the LLM what to do next (reason)
  3. Execute tool calls (act)
  4. Store results to shared memory (observe)
  5. Repeat until the LLM signals done or stop event fires

Agents check stop.event before EVERY tool call so the kill switch is
always respected within one tool-call latency.
"""

import asyncio
import logging
from abc import ABC, abstractmethod

from core.audit import AuditLog
from core.stop import stop
from llm.client import LLMClient, LLMResponse
from memory.models import Finding, FindingType, Task
from memory.store import FindingsStore
from tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

MAX_TURNS = 50


class BaseAgent(ABC):
    role: str

    def __init__(
        self,
        store: FindingsStore,
        registry: ToolRegistry,
        audit: AuditLog,
        llm: LLMClient,
    ):
        self.store = store
        self.registry = registry
        self.audit = audit
        self.llm = llm
        self.inbox: asyncio.Queue[Task | None] = asyncio.Queue()
        self._running = False

    @abstractmethod
    def system_prompt(self) -> str:
        """Role-specific system prompt."""

    async def run(self):
        """Main loop: pull tasks from inbox and execute until stopped."""
        self._running = True
        logger.info(f"[{self.role}] started")
        try:
            while not stop.is_set():
                try:
                    task = await asyncio.wait_for(self.inbox.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                if task is None:
                    break
                await self._react(task)
        finally:
            self._running = False
            logger.info(f"[{self.role}] stopped (reason: {stop.reason or 'task complete'})")

    async def assign(self, task: Task):
        await self.inbox.put(task)

    async def shutdown(self):
        await self.inbox.put(None)

    async def _react(self, task: Task):
        """Single ReAct loop for one task."""
        await self.audit.record_decision(self.role, f"starting task: {task.goal}")

        messages = [{"role": "user", "content": self._build_user_message(task)}]
        tools = self.registry.schemas()

        for turn in range(MAX_TURNS):
            if stop.is_set():
                return

            response: LLMResponse = await self.llm.think(
                system=self.system_prompt(),
                messages=messages,
                tools=tools,
            )

            if response.text:
                await self.audit.record_decision(self.role, response.text)

            if response.stop_reason == "end_turn":
                logger.info(f"[{self.role}] task complete after {turn + 1} turns")
                await self._on_complete(response.text, task)
                return

            if response.stop_reason == "tool_use":
                tool_results = await self._execute_tool_calls(response)
                messages.append({"role": "assistant", "content": response.raw_content})
                messages.append({"role": "user", "content": tool_results})
            else:
                logger.warning(f"[{self.role}] unexpected stop_reason: {response.stop_reason}")
                return

        logger.warning(f"[{self.role}] hit MAX_TURNS ({MAX_TURNS}), stopping task")

    async def _execute_tool_calls(self, response: LLMResponse) -> list[dict]:
        results = []
        for tc in response.tool_calls:
            if stop.is_set():
                results.append({
                    "type": "tool_result",
                    "tool_use_id": tc.id,
                    "content": "Campaign stopped.",
                })
                continue

            await self.audit.record_tool_call(self.role, tc.name, tc.args)
            result_str = await self.registry.call(tc.name, tc.args)
            await self.audit.record_tool_result(self.role, tc.name, result_str)

            await self._parse_and_store(tc.name, tc.args, result_str)

            results.append({
                "type": "tool_result",
                "tool_use_id": tc.id,
                "content": result_str,
            })
        return results

    async def _parse_and_store(self, tool_name: str, args: dict, result: str):
        """Override in subclasses to extract structured findings from tool output."""

    async def _on_complete(self, summary: str, task: Task):
        """Called when the LLM signals it's done with a task."""
        if summary:
            await self.store.add(Finding(
                type=FindingType.NOTE,
                source_agent=self.role,
                data={"summary": summary, "task": task.goal},
            ))

    def _build_user_message(self, task: Task) -> str:
        parts = [f"Goal: {task.goal}"]
        if task.context:
            parts.append(f"Context: {task.context}")
        return "\n".join(parts)
