"""
Tool registry. Agents declare tools with @tool; the registry builds the
LLM tool-use schema from the function signature + explicit schema dict.
Scope is checked here (Python layer) before delegating to the Go runner.
The Go runner enforces scope again as an authoritative second gate.

Concurrency limiting was removed from this file — it now lives in the
Go runner (tools-runner/executor.go) as goroutine channel semaphores,
which cancel cleanly when the HTTP request context is closed.
"""

import asyncio
import inspect
import logging
from dataclasses import dataclass
from typing import Any, Callable

from core.scope import Scope, ScopeViolation
from core.stop import stop

logger = logging.getLogger(__name__)

_registry: dict[str, "ToolDef"] = {}


@dataclass
class ToolDef:
    name: str
    description: str
    fn: Callable
    schema: dict
    needs_scope_check: bool = True


def tool(
    description: str,
    scope_check_param: str | None = "target",
    schema: dict | None = None,
):
    """Decorator to register a function as an agent tool."""
    def decorator(fn: Callable) -> Callable:
        tool_schema = schema or _infer_schema(fn)
        _registry[fn.__name__] = ToolDef(
            name=fn.__name__,
            description=description,
            fn=fn,
            schema=tool_schema,
            needs_scope_check=scope_check_param is not None,
        )
        return fn
    return decorator


def _infer_schema(fn: Callable) -> dict:
    sig = inspect.signature(fn)
    properties: dict[str, Any] = {}
    required = []
    for name, param in sig.parameters.items():
        if name in ("scope", "self"):
            continue
        properties[name] = {"type": "string"}
        if param.default is inspect.Parameter.empty:
            required.append(name)
    return {"type": "object", "properties": properties, "required": required}


class ToolRegistry:
    def __init__(self, scope: Scope, enabled: list[str] | None = None):
        self.scope = scope
        self.enabled = set(enabled) if enabled else set(_registry.keys())

    def schemas(self) -> list[dict]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.schema,
            }
            for t in _registry.values()
            if t.name in self.enabled
        ]

    async def call(self, name: str, args: dict) -> str:
        if name not in _registry:
            return f"ERROR: unknown tool '{name}'"
        if name not in self.enabled:
            return f"ERROR: tool '{name}' not enabled for this agent"
        if stop.is_set():
            return "ERROR: campaign stopped"

        td = _registry[name]

        # Python-layer scope check — fast path before hitting the network.
        # The Go runner also checks; this prevents even sending the request.
        if td.needs_scope_check and "target" in args:
            try:
                self.scope.assert_in_scope(args["target"])
            except ScopeViolation as e:
                stop.trigger(f"scope_violation:{e}")
                return f"SCOPE VIOLATION: {e} — campaign halted"

        logger.info("[TOOL] %s(%s)", name, args)
        try:
            result = td.fn(**args)
            if asyncio.iscoroutine(result):
                result = await result
            return str(result)
        except Exception as e:
            logger.error("[TOOL] %s failed: %s", name, e)
            return f"ERROR: {e}"
