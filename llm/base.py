"""
Abstract LLM provider interface.

All providers accept:
  - system:   string
  - messages: Anthropic-style list (role + content blocks)
  - tools:    Anthropic-style tool schemas [{name, description, input_schema}]

All providers return a unified LLMResponse.
Each provider handles the format conversion internally.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict[str, Any]


@dataclass
class LLMResponse:
    stop_reason: str          # "end_turn" | "tool_use" | "stop"
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw_content: list = field(default_factory=list)


class LLMProvider(ABC):
    model: str

    @abstractmethod
    async def complete(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict],
    ) -> LLMResponse: ...
