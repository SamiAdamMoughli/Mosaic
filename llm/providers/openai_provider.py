"""
OpenAI provider. Handles both GPT-4o and reasoning models (o3, o4-mini).

Reasoning models support tool use and system messages but have a different
max_tokens param name and benefit from reasoning_effort control.
"""

import json
import uuid

import openai as sdk

from llm.base import LLMProvider, LLMResponse, ToolCall

REASONING_MODELS = {"o1", "o1-mini", "o3", "o3-mini", "o4-mini"}


def _to_openai_tools(tools: list[dict]) -> list[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        }
        for t in tools
    ]


def _to_openai_messages(messages: list[dict]) -> list[dict]:
    """Convert Anthropic-style message list to OpenAI format."""
    out = []
    for msg in messages:
        role = msg["role"]
        content = msg["content"]

        if isinstance(content, str):
            out.append({"role": role, "content": content})
            continue

        # content is a list of blocks
        text_parts = []
        tool_calls = []
        tool_results = []

        for block in content:
            btype = block.get("type") if isinstance(block, dict) else getattr(block, "type", None)

            if btype == "text":
                text = block.get("text") if isinstance(block, dict) else block.text
                text_parts.append(text)

            elif btype == "tool_use":
                if isinstance(block, dict):
                    tid, name, inp = block["id"], block["name"], block["input"]
                else:
                    tid, name, inp = block.id, block.name, block.input
                tool_calls.append({
                    "id": tid,
                    "type": "function",
                    "function": {"name": name, "arguments": json.dumps(inp)},
                })

            elif btype == "tool_result":
                if isinstance(block, dict):
                    tid = block["tool_use_id"]
                    result_content = block.get("content", "")
                else:
                    tid = block.tool_use_id
                    result_content = getattr(block, "content", "")
                if isinstance(result_content, list):
                    result_content = " ".join(
                        (b.get("text") if isinstance(b, dict) else b.text)
                        for b in result_content if (b.get("type") if isinstance(b, dict) else b.type) == "text"
                    )
                tool_results.append({"tool_call_id": tid, "content": str(result_content)})

        if tool_calls:
            m: dict = {"role": "assistant"}
            if text_parts:
                m["content"] = " ".join(text_parts)
            m["tool_calls"] = tool_calls
            out.append(m)
        elif tool_results:
            for tr in tool_results:
                out.append({"role": "tool", **tr})
        else:
            out.append({"role": role, "content": " ".join(text_parts)})

    return out


class OpenAIProvider(LLMProvider):
    def __init__(self, model: str, reasoning_effort: str = "high"):
        self.model = model
        self.reasoning_effort = reasoning_effort
        self._client = sdk.AsyncOpenAI()

    async def complete(self, system: str, messages: list[dict], tools: list[dict]) -> LLMResponse:
        is_reasoning = self.model in REASONING_MODELS
        oai_messages = [{"role": "system", "content": system}] + _to_openai_messages(messages)

        kwargs: dict = {"model": self.model, "messages": oai_messages}

        if is_reasoning:
            kwargs["max_completion_tokens"] = 16000
            kwargs["reasoning_effort"] = self.reasoning_effort
        else:
            kwargs["max_tokens"] = 8096

        if tools:
            kwargs["tools"] = _to_openai_tools(tools)
            kwargs["tool_choice"] = "auto"

        resp = await self._client.chat.completions.create(**kwargs)
        choice = resp.choices[0]
        msg = choice.message

        text = msg.content or ""
        tool_calls = []

        if msg.tool_calls:
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}
                tool_calls.append(ToolCall(id=tc.id, name=tc.function.name, args=args))

        stop = "tool_use" if tool_calls else "end_turn"
        # Populate raw_content in Anthropic format so base.py can reconstruct
        # message history correctly on multi-turn tool-use loops.
        raw_content: list = []
        if text:
            raw_content.append({"type": "text", "text": text})
        for tc in tool_calls:
            raw_content.append({"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.args})
        return LLMResponse(stop_reason=stop, text=text, tool_calls=tool_calls, raw_content=raw_content)
