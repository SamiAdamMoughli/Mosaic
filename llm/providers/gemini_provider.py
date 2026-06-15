"""
Google Gemini provider via google-genai SDK.
Used for high-frequency tool-calling agents (Flash) and long-context synthesis (Pro).
"""

import json

from google import genai
from google.genai import types

from llm.base import LLMProvider, LLMResponse, ToolCall


def _to_gemini_tools(tools: list[dict]) -> list[types.Tool] | None:
    if not tools:
        return None
    declarations = []
    for t in tools:
        schema = t["input_schema"]
        declarations.append(
            types.FunctionDeclaration(
                name=t["name"],
                description=t["description"],
                parameters=schema,
            )
        )
    return [types.Tool(function_declarations=declarations)]


def _to_gemini_contents(messages: list[dict]) -> list[types.Content]:
    contents = []
    for msg in messages:
        role = "user" if msg["role"] == "user" else "model"
        content = msg["content"]
        parts = []

        if isinstance(content, str):
            parts.append(types.Part(text=content))
        else:
            for block in content:
                btype = block.get("type") if isinstance(block, dict) else getattr(block, "type", None)

                if btype == "text":
                    text = block.get("text") if isinstance(block, dict) else block.text
                    parts.append(types.Part(text=text))

                elif btype == "tool_use":
                    if isinstance(block, dict):
                        name, inp = block["name"], block["input"]
                    else:
                        name, inp = block.name, block.input
                    parts.append(types.Part(function_call=types.FunctionCall(name=name, args=inp)))

                elif btype == "tool_result":
                    if isinstance(block, dict):
                        result = block.get("content", "")
                        # find the tool name from the id — Gemini needs name, use id as fallback
                        name = block.get("tool_use_id", "tool")
                    else:
                        result = getattr(block, "content", "")
                        name = getattr(block, "tool_use_id", "tool")
                    if isinstance(result, list):
                        result = " ".join(
                            (b.get("text") if isinstance(b, dict) else b.text)
                            for b in result
                        )
                    parts.append(types.Part(
                        function_response=types.FunctionResponse(
                            name=name, response={"result": str(result)}
                        )
                    ))

        if parts:
            contents.append(types.Content(role=role, parts=parts))
    return contents


class GeminiProvider(LLMProvider):
    def __init__(self, model: str):
        self.model = model
        self._client = genai.Client()

    async def complete(self, system: str, messages: list[dict], tools: list[dict]) -> LLMResponse:
        contents = _to_gemini_contents(messages)
        gemini_tools = _to_gemini_tools(tools)

        config = types.GenerateContentConfig(
            system_instruction=system,
            max_output_tokens=8096,
            tools=gemini_tools,
        )

        resp = await self._client.aio.models.generate_content(
            model=self.model,
            contents=contents,
            config=config,
        )

        text = ""
        tool_calls = []

        for part in resp.candidates[0].content.parts:
            if part.text:
                text += part.text
            elif part.function_call:
                fc = part.function_call
                tool_calls.append(ToolCall(
                    id=fc.name,
                    name=fc.name,
                    args=dict(fc.args) if fc.args else {},
                ))

        stop = "tool_use" if tool_calls else "end_turn"
        # Populate raw_content in Anthropic format so base.py can reconstruct
        # message history correctly on multi-turn tool-use loops.
        raw_content: list = []
        if text:
            raw_content.append({"type": "text", "text": text})
        for tc in tool_calls:
            raw_content.append({"type": "tool_use", "id": tc.id, "name": tc.name, "input": tc.args})
        return LLMResponse(stop_reason=stop, text=text, tool_calls=tool_calls, raw_content=raw_content)
