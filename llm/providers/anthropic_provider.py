import anthropic as sdk

from llm.base import LLMProvider, LLMResponse, ToolCall


class AnthropicProvider(LLMProvider):
    def __init__(self, model: str):
        self.model = model
        self._client = sdk.AsyncAnthropic()

    async def complete(self, system: str, messages: list[dict], tools: list[dict]) -> LLMResponse:
        kwargs: dict = {
            "model": self.model,
            "max_tokens": 8096,
            "system": system,
            "messages": messages,
        }
        if tools:
            kwargs["tools"] = tools

        resp = await self._client.messages.create(**kwargs)

        text = ""
        tool_calls = []
        for block in resp.content:
            if block.type == "text":
                text += block.text
            elif block.type == "tool_use":
                tool_calls.append(ToolCall(id=block.id, name=block.name, args=block.input))

        return LLMResponse(
            stop_reason="tool_use" if tool_calls else "end_turn",
            text=text,
            tool_calls=tool_calls,
            raw_content=resp.content,
        )
