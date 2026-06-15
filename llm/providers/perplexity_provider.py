"""
Perplexity Sonar Pro provider.

Perplexity uses an OpenAI-compatible API with live web search baked in.
No tool use — the model's built-in search is the capability we want.
Returns text with inline citations from the web.
"""

import openai as sdk

from llm.base import LLMProvider, LLMResponse


class PerplexityProvider(LLMProvider):
    BASE_URL = "https://api.perplexity.ai"

    def __init__(self, model: str = "sonar-pro"):
        self.model = model
        import os
        self._client = sdk.AsyncOpenAI(
            api_key=os.environ.get("PERPLEXITY_API_KEY", ""),
            base_url=self.BASE_URL,
        )

    async def complete(self, system: str, messages: list[dict], tools: list[dict]) -> LLMResponse:
        oai_messages = [{"role": "system", "content": system}]
        for msg in messages:
            content = msg["content"]
            if isinstance(content, list):
                text = " ".join(
                    (b.get("text") if isinstance(b, dict) else getattr(b, "text", ""))
                    for b in content
                    if (b.get("type") if isinstance(b, dict) else getattr(b, "type", "")) == "text"
                )
            else:
                text = str(content)
            oai_messages.append({"role": msg["role"], "content": text})

        resp = await self._client.chat.completions.create(
            model=self.model,
            messages=oai_messages,
            max_tokens=4096,
        )

        text = resp.choices[0].message.content or ""
        return LLMResponse(stop_reason="end_turn", text=text, tool_calls=[])
