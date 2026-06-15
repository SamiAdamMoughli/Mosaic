"""
LLM client. Maps agent roles to the right provider + model and vends
a unified think() interface that all agents call.

Retry policy: 3 attempts with 2 s then 8 s back-off on transient errors
(429 rate limit, 5xx server errors, connection failures). Non-retryable
errors (4xx auth, bad request) are raised immediately.
"""

import asyncio
import logging

from llm.base import LLMProvider, LLMResponse

logger = logging.getLogger(__name__)

_MAX_ATTEMPTS = 3
_RETRY_DELAYS = (2.0, 8.0)  # seconds between attempts 1→2 and 2→3

_RETRYABLE_NAMES = {
    "ResourceExhausted",    # google-genai 429
    "ServiceUnavailable",   # google-genai 503
    "InternalServerError",  # google-genai 500
    "DeadlineExceeded",     # google-genai timeout
    "APIConnectionError",   # openai / anthropic network error
}


def _is_retryable(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None)
    if status is not None:
        return status == 429 or status >= 500
    name = type(exc).__name__
    return name in _RETRYABLE_NAMES or "Connection" in name or "Timeout" in name


# (provider_name, model_id) per agent role
ROLE_MAP: dict[str, tuple[str, str]] = {
    "orchestrator":          ("openai",      "o3"),
    "validator":             ("openai",      "gpt-4o-mini"),
    "osint_collector":       ("perplexity",  "sonar-pro"),
    "dns_enumerator":        ("google",      "gemini-2.5-flash"),
    "network_mapper":        ("google",      "gemini-2.5-flash"),
    "port_scanner":          ("google",      "gemini-2.5-flash"),
    "service_fingerprinter": ("openai",      "gpt-4o-mini"),
    "web_recon":             ("anthropic",   "claude-sonnet-4-6"),
    "report_synthesiser":    ("google",      "gemini-2.5-pro"),
}

_DEFAULT = ("anthropic", "claude-sonnet-4-6")


def _make_provider(provider_name: str, model: str) -> LLMProvider:
    if provider_name == "anthropic":
        from llm.providers.anthropic_provider import AnthropicProvider
        return AnthropicProvider(model)
    if provider_name == "openai":
        from llm.providers.openai_provider import OpenAIProvider
        return OpenAIProvider(model)
    if provider_name == "google":
        from llm.providers.gemini_provider import GeminiProvider
        return GeminiProvider(model)
    if provider_name == "perplexity":
        from llm.providers.perplexity_provider import PerplexityProvider
        return PerplexityProvider(model)
    raise ValueError(f"Unknown provider: {provider_name}")


class LLMClient:
    """One client per agent — created via LLMClient.for_role()."""

    def __init__(self, provider: LLMProvider):
        self._provider = provider

    @classmethod
    def for_role(cls, role: str) -> "LLMClient":
        provider_name, model = ROLE_MAP.get(role, _DEFAULT)
        return cls(_make_provider(provider_name, model))

    @property
    def model(self) -> str:
        return self._provider.model

    async def think(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict],
    ) -> LLMResponse:
        for attempt in range(_MAX_ATTEMPTS):
            try:
                return await self._provider.complete(system, messages, tools)
            except Exception as exc:
                if attempt == _MAX_ATTEMPTS - 1 or not _is_retryable(exc):
                    raise
                delay = _RETRY_DELAYS[attempt]
                logger.warning(
                    "[llm] transient error (attempt %d/%d): %s — retry in %.0fs",
                    attempt + 1, _MAX_ATTEMPTS, exc, delay,
                )
                await asyncio.sleep(delay)
        raise RuntimeError("unreachable")
