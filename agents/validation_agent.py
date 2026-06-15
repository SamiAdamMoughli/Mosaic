"""
Validation Agent — GPT-4o-mini.

Sits between raw findings and the orchestrator. Subscribes to noisy
finding types (HOST, PORT, SUBDOMAIN) that specialist agents produce
in bulk. Batches them, asks the LLM to filter noise, then calls
store.confirm() on legitimate findings so the orchestrator acts on them.

Noise it filters:
  - Wildcard DNS entries (*.example.com artifacts)
  - Tool metadata lines mistakenly parsed as subdomains
  - Broadcast / network addresses (.0, .255) parsed as HOST findings
  - Ports where the host field is empty or malformed
  - CDN edge nodes and parking-page IPs (heuristic, model judgment)
"""

import asyncio
import logging
import re

from core.audit import AuditLog
from core.stop import stop
from llm.client import LLMClient
from memory.models import Finding, FindingType
from memory.store import FindingsStore

logger = logging.getLogger(__name__)

# Collect findings for up to this long before making a validation batch call
BATCH_WINDOW = 3.0
BATCH_MAX = 50

# Types the validator watches — everything else is auto-confirmed by the store
VALIDATE_TYPES = {
    FindingType.HOST,
    FindingType.PORT,
    FindingType.SUBDOMAIN,
}

_CONFIRM_RE = re.compile(r"^CONFIRM\s+(\d+)", re.MULTILINE)
_REJECT_RE = re.compile(r"^REJECT\s+(\d+)", re.MULTILINE)

_SYSTEM = (
    "You are a recon findings validator for an authorised red team.\n"
    "Your job: decide which raw findings are genuine discoveries vs tool noise.\n\n"
    "Common noise to REJECT:\n"
    "  SUBDOMAIN — wildcard entries (start with * or contain *), lines that look\n"
    "    like tool progress/error messages, entries with spaces or invalid chars,\n"
    "    parking-page domains.\n"
    "  HOST — network address (.0), broadcast (.255), loopback (127.x),\n"
    "    link-local (169.254.x), host fields that are empty or contain '()'.\n"
    "  PORT — entries with empty host, port 0, or clearly invalid port numbers.\n\n"
    "When uncertain, CONFIRM (false negatives are worse than false positives here).\n\n"
    "For each numbered finding respond with exactly:\n"
    "  CONFIRM <n>  — or —  REJECT <n> <brief reason>\n"
    "Output only these lines, one per finding."
)


class ValidationAgent:
    """Filters noisy HOST/PORT/SUBDOMAIN findings before the orchestrator sees them."""

    role = "validator"

    def __init__(
        self,
        store: FindingsStore,
        audit: AuditLog,
        llm: LLMClient,
    ):
        self.store = store
        self.audit = audit
        self.llm = llm
        self._queue = store.subscribe(VALIDATE_TYPES)

    async def run(self) -> None:
        logger.info("[validator] started")
        while not stop.is_set():
            batch = await self._drain_batch()
            if batch:
                await self._validate_batch(batch)
        logger.info("[validator] stopped")

    async def _drain_batch(self) -> list[Finding]:
        batch: list[Finding] = []
        deadline = asyncio.get_event_loop().time() + BATCH_WINDOW

        while len(batch) < BATCH_MAX:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                f = await asyncio.wait_for(
                    self._queue.get(), timeout=max(0.05, remaining)
                )
                batch.append(f)
            except asyncio.TimeoutError:
                break
        return batch

    async def _validate_batch(self, batch: list[Finding]) -> None:
        if stop.is_set():
            return

        lines = []
        for i, f in enumerate(batch, 1):
            lines.append(f"{i}. [{f.type.value}] {f.data}")
        findings_text = "\n".join(lines)

        logger.debug("[validator] validating %d findings", len(batch))

        try:
            response = await self.llm.think(
                system=_SYSTEM,
                messages=[{"role": "user", "content": findings_text}],
                tools=[],
            )
        except Exception as exc:
            # On LLM failure, confirm everything — don't block the campaign
            logger.warning("[validator] LLM error, auto-confirming batch: %s", exc)
            for f in batch:
                await self.store.confirm(f.id)
            return

        text = response.text or ""
        await self.audit.record_decision("validator", text[:500])

        confirmed_nums = {int(m.group(1)) for m in _CONFIRM_RE.finditer(text)}
        rejected_nums = {int(m.group(1)) for m in _REJECT_RE.finditer(text)}

        for i, f in enumerate(batch, 1):
            if i in rejected_nums:
                logger.info(
                    "[validator] REJECTED [%s] %s", f.type.value, f.data
                )
            else:
                # CONFIRM explicitly, or no verdict (default confirm)
                if i not in confirmed_nums and i not in rejected_nums:
                    logger.debug("[validator] no verdict for #%d, confirming", i)
                await self.store.confirm(f.id)
