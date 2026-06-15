"""
Global kill switch. Every agent checks stop.event before executing any action.
Triggered by: SIGINT/SIGTERM, stop file, or explicit call to stop.trigger().
"""

import asyncio
import signal
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

STOP_FILE = Path("/tmp/.redteam_stop")


class StopController:
    def __init__(self):
        self.event = asyncio.Event()
        self.reason: str | None = None

    def trigger(self, reason: str = "manual"):
        if not self.event.is_set():
            self.reason = reason
            self.event.set()
            logger.warning(f"[STOP] Kill switch triggered: {reason}")

    def is_set(self) -> bool:
        return self.event.is_set()

    async def wait(self):
        await self.event.wait()

    def register_signals(self):
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda s=sig: self.trigger(f"signal:{s.name}"))

    async def watch_stop_file(self):
        """Out-of-band kill: `touch /tmp/.redteam_stop` halts all agents."""
        STOP_FILE.unlink(missing_ok=True)
        try:
            while not self.event.is_set():
                if STOP_FILE.exists():
                    self.trigger("stop_file")
                    break
                await asyncio.sleep(0.5)
        finally:
            STOP_FILE.unlink(missing_ok=True)


stop = StopController()
