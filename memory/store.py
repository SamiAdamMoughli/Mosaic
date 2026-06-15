"""
Shared findings blackboard. All agents read and write here.

Two subscriber tiers:
  subscribe()           — receives every new finding immediately (raw)
  subscribe_confirmed() — receives findings only after ValidationAgent
                          calls confirm(); used by the orchestrator for
                          noisy types (HOST, PORT, SUBDOMAIN)

Deduplication: if a Finding has a dedup_key, duplicate inserts are
silently dropped — no notification, no error. This prevents amass +
subfinder from writing the same subdomain twice.
"""

import asyncio
import json
import logging
import sqlite3
from pathlib import Path
from typing import Callable

from memory.models import Finding, FindingType

logger = logging.getLogger(__name__)

# Finding types that skip validation and flow directly to confirmed subscribers.
# These are rich, tool-output findings — not candidate strings that need filtering.
AUTO_CONFIRM_TYPES = {
    FindingType.SERVICE,
    FindingType.NETWORK_MAP,
    FindingType.DNS_RECORD,
    FindingType.ZONE_XFER,
    FindingType.WEB_TECH,
    FindingType.ENDPOINT,
    FindingType.WEB_FINDING,
    FindingType.EMAIL,
    FindingType.CREDENTIAL,
    FindingType.EXPOSURE,
    FindingType.ORG_INFO,
    FindingType.NOTE,
    FindingType.SUMMARY,
}


class FindingsStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._lock = asyncio.Lock()
        self._subscribers: list[tuple[set[FindingType], asyncio.Queue]] = []
        self._confirmed_subscribers: list[tuple[set[FindingType], asyncio.Queue]] = []
        self._init_db()

    def _init_db(self):
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                type     TEXT    NOT NULL,
                source_agent TEXT NOT NULL,
                data     TEXT    NOT NULL,
                ts       TEXT    NOT NULL,
                dedup_key TEXT   UNIQUE,
                confirmed INTEGER NOT NULL DEFAULT 0
            )
        """)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Subscription
    # ------------------------------------------------------------------

    def subscribe(self, types: set[FindingType]) -> asyncio.Queue:
        """Queue that receives every new finding of the given types (raw)."""
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.append((types, q))
        return q

    def subscribe_confirmed(self, types: set[FindingType]) -> asyncio.Queue:
        """Queue that only receives findings after confirm() is called."""
        q: asyncio.Queue = asyncio.Queue()
        self._confirmed_subscribers.append((types, q))
        return q

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    async def add(self, finding: Finding) -> Finding | None:
        """
        Persist a finding. Returns None if deduplicated (silent drop).
        Auto-confirms rich finding types and notifies confirmed subscribers.
        """
        dedup_key = finding.dedup_key or None
        auto = finding.type in AUTO_CONFIRM_TYPES
        confirmed_int = 1 if auto else 0

        async with self._lock:
            try:
                cur = self._conn.execute(
                    """INSERT INTO findings
                       (type, source_agent, data, ts, dedup_key, confirmed)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        finding.type.value,
                        finding.source_agent,
                        json.dumps(finding.data),
                        finding.ts.isoformat(),
                        dedup_key,
                        confirmed_int,
                    ),
                )
                self._conn.commit()
                finding.id = cur.lastrowid or 0
                finding.confirmed = bool(auto)
            except sqlite3.IntegrityError:
                # dedup_key collision — silent drop
                logger.debug("[STORE] dedup drop: %s", finding.dedup_key)
                return None

        logger.info("[STORE] %s", finding)

        # Raw subscribers always get the finding
        for types, q in self._subscribers:
            if finding.type in types:
                await q.put(finding)

        # Confirmed subscribers get it immediately for auto-confirm types
        if auto:
            for types, q in self._confirmed_subscribers:
                if finding.type in types:
                    await q.put(finding)

        return finding

    async def confirm(self, finding_id: int) -> bool:
        """
        Mark a finding as validated. Notifies confirmed subscribers.
        Returns False if already confirmed or not found.
        """
        async with self._lock:
            row = self._conn.execute(
                "SELECT id, type, source_agent, data, ts, confirmed "
                "FROM findings WHERE id=?",
                (finding_id,),
            ).fetchone()

            if not row or row[5]:  # not found or already confirmed
                return False

            self._conn.execute(
                "UPDATE findings SET confirmed=1 WHERE id=?", (finding_id,)
            )
            self._conn.commit()

        finding = Finding(
            id=row[0],
            type=FindingType(row[1]),
            source_agent=row[2],
            data=json.loads(row[3]),
            confirmed=True,
        )
        logger.debug("[STORE] confirmed: %s", finding)

        for types, q in self._confirmed_subscribers:
            if finding.type in types:
                await q.put(finding)

        return True

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def query(
        self,
        types: list[FindingType] | None = None,
        filter_fn: Callable[[Finding], bool] | None = None,
    ) -> list[Finding]:
        placeholders = ",".join("?" * len(types)) if types else ""
        sql = "SELECT id, type, source_agent, data, ts FROM findings"
        params: list = []
        if types:
            sql += f" WHERE type IN ({placeholders})"
            params = [t.value for t in types]

        async with self._lock:
            rows = self._conn.execute(sql, params).fetchall()

        findings = []
        for row in rows:
            f = Finding(
                id=row[0],
                type=FindingType(row[1]),
                source_agent=row[2],
                data=json.loads(row[3]),
            )
            if filter_fn is None or filter_fn(f):
                findings.append(f)
        return findings

    async def get_summary(self) -> dict:
        async with self._lock:
            counts = dict(
                self._conn.execute(
                    "SELECT type, COUNT(*) FROM findings GROUP BY type"
                ).fetchall()
            )
        return counts
