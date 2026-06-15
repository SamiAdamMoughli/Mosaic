"""
Entry point for the recon campaign.

Usage:
    python cli.py --networks 10.0.0.0/24 --domains example.com
    python cli.py --networks 10.0.0.0/24 192.168.1.0/24 \\
                  --domains corp.example.com \\
                  --goal "Map the full internal attack surface"

Kill at any time:
    Ctrl+C
    touch /tmp/.redteam_stop

Prerequisites:
    Build the Go tool runner once before the first campaign:
        make runner          # builds ./recon-runner
    Or manually:
        cd tools-runner && go build -o ../recon-runner .
"""

import argparse
import asyncio
import json
import logging
import shutil
import subprocess as _sp
import sys
from pathlib import Path

from agents.dns_agent import DNSAgent
from agents.network_mapper import NetworkMapperAgent
from agents.orchestrator import OrchestratorAgent
from agents.osint_agent import OSINTAgent
from agents.port_scanner import PortScannerAgent
from agents.report_agent import ReportAgent
from agents.service_fingerprinter import ServiceFingerprinterAgent
from agents.validation_agent import ValidationAgent
from agents.web_recon_agent import WebReconAgent
from core.audit import AuditLog
from core.scope import Scope
from core.stop import stop
from core.tools_check import MissingRequiredTool, check_tools
from llm.client import LLMClient
from memory.models import FindingType
from memory.store import FindingsStore
import tools.runner_client as runner_client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

RUN_DIR = Path("runs")
_RUNNER_PORT = 7373


def _find_runner() -> str | None:
    """Find the compiled Go runner binary."""
    here = Path(__file__).parent
    candidates = [
        here / "recon-runner",                    # built at repo root
        here / "tools-runner" / "recon-runner",   # built in-place (dev)
        Path(shutil.which("recon-runner") or ""),  # on PATH
    ]
    for p in candidates:
        if p and p.exists():
            return str(p)
    return None


async def _start_runner(scope: Scope) -> "_sp.Popen[bytes] | None":
    """Start the Go tool runner and wait until it answers /health."""
    binary = _find_runner()
    if not binary:
        logger.warning(
            "recon-runner not found — tool calls will fail. "
            "Build it first:  make runner"
        )
        return None

    scope_cfg = {
        "networks": [str(n) for n in scope.networks],
        "domains":  scope.domains,
        "excluded": [str(n) for n in scope.excluded],
    }
    proc = _sp.Popen(
        [binary, "--port", str(_RUNNER_PORT), "--scope", json.dumps(scope_cfg)],
        stdout=_sp.DEVNULL,
        stderr=_sp.DEVNULL,
    )

    if await runner_client.wait_ready(timeout=10.0):
        logger.info("recon-runner ready on :%d  (pid %d)", _RUNNER_PORT, proc.pid)
        return proc

    logger.warning("recon-runner failed to start; tool calls will fail")
    proc.terminate()
    return None


def _make_factory(scope: Scope, store: FindingsStore, audit: AuditLog):
    """Return a callable that instantiates agents by type name."""
    def factory(agent_type: str):
        if agent_type == "osint":
            return OSINTAgent(scope, store, audit, LLMClient.for_role("osint_collector"))
        if agent_type == "dns":
            return DNSAgent(scope, store, audit, LLMClient.for_role("dns_enumerator"))
        if agent_type == "network":
            return NetworkMapperAgent(scope, store, audit, LLMClient.for_role("network_mapper"))
        if agent_type == "port":
            return PortScannerAgent(scope, store, audit, LLMClient.for_role("port_scanner"))
        if agent_type == "fingerprint":
            return ServiceFingerprinterAgent(
                scope, store, audit, LLMClient.for_role("service_fingerprinter")
            )
        if agent_type == "web":
            return WebReconAgent(scope, store, audit, LLMClient.for_role("web_recon"))
        if agent_type == "report":
            return ReportAgent(scope, store, audit, LLMClient.for_role("report_synthesiser"))
        return None
    return factory


async def run(args: argparse.Namespace) -> None:
    """Wire infrastructure and launch the campaign."""
    try:
        check_tools()
    except MissingRequiredTool as exc:
        logger.error("Tool check failed: %s", exc)
        return

    ts = int(asyncio.get_event_loop().time())
    run_dir = RUN_DIR / f"campaign_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)

    scope = Scope.from_config({
        "networks": args.networks or [],
        "domains":  args.domains or [],
        "excluded": args.exclude or [],
    })

    runner_proc = await _start_runner(scope)

    store = FindingsStore(run_dir / "findings.db")
    audit = AuditLog(run_dir / "audit.jsonl")
    factory = _make_factory(scope, store, audit)
    orchestrator = OrchestratorAgent(
        scope, store, audit, LLMClient.for_role("orchestrator"), factory
    )
    validator = ValidationAgent(store, audit, LLMClient.for_role("validator"))

    stop.register_signals()
    watcher = asyncio.create_task(stop.watch_stop_file())
    validator_task = asyncio.create_task(validator.run())

    logger.info("Campaign starting → %s", run_dir)
    logger.info("Networks : %s", [str(n) for n in scope.networks])
    logger.info("Domains  : %s", scope.domains)
    logger.info("Runner   : %s", "running" if runner_proc else "NOT FOUND — tool calls will fail")
    logger.info("Kill: Ctrl+C  or  touch /tmp/.redteam_stop")
    logger.info("-" * 60)

    try:
        await orchestrator.run_campaign(args.goal)
    except Exception:  # noqa: BLE001
        logger.exception("Campaign error")
    finally:
        stop.trigger("campaign_complete")
        validator_task.cancel()
        watcher.cancel()
        await runner_client.close()

        if runner_proc is not None:
            runner_proc.terminate()
            try:
                runner_proc.wait(timeout=5)
            except _sp.TimeoutExpired:
                runner_proc.kill()

        if stop.reason:
            await audit.record_stop(stop.reason)

        summary = await store.get_summary()
        logger.info("Findings : %s", summary)
        logger.info("Audit    : %s", run_dir / "audit.jsonl")
        logger.info("Database : %s", run_dir / "findings.db")

        reports = await store.query(types=[FindingType.SUMMARY])
        if reports:
            report_path = run_dir / "report.md"
            report_path.write_text(reports[-1].data.get("report", ""))
            logger.info("Report   : %s", report_path)


def main() -> None:
    """Parse CLI args and start the event loop."""
    parser = argparse.ArgumentParser(
        description="AI-orchestrated recon campaign",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--networks", nargs="*", default=[],
        help="In-scope CIDR ranges e.g. 10.0.0.0/24",
    )
    parser.add_argument(
        "--domains", nargs="*", default=[],
        help="In-scope domain names e.g. corp.example.com",
    )
    parser.add_argument(
        "--exclude", nargs="*", default=[],
        help="Excluded CIDR ranges",
    )
    parser.add_argument(
        "--goal",
        default=(
            "Map the complete internal attack surface: "
            "hosts, services, web applications, and DNS footprint."
        ),
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.networks and not args.domains:
        parser.error("Provide at least --networks or --domains")

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
