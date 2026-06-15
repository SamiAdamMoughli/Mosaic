"""
Startup tool availability check.

Runs before the campaign starts. Fails fast if required tools are
missing; prints warnings for recommended tools that aren't installed.
"""

import logging
import shutil

logger = logging.getLogger(__name__)

REQUIRED = ["nmap", "subfinder", "httpx", "nuclei"]

RECOMMENDED = [
    "amass", "dnsx", "masscan", "rustscan",
    "katana", "ffuf", "gowitness", "gau",
    "theHarvester", "fierce",
]


class MissingRequiredTool(RuntimeError):
    pass


def check_tools() -> None:
    """
    Verify tool availability. Raises MissingRequiredTool if any
    required tool is absent. Logs warnings for missing recommended tools.
    """
    missing_required = [t for t in REQUIRED if not shutil.which(t)]
    missing_recommended = [t for t in RECOMMENDED if not shutil.which(t)]

    if missing_recommended:
        logger.warning(
            "Optional tools not found (some recon phases will be skipped): %s",
            ", ".join(missing_recommended),
        )

    if missing_required:
        msg = (
            f"Required tools missing: {', '.join(missing_required)}\n"
            "Install them and re-run. On macOS: brew install nmap nuclei "
            "projectdiscovery/tap/subfinder projectdiscovery/tap/httpx"
        )
        raise MissingRequiredTool(msg)

    logger.info(
        "Tool check passed (%d/%d recommended available)",
        len(RECOMMENDED) - len(missing_recommended),
        len(RECOMMENDED),
    )
