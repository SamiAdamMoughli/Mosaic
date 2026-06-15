"""
Scope enforcement. Every tool call passes through check() before execution.
If a target falls outside the defined scope, the action is rejected and the
stop controller is notified — scope violations auto-halt the campaign.
"""

import ipaddress
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Scope:
    networks: list[ipaddress.IPv4Network] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    excluded: list[ipaddress.IPv4Network] = field(default_factory=list)

    @classmethod
    def from_config(cls, cfg: dict) -> "Scope":
        return cls(
            networks=[ipaddress.IPv4Network(n, strict=False) for n in cfg.get("networks", [])],
            domains=[d.lower() for d in cfg.get("domains", [])],
            excluded=[ipaddress.IPv4Network(n, strict=False) for n in cfg.get("excluded", [])],
        )

    def check(self, target: str) -> bool:
        """Return True if target is in scope. Raises ScopeViolation otherwise."""
        try:
            addr = ipaddress.IPv4Address(target)
            for net in self.excluded:
                if addr in net:
                    raise ScopeViolation(f"{target} is in excluded range {net}")
            for net in self.networks:
                if addr in net:
                    return True
            raise ScopeViolation(f"{target} not in any allowed network")
        except ipaddress.AddressValueError:
            host = target.lower().split(":")[0]
            for domain in self.domains:
                if host == domain or host.endswith(f".{domain}"):
                    return True
            raise ScopeViolation(f"{target} not in allowed domains")

    def assert_in_scope(self, target: str):
        self.check(target)


class ScopeViolation(Exception):
    pass
