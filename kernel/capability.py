"""Capability tokens: mint + verify.

A capability is minted from the Plan before any untrusted value is substituted into
the args, so the scope cannot be widened by injected text.
"""
import time
import uuid
from typing import Optional

import config
from contracts import Capability
from kernel.taint import unwrap


class CapabilityDenied(Exception):
    pass


def mint(tool: str, scope: dict, ttl: Optional[float] = None, single_use: bool = True) -> Capability:
    ttl = config.CAP_TTL_SECONDS if ttl is None else ttl
    return Capability(cap_id=uuid.uuid4().hex, tool=tool, scope=dict(scope),
                      expires_at=time.time() + ttl, single_use=single_use)


def verify(cap: Capability, tool: str, args: dict, used: Optional[set] = None,
           now: Optional[float] = None) -> None:
    """Raise CapabilityDenied unless the capability authorises exactly this call.
    On success a single-use cap is recorded in `used`."""
    if not isinstance(cap, Capability):
        raise CapabilityDenied("no capability presented")
    now = time.time() if now is None else now
    if now >= cap.expires_at:
        raise CapabilityDenied("capability expired")
    if cap.single_use and used is not None and cap.cap_id in used:
        raise CapabilityDenied("capability already used")
    if cap.tool != tool:
        raise CapabilityDenied(f"capability is for {cap.tool}, not {tool}")
    plain = unwrap(args)
    for key, expected in cap.scope.items():
        if key not in plain:
            raise CapabilityDenied(f"scoped arg {key!r} missing")
        if plain[key] != expected:
            raise CapabilityDenied(f"arg {key!r} outside capability scope")
    if cap.single_use and used is not None:
        used.add(cap.cap_id)
