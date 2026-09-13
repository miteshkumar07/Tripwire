"""ToolBroker - THE ONLY DOOR to adapters. Only module allowed to import adapters/.

Every call passes, in order: capability -> taint policy -> canary -> egress -> adapter.
Each failure emits its trace event and raises. Results come back wrapped as Tainted.
"""
import time
from typing import Any, Optional

import config
from adapters.base import Adapter, AdapterError
from adapters.fake_github import FakeGitHub
from adapters.fake_linear import FakeLinear
from adapters.fake_slack import FakeSlack
from contracts import TRACE_KINDS, Capability, Tainted, TraceEvent
from kernel import canary, capability as capmod, egress, taint
from kernel.canary import CanaryHit
from kernel.capability import CapabilityDenied
from kernel.egress import EgressDenied
from kernel.policy import ApprovalPolicy, AutoDeny
from kernel.taint import TaintDenied, unwrap

_MAX_DETAIL_CHARS = 300

KERNEL_DENIALS = (CapabilityDenied, TaintDenied, CanaryHit, EgressDenied)


class RunHalted(Exception):
    """Raised for every call after a canary hit. The run is over."""


def _preview(value: Any) -> Any:
    """Short, JSON-friendly rendering of a value for the trace."""
    if isinstance(value, Tainted):
        return {"tainted": value.trust, "origin": value.origin, "value": _preview(value.value)}
    if isinstance(value, dict):
        return {str(k): _preview(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_preview(v) for v in list(value)[:10]]
    if isinstance(value, str) and len(value) > _MAX_DETAIL_CHARS:
        return value[:_MAX_DETAIL_CHARS] + f"...(+{len(value) - _MAX_DETAIL_CHARS})"
    return value


class Trace:
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.events: list[TraceEvent] = []

    def emit(self, kind: str, tool: Optional[str] = None, detail: Optional[dict] = None) -> TraceEvent:
        if kind not in TRACE_KINDS:
            raise ValueError(f"unknown trace kind {kind!r}")
        event = TraceEvent(run_id=self.run_id, seq=len(self.events), ts=time.time(),
                           kind=kind, tool=tool, detail=_preview(detail or {}))
        self.events.append(event)
        return event


class ToolBroker:
    def __init__(self, adapters: dict[str, Adapter], run_id: str,
                 approval_policy: Optional[ApprovalPolicy] = None) -> None:
        self.adapters = adapters
        self.run_id = run_id
        self.approval_policy = approval_policy
        self.trace = Trace(run_id)
        self.used_caps: set[str] = set()
        self.canaries: set[str] = {config.CANARY}
        self.halted = False

    @classmethod
    def with_fakes(cls, run_id: str, approval_policy: Optional[ApprovalPolicy] = None) -> "ToolBroker":
        adapters = {a.name: a for a in (FakeGitHub(), FakeLinear(), FakeSlack())}
        return cls(adapters, run_id, approval_policy)

    def reset(self, seed: dict) -> None:
        seed = seed or {}
        for name, adapter in self.adapters.items():
            adapter.reset(seed.get(name, {}))
        self.used_caps = set()
        self.halted = False
        self.canaries = {config.CANARY}
        seeded = (seed.get("secrets") or {}).get("canary")
        if seeded:
            self.canaries.add(seeded)

    def snapshot(self) -> dict:
        return {name: adapter.snapshot() for name, adapter in self.adapters.items()}

    def call(self, tool: str, args: dict, capability: Capability) -> Tainted:
        if self.halted:
            self.trace.emit("error", tool, {"reason": "run halted after canary hit"})
            raise RunHalted("run halted after canary hit")

        app, _, op = tool.partition(".")
        adapter = self.adapters.get(app)
        if adapter is None or not op:
            self.trace.emit("error", tool, {"reason": "unknown tool"})
            raise AdapterError(f"unknown tool {tool!r}")

        cap_id = getattr(capability, "cap_id", None)

        # 1. capability
        try:
            capmod.verify(capability, tool, args, self.used_caps)
        except CapabilityDenied as e:
            self.trace.emit("cap_denied", tool, {"reason": str(e), "cap_id": cap_id})
            raise

        # 2. taint policy (rule of two)
        if taint.policy(tool, args):
            reason = "untrusted-derived args on an irreversible or external tool"
            policy = self.approval_policy or AutoDeny()
            self.trace.emit("approval_required", tool, {
                "reason": reason, "untrusted_args": taint.untrusted_keys(args),
                "policy": policy.name})
            if not policy.approve(tool, args, reason):
                self.trace.emit("taint_denied", tool, {
                    "reason": "approval refused", "untrusted_args": taint.untrusted_keys(args)})
                raise TaintDenied(f"{tool}: approval refused for untrusted-derived args")

        # 3. canary (outbound secrets). Never echo the args into the trace here.
        try:
            canary.scan(args, self.canaries)
        except CanaryHit as e:
            self.halted = True
            self.trace.emit("canary_hit", tool, {"reason": str(e), "origin": e.origin, "cap_id": cap_id})
            raise

        # 4. egress allowlist
        try:
            egress.check(tool, args)
        except EgressDenied as e:
            self.trace.emit("egress_denied", tool, {"reason": str(e), "cap_id": cap_id})
            raise

        # 5. adapter
        self.trace.emit("tool_call", tool, {"cap_id": cap_id, "args": args})
        try:
            result = adapter._call(op, unwrap(args))
        except AdapterError as e:
            self.trace.emit("error", tool, {"reason": str(e)})
            raise
        self.trace.emit("tool_result", tool, {"result": result})
        return Tainted(value=result, origin=f"{app}:{op}", trust="untrusted")
