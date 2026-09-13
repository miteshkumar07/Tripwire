"""ToolBroker - THE ONLY DOOR to adapters. Only module allowed to import adapters/.

Phase 1: pass-through. Calls the adapter, wraps the result in Tainted, emits trace
events. The `call` signature is final; later phases only add checks inside it.
"""
import time
from typing import Any, Optional

from adapters.base import Adapter, AdapterError
from adapters.fake_github import FakeGitHub
from adapters.fake_linear import FakeLinear
from adapters.fake_slack import FakeSlack
from contracts import TRACE_KINDS, Capability, Tainted, TraceEvent

_MAX_DETAIL_CHARS = 300


def _preview(value: Any) -> Any:
    """Short, JSON-friendly rendering of a value for the trace."""
    if isinstance(value, Tainted):
        return {"tainted": value.trust, "origin": value.origin, "value": _preview(value.value)}
    if isinstance(value, dict):
        return {k: _preview(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_preview(v) for v in value[:10]]
    if isinstance(value, str) and len(value) > _MAX_DETAIL_CHARS:
        return value[:_MAX_DETAIL_CHARS] + f"...(+{len(value) - _MAX_DETAIL_CHARS})"
    return value


def unwrap(value: Any) -> Any:
    if isinstance(value, Tainted):
        return unwrap(value.value)
    if isinstance(value, dict):
        return {k: unwrap(v) for k, v in value.items()}
    if isinstance(value, list):
        return [unwrap(v) for v in value]
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
    def __init__(self, adapters: dict[str, Adapter], run_id: str, approval_policy=None) -> None:
        self.adapters = adapters
        self.run_id = run_id
        self.approval_policy = approval_policy
        self.trace = Trace(run_id)
        self.used_caps: set[str] = set()

    @classmethod
    def with_fakes(cls, run_id: str, approval_policy=None) -> "ToolBroker":
        adapters = {a.name: a for a in (FakeGitHub(), FakeLinear(), FakeSlack())}
        return cls(adapters, run_id, approval_policy)

    def reset(self, seed: dict) -> None:
        for name, adapter in self.adapters.items():
            adapter.reset((seed or {}).get(name, {}))

    def snapshot(self) -> dict:
        return {name: adapter.snapshot() for name, adapter in self.adapters.items()}

    def call(self, tool: str, args: dict, capability: Capability) -> Tainted:
        app, _, op = tool.partition(".")
        adapter = self.adapters.get(app)
        if adapter is None or not op:
            self.trace.emit("error", tool, {"reason": "unknown tool"})
            raise AdapterError(f"unknown tool {tool!r}")

        self.trace.emit("tool_call", tool, {
            "cap_id": getattr(capability, "cap_id", None), "args": args})
        try:
            result = adapter._call(op, unwrap(args))
        except AdapterError as e:
            self.trace.emit("error", tool, {"reason": str(e)})
            raise
        self.trace.emit("tool_result", tool, {"result": result})
        return Tainted(value=result, origin=f"{app}:{op}", trust="untrusted")
