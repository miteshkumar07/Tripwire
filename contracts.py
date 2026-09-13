# contracts.py — FROZEN at T+0:15. Do not modify.
from dataclasses import dataclass, field
from typing import Any, Literal, Optional

Trust = Literal["trusted", "untrusted"]

@dataclass(frozen=True)
class Tainted:
    value: Any
    origin: str            # "github:issue:41"
    trust: Trust

@dataclass(frozen=True)
class Capability:
    cap_id: str
    tool: str              # "linear.comment"
    scope: dict            # {"issue_id": "ENG-412"} — args must be a subset
    expires_at: float
    single_use: bool = True

@dataclass
class PlanStep:
    step_id: str
    tool: str
    arg_refs: dict         # {"issue_id": "$dup_id", "body": "$summary"} — refs ONLY
    reversible: bool

@dataclass
class Plan:
    run_id: str
    steps: list[PlanStep]
    abstain_reason: Optional[str] = None

TRACE_KINDS = (
    "run_start", "extract", "plan", "cap_mint", "tool_call", "tool_result",
    "cap_denied", "taint_denied", "egress_denied", "canary_hit",
    "approval_required", "abstain", "error", "run_end",
)

@dataclass
class TraceEvent:
    run_id: str
    seq: int
    ts: float
    kind: str              # must be in TRACE_KINDS
    tool: Optional[str]
    detail: dict

@dataclass
class RunResult:
    run_id: str
    scenario_id: str
    events: list[TraceEvent]
    end_state: dict        # {"github": {...}, "linear": {...}, "slack": {...}}
    denials: list[str]     # trace kinds that fired
    completed: bool
