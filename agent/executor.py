"""Mints capabilities from the plan, substitutes args, drives the broker.

Order per run: read issue -> extract (quarantined) -> dedupe -> plan -> mint every
capability from the plan -> substitute $symbols -> broker.call each step.
"""
import dataclasses
import re
import time
from typing import Optional

import config
from agent import extractor, planner
from contracts import Plan, PlanStep, RunResult, Tainted
from kernel import capability as capmod
from kernel.broker import KERNEL_DENIALS, RunHalted, ToolBroker
from kernel.canary import CanaryHit
from kernel.taint import concat, endorse, unwrap

DENIAL_KINDS = ("cap_denied", "taint_denied", "egress_denied", "canary_hit")
# Structural args decide WHERE an effect lands. The capability pins them.
SCOPED_ARGS = frozenset({"channel", "team_id", "issue_id", "number"})
LINEAR_ID = re.compile(r"^[A-Z][A-Z0-9]{0,9}-\d{1,7}$")
DEDUPE_LIMIT = 3
_WORD = re.compile(r"[^\w\s.,;:'\"()\-/]")


class SymbolTable:
    """$name -> Tainted value. Owned by the executor; the planner only sees names + docs."""

    def __init__(self) -> None:
        self._values: dict[str, Tainted] = {}
        self._docs: dict[str, str] = {}

    def define(self, name: str, value: Tainted, doc: str) -> None:
        self._values[name] = value
        self._docs[name] = doc

    def docs(self) -> dict[str, str]:
        return dict(self._docs)

    def resolve(self, ref: str) -> Tainted:
        return self._values[ref]


def _trusted(value, origin: str) -> Tainted:
    return Tainted(value=value, origin=origin, trust="trusted")


def reduce_dedupe(results: Tainted) -> list[Tainted]:
    """Search results -> [{id, title, score}] with ids endorsed by format."""
    reduced = []
    for hit in (unwrap(results) or [])[:DEDUPE_LIMIT]:
        issue_id = str(hit.get("id", ""))
        if not LINEAR_ID.match(issue_id):
            continue
        title = re.sub(r"\s+", " ", _WORD.sub("", str(hit.get("title", ""))))[:120]
        reduced.append({
            "id": endorse(Tainted(issue_id, "linear:search_issues", "untrusted"), {issue_id}),
            "title": Tainted(title, f"linear:issue:{issue_id}", "untrusted"),
            "score": float(hit.get("score", 0.0)),
        })
    return reduced


def build_symbols(number: int, fields: dict, candidates: list) -> SymbolTable:
    """Composite text is built with concat(), so every part keeps its own trust and origin
    all the way to the broker's canary scan."""
    severity = endorse(fields["severity"], extractor.SEVERITIES).value
    area = endorse(fields["area"], extractor.AREAS).value
    summary = fields["summary"]
    url = f"https://github.com/{config.GITHUB_REPO}/issues/{number}"

    t = SymbolTable()
    t.define("$team_id", _trusted(config.LINEAR_TEAM_ID, "config"), "Linear team for new tickets")
    t.define("$channel_bugs", _trusted(config.SLACK_CHANNEL_BUGS, "config"),
             "Slack #tw-bugs, for high or critical severity")
    t.define("$channel_general", _trusted(config.SLACK_CHANNEL_GENERAL, "config"),
             "Slack #tw-general, for low or medium severity")
    t.define("$ticket_title", concat(f"GH#{number} [{severity}/{area}] ", summary),
             "Title for a new Linear ticket")
    t.define("$ticket_description",
             concat(summary, f"\n\nReported on GitHub: {url}\nSeverity: {severity}\nArea: {area}"),
             "Description for a new Linear ticket")
    t.define("$slack_text",
             _trusted(f"Triaged {severity} {area} bug from GitHub #{number}: {url}", "executor:template"),
             "Slack notification text")
    for i, cand in enumerate(candidates, start=1):
        issue_id = cand["id"].value
        t.define(f"$dup_{i}", cand["id"], f"Linear ticket id of dedupe candidate #{i}")
        # Quote the matched ticket's TITLE (short, written by our team). Never its description.
        t.define(f"$dup_{i}_comment",
                 concat(f"Duplicate of {issue_id}: ", cand["title"],
                        f"\n\nAnother report on GitHub #{number}: {url}\n\n", summary),
                 f"Comment body for dedupe candidate #{i} (use only with $dup_{i})")
    return t


def mint_for_step(step: PlanStep, symbols: SymbolTable, broker: ToolBroker):
    """Mint BEFORE substitution. The scope holds only structural args bound to trusted,
    non-extractor symbols. Returns None (and traces a denial) if the plan binds a
    structural arg to untrusted data."""
    scope = {}
    for arg, ref in step.arg_refs.items():
        if arg not in SCOPED_ARGS:
            continue
        sym = symbols.resolve(ref)
        if sym.trust != "trusted" or sym.origin.startswith("github:"):
            broker.trace.emit("cap_denied", step.tool, {
                "step_id": step.step_id, "reason": f"structural arg {arg!r} bound to untrusted {ref}"})
            return None
        scope[arg] = sym.value
    cap = capmod.mint(step.tool, scope)
    broker.trace.emit("cap_mint", step.tool, {
        "step_id": step.step_id, "cap_id": cap.cap_id, "scope": scope,
        "arg_refs": step.arg_refs, "minted_before_substitution": True})
    return cap


def _read(broker: ToolBroker, tool: str, args: dict) -> Tainted:
    scope = {k: unwrap(v) for k, v in args.items()
             if k in SCOPED_ARGS and isinstance(v, Tainted) and v.trust == "trusted"}
    cap = capmod.mint(tool, scope)
    broker.trace.emit("cap_mint", tool, {"cap_id": cap.cap_id, "scope": scope, "step_id": "read"})
    return broker.call(tool, args, cap)


def run_issue(broker: ToolBroker, issue_number: int, scenario_id: str = "adhoc",
              client=None) -> RunResult:
    trace = broker.trace
    started = time.time()
    policy_name = getattr(broker.approval_policy, "name", None)
    trace.emit("run_start", None, {"scenario_id": scenario_id, "issue_number": issue_number,
                                   "approval_policy": policy_name})
    tokens = {"input_tokens": 0, "output_tokens": 0}
    halted = abstained = crashed = False
    succeeded = 0
    plan: Optional[Plan] = None

    try:
        number = _trusted(int(issue_number), "operator")
        issue = _read(broker, "github.get_issue", {"number": number})
        comments = _read(broker, "github.get_comments", {"number": number})

        origin = f"github:issue:{int(issue_number)}"
        # Quarantine boundary: the raw text is unwrapped here and only here, for the extractor.
        fields, xmeta = extractor.extract(unwrap(issue), unwrap(comments), origin, client=client)
        for k in tokens:
            tokens[k] += xmeta["usage"].get(k, 0)
        trace.emit("extract", None, {"fields": fields, **xmeta})

        search = _read(broker, "linear.search_issues", {
            "query": fields["summary"], "team_id": _trusted(config.LINEAR_TEAM_ID, "config"),
            "limit": DEDUPE_LIMIT})
        candidates = reduce_dedupe(search)
        symbols = build_symbols(int(issue_number), fields, candidates)

        typed = {k: v.value for k, v in fields.items()}  # primitives only, per plan contract
        dedupe_view = [{"id": c["id"].value, "title": c["title"].value, "score": c["score"]}
                       for c in candidates]
        plan, pmeta = planner.plan(broker.run_id, typed, dedupe_view, symbols.docs(), client=client)
        for k in tokens:
            tokens[k] += pmeta["usage"].get(k, 0)
        trace.emit("plan", None, {"steps": [dataclasses.asdict(s) for s in plan.steps],
                                  "abstain_reason": plan.abstain_reason, **pmeta})

        if plan.abstain_reason:
            abstained = True
            trace.emit("abstain", None, {"reason": plan.abstain_reason})
        else:
            minted = [(step, mint_for_step(step, symbols, broker)) for step in plan.steps]
            for step, cap in minted:
                if cap is None:
                    continue
                args = {arg: symbols.resolve(ref) for arg, ref in step.arg_refs.items()}
                try:
                    broker.call(step.tool, args, cap)
                    succeeded += 1
                except (CanaryHit, RunHalted):
                    halted = True
                    break
                except KERNEL_DENIALS:
                    continue  # steps are independent; never retry a denied step
                except Exception:
                    continue  # adapter failure, already traced by the broker
    except (CanaryHit, RunHalted):
        halted = True
    except Exception as e:  # LLM/API failure or bug: trace it, never crash the eval suite
        crashed = True
        trace.emit("error", None, {"reason": f"{type(e).__name__}: {e}"})

    completed = not halted and not crashed and (abstained or succeeded > 0)
    tool_calls = sum(1 for e in trace.events if e.kind == "tool_call")
    trace.emit("run_end", None, {"completed": completed, "halted": halted, "steps_succeeded": succeeded,
                                 "tool_calls": tool_calls, "tokens": tokens,
                                 "wall_clock_s": round(time.time() - started, 3)})
    denials = sorted({e.kind for e in trace.events if e.kind in DENIAL_KINDS})
    return RunResult(run_id=broker.run_id, scenario_id=scenario_id, events=list(trace.events),
                     end_state=broker.snapshot(), denials=denials, completed=completed)


def result_to_dict(result: RunResult) -> dict:
    return dataclasses.asdict(result)
