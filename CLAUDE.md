# Tripwire

A multi-app agent that triages public GitHub issues into Linear + Slack, built so that
prompt injection in the issue body cannot make it act outside its plan.

## Hard invariants — never violate these

1. `contracts.py` is frozen. If code seems to need a change there, the code is wrong.
2. Nothing imports anything from `adapters/` except `kernel/broker.py`. No exceptions.
   Adapter methods are prefixed `_` to make violations obvious.
3. `agent/planner.py` must never receive raw untrusted text. It takes only the typed
   dict returned by `agent/extractor.py`. If you find yourself passing a body string
   into the planner, stop.
4. Every value that originated outside the system is wrapped in `Tainted` at the
   boundary and stays wrapped. Do not `.value` it out except inside the broker.
5. Every broker decision emits a `TraceEvent`. A denial that is not traced is a bug.
6. Capabilities are minted from the Plan, before argument substitution. Never mint a
   capability from a value that came out of the extractor.
7. Approval policy is injected, never hardcoded. Eval mode must never block on input.
8. No async. Everything is synchronous. No threads.
9. No agent frameworks. No langchain, no langgraph, no crewai. Plain Python.
10. LLM calls are temperature 0. All eval assertions are on adapter end-state, never on
    model text.

## Layout
contracts.py            frozen types
config.py               allowlists, canary, env
kernel/broker.py        THE ONLY DOOR to adapters
kernel/capability.py    mint + verify
kernel/taint.py         taint propagation + rule-of-two policy
kernel/canary.py        egress scanning for secrets
kernel/egress.py        recipient/channel/url allowlist
kernel/policy.py        ApprovalPolicy: AutoApprove | AutoDeny | Interactive
adapters/base.py        Adapter interface
adapters/fake_*.py      in-memory, seedable, resettable
adapters/real_*.py      requests + Authorization header
agent/extractor.py      quarantined LLM call, strict schema
agent/planner.py        privileged, sees typed fields only
agent/executor.py       mint caps, drive broker, handle denials
evals/scenarios/*.yaml  40 scenarios
evals/runner.py         run all, assert end-state
evals/report.py         scoreboard.md + scoreboard.json
demo/viewer.html        renders a trace JSON file
run.py                  CLI: run one scenario, or --real

## Workflow
Work one phase at a time. Run `pytest` before every commit. Do not start the next
phase until tests pass.
