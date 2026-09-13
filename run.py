"""CLI: run one scenario against fakes, or --real.

  python run.py --scenario evals/scenarios/ben_01_checkout_safari.yaml
  python run.py --real --github-issue 3            (Phase 6)
"""
import argparse
import json
import sys
import uuid
from pathlib import Path

from rich.console import Console
from rich.table import Table

from agent.executor import DENIAL_KINDS, result_to_dict, run_issue
from evals.loader import load_scenario
from kernel.broker import ToolBroker
from kernel.policy import AutoApprove, AutoDeny, Interactive

RUNS_DIR = Path(__file__).resolve().parent / "runs"
POLICIES = {"auto_approve": AutoApprove, "auto_deny": AutoDeny, "interactive": Interactive}


def print_trace(result, console: Console) -> None:
    table = Table(title=f"{result.scenario_id}  ({result.run_id})", show_lines=False)
    for col in ("#", "kind", "tool", "detail"):
        table.add_column(col, overflow="fold")
    for e in result.events:
        style = "bold red" if e.kind in DENIAL_KINDS else ("yellow" if e.kind in ("approval_required", "abstain", "error") else "")
        detail = json.dumps(e.detail, default=str)
        table.add_row(str(e.seq), e.kind, e.tool or "", detail[:240], style=style)
    console.print(table)
    snap = result.end_state
    console.print(
        f"completed={result.completed} denials={result.denials} "
        f"linear_created={len(snap['linear']['created'])} linear_comments={len(snap['linear']['comments'])} "
        f"slack_messages={len(snap['slack']['messages'])}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--scenario", help="scenario YAML to run against fake adapters")
    p.add_argument("--real", action="store_true", help="use real GitHub/Linear/Slack (Interactive approval)")
    p.add_argument("--github-issue", type=int, help="issue number to triage")
    p.add_argument("--policy", choices=sorted(POLICIES), help="approval policy for fake runs")
    args = p.parse_args(argv)
    console = Console()

    if args.real:
        console.print("[red]Real adapters are built in Phase 6.[/red]")
        return 2
    if not args.scenario:
        p.error("--scenario is required for fake runs")

    scenario = load_scenario(args.scenario)
    default_policy = "auto_deny" if scenario["id"].startswith("atk_") else "auto_approve"
    policy = POLICIES[args.policy or default_policy]()
    run_id = f"{scenario['id']}-{uuid.uuid4().hex[:8]}"
    broker = ToolBroker.with_fakes(run_id, approval_policy=policy)
    broker.reset(scenario["seed"])
    number = args.github_issue or scenario["seed"]["github"]["issues"][0]["number"]

    result = run_issue(broker, number, scenario_id=scenario["id"])
    print_trace(result, console)
    RUNS_DIR.mkdir(exist_ok=True)
    out = RUNS_DIR / f"{run_id}.json"
    out.write_text(json.dumps(result_to_dict(result), indent=2, default=str))
    console.print(f"trace written to {out}")
    return 0 if result.completed else 1


if __name__ == "__main__":
    sys.exit(main())
