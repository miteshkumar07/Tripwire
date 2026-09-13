"""Emit scoreboard.md and scoreboard.json.

  python -m evals.report     # rebuild the scoreboard from runs/*.json
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import config

ROOT = Path(__file__).resolve().parent.parent


def _mean(values):
    values = list(values)
    return round(sum(values) / len(values), 2) if values else 0.0


def _rate(n, d):
    return round(n / d, 3) if d else 0.0


def summarize(records: list[dict]) -> dict:
    benign = [r for r in records if r["kind"] == "benign"]
    attacks = [r for r in records if r["kind"] == "attack"]

    per_family: dict[str, dict] = {}
    for r in attacks:
        fam = per_family.setdefault(r["family"], {"n": 0, "blocked": 0, "as_expected": 0})
        fam["n"] += 1
        fam["blocked"] += r["safe"]
        fam["as_expected"] += r["passed"]

    got_through = [{
        "id": r["id"],
        "family": r["family"],
        "failed_safety_checks": [c for c in r["checks"] if not c["ok"] and c["category"] == "safety"],
        "should_have_fired": r["expected_denials"],
        "fired": r["denials"],
        "trace_file": r["trace_file"],
    } for r in attacks if not r["safe"]]

    mismatches = [{
        "id": r["id"],
        "kind": r["kind"],
        "failed_checks": [c for c in r["checks"] if not c["ok"]],
        "trace_file": r["trace_file"],
    } for r in records if not r["passed"] and (r["safe"] or r["kind"] == "benign")]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "models": {"extractor": config.MODEL_EXTRACTOR, "planner": config.MODEL_PLANNER},
        "benign": {"n": len(benign), "succeeded": sum(r["passed"] for r in benign),
                   "success_rate": _rate(sum(r["passed"] for r in benign), len(benign)),
                   "unsafe": [r["id"] for r in benign if not r["safe"]]},
        "attacks": {"n": len(attacks), "blocked": sum(r["safe"] for r in attacks),
                    "block_rate": _rate(sum(r["safe"] for r in attacks), len(attacks)),
                    "as_expected": sum(r["passed"] for r in attacks),
                    "per_family": per_family},
        "got_through": got_through,
        "mismatches": mismatches,
        "means": {"tool_calls": _mean(r["tool_calls"] for r in records),
                  "wall_clock_s": _mean(r["wall_clock_s"] for r in records),
                  "tokens": _mean(r["tokens"] for r in records)},
        "scenarios": [{k: r[k] for k in ("id", "family", "passed", "safe", "completed", "denials",
                                          "expected_denials", "tool_calls", "tokens", "wall_clock_s")}
                      for r in records],
    }


def _fmt_check(c):
    return f"`{c['name']}` expected {c['expected']} got {c['actual']}"


def render_markdown(s: dict) -> str:
    b, a = s["benign"], s["attacks"]
    lines = [
        "# Tripwire scoreboard",
        "",
        f"Generated {s['generated_at']} · extractor `{s['models']['extractor']}` · planner `{s['models']['planner']}` · temperature 0",
        "",
        "| Metric | Result |",
        "|---|---|",
        f"| Benign task success | **{b['succeeded']}/{b['n']}** |",
        f"| Attacks blocked (no harmful end state) | **{a['blocked']}/{a['n']}** |",
        f"| Attacks blocked by the expected defence | {a['as_expected']}/{a['n']} |",
        f"| Mean tool calls per run | {s['means']['tool_calls']} |",
        f"| Mean wall-clock per run | {s['means']['wall_clock_s']}s |",
        f"| Mean tokens per run | {s['means']['tokens']} |",
        "",
        "## Attacks by family",
        "",
        "| Family | Blocked | As expected |",
        "|---|---|---|",
    ]
    for fam, v in sorted(a["per_family"].items()):
        lines.append(f"| {fam} | {v['blocked']}/{v['n']} | {v['as_expected']}/{v['n']} |")

    lines += ["", "## Attacks that got through", ""]
    if not s["got_through"]:
        lines.append("None.")
    for g in s["got_through"]:
        lines.append(f"- **{g['id']}** ({g['family']}): " + "; ".join(_fmt_check(c) for c in g["failed_safety_checks"])
                     + f". Should have fired: {g['should_have_fired'] or 'n/a'}; fired: {g['fired']}. Trace: `{g['trace_file']}`")

    lines += ["", "## Other mismatches (no harmful effect)", ""]
    if not s["mismatches"]:
        lines.append("None.")
    for m in s["mismatches"]:
        lines.append(f"- **{m['id']}** ({m['kind']}): " + "; ".join(_fmt_check(c) for c in m["failed_checks"])
                     + f". Trace: `{m['trace_file']}`")

    lines += ["", "## All scenarios", "", "| Scenario | Family | Passed | Safe | Denials fired | Expected |",
              "|---|---|---|---|---|---|"]
    for r in s["scenarios"]:
        lines.append(f"| {r['id']} | {r['family']} | {'yes' if r['passed'] else 'no'} | "
                     f"{'yes' if r['safe'] else '**no**'} | {', '.join(r['denials']) or '-'} | "
                     f"{', '.join(r['expected_denials']) or '-'} |")
    lines.append("")
    return "\n".join(lines)


def write(records: list[dict], out_dir: Path = ROOT) -> tuple[Path, Path]:
    summary = summarize(records)
    md_path, json_path = Path(out_dir) / "scoreboard.md", Path(out_dir) / "scoreboard.json"
    md_path.write_text(render_markdown(summary))
    json_path.write_text(json.dumps(summary, indent=2))
    return md_path, json_path


def main() -> int:
    records = [json.loads(p.read_text())["record"] for p in sorted((ROOT / "runs").glob("*.json"))
               if "record" in json.loads(p.read_text())]
    md_path, _ = write(records)
    print(md_path.read_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
