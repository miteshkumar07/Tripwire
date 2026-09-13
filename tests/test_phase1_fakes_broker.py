import re
import time
from pathlib import Path

import pytest

from contracts import Capability, Tainted
from evals.loader import load, load_scenario
from kernel.broker import ToolBroker

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = Path(__file__).parent / "fixtures" / "sample_scenario.yaml"


def _cap(tool, scope=None):
    return Capability(cap_id="test", tool=tool, scope=scope or {}, expires_at=time.time() + 60)


@pytest.fixture
def broker():
    seed, _ = load(FIXTURE)
    b = ToolBroker.with_fakes("run-test")
    b.reset(seed)
    return b


def test_loader_returns_seed_and_expect():
    seed, expect = load(FIXTURE)
    assert seed["github"]["issues"][0]["number"] == 41
    assert expect["denials_include"] == ["egress_denied"]
    assert load_scenario(FIXTURE)["family"] == "exfiltration"


def test_broker_call_changes_snapshot(broker):
    before = broker.snapshot()
    result = broker.call("linear.create_issue",
                         {"team_id": "T1", "title": "Safari checkout", "description": "x"},
                         _cap("linear.create_issue"))
    after = broker.snapshot()
    assert before != after
    assert after["linear"]["created"] == [result.value["id"]]
    assert isinstance(result, Tainted) and result.trust == "untrusted"
    kinds = [e.kind for e in broker.trace.events]
    assert kinds == ["tool_call", "tool_result"]


def test_all_fake_ops(broker):
    gh = broker.call("github.list_issues", {}, _cap("github.list_issues")).value
    assert gh[0]["number"] == 41
    assert broker.call("github.get_issue", {"number": 41}, _cap("github.get_issue")).value["author"] == "randomperson"
    assert broker.call("github.get_comments", {"number": 41}, _cap("github.get_comments")).value == []
    hits = broker.call("linear.search_issues", {"query": "checkout broken"}, _cap("linear.search_issues")).value
    assert hits[0]["id"] == "ENG-100"
    broker.call("linear.comment", {"issue_id": "ENG-100", "body": "dup"}, _cap("linear.comment"))
    broker.call("linear.close_issue", {"issue_id": "ENG-100"}, _cap("linear.close_issue"))
    broker.call("slack.post_message", {"channel": "C_BUGS", "text": "hi"}, _cap("slack.post_message"))
    assert broker.call("slack.list_channels", {}, _cap("slack.list_channels")).value == [{"id": "C_BUGS"}, {"id": "C_GENERAL"}]
    snap = broker.snapshot()
    assert snap["linear"]["comments"] == [{"issue_id": "ENG-100", "body": "dup"}]
    assert snap["linear"]["closed"] == ["ENG-100"]
    assert snap["slack"]["messages"][0]["channel"] == "C_BUGS"


def test_broker_unwraps_tainted_args(broker):
    body = Tainted(value="from issue", origin="github:issue:41", trust="untrusted")
    broker.call("linear.comment", {"issue_id": "ENG-100", "body": body}, _cap("linear.comment"))
    assert broker.snapshot()["linear"]["comments"][0]["body"] == "from issue"


def test_adapter_errors_are_traced(broker):
    with pytest.raises(Exception):
        broker.call("slack.post_message", {"channel": "C_NOPE", "text": "x"}, _cap("slack.post_message"))
    assert broker.trace.events[-1].kind == "error"


def test_only_broker_imports_adapters():
    pattern = re.compile(r"^\s*(from|import)\s+adapters\b", re.M)
    offenders = []
    for path in ROOT.rglob("*.py"):
        rel = path.relative_to(ROOT)
        if rel.parts[0] in (".venv", "adapters", "tests") or rel == Path("kernel/broker.py"):
            continue
        if pattern.search(path.read_text()):
            offenders.append(str(rel))
    assert offenders == []
