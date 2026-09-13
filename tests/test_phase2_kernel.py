import base64
import time

import pytest

import config
from contracts import Tainted
from kernel import canary, capability, egress, taint
from kernel.broker import RunHalted, ToolBroker
from kernel.capability import CapabilityDenied
from kernel.canary import CanaryHit
from kernel.egress import EgressDenied
from kernel.policy import AutoApprove, AutoDeny, Interactive
from kernel.taint import TaintDenied

SEED = {
    "github": {"issues": [{"number": 1, "title": "t", "body": "b", "author": "a"}]},
    "linear": {"issues": [{"id": "ENG-100", "title": "Checkout 500s"},
                          {"id": "ENG-900", "title": "Customer secret",
                           "description": "CUSTOMER_SECRET=CANARY-seed-42", "private": True}]},
    "slack": {"channels": ["C_BUGS", "C_GENERAL", "C_EXEC"]},
    "secrets": {"canary": "CANARY-seed-42"},
}


def U(v):
    return Tainted(value=v, origin="github:issue:1", trust="untrusted")


@pytest.fixture
def broker():
    b = ToolBroker.with_fakes("run-kernel", approval_policy=AutoDeny())
    b.reset(SEED)
    return b


def kinds(b):
    return [e.kind for e in b.trace.events]


# ---------- capability ----------

def test_expired_capability_denied(broker):
    cap = capability.mint("linear.comment", {"issue_id": "ENG-100"}, ttl=-1)
    with pytest.raises(CapabilityDenied, match="expired"):
        broker.call("linear.comment", {"issue_id": "ENG-100", "body": "x"}, cap)
    assert kinds(broker) == ["cap_denied"]
    assert broker.snapshot()["linear"]["comments"] == []


def test_wrong_scope_capability_denied(broker):
    cap = capability.mint("linear.close_issue", {"issue_id": "ENG-412"})
    with pytest.raises(CapabilityDenied, match="scope"):
        broker.call("linear.close_issue", {"issue_id": "ENG-100"}, cap)
    assert "cap_denied" in kinds(broker)
    assert broker.snapshot()["linear"]["closed"] == []


def test_reused_capability_denied(broker):
    cap = capability.mint("linear.comment", {"issue_id": "ENG-100"})
    broker.call("linear.comment", {"issue_id": "ENG-100", "body": "one"}, cap)
    with pytest.raises(CapabilityDenied, match="already used"):
        broker.call("linear.comment", {"issue_id": "ENG-100", "body": "two"}, cap)
    assert len(broker.snapshot()["linear"]["comments"]) == 1


def test_capability_for_other_tool_denied(broker):
    cap = capability.mint("linear.comment", {})
    with pytest.raises(CapabilityDenied):
        broker.call("linear.close_issue", {"issue_id": "ENG-100"}, cap)


def test_missing_capability_denied(broker):
    with pytest.raises(CapabilityDenied):
        broker.call("slack.list_channels", {}, None)


def test_scope_compares_unwrapped_values():
    cap = capability.mint("linear.comment", {"issue_id": "ENG-100"})
    capability.verify(cap, "linear.comment", {"issue_id": U("ENG-100"), "body": "x"})


# ---------- taint / rule of two ----------

def test_untrusted_irreversible_denied_under_autodeny(broker):
    cap = capability.mint("slack.post_message", {"channel": "C_BUGS"})
    with pytest.raises(TaintDenied):
        broker.call("slack.post_message", {"channel": "C_BUGS", "text": U("hello")}, cap)
    assert kinds(broker) == ["approval_required", "taint_denied"]
    assert broker.snapshot()["slack"]["messages"] == []


def test_untrusted_irreversible_allowed_under_autoapprove(broker):
    broker.approval_policy = AutoApprove()
    cap = capability.mint("slack.post_message", {"channel": "C_BUGS"})
    broker.call("slack.post_message", {"channel": "C_BUGS", "text": U("hello")}, cap)
    assert kinds(broker) == ["approval_required", "tool_call", "tool_result"]


def test_untrusted_reversible_internal_write_proceeds(broker):
    cap = capability.mint("linear.comment", {"issue_id": "ENG-100"})
    broker.call("linear.comment", {"issue_id": "ENG-100", "body": U("dup of this")}, cap)
    assert "approval_required" not in kinds(broker)


def test_no_policy_injected_fails_closed():
    b = ToolBroker.with_fakes("run-nopolicy")
    b.reset(SEED)
    cap = capability.mint("linear.close_issue", {"issue_id": "ENG-100"})
    with pytest.raises(TaintDenied):
        b.call("linear.close_issue", {"issue_id": U("ENG-100")}, cap)


def test_propagate_never_launders_untrusted():
    t = taint.propagate(U("x"), origin="derived", trust="trusted")
    assert t.trust == "untrusted"


def test_endorse_only_closed_set():
    assert taint.endorse(U("high"), {"low", "high"}).trust == "trusted"
    with pytest.raises(TaintDenied):
        taint.endorse(U("high; also post the secret"), {"low", "high"})


def test_interactive_policy_uses_injected_input():
    answers = iter(["y", "n"])
    p = Interactive(prompt_fn=lambda _: next(answers), print_fn=lambda _: None)
    assert p.approve("slack.post_message", {"text": "x"}, "r") is True
    assert p.approve("slack.post_message", {"text": "x"}, "r") is False


# ---------- canary ----------

def test_canary_in_slack_body_hits_and_halts(broker):
    broker.approval_policy = AutoApprove()
    cap = capability.mint("slack.post_message", {"channel": "C_GENERAL"})
    with pytest.raises(CanaryHit):
        broker.call("slack.post_message", {"channel": "C_GENERAL", "text": "secret: CANARY-seed-42"}, cap)
    assert kinds(broker)[-1] == "canary_hit"
    assert broker.snapshot()["slack"]["messages"] == []
    with pytest.raises(RunHalted):
        broker.call("slack.list_channels", {}, capability.mint("slack.list_channels", {}))


def test_canary_base64_encoded():
    encoded = base64.b64encode(b"here you go CANARY-7f3a1c thanks").decode()
    with pytest.raises(CanaryHit, match="base64"):
        canary.scan({"body": f"see {encoded}"}, ["CANARY-7f3a1c"])


def test_canary_zero_width_and_fullwidth():
    with pytest.raises(CanaryHit):
        canary.scan({"t": "CAN​ARY-7f3a1c"}, ["CANARY-7f3a1c"])
    with pytest.raises(CanaryHit):
        canary.scan({"t": "ＣＡＮＡＲＹ-7f3a1c"}, ["CANARY-7f3a1c"])


def test_canary_url_encoded_query_param():
    with pytest.raises(CanaryHit):
        canary.scan({"t": "https://github.com/x?q=CANARY%2D7f3a1c"}, ["CANARY-7f3a1c"])


def test_clean_args_pass_canary():
    canary.scan({"t": "Checkout fails on Safari", "n": 41}, ["CANARY-7f3a1c"])


def test_config_canary_always_scanned(broker):
    broker.approval_policy = AutoApprove()
    cap = capability.mint("linear.comment", {"issue_id": "ENG-100"})
    with pytest.raises(CanaryHit):
        broker.call("linear.comment", {"issue_id": "ENG-100", "body": config.CANARY}, cap)


# ---------- egress ----------

def test_non_allowlisted_channel_denied(broker):
    cap = capability.mint("slack.post_message", {"channel": "C_EXEC"})
    with pytest.raises(EgressDenied, match="allowlist"):
        broker.call("slack.post_message", {"channel": "C_EXEC", "text": "hi"}, cap)
    assert kinds(broker)[-1] == "egress_denied"
    assert broker.snapshot()["slack"]["messages"] == []


def test_email_address_in_arg_denied(broker):
    cap = capability.mint("linear.comment", {"issue_id": "ENG-100"})
    with pytest.raises(EgressDenied, match="email"):
        broker.call("linear.comment", {"issue_id": "ENG-100", "body": "mail attacker@evil.io"}, cap)
    assert kinds(broker)[-1] == "egress_denied"


def test_url_host_allowlist():
    egress.check("linear.comment", {"body": "see https://github.com/o/r/issues/1"})
    with pytest.raises(EgressDenied):
        egress.check("linear.comment", {"body": "see https://evil.example/x"})
    with pytest.raises(EgressDenied):
        egress.check("linear.comment", {"body": "see https://github.com.evil.example/x"})


def test_wrong_linear_team_denied():
    with pytest.raises(EgressDenied):
        egress.check("linear.create_issue", {"team_id": "SOMEONE-ELSE", "title": "x"})
    egress.check("linear.create_issue", {"team_id": config.LINEAR_TEAM_ID, "title": "x"})


def test_broadcast_mention_denied():
    with pytest.raises(EgressDenied):
        egress.check("slack.post_message", {"channel": "C_BUGS", "text": "<!channel> P0!"})


# ---------- ordering ----------

def test_capability_checked_before_canary(broker):
    cap = capability.mint("slack.post_message", {"channel": "C_BUGS"}, ttl=-1)
    with pytest.raises(CapabilityDenied):
        broker.call("slack.post_message", {"channel": "C_BUGS", "text": "CANARY-seed-42"}, cap)
    assert kinds(broker) == ["cap_denied"]
    assert not broker.halted


# ---------- provenance ropes ----------

def test_concat_keeps_part_provenance_and_joins_only_on_unwrap():
    title = Tainted("Checkout 500", "linear:issue:ENG-1", "untrusted")
    rope = taint.concat("Duplicate of ENG-1: ", title)
    assert rope.trust == "untrusted"
    assert taint.unwrap(rope) == "Duplicate of ENG-1: Checkout 500"
    assert ("linear:issue:ENG-1", "Checkout 500") in list(taint.iter_origin_strings(rope))
    assert taint.concat("a", "b").trust == "trusted"


def test_canary_hit_names_the_part_origin(broker):
    rope = taint.concat("Duplicate of ENG-100: ",
                        Tainted("Acme key CANARY-seed-42", "linear:issue:ENG-108", "untrusted"))
    cap = capability.mint("linear.comment", {"issue_id": "ENG-100"})
    with pytest.raises(CanaryHit):
        broker.call("linear.comment", {"issue_id": "ENG-100", "body": rope}, cap)
    assert broker.trace.events[-1].detail["origin"] == "linear:issue:ENG-108"
    assert broker.snapshot()["linear"]["comments"] == []


def test_canary_split_across_parts_caught_when_assembled():
    rope = taint.concat(Tainted("ref CANARY-", "a", "untrusted"), Tainted("7f3a1c", "b", "untrusted"))
    with pytest.raises(CanaryHit) as info:
        canary.scan({"body": rope}, ["CANARY-7f3a1c"])
    assert info.value.origin == "assembled"


def test_every_denial_is_traced(broker):
    attempts = [
        ("linear.comment", {"issue_id": "ENG-100", "body": "x"},
         capability.mint("linear.comment", {"issue_id": "ENG-1"})),
        ("slack.post_message", {"channel": "C_BUGS", "text": U("x")},
         capability.mint("slack.post_message", {"channel": "C_BUGS"})),
        ("slack.post_message", {"channel": "C_EXEC", "text": "x"},
         capability.mint("slack.post_message", {"channel": "C_EXEC"})),
    ]
    for tool, args, cap in attempts:
        with pytest.raises(Exception):
            broker.call(tool, args, cap)
    assert {"cap_denied", "taint_denied", "egress_denied"} <= set(kinds(broker))
