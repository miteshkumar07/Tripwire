"""Real adapters against a fake HTTP session: request shape, response mapping, errors.
No network."""
import time

import pytest

import config
from adapters.base import AdapterError
from adapters.real_github import RealGitHub
from adapters.real_linear import RealLinear
from adapters.real_slack import RealSlack
from contracts import Capability
from kernel.broker import ToolBroker
from kernel.egress import EgressDenied
from kernel.policy import AutoApprove


class Resp:
    def __init__(self, data, status=200):
        self._data, self.status_code = data, status

    def json(self):
        return self._data


class Session:
    def __init__(self, handler):
        self.handler, self.calls = handler, []

    def get(self, url, headers=None, params=None, timeout=None):
        self.calls.append({"method": "GET", "url": url, "params": params, "headers": headers})
        return self.handler("GET", url, params)

    def post(self, url, headers=None, json=None, timeout=None):
        self.calls.append({"method": "POST", "url": url, "json": json, "headers": headers})
        return self.handler("POST", url, json)


# ---------- GitHub ----------

def test_github_get_issue_maps_fields_and_uses_bearer():
    def handler(method, url, _):
        if url.endswith("/issues/7"):
            return Resp({"number": 7, "title": "T", "body": None, "state": "open", "user": {"login": "octo"}})
        if url.endswith("/users/octo"):
            return Resp({"name": "Octo Cat"})
        raise AssertionError(url)
    s = Session(handler)
    issue = RealGitHub(token="tok", repo="o/r", session=s)._call("get_issue", {"number": 7})
    assert issue == {"number": 7, "title": "T", "body": "", "author": "octo", "author_name": "Octo Cat", "state": "open"}
    assert s.calls[0]["headers"]["Authorization"] == "Bearer tok"
    assert s.calls[0]["url"] == "https://api.github.com/repos/o/r/issues/7"


def test_github_list_skips_pull_requests_and_http_errors_raise():
    s = Session(lambda *_: Resp([{"number": 1, "title": "a", "state": "open"},
                                 {"number": 2, "title": "pr", "state": "open", "pull_request": {}}]))
    assert [i["number"] for i in RealGitHub(token="t", repo="o/r", session=s)._call("list_issues", {})] == [1]
    with pytest.raises(AdapterError, match="404"):
        RealGitHub(token="t", repo="o/r", session=Session(lambda *_: Resp({}, 404)))._call("get_comments", {"number": 9})


# ---------- Linear ----------

TEAM_ISSUES = {"data": {"issues": {"nodes": [
    {"id": "u1", "identifier": "TRI-5", "title": "Checkout 500 error on Safari", "description": "",
     "state": {"name": "Todo", "type": "unstarted"}},
    {"id": "u2", "identifier": "TRI-6", "title": "Password reset email delayed", "description": None,
     "state": {"name": "Todo", "type": "unstarted"}},
]}}}


def test_linear_search_scores_locally_and_returns_identifiers():
    s = Session(lambda *_: Resp(TEAM_ISSUES))
    hits = RealLinear(api_key="k", team_id="team-1", session=s)._call(
        "search_issues", {"query": "Checkout returns a 500 error on Safari"})
    assert hits[0]["id"] == "TRI-5" and hits[0]["score"] == 1.0
    assert s.calls[0]["json"]["variables"] == {"team": "team-1", "first": 100}
    assert s.calls[0]["headers"]["Authorization"] == "k"


def test_linear_comment_resolves_identifier_then_creates_comment():
    def handler(_, __, body):
        if "issue(id:" in body["query"]:
            return Resp({"data": {"issue": {"id": "uuid-5", "identifier": "TRI-5"}}})
        return Resp({"data": {"commentCreate": {"success": True, "comment": {"id": "c1", "url": "https://linear.app/x"}}}})
    s = Session(handler)
    linear = RealLinear(api_key="k", team_id="team-1", session=s)
    linear._call("comment", {"issue_id": "TRI-5", "body": "dup"})
    assert s.calls[1]["json"]["variables"] == {"input": {"issueId": "uuid-5", "body": "dup"}}
    assert linear.comments == [{"issue_id": "TRI-5", "body": "dup"}]


def test_linear_create_records_identifier_and_graphql_errors_raise():
    s = Session(lambda *_: Resp({"data": {"issueCreate": {"success": True, "issue": {
        "id": "u9", "identifier": "TRI-9", "url": "https://linear.app/t/TRI-9"}}}}))
    linear = RealLinear(api_key="k", team_id="team-1", session=s)
    assert linear._call("create_issue", {"team_id": "team-1", "title": "t", "description": "d"})["id"] == "TRI-9"
    assert linear.created == ["TRI-9"]
    bad = RealLinear(api_key="k", team_id="team-1",
                     session=Session(lambda *_: Resp({"errors": [{"message": "Authentication required"}]}, 400)))
    with pytest.raises(AdapterError, match="Authentication required"):
        bad._call("search_issues", {"query": "checkout broken"})


# ---------- Slack ----------

def test_slack_post_disables_mentions_and_records_message():
    s = Session(lambda *_: Resp({"ok": True, "channel": "C1", "ts": "1.2"}))
    slack = RealSlack(token="xoxb", session=s)
    slack._call("post_message", {"channel": "C1", "text": "hi"})
    sent = s.calls[0]["json"]
    assert sent["link_names"] is False and sent["unfurl_links"] is False
    assert s.calls[0]["headers"]["Authorization"] == "Bearer xoxb"
    assert slack.messages == [{"channel": "C1", "text": "hi", "ts": "1.2"}]


def test_slack_not_ok_raises_with_error_code():
    s = Session(lambda *_: Resp({"ok": False, "error": "not_in_channel"}))
    with pytest.raises(AdapterError, match="not_in_channel"):
        RealSlack(token="x", session=s)._call("post_message", {"channel": "C1", "text": "hi"})


# ---------- wiring ----------

def test_real_adapters_cannot_be_reset():
    for adapter in (RealGitHub(token="t", repo="o/r", session=Session(None)),
                    RealLinear(api_key="k", team_id="t", session=Session(None)),
                    RealSlack(token="x", session=Session(None))):
        with pytest.raises(NotImplementedError):
            adapter.reset({})


def test_with_real_requires_explicit_policy():
    with pytest.raises(ValueError):
        ToolBroker.with_real("r", approval_policy=None)


def test_kernel_denies_before_any_http_call():
    s = Session(lambda *_: pytest.fail("network must not be reached"))
    broker = ToolBroker({"slack": RealSlack(token="x", session=s)}, "r", approval_policy=AutoApprove())
    cap = Capability(cap_id="c1", tool="slack.post_message", scope={"channel": "C_EXEC"}, expires_at=time.time() + 60)
    with pytest.raises(EgressDenied):
        broker.call("slack.post_message", {"channel": "C_EXEC", "text": "hi"}, cap)
    assert s.calls == []


def test_use_real_apps_switches_allowlist(monkeypatch):
    for name in ("SLACK_CHANNEL_BUGS", "SLACK_CHANNEL_GENERAL", "SLACK_ALLOWED_CHANNELS"):
        monkeypatch.setattr(config, name, getattr(config, name))  # restored after the test
    monkeypatch.setattr(config, "REAL_SLACK_CHANNEL_BUGS", "CREALBUGS")
    monkeypatch.setattr(config, "REAL_SLACK_CHANNEL_GENERAL", "CREALGEN")
    config.use_real_apps()
    assert config.SLACK_ALLOWED_CHANNELS == {"CREALBUGS", "CREALGEN"}
    monkeypatch.setattr(config, "REAL_SLACK_CHANNEL_BUGS", "")
    with pytest.raises(RuntimeError):
        config.use_real_apps()
