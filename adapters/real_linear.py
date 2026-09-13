"""Real Linear adapter (requests + Authorization header, GraphQL).

Duplicate search fetches the team's open issues and scores titles locally with the same
matcher as the fake, so eval and live dedupe behave the same way.
"""
import requests

import config
from adapters.base import Adapter, AdapterError, title_match_score, tokens

GRAPHQL = "https://api.linear.app/graphql"
TIMEOUT = 20
ISSUE_FIELDS = "id identifier title description state { name type }"


class RealLinear(Adapter):
    name = "linear"

    def __init__(self, api_key: str | None = None, team_id: str | None = None, session=None) -> None:
        self.team_id = team_id or config.LINEAR_TEAM_ID
        self.session = session or requests.Session()
        self.headers = {"Authorization": api_key or config.LINEAR_API_KEY, "Content-Type": "application/json"}
        # Effects of this session, so snapshots have the same shape as the fake's.
        self.created: list[str] = []
        self.comments: list[dict] = []
        self.closed: list[str] = []

    def reset(self, seed: dict) -> None:
        raise NotImplementedError("real adapters cannot be reset")

    def _call(self, op: str, args: dict):
        return self._dispatch(op, args)

    def _gql(self, query: str, variables: dict | None = None) -> dict:
        try:
            resp = self.session.post(GRAPHQL, json={"query": query, "variables": variables or {}},
                                     headers=self.headers, timeout=TIMEOUT)
        except requests.RequestException as e:
            raise AdapterError(f"linear: {type(e).__name__}") from e
        try:
            data = resp.json()
        except ValueError:
            data = {}
        if data.get("errors"):
            raise AdapterError(f"linear: {data['errors'][0].get('message')}")
        if resp.status_code >= 400 or "data" not in data:
            raise AdapterError(f"linear: HTTP {resp.status_code}")
        return data["data"]

    def _team_issues(self, first: int = 100) -> list[dict]:
        query = """query($team: ID!, $first: Int!) {
          issues(first: $first, filter: {team: {id: {eq: $team}}, state: {type: {nin: ["completed", "canceled"]}}}) {
            nodes { %s }
          }
        }""" % ISSUE_FIELDS
        return self._gql(query, {"team": self.team_id, "first": first})["issues"]["nodes"]

    def _issue_uuid(self, identifier: str) -> str:
        data = self._gql("query($id: String!) { issue(id: $id) { id identifier } }", {"id": identifier})
        if not data.get("issue"):
            raise AdapterError(f"linear: issue {identifier} not found")
        return data["issue"]["id"]

    def _op_search_issues(self, query: str, team_id: str | None = None, limit: int = 5):
        q = tokens(query)
        if not q:
            return []
        hits = []
        for issue in self._team_issues():
            description = issue.get("description") or ""
            if q & tokens(issue["title"] + " " + description):
                hits.append({
                    "id": issue["identifier"],
                    "title": issue["title"],
                    "description": description,
                    "state": issue["state"]["name"],
                    "score": title_match_score(q, issue["title"]),
                })
        hits.sort(key=lambda h: (-h["score"], h["id"]))
        return hits[: int(limit)]

    def _op_create_issue(self, team_id: str, title: str, description: str = "", priority: int | None = None):
        issue_input = {"teamId": team_id, "title": title, "description": description}
        if priority is not None:
            issue_input["priority"] = int(priority)
        data = self._gql("""mutation($input: IssueCreateInput!) {
          issueCreate(input: $input) { success issue { id identifier url } }
        }""", {"input": issue_input})["issueCreate"]
        if not data.get("success"):
            raise AdapterError("linear: issueCreate failed")
        identifier = data["issue"]["identifier"]
        self.created.append(identifier)
        return {"id": identifier, "url": data["issue"]["url"]}

    def _op_comment(self, issue_id: str, body: str):
        uuid = self._issue_uuid(issue_id)
        data = self._gql("""mutation($input: CommentCreateInput!) {
          commentCreate(input: $input) { success comment { id url } }
        }""", {"input": {"issueId": uuid, "body": body}})["commentCreate"]
        if not data.get("success"):
            raise AdapterError("linear: commentCreate failed")
        self.comments.append({"issue_id": issue_id, "body": body})
        return {"ok": True, "issue_id": issue_id, "url": data["comment"]["url"]}

    def _op_close_issue(self, issue_id: str):
        uuid = self._issue_uuid(issue_id)
        states = self._gql("query($team: String!) { team(id: $team) { states { nodes { id type } } } }",
                           {"team": self.team_id})["team"]["states"]["nodes"]
        done = next((s["id"] for s in states if s["type"] == "completed"), None)
        if done is None:
            raise AdapterError("linear: team has no completed state")
        data = self._gql("""mutation($id: String!, $input: IssueUpdateInput!) {
          issueUpdate(id: $id, input: $input) { success }
        }""", {"id": uuid, "input": {"stateId": done}})["issueUpdate"]
        if not data.get("success"):
            raise AdapterError("linear: issueUpdate failed")
        self.closed.append(issue_id)
        return {"ok": True, "issue_id": issue_id}

    def snapshot(self) -> dict:
        issues = [{"id": i["identifier"], "title": i["title"], "description": i.get("description") or "",
                   "state": i["state"]["name"]} for i in self._team_issues(first=50)]
        return {"issues": issues, "created": list(self.created),
                "comments": list(self.comments), "closed": list(self.closed)}
