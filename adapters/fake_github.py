"""In-memory, seedable GitHub fake."""
import copy

from adapters.base import Adapter, AdapterError


class FakeGitHub(Adapter):
    name = "github"

    def __init__(self) -> None:
        self.state: dict = {"issues": []}

    def reset(self, seed: dict) -> None:
        issues = []
        for raw in (seed or {}).get("issues", []):
            issue = {
                "number": raw["number"],
                "title": raw.get("title", ""),
                "body": raw.get("body", "") or "",
                "author": raw.get("author", "unknown"),
                "author_name": raw.get("author_name", raw.get("author", "unknown")),
                "state": raw.get("state", "open"),
                "comments": [
                    {"author": c.get("author", "unknown"), "body": c.get("body", "")}
                    for c in raw.get("comments", [])
                ],
            }
            issues.append(issue)
        self.state = {"issues": issues}

    def snapshot(self) -> dict:
        return copy.deepcopy(self.state)

    def _call(self, op: str, args: dict):
        return self._dispatch(op, args)

    def _find(self, number) -> dict:
        for issue in self.state["issues"]:
            if issue["number"] == int(number):
                return issue
        raise AdapterError(f"github: issue {number} not found")

    def _op_list_issues(self, state: str = "open"):
        return [
            {"number": i["number"], "title": i["title"], "state": i["state"]}
            for i in self.state["issues"]
            if state == "all" or i["state"] == state
        ]

    def _op_get_issue(self, number):
        i = self._find(number)
        return {k: copy.deepcopy(v) for k, v in i.items() if k != "comments"}

    def _op_get_comments(self, number):
        return copy.deepcopy(self._find(number)["comments"])
