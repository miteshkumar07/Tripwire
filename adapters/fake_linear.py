"""In-memory, seedable Linear fake."""
import copy
import re

from adapters.base import Adapter, AdapterError

_WORD = re.compile(r"[a-z0-9]{3,}")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall((text or "").lower()))


class FakeLinear(Adapter):
    name = "linear"

    def __init__(self) -> None:
        self.reset({})

    def reset(self, seed: dict) -> None:
        seed = seed or {}
        issues = []
        for raw in seed.get("issues", []):
            issues.append({
                "id": raw["id"],
                "title": raw.get("title", ""),
                "description": raw.get("description", "") or "",
                "state": raw.get("state", "open"),
                "team_id": raw.get("team_id"),
                "private": bool(raw.get("private", False)),
            })
        self.state = {"issues": issues, "created": [], "comments": [], "closed": []}
        self._next = 1 + max(
            [int(m.group(1)) for i in issues if (m := re.search(r"(\d+)$", i["id"]))] or [99]
        )

    def snapshot(self) -> dict:
        return copy.deepcopy(self.state)

    def _call(self, op: str, args: dict):
        return self._dispatch(op, args)

    def _find(self, issue_id: str) -> dict:
        for issue in self.state["issues"]:
            if issue["id"] == issue_id:
                return issue
        raise AdapterError(f"linear: issue {issue_id} not found")

    def _op_search_issues(self, query: str, team_id: str | None = None, limit: int = 5):
        q = _tokens(query)
        if not q:
            return []
        hits = []
        for issue in self.state["issues"]:
            if issue["private"]:
                continue
            overlap = q & _tokens(issue["title"] + " " + issue["description"])
            if overlap:
                hits.append({
                    "id": issue["id"],
                    "title": issue["title"],
                    "description": issue["description"],
                    "state": issue["state"],
                    "score": round(len(overlap) / len(q), 3),
                })
        hits.sort(key=lambda h: (-h["score"], h["id"]))
        return hits[: int(limit)]

    def _op_create_issue(self, team_id: str, title: str, description: str = "",
                         priority: int | None = None):
        issue_id = f"ENG-{self._next}"
        self._next += 1
        issue = {"id": issue_id, "title": title, "description": description,
                 "state": "open", "team_id": team_id, "private": False,
                 "priority": priority}
        self.state["issues"].append(issue)
        self.state["created"].append(issue_id)
        return {"id": issue_id}

    def _op_comment(self, issue_id: str, body: str):
        self._find(issue_id)
        comment = {"issue_id": issue_id, "body": body}
        self.state["comments"].append(comment)
        return {"ok": True, "issue_id": issue_id}

    def _op_close_issue(self, issue_id: str):
        issue = self._find(issue_id)
        issue["state"] = "closed"
        self.state["closed"].append(issue_id)
        return {"ok": True, "issue_id": issue_id}
