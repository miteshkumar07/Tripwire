"""Real GitHub adapter (requests + Authorization header). Read-only: the agent never
writes to GitHub."""
import requests

import config
from adapters.base import Adapter, AdapterError

API = "https://api.github.com"
TIMEOUT = 20


class RealGitHub(Adapter):
    name = "github"

    def __init__(self, token: str | None = None, repo: str | None = None, session=None) -> None:
        self.repo = repo or config.GITHUB_REPO
        self.session = session or requests.Session()
        self.headers = {
            "Authorization": f"Bearer {token or config.GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def reset(self, seed: dict) -> None:
        raise NotImplementedError("real adapters cannot be reset")

    def _call(self, op: str, args: dict):
        return self._dispatch(op, args)

    def _get(self, path: str, params: dict | None = None):
        try:
            resp = self.session.get(f"{API}{path}", headers=self.headers, params=params, timeout=TIMEOUT)
        except requests.RequestException as e:
            raise AdapterError(f"github: {type(e).__name__}") from e
        if resp.status_code >= 400:
            raise AdapterError(f"github: HTTP {resp.status_code} for {path}")
        return resp.json()

    def _op_list_issues(self, state: str = "open"):
        data = self._get(f"/repos/{self.repo}/issues", {"state": state, "per_page": 50})
        return [{"number": i["number"], "title": i["title"], "state": i["state"]}
                for i in data if "pull_request" not in i]

    def _op_get_issue(self, number):
        issue = self._get(f"/repos/{self.repo}/issues/{int(number)}")
        if "pull_request" in issue:
            raise AdapterError(f"github: #{number} is a pull request, not an issue")
        login = (issue.get("user") or {}).get("login", "unknown")
        try:
            display_name = self._get(f"/users/{login}").get("name") or login
        except AdapterError:
            display_name = login
        return {
            "number": issue["number"],
            "title": issue.get("title") or "",
            "body": issue.get("body") or "",
            "author": login,
            "author_name": display_name,
            "state": issue.get("state", "open"),
        }

    def _op_get_comments(self, number):
        data = self._get(f"/repos/{self.repo}/issues/{int(number)}/comments", {"per_page": 50})
        return [{"author": (c.get("user") or {}).get("login", "unknown"), "body": c.get("body") or ""}
                for c in data]

    def snapshot(self) -> dict:
        return {"issues": self._op_list_issues("open")}
