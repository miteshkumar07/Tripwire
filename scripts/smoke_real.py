"""One read-only call to each of GitHub, Linear and Slack using the env tokens.

Usage: python scripts/smoke_real.py
Prints one line per app. Never prints tokens.
"""
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402

TIMEOUT = 15


def check_github() -> str:
    r = requests.get(
        f"https://api.github.com/repos/{config.GITHUB_REPO}",
        headers={"Authorization": f"Bearer {config.GITHUB_TOKEN}",
                 "Accept": "application/vnd.github+json"},
        timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if not data.get("has_issues"):
        raise RuntimeError("repo has Issues disabled")
    return f"repo {data['full_name']} (issues enabled, open={data.get('open_issues_count')})"


def check_linear() -> str:
    q = "{ viewer { name } teams { nodes { id key name } } }"
    r = requests.post("https://api.linear.app/graphql", json={"query": q},
                      headers={"Authorization": config.LINEAR_API_KEY}, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if data.get("errors"):
        raise RuntimeError(data["errors"][0].get("message"))
    teams = data["data"]["teams"]["nodes"]
    match = [t for t in teams if t["id"] == config.LINEAR_TEAM_ID]
    if not match:
        keys = ", ".join(f"{t['key']}={t['id']}" for t in teams)
        raise RuntimeError(f"LINEAR_TEAM_ID not among your teams: {keys}")
    return f"viewer {data['data']['viewer']['name']}, team {match[0]['key']} ({match[0]['name']})"


def check_slack() -> str:
    h = {"Authorization": f"Bearer {config.SLACK_BOT_TOKEN}"}
    auth = requests.post("https://slack.com/api/auth.test", headers=h, timeout=TIMEOUT).json()
    if not auth.get("ok"):
        raise RuntimeError(f"auth.test: {auth.get('error')}")
    chans = requests.get("https://slack.com/api/conversations.list", headers=h,
                         params={"types": "public_channel", "limit": 200},
                         timeout=TIMEOUT).json()
    if not chans.get("ok"):
        raise RuntimeError(f"conversations.list: {chans.get('error')} "
                           f"(needed={chans.get('needed')})")
    tw = {c["name"]: (c["id"], c.get("is_member")) for c in chans["channels"]
          if c["name"].startswith("tw-")}
    return f"bot {auth.get('user')} in team {auth.get('team')}; tw-* channels (id, bot_is_member): {tw}"


def main() -> int:
    failures = 0
    for name, fn in (("GitHub", check_github), ("Linear", check_linear), ("Slack", check_slack)):
        try:
            print(f"[OK]   {name}: {fn()}")
        except Exception as e:  # report every app, do not stop at the first failure
            failures += 1
            print(f"[FAIL] {name}: {type(e).__name__}: {e}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
