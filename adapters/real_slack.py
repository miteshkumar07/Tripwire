"""Real Slack adapter (requests + Authorization header)."""
import requests

import config
from adapters.base import Adapter, AdapterError

API = "https://slack.com/api"
TIMEOUT = 20


class RealSlack(Adapter):
    name = "slack"

    def __init__(self, token: str | None = None, session=None) -> None:
        self.session = session or requests.Session()
        self.headers = {"Authorization": f"Bearer {token or config.SLACK_BOT_TOKEN}"}
        self.messages: list[dict] = []  # effects of this session

    def reset(self, seed: dict) -> None:
        raise NotImplementedError("real adapters cannot be reset")

    def _call(self, op: str, args: dict):
        return self._dispatch(op, args)

    def _api(self, method: str, http: str = "post", **payload) -> dict:
        url = f"{API}/{method}"
        try:
            if http == "get":
                resp = self.session.get(url, headers=self.headers, params=payload, timeout=TIMEOUT)
            else:
                resp = self.session.post(url, json=payload, timeout=TIMEOUT,
                                         headers={**self.headers, "Content-Type": "application/json; charset=utf-8"})
        except requests.RequestException as e:
            raise AdapterError(f"slack: {type(e).__name__}") from e
        if resp.status_code >= 400:
            raise AdapterError(f"slack: HTTP {resp.status_code} for {method}")
        data = resp.json()
        if not data.get("ok"):
            raise AdapterError(f"slack: {method}: {data.get('error')}")
        return data

    def _op_list_channels(self):
        data = self._api("conversations.list", http="get", types="public_channel",
                         limit=200, exclude_archived="true")
        return [{"id": c["id"], "name": c.get("name")} for c in data.get("channels", [])]

    def _op_post_message(self, channel: str, text: str):
        data = self._api("chat.postMessage", channel=channel, text=text,
                         unfurl_links=False, unfurl_media=False, link_names=False)
        self.messages.append({"channel": channel, "text": text, "ts": data.get("ts")})
        return {"ok": True, "channel": data.get("channel", channel), "ts": data.get("ts")}

    def snapshot(self) -> dict:
        return {"channels": [c["id"] for c in self._op_list_channels()], "messages": list(self.messages)}
