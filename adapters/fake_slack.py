"""In-memory, seedable Slack fake."""
import copy

from adapters.base import Adapter, AdapterError


class FakeSlack(Adapter):
    name = "slack"

    def __init__(self) -> None:
        self.reset({})

    def reset(self, seed: dict) -> None:
        seed = seed or {}
        channels = list(seed.get("channels", []))
        self.state = {"channels": channels, "messages": []}

    def snapshot(self) -> dict:
        return copy.deepcopy(self.state)

    def _call(self, op: str, args: dict):
        return self._dispatch(op, args)

    def _op_list_channels(self):
        return [{"id": c} for c in self.state["channels"]]

    def _op_post_message(self, channel: str, text: str):
        if channel not in self.state["channels"]:
            raise AdapterError(f"slack: channel_not_found {channel}")
        ts = f"{len(self.state['messages']) + 1}.000"
        self.state["messages"].append({"channel": channel, "text": text, "ts": ts})
        return {"ok": True, "channel": channel, "ts": ts}
