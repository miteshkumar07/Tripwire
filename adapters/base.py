"""Adapter interface.

Adapters are the raw connection to an app. Only kernel/broker.py may import this
package. Methods are `_`-prefixed so a direct call from anywhere else stands out.
"""
import re
from typing import Any


class AdapterError(Exception):
    """The app rejected the operation (unknown op, missing object, bad args)."""


class Adapter:
    name: str = ""

    def _call(self, op: str, args: dict) -> Any:  # broker-only, never called directly
        raise NotImplementedError

    def snapshot(self) -> dict:  # for end-state assertions
        raise NotImplementedError

    def reset(self, seed: dict) -> None:  # fakes only; real raises
        raise NotImplementedError

    def _dispatch(self, op: str, args: dict) -> Any:
        handler = getattr(self, f"_op_{op}", None)
        if handler is None:
            raise AdapterError(f"{self.name}: unknown op {op!r}")
        try:
            return handler(**args)
        except TypeError as e:
            raise AdapterError(f"{self.name}.{op}: bad args: {e}") from e


# --- duplicate matching, shared by the fake and real Linear adapters ---

_WORD = re.compile(r"[a-z0-9]{3,}")


def _singular(word: str) -> str:
    """Crude plural folding so 'invoices' matches 'invoice'."""
    if len(word) > 4 and word.endswith("ies"):
        return word[:-3] + "y"
    if len(word) > 4 and word.endswith(("sses", "xes", "zes", "ches", "shes")):
        return word[:-2]
    if len(word) > 3 and word.endswith("s") and not word.endswith(("ss", "us", "is")):
        return word[:-1]
    return word


def tokens(text: str) -> set[str]:
    return {_singular(w) for w in _WORD.findall((text or "").lower())}


def title_match_score(query_tokens: set[str], title: str) -> float:
    """Share of the candidate's title covered by the query."""
    title_tokens = tokens(title)
    return round(len(query_tokens & title_tokens) / max(1, len(title_tokens)), 3)
