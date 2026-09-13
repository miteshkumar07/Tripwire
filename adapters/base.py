"""Adapter interface.

Adapters are the raw connection to an app. Only kernel/broker.py may import this
package. Methods are `_`-prefixed so a direct call from anywhere else stands out.
"""
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
