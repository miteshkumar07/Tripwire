"""Taint propagation and the rule-of-two approval policy.

Rule of two: a tool call whose args derive from untrusted data AND whose effect is
irreversible or leaves the system requires human approval.
"""
from typing import Any, Iterable, Iterator

from contracts import Tainted

IRREVERSIBLE_OR_EXTERNAL = frozenset({
    "linear.create_issue", "linear.close_issue", "slack.post_message",
})


class TaintDenied(Exception):
    pass


def propagate(value: Any, origin: str, trust: str) -> Tainted:
    """Wrap `value`. Untrusted is sticky: re-wrapping untrusted data never launders it."""
    if isinstance(value, Tainted):
        if value.trust == "untrusted":
            trust = "untrusted"
        value = value.value
    return Tainted(value=value, origin=origin, trust=trust)


def endorse(value: Tainted, allowed: Iterable) -> Tainted:
    """Declassify a value ONLY if it is a member of a closed, config-owned set.
    A value drawn from a fixed enum carries no attacker-chosen text."""
    allowed = frozenset(allowed)
    raw = value.value if isinstance(value, Tainted) else value
    if isinstance(raw, (dict, list, set, tuple)) or raw not in allowed:
        raise TaintDenied(f"cannot endorse value outside closed set: {raw!r}")
    origin = value.origin if isinstance(value, Tainted) else "literal"
    return Tainted(value=raw, origin=f"{origin}|endorsed", trust="trusted")


def unwrap(value: Any) -> Any:
    if isinstance(value, Tainted):
        return unwrap(value.value)
    if isinstance(value, dict):
        return {k: unwrap(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [unwrap(v) for v in value]
    return value


def iter_strings(value: Any) -> Iterator[str]:
    """Every string reachable in a (possibly Tainted) structure, including dict keys and
    stringified scalars."""
    if isinstance(value, Tainted):
        yield from iter_strings(value.value)
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from iter_strings(v)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from iter_strings(v)
    elif isinstance(value, str):
        yield value
    elif value is not None:
        yield str(value)


def _untrusted(value: Any) -> bool:
    if isinstance(value, Tainted):
        return value.trust == "untrusted" or _untrusted(value.value)
    if isinstance(value, dict):
        return any(_untrusted(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_untrusted(v) for v in value)
    return False


def is_untrusted_derived(args: dict) -> bool:
    return _untrusted(args)


def untrusted_keys(args: dict) -> list[str]:
    return sorted(k for k, v in args.items() if _untrusted(v))


def policy(tool: str, args: dict) -> bool:
    """True when the call requires human approval."""
    return tool in IRREVERSIBLE_OR_EXTERNAL and is_untrusted_derived(args)
