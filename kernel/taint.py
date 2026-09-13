"""Taint propagation and the rule-of-two approval policy.

Rule of two: a tool call whose args derive from untrusted data AND whose effect is
irreversible or leaves the system requires human approval.

Composite text is built with `concat`, which keeps every part's own trust and origin
(a "rope") instead of flattening them into one string. Parts are only joined by
`unwrap`, inside the broker, right before the adapter call.
"""
from typing import Any, Iterable, Iterator

from contracts import Tainted

IRREVERSIBLE_OR_EXTERNAL = frozenset({
    "linear.create_issue", "linear.close_issue", "slack.post_message",
})

TEMPLATE_ORIGIN = "executor:template"


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


def _is_rope(value: Any) -> bool:
    return isinstance(value, tuple) and len(value) > 0 and all(isinstance(p, Tainted) for p in value)


def concat(*parts) -> Tainted:
    """Join text parts while keeping each part's provenance. Plain strings are trusted
    executor template text."""
    wrapped = tuple(p if isinstance(p, Tainted) else Tainted(str(p), TEMPLATE_ORIGIN, "trusted")
                    for p in parts)
    trust = "untrusted" if any(_untrusted(p) for p in wrapped) else "trusted"
    origins = ",".join(dict.fromkeys(p.origin for p in wrapped))
    return Tainted(value=wrapped, origin=f"concat({origins})", trust=trust)


def unwrap(value: Any) -> Any:
    if isinstance(value, Tainted):
        return unwrap(value.value)
    if _is_rope(value):
        return "".join(str(unwrap(p)) for p in value)
    if isinstance(value, dict):
        return {k: unwrap(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [unwrap(v) for v in value]
    return value


def iter_origin_strings(value: Any, origin: str = "literal") -> Iterator[tuple[str, str]]:
    """(origin, text) for every string reachable in a (possibly Tainted) structure,
    including dict keys and stringified scalars. Rope parts are yielded separately."""
    if isinstance(value, Tainted):
        yield from iter_origin_strings(value.value, value.origin)
    elif isinstance(value, dict):
        for k, v in value.items():
            yield origin, str(k)
            yield from iter_origin_strings(v, origin)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from iter_origin_strings(v, origin)
    elif isinstance(value, str):
        yield origin, value
    elif value is not None:
        yield origin, str(value)


def iter_strings(value: Any) -> Iterator[str]:
    for _, text in iter_origin_strings(value):
        yield text


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
