"""Recipient / channel / URL / email allowlist checks.

Destinations come from config, never from extracted content.
"""
import re
import unicodedata
from urllib.parse import urlparse

import config
from kernel.taint import iter_strings, unwrap

ALLOWED_URL_HOSTS = frozenset({"github.com", "api.github.com", "linear.app", "slack.com"})

URL_RE = re.compile(r"\b(?:[a-z][a-z0-9+.-]*)://[^\s<>\"'`]+", re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
# Broadcast mentions widen the recipient set from "the channel" to "every member's phone".
BROADCAST_RE = re.compile(r"<!(?:channel|here|everyone)\b[^>]*>|(?<![\w@])@(?:channel|here|everyone)\b", re.I)
ZERO_WIDTH = re.compile("[­᠎​-‏‪-‮⁠-⁤﻿]")


class EgressDenied(Exception):
    pass


def _host_allowed(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in ALLOWED_URL_HOSTS)


def check(tool: str, args: dict) -> None:
    plain = unwrap(args)

    if tool == "slack.post_message" and plain.get("channel") not in config.SLACK_ALLOWED_CHANNELS:
        raise EgressDenied(f"slack channel {plain.get('channel')!r} not on allowlist")
    if tool.startswith("linear.") and "team_id" in plain and plain["team_id"] != config.LINEAR_TEAM_ID:
        raise EgressDenied("linear team not on allowlist")
    if tool.startswith("github.") and "repo" in plain and plain["repo"] != config.GITHUB_REPO:
        raise EgressDenied("github repo not on allowlist")

    for text in iter_strings(plain):
        norm = ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", text))
        for url in URL_RE.findall(norm):
            parsed = urlparse(url)
            if parsed.scheme.lower() not in ("http", "https") or not _host_allowed(parsed.hostname):
                raise EgressDenied(f"url host {parsed.hostname!r} not on allowlist")
        if EMAIL_RE.search(norm):
            raise EgressDenied("email address in outbound args")
        if tool == "slack.post_message" and BROADCAST_RE.search(norm):
            raise EgressDenied("broadcast mention widens recipients")
