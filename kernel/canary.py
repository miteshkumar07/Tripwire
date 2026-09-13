"""Egress scanning for canary secrets.

Every outbound argument is scanned in two passes:
  1. each provenance part on its own (a rope's parts separately), so a hit names the
     origin the secret came from, e.g. "linear:issue:ENG-108";
  2. the assembled strings, so a canary split across two parts is still caught.
Each text is checked in raw, unicode-normalised, zero-width-stripped, whitespace-collapsed,
URL-decoded and base64-decoded forms.
Known gap: cross-script homoglyphs (e.g. Cyrillic 'А' for Latin 'A') survive NFKC.
"""
import base64
import binascii
import re
import unicodedata
import urllib.parse
from typing import Iterable, Iterator, Optional

import config
from kernel.taint import iter_origin_strings, iter_strings, unwrap

ZERO_WIDTH = re.compile("[­᠎​-‏‪-‮⁠-⁤﻿]")
B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")


class CanaryHit(Exception):
    def __init__(self, message: str, origin: Optional[str] = None) -> None:
        super().__init__(message)
        self.origin = origin


def _b64_decodes(text: str) -> Iterator[str]:
    for token in B64_TOKEN.findall(text):
        padded = token + "=" * (-len(token) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                yield decoder(padded).decode("utf-8", errors="ignore")
            except (binascii.Error, ValueError):
                continue


def _forms(text: str) -> Iterator[tuple[str, str]]:
    yield "raw", text
    norm = ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", text))
    yield "normalised", norm
    collapsed = re.sub(r"\s+", "", norm)
    yield "whitespace_collapsed", collapsed
    yield "url_decoded", urllib.parse.unquote_plus(norm)
    for source in (norm, collapsed):
        for decoded in _b64_decodes(source):
            yield "base64", ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", decoded))


def scan(args, canaries: Optional[Iterable[str]] = None) -> None:
    secrets = {c.lower() for c in (canaries if canaries is not None else [config.CANARY]) if c}
    parts = list(iter_origin_strings(args))
    assembled = [("assembled", text) for text in iter_strings(unwrap(args))]
    for origin, text in parts + assembled:
        for form_name, form in _forms(text):
            low = form.lower()
            for secret in secrets:
                if secret in low:
                    raise CanaryHit(f"canary found in outbound args ({form_name} form, origin {origin})",
                                    origin=origin)
