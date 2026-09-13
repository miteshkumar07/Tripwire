"""Static guards for demo/viewer.html: one self-contained file that never turns trace text into markup."""
import re
from pathlib import Path

VIEWER = Path(__file__).resolve().parent.parent / "demo" / "viewer.html"


def test_viewer_is_self_contained():
    html = VIEWER.read_text()
    assert not re.search(r"<script[^>]+src=", html, re.I)
    assert not re.search(r"<link[^>]+href=", html, re.I)
    assert not re.search(r"\b(fetch|XMLHttpRequest|import\s*\(|@import)\b", html)
    assert not re.search(r"url\(\s*['\"]?https?:", html)


def test_viewer_never_renders_trace_text_as_html():
    script = VIEWER.read_text().split("<script>", 1)[1]
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in script, sink


def test_viewer_colours_denials_red_and_capabilities_blue():
    html = VIEWER.read_text()
    assert '"cap_denied", "taint_denied", "egress_denied", "canary_hit"' in html
    assert "li.cat-denial .card" in html and "var(--red" in html
    assert "li.cat-cap .card" in html and "var(--blue" in html
