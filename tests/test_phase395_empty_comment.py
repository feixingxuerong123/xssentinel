# -*- coding: utf-8 -*-
"""Phase 395: `<!-->` / `<!--->` are EMPTY, CLOSED comments (WHATWG 13.2.5.6).

Measured root cause of the last Phase 392 corpus missed row: the polyglot
`/*<!--></Style/...<K/contentEditable/autoFocus/OnFocus=...>` fired in
Chromium while the sandbox read inert -- the old comment rule only knew
`-->` / `--!>` endings, so `<!-->` read as an unterminated comment that
swallowed the entire remainder (marker text "unterminated comment swallowed
the remainder"), and the live <K autofocus/onfocus> element never existed in
the parsed tree.

Regression pins: `<!--x` (unterminated) still swallows to EOF; a plain
`<!-->` inside inert content stays inert.
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from xssentinel.core.sandbox import judge  # noqa: E402

SHELL = '<!doctype html><html><body><div id="c">%s</div></body></html>'
TOKEN = "xssv_p395t"


def test_empty_comment_closes_and_releases_following_markup():
    page = SHELL % f"/*<!--><K/contentEditable/autoFocus/OnFocus=alert('{TOKEN}')>"
    v = judge(page, TOKEN, sink="parser")
    assert v.state == "live", v.reason


def test_dash_variant_empty_comment_also_closes():
    page = SHELL % f"<!---><input autofocus onfocus=alert('{TOKEN}')>"
    v = judge(page, TOKEN, sink="parser")
    assert v.state == "live", v.reason


def test_unterminated_comment_still_swallows_to_eof():
    # `<!--x` (no abrupt close) is an unterminated comment: the parse notes
    # it and judge() defers instead of going inert (the honest rule from the
    # table-scope measurement -- never inert when something was un-modelled)
    page = SHELL % f"<!--x<input autofocus onfocus=alert('{TOKEN}')>"
    v = judge(page, TOKEN, sink="parser")
    assert v.state == "unknown", v.reason
    assert "swallowed the remainder" in v.reason


def test_empty_comment_in_inert_context_stays_inert():
    page = SHELL % "<!-->plain text only"
    v = judge(page, "nothing-here", sink="parser")
    assert v.state == "inert", v.reason
