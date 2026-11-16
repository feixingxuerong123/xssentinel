"""Phase 398: the ``dom_engine`` value set must stay ONE contract.

Phase 397 made ``off`` real in both ``_resolve_dom_engine`` copies, but the
CLI still rejected ``--dom-engine off`` (argparse rc=2) while the MCP tool
schema had accepted it all along, and README.md listed only three values.
The declaration lived in N places with nothing pinning them together --
AGENTS.md's "three reusable rules" (Phase 207) say the fix is a guard, not
more careful copying.

Every value here is read from a REAL entry point: the live argparse action,
the live MCP tool schema, and the README's declared brace list.  The core
arm calls both real resolvers with a sentinel analyzer, so "was a browser
constructed?" is measurable without depending on local Chromium.

Adding a fifth value is allowed but must trip this guard: update all three
declarations, _EXPECTED, and the measurement fact table in the same round.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from xssentinel.__main__ import build_parser
from xssentinel.api.mcp_server import _TOOL_SCAN_SCHEMA
from xssentinel.core import dom_engine as de_mod
from xssentinel.core.async_scanner import AsyncScanner
from xssentinel.core.requester import Requester
from xssentinel.core.scanner import Scanner

ROOT = Path(__file__).resolve().parents[1]


def _cli_action():
    parser = build_parser("scan")
    return next(a for a in parser._actions if a.dest == "dom_engine")


def _cli_values():
    return list(_cli_action().choices)


def _mcp_values():
    return list(_TOOL_SCAN_SCHEMA["properties"]["dom_engine"]["enum"])


def _readme_brace_values():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(r"--dom-engine \{([^}]+)\}", text)
    assert m, "README.md no longer declares the --dom-engine value set"
    return [s.strip() for s in m.group(1).split(",")]


class _SentinelAnalyzer:
    def __init__(self, **kw):
        self.kw = kw

    @staticmethod
    def available() -> bool:
        return True


@pytest.fixture
def sentinel(monkeypatch):
    monkeypatch.setattr(de_mod, "DynamicDomAnalyzer", _SentinelAnalyzer)
    return _SentinelAnalyzer


# Domain knowledge, NOT a second declaration: the assert below pins this
# dict's key set to the live declarations so a value cannot be added or
# dropped on one side without failing this guard.
_EXPECTED = {
    "auto": "sentinel",
    "playwright": "sentinel",
    "static": "none",
    "off": "none",
}


def test_three_declarations_are_the_same_set():
    cli, mcp, doc = _cli_values(), _mcp_values(), _readme_brace_values()
    assert set(cli) == set(mcp) == set(doc), (cli, mcp, doc)
    assert "off" in cli, "Phase 397's public value must be reachable from CLI"
    # A value added or removed on only one side must trip this guard.
    assert len(cli) == len(set(cli)) == 4


def test_defaults_agree_and_stay_auto():
    assert _cli_action().default == "auto"
    assert _TOOL_SCAN_SCHEMA["properties"]["dom_engine"]["default"] == "auto"


def test_cli_really_accepts_every_declared_value():
    """Not a text check: parse_args must actually accept each declared value."""
    parser = build_parser("scan")
    for v in _cli_values():
        ns = parser.parse_args(
            ["-u", "http://127.0.0.1:9/?q=1", "--dom-engine", v])
        assert ns.dom_engine == v
    with pytest.raises(SystemExit) as ei:
        parser.parse_args(
            ["-u", "http://127.0.0.1:9/?q=1", "--dom-engine", "bogus"])
    assert ei.value.code == 2


def test_every_declared_value_is_implemented_on_both_engines(sentinel):
    """Both hand-written resolvers must agree for EVERY declared value."""
    values = set(_cli_values())
    assert set(_EXPECTED) == values, (
        f"declared value set drifted: {values} vs {set(_EXPECTED)}")

    def kind(obj):
        if isinstance(obj, sentinel):
            return "sentinel"
        if obj is None:
            return "none"
        return type(obj).__name__

    for v in sorted(values):
        sc = Scanner(requester=Requester(timeout=5), dom_engine=v)
        asc = AsyncScanner(dom_engine=v)
        sync_kind = kind(sc._resolve_dom_engine())
        async_kind = kind(asc._resolve_dom_engine())
        assert sync_kind == async_kind == _EXPECTED[v], (
            v, sync_kind, async_kind)


def test_both_user_facing_descriptions_explain_off():
    desc = _TOOL_SCAN_SCHEMA["properties"]["dom_engine"]["description"].lower()
    assert "'off' disables the dom layer" in desc
    assert "off disables" in _cli_action().help.lower()


def test_en_readme_documents_off_too():
    """The EN README has no brace list; it must at least show the flag."""
    text = (ROOT / "README.en.md").read_text(encoding="utf-8")
    assert "--dom-engine off" in text
