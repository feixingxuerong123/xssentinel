"""Phase 344: named program modes, and a `--help` that fits on a screen.

Two separate problems, one fix each.

**A. Names.**  `serve`, `selftest` and `mcp` are programs that happened to grow
up inside a scanner CLI.  They are now spellable as `xssentinel <mode>`; the
subcommand is stripped from argv and replaced by the flag that already selects
that mode, so there is exactly one code path per mode and no second definition
of what `serve` means.

**B. Display.**  157 flags / 650 lines is not a help page, it is a wall.  Each
non-scan mode now shows only the flags it uses.  Hiding is `help=SUPPRESS`,
which argparse applies to DISPLAY only -- `xssentinel serve --headless` still
parses.  That distinction is the whole safety argument for this change, so it
gets its own test.

Nothing here changes what any flag does.  Every invocation that worked before
still works, including the flat forms (`xssentinel --serve`), which keep the
full help on purpose: they are the old spelling, and an old spelling that
suddenly documents less would be a different kind of surprise.
"""
from __future__ import annotations

import argparse

import pytest

from xssentinel.__main__ import (_MODE_VISIBLE, _SUBCOMMANDS, _split_subcommand,
                                 build_parser)


# ---------------------------------------------------------------------------
# A. Subcommand -> flag mapping
# ---------------------------------------------------------------------------
def test_scan_prefix_is_stripped():
    """`scan` is the default mode and adds nothing."""
    assert _split_subcommand(["scan", "-u", "http://x/"]) == \
        ("scan", ["-u", "http://x/"])


def test_serve_maps_to_its_flag():
    assert _split_subcommand(["serve", "--port", "9000"]) == \
        ("serve", ["--serve", "--port", "9000"])


def test_selftest_and_mcp_map_to_their_flags():
    assert _split_subcommand(["selftest"]) == ("selftest", ["--self-test"])
    assert _split_subcommand(["mcp"]) == ("mcp", ["--mcp"])


def test_unknown_first_argument_is_left_alone():
    """This is what keeps `xssentinel -u X` and `xssentinel --serve` working:
    an unrecognised first token is not a subcommand, it is the start of the
    flag list."""
    assert _split_subcommand(["-u", "http://x/"]) == ("scan", ["-u", "http://x/"])
    assert _split_subcommand(["--serve"]) == ("scan", ["--serve"])


def test_empty_argv_is_scan():
    assert _split_subcommand([]) == ("scan", [])


def test_every_subcommand_has_a_mapping():
    """A name in the table with no flag would silently become a scan."""
    for name, extra in _SUBCOMMANDS.items():
        assert isinstance(extra, tuple), name
    assert set(_SUBCOMMANDS) == {"scan", "serve", "selftest", "mcp"}


def test_scan_accepts_everything_it_used_to():
    """The default mode must still parse the flags the tests/CI use."""
    ap = build_parser("scan")
    args = ap.parse_args(["-u", "http://127.0.0.1:1/", "--headless",
                          "--crawl", "--async", "-f", "json"])
    assert args.headless and args.crawl and args.async_mode


# ---------------------------------------------------------------------------
# B. Per-mode help
# ---------------------------------------------------------------------------
def _help_lines(mode: str) -> int:
    return len(build_parser(mode).format_help().splitlines())


def test_serve_help_is_short():
    """`serve --help` used to dump all 650 lines for 8 flags."""
    assert _help_lines("serve") < 60, (
        f"serve help is {_help_lines('serve')} lines -- the hiding broke")


def test_scan_help_is_still_complete():
    """scan is the mode that really does take every flag; hiding there would
    be a lie, not a convenience."""
    assert _help_lines("scan") > 500


def test_hiding_does_not_disable_parsing():
    """The safety argument for part B: SUPPRESS is display-only.

    If this ever fails, someone replaced the display switch with a real
    restriction and broke `xssentinel serve --headless` -- a working
    invocation that its own help no longer mentions.
    """
    args = build_parser("serve").parse_args(
        ["--serve", "--port", "9000", "--headless"])
    assert args.port == 9000
    assert args.headless is True, "SUPPRESS became a real restriction"


def test_serve_help_hides_scan_only_flags():
    text = build_parser("serve").format_help()
    assert "--port" in text
    assert "--crawl-depth" not in text
    assert "--max-transforms" not in text


def test_mcp_help_hides_scan_only_flags():
    text = build_parser("mcp").format_help()
    assert "--mcp" in text
    assert "-u, --url" not in text


def test_each_mode_documents_its_own_invocation():
    """The epilog is the only place a reader learns the other spellings."""
    assert "xssentinel serve" in build_parser("serve").epilog
    assert "xssentinel --serve" in build_parser("serve").epilog
    assert "xssentinel mcp" in build_parser("mcp").epilog


def test_mode_visible_lists_are_real_dests():
    """A typo in _MODE_VISIBLE hides a flag nobody meant to hide.

    Checked against the parser's actual actions rather than by rebuilding the
    flag name from the dest: `--webhook` has dest `webhook_urls`, so the
    name-derived guess would be wrong for exactly the flag that matters most
    to an API deployment.
    """
    all_dests = {a.dest for a in build_parser("scan")._actions}
    for mode, names in _MODE_VISIBLE.items():
        unknown = names - all_dests
        assert not unknown, f"{mode} lists unknown dests: {sorted(unknown)}"
        ap = build_parser(mode)
        by_dest = {a.dest: a for a in ap._actions if a.option_strings}
        for name in names:
            action = by_dest[name]
            assert action.help is not argparse.SUPPRESS, (
                f"{mode} hides {action.option_strings} although it needs it")


# ---------------------------------------------------------------------------
# The flag count quoted in scan's help must match what is printed
# ---------------------------------------------------------------------------
def test_scan_help_flag_count_is_honest():
    ap = build_parser("scan")
    shown = len({a.dest for a in ap._actions
                 if a.option_strings and a.help is not argparse.SUPPRESS})
    assert f"({shown} flags below" in ap.epilog


@pytest.mark.parametrize("mode", ["serve", "selftest", "mcp"])
def test_non_scan_modes_do_not_quote_a_flag_count(mode):
    """Their epilogs are examples, not an index -- a count there would be the
    same rotting number in a place nobody thinks to update."""
    assert "{flags}" not in build_parser(mode).epilog
