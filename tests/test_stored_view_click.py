# -*- coding: utf-8 -*-
"""Phase 284: `--stored-view-click` must be able to click a SEQUENCE.

One click is not enough for a paginated view: the stored row lands on page
3 and "Next page" has to be clicked twice.  The flag was single-shot, so a
paginated admin feedback table (10 rows/page, measured on Juice Shop)
could not be reached at all.

These tests lock the three places the contract has to hold:
  1. the CLI flag is repeatable (a list, not the last value winning),
  2. cli_runner passes that list through unchanged,
  3. dom_engine treats a list as an ORDERED sequence and still accepts a
     plain string (Phase 282 callers keep working).

No browser and no network: (1) and (2) are parseable offline, and (3) is
pinned as source because the engine can only be exercised with Playwright.
"""
from __future__ import annotations

import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(ROOT, "xssentinel", "__main__.py")
RUNNER = os.path.join(ROOT, "xssentinel", "cli_runner.py")
ENGINE = os.path.join(ROOT, "xssentinel", "core", "dom_engine.py")


def _src(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class TestCliFlag:
    def test_flag_is_repeatable(self):
        from xssentinel.__main__ import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "-u", "http://h/p",
            "--stored-inject", "http://h/w",
            "--stored-view", "http://h/v",
            "--stored-dom",
            "--stored-view-click", "button.next",
            "--stored-view-click", "button.next",
        ])
        assert args.stored_view_click == ["button.next", "button.next"], (
            "a repeated --stored-view-click must accumulate, not overwrite")

    def test_single_use_still_parses(self):
        from xssentinel.__main__ import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "-u", "http://h/p", "--stored-inject", "http://h/w",
            "--stored-view", "http://h/v", "--stored-dom",
            "--stored-view-click", "mat-card",
        ])
        assert args.stored_view_click == ["mat-card"]


class TestWiring:
    def test_runner_forwards_the_list(self):
        src = _src(RUNNER)
        assert "args, \"stored_view_click\", None)" in src
        assert "view_click=" in src

    def test_engine_accepts_a_sequence(self):
        src = _src(ENGINE)
        assert "click_selector: str | list | None = None" in src
        assert "isinstance(click_selector, list)" in src
        assert "for sel in selectors:" in src

    def test_engine_does_not_fake_a_successful_click(self):
        """A failed click must stay a failed click.

        Falling back to ``dispatch_event`` would report the interaction as
        performed while the app never saw it -- a silent fake success, which
        is worse than a visible miss.
        """
        src = _src(ENGINE)
        assert "dispatch_event(\"click\")" not in src


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
