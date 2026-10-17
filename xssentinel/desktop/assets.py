# -*- coding: utf-8 -*-
"""Locate and load the console's single-page UI.

The page lives in ``ui/index.html`` next to this module and is read from
disk on every request (it is a few tens of KB, and reading beats caching a
stale copy while the file is being edited).  It resolves the same way from a
source checkout and from an installed wheel, because the path is derived
from ``__file__`` rather than from the working directory.
"""
from __future__ import annotations

import os

_HERE = os.path.dirname(os.path.abspath(__file__))
UI_PATH = os.path.join(_HERE, "ui", "index.html")


def ui_path() -> str:
    """Absolute path of the console page."""
    return UI_PATH


def load_ui_html() -> str:
    """Return the console HTML, or a minimal error page if it is missing.

    A missing asset is a packaging bug, not a request error the user caused,
    so the fallback says exactly that instead of returning an empty page.
    """
    try:
        with open(UI_PATH, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
                "<title>XSSentinel</title></head><body>"
                "<p>控制台页面缺失（ui/index.html 未随包安装）。"
                "请从源码检出运行，或重新安装本包。</p>"
                "</body></html>")
