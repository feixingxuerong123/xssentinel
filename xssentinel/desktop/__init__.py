# -*- coding: utf-8 -*-
"""XSSentinel desktop console.

A single-process desktop front-end over the project's own REST API::

    python -m xssentinel.desktop            # or: xssentinel-desktop
    python -m xssentinel.desktop --no-window
    python -m xssentinel.desktop --backend tkinter

See :mod:`xssentinel.desktop.app` for the entry point and
:mod:`xssentinel.desktop.shell` for the window backends.
"""
from __future__ import annotations

from .app import build_server, install_ui_route, main
from .assets import load_ui_html, ui_path

__all__ = ["build_server", "install_ui_route", "main",
           "load_ui_html", "ui_path"]
