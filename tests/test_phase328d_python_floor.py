# -*- coding: utf-8 -*-
"""Phase 328d: pin the Python/dependency floor contract.

The floor exists because the fixed dependency releases require >=3.10
(measured in docs/DEPENDENCY_AUDIT.md).  Lowering it silently makes a fresh
3.9 install resolve the vulnerable versions again, so the contract is pinned
here rather than left to review.
"""
from __future__ import annotations

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name: str) -> str:
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


def test_pyproject_pins_the_python_floor():
    text = _read("pyproject.toml")
    assert 'requires-python = ">=3.10"' in text
    assert '"Programming Language :: Python :: 3.9"' not in text
    assert '"Programming Language :: Python :: 3.10"' in text


def test_runtime_floors_are_the_fixed_releases():
    text = _read("pyproject.toml")
    for spec in ("requests>=2.33.0", "urllib3>=2.8.0", "soupsieve>=2.9.0"):
        assert spec in text, spec


def test_optional_floors_are_the_fixed_releases():
    text = _read("pyproject.toml")
    for spec in ("aiohttp>=3.14.4", "flask>=3.1.3", "werkzeug>=3.1.9"):
        assert spec in text, spec


def test_docs_state_the_floor():
    for name in ("README.md", "README.en.md", "SECURITY.md"):
        text = _read(name)
        if name.startswith("README"):
            assert "python-3.10%2B" in text, name
        else:
            assert "Python 3.9 不再支持" in text, name
