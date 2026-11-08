"""Phase 366: propose's GENERATION timeout is config-driven, not hard-coded 60s.

Why this exists. ``propose_and_verify`` used to call
``pool.complete(..., timeout=60)``. A local GLM-5.3-Flash answered the same
proposal prompt in **68.5s** -- already past that line -- so the tool reported
``LLM pool exhausted`` for a model that was working. That is a misdiagnosis
the caller cannot see through: "model unavailable" vs "model slow" lead to
opposite operator decisions.

Contract locked here:
  * omitted ``llm_timeout`` forwards ``None``, i.e. "use LLMPool.timeout"
    (90s default, or whatever the pool config sets);
  * an explicit ``llm_timeout`` is forwarded unchanged;
  * the source contains no hard-coded ``timeout=60`` in this path.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.llm_propose import propose_and_verify  # noqa: E402


class _Resp:
    def __init__(self, text: str = "<html><body>x</body></html>"):
        self.text = text
        self.headers: dict = {}


class _Requester:
    def request(self, method, url, **kw):
        return _Resp()


class _Candidate:
    model = "fake-model"


class _Result:
    text = '["<script>alert(1)</script>"]'
    candidate = _Candidate()
    attempts: list = []
    failovers = 0


class _Pool:
    def __init__(self):
        self.kw = None

    def complete(self, messages, **kw):
        self.kw = kw
        return _Result()


def test_generation_timeout_defaults_to_pool_config():
    pool = _Pool()
    propose_and_verify(_Requester(), "http://t/x?q=1", "q", pool=pool)
    assert pool.kw is not None
    assert pool.kw.get("timeout") is None, (
        "None means 'use LLMPool.timeout'. A hard-coded number here turns a "
        "slow local model into a misleading 'pool exhausted'.")


def test_explicit_llm_timeout_is_forwarded():
    pool = _Pool()
    propose_and_verify(_Requester(), "http://t/x", "q", pool=pool,
                       llm_timeout=180)
    assert pool.kw.get("timeout") == 180


def test_no_hardcoded_generation_timeout_in_source():
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "xssentinel" / "core" / "llm_propose.py").read_text(encoding="utf-8")
    assert "timeout=60" not in src
