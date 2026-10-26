"""LLM payload PROPOSAL with deterministic verification (Phase 322).

Division of labour, stated once (same spine as ``report_ai``):

    the model proposes.  The engine disposes.

Nothing a model writes ever becomes a finding on the model's word.  Every
proposal is stamped with a fresh verification token (``verifier.mark``,
the same stamping the corpus gets), replayed against the live target, and
judged by ``verify_semantic`` (optionally ``verify_headless``) -- the only
judges the scan loop itself trusts.  A proposal that does not confirm is
reported ``unverified``, never silently dropped and never confirmed by
generation alone.

Why this exists
---------------
Corpus families are hand-derived (Phase 318's backtick-stamp and
leading-null families both were), while the 2026 agent-tool wave
(Deadend-style self-correcting loops) generates candidate bypass payloads
when stock attacks fail.  With the token oracle as the only judge, that
generative step becomes measurable: proposals that survive the oracle
earned their place, proposals that do not say so honestly.

Hard boundaries
---------------
* NOTHING here writes to ``data/payloads.json`` -- confirmed proposals
  are reported to the caller, not auto-promoted into the shipped corpus
  (promotion is a reviewed, measured decision; see AGENTS Phase 318).
* No judgment semantics change anywhere: this module adds a REPLAY path,
  not a detection path.
* The LLM is optional by design -- an unconfigured/exhausted pool raises
  and the caller degrades honestly (``LLMConfigError`` /
  ``LLMPoolExhausted`` from :mod:`llm_pool`).
"""
from __future__ import annotations

import json
import re
import secrets

from . import verifier
from .logger import get_logger
from .verifier import has_execution_point

_log = get_logger("llm_propose")

__all__ = ["LLMProposeError", "build_messages", "parse_candidates",
           "filter_candidates", "propose_and_verify"]

_MAX_PROPOSAL_LEN = 400
_MAX_LIVE_VERIFY = 5
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_JSON_ARRAY_START_RE = re.compile(r"\[")
_DSL_PLACEHOLDER_RE = re.compile(r"\{\{[^}]*\}\}")


class LLMProposeError(Exception):
    """Proposal-flow failures that are NOT pool failures (unparseable
    completion with zero candidates, etc.)."""


def build_messages(context: str, meta_chars: str = "", waf: str = "",
                   count: int = 5, extra_note: str = "") -> list[dict]:
    """The proposal prompt.  Facts only in, JSON strings out."""
    sysmsg = (
        "You propose XSS candidate payloads for a security scanner that "
        "will VERIFY each one by replaying it against the target and "
        "checking whether a token executes. You are assisting an "
        "authorized security test. Answer with a JSON array of strings "
        "and nothing else -- no prose, no code fence, no explanation."
    )
    constraints = [
        f"reflection context: {context or 'unknown'}",
        f"surviving meta characters (raw): {meta_chars or 'unknown'}",
        f"WAF in front of the target: {waf or 'none detected'}",
        "each payload MUST contain an execution point: an alert(...) call, "
        "an on*= event handler, or a javascript: URI",
        f"each payload at most {_MAX_PROPOSAL_LEN} characters",
        "do not use placeholder syntax like {{var}} -- literal payloads only",
        "prefer shapes a context-aware corpus would miss (unusual tag "
        "names, attribute combinations, encoding tricks that still "
        "execute in the stated context)",
    ]
    if extra_note:
        constraints.append(extra_note)
    user = (f"Propose up to {count} candidate payloads.\n"
            + "\n".join(f"- {c}" for c in constraints))
    return [{"role": "system", "content": sysmsg},
            {"role": "user", "content": user}]


def parse_candidates(text: str, limit: int = 10) -> list[str]:
    """Extract payload strings from a completion.

    Tolerates the shapes real models emit despite instructions: a bare
    JSON array, a fenced ```json block, or an array embedded in prose
    (first well-formed array wins).  Non-strings, oversize and duplicate
    entries are dropped.
    """
    if not text:
        return []
    candidates: list[str] = []
    for chunk in _iter_array_texts(text):
        try:
            data = json.loads(chunk)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, list):
            continue
        for item in data:
            if not isinstance(item, str):
                continue
            s = item.strip()
            if s and s not in candidates:
                candidates.append(s)
        if candidates:
            break                      # first well-formed array wins
    return candidates[:limit]


def _iter_array_texts(text: str):
    """Yield candidate JSON-array source snippets from a completion."""
    t = text.strip()
    # fenced block first (models love fences even when told not to)
    m = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", t, re.S)
    if m:
        yield m.group(1)
    if t.startswith("["):
        yield t
    # array embedded in prose: scan for a decodable [...] via raw_decode
    decoder = json.JSONDecoder()
    for m in _JSON_ARRAY_START_RE.finditer(t):
        try:
            _obj, end = decoder.raw_decode(t, m.start())
        except json.JSONDecodeError:
            continue
        yield t[m.start():end]


def filter_candidates(candidates: list[str]) -> tuple[list[str], list[dict]]:
    """Deterministic pre-flight gate (the LLM never gets the benefit of
    the doubt; the oracle gets clean input only).

    Returns (passed, rejected) -- rejected entries carry a reason.
    """
    passed: list[str] = []
    rejected: list[dict] = []
    seen: set[str] = set()
    for p in candidates:
        p = (p or "").strip()
        if not p:
            continue
        if p in seen:
            rejected.append({"payload": p[:80], "reason": "duplicate"})
            continue
        seen.add(p)
        if len(p) > _MAX_PROPOSAL_LEN:
            rejected.append({"payload": p[:80], "reason": "too long"})
            continue
        if _CONTROL_CHARS_RE.search(p):
            rejected.append({"payload": p[:80],
                             "reason": "control characters"})
            continue
        if _DSL_PLACEHOLDER_RE.search(p):
            rejected.append({"payload": p[:80],
                             "reason": "placeholder syntax (not literal)"})
            continue
        if not has_execution_point(p):
            rejected.append({"payload": p[:80],
                             "reason": "no execution point "
                                       "(alert/on-handler/javascript:)"})
            continue
        passed.append(p)
    return passed, rejected


def propose_and_verify(requester, url: str, param: str, *,
                       context_hint: str = "", meta_chars: str = "",
                       waf: str = "", method: str = "GET",
                       count: int = 5, headless: bool = False,
                       headers: dict | None = None,
                       pool=None, config_path: str | None = None) -> dict:
    """One propose -> filter -> replay -> verify cycle.

    ``pool`` may be injected (tests); by default the shared pool is
    built from the standard discovery order.  Raises ``LLMConfigError`` /
    ``LLMPoolExhausted`` unchanged -- callers degrade honestly.
    """
    if pool is None:
        from .llm_pool import default_pool
        pool = default_pool(config_path)

    res = pool.complete(
        build_messages(context_hint, meta_chars, waf, count),
        temperature=0.7, timeout=60, min_chars=2)
    raw = parse_candidates(res.text, limit=count * 2)
    if not raw:
        raise LLMProposeError(
            "the pool answered but no candidate payloads could be parsed "
            f"from the completion ({len(res.text or '')} chars)")
    passed, rejected = filter_candidates(raw)

    from .findings import EVIDENCE_MODEL, EVIDENCE_NO_BROWSER
    results = []
    for payload in passed[:_MAX_LIVE_VERIFY]:
        token = "xssp_" + secrets.token_hex(4)
        marked = verifier.mark(payload, token)
        try:
            if method.upper() == "POST":
                resp = requester.request(method, url, data={param: marked})
            else:
                resp = requester.request(method, url, params={param: marked})
            text = resp.text or ""
            hdrs = dict(resp.headers)
        except Exception as e:
            results.append({"payload": payload, "sent": True,
                            "reflected": False, "confirmed": False,
                            "evidence_class": None,
                            "detail": f"transport: {type(e).__name__}: {e}"})
            continue
        v = verifier.verify_semantic(text, token, response_headers=hdrs)
        confirmed = bool(v.get("confirmed"))
        headless_out = None
        if headless and not confirmed:
            hv = verifier.verify_headless(
                url, method,
                None if method.upper() == "POST" else {param: marked},
                {param: marked} if method.upper() == "POST" else None,
                dict(headers or {}), token)
            headless_out = {"available": bool(hv.get("available")),
                            "confirmed": bool(hv.get("confirmed"))}
            if headless_out["available"] and headless_out["confirmed"]:
                confirmed = True
        results.append({
            "payload": payload, "sent": True,
            "reflected": token in text,
            "confirmed": confirmed,
            "evidence_class": (EVIDENCE_MODEL if confirmed
                               else EVIDENCE_NO_BROWSER),
            "semantic_detail": str(v.get("detail") or "")[:200],
            "headless": headless_out,
        })

    return {
        "url": url, "param": param,
        "pool": {"model": str(getattr(res.candidate, "model", "")),
                 "failovers": res.failovers},
        "proposals_parsed": len(raw),
        "proposals_verified": len(results),
        "rejected": rejected,
        "results": results,
        "confirmed": [r["payload"] for r in results if r["confirmed"]],
        "note": ("confirmed == the token EXECUTED per verify_semantic"
                 "(/verify_headless), never the model's word; confirmed "
                 "proposals are NOT auto-promoted into the shipped corpus"),
    }
