"""nuclei dast template -> payload-corpus bridge (Phase 322).

Why
---
The nuclei ecosystem's moat is its community template flywheel (templates
v10.5.0 alone added 295 checks in Oct 2026); XSSentinel's corpus grows by
curated hand additions (Phase 318's backtick-stamp and leading-null
families were both hand-derived).  This bridge imports the PAYLOAD side of
XSS-relevant dast templates into the custom-payload channel, so the
community's corpus growth can be consumed without touching judgment:
imported payloads ride the queue tail behind the context-matched ladder
and are confirmed by the same token/verify_semantic machinery as every
corpus payload.  Nothing here changes what "confirmed" means.

What this bridge is NOT
-----------------------
It does not run nuclei templates.  Matchers (interactsh OOB callbacks,
DSL expressions like ``contains(interactsh_protocol,'dns')``) are nuclei
machinery -- reimplementing them would fork the semantics, not borrow the
corpus.  Payloads whose detection story depends on an OOB callback are
counted in ``skipped["oob"]`` and never silently mistranslated into
something the reflection loop could half-honor.

Requires PyYAML (optional dependency).  Missing -> :class:`NucleiImportError`
naming the install; the scan itself never degrades because of this module.
"""
from __future__ import annotations

import os
import re

from .logger import get_logger

_log = get_logger("nuclei_import")

__all__ = ["NucleiImportError", "extract_payloads", "merge_into_custom",
           "is_xss_relevant"]

#: Hard bounds -- the bridge feeds a bounded probe budget, not a dump.
_MAX_PAYLOAD_LEN = 600
_MAX_TEMPLATES = 2000

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_INTERACTSH_RE = re.compile(r"\{\{\s*interactsh", re.I)
#: Any surviving {{...}} after the fuzz cross-references resolved is a
#: nuclei DSL placeholder/function call ({{first}}, {{url_encode(x)}},
#: {{rand_base(...)}}) -- NOT a literal payload.  Sending one verbatim is
#: meaningless against a real target; measured on the local dast corpus
#: where the only two "payloads" left after OOB filtering were exactly
#: these two shapes.
_NUCLEI_DSL_RE = re.compile(r"\{\{[^}]*\}\}")
#: Path/host/plain-word shape.  XSS-tagged CVE templates legitimately
#: carry payloads blocks that hold PATHS ("/wp-login", "/") -- an xss tag
#: on the template does not make every string in it a payload (measured:
#: CVE-2021-24522 was the only import left from the whole local http
#: tree, and all three strings were paths).
_PATHLIKE_RE = re.compile(r"^[/\w .:@-]*$")
_ON_ATTR_RE = re.compile(r"\son[a-z]+\s*=", re.I)
_CALLED_ALERT_RE = re.compile(r"alert\s*[(`]")


class NucleiImportError(Exception):
    """Raised for bridge-level failures (missing dependency, bad path)."""


def _load_yaml_file(path: str):
    try:
        import yaml
    except ImportError as e:                       # pragma: no cover
        raise NucleiImportError(
            "PyYAML is required for --nuclei-dast "
            "(pip install 'xssentinel[nuclei]' or pip install pyyaml)"
        ) from e
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return yaml.safe_load(f)


def _iter_yaml_files(path: str) -> list[str]:
    if os.path.isfile(path):
        return [path]
    if os.path.isdir(path):
        out: list[str] = []
        for root, _dirs, files in os.walk(path):
            for name in sorted(files):
                if name.endswith((".yaml", ".yml")):
                    out.append(os.path.join(root, name))
                    if len(out) >= _MAX_TEMPLATES:
                        _log.warning("nuclei-dast: template cap %d hit at %s",
                                     _MAX_TEMPLATES, path)
                        return out
        return out
    raise NucleiImportError(f"nuclei-dast path not found: {path}")


def is_xss_relevant(info: dict, payload: str) -> bool:
    """XSS-relevant when the template says so (tags) or the payload shape
    is an HTML/JS breakout the reflection loop could actually deliver."""
    tags = (info or {}).get("tags") or ""
    if isinstance(tags, list):
        tags = ",".join(str(t) for t in tags)
    if "xss" in str(tags).lower().split(","):
        return not _PATHLIKE_RE.fullmatch(payload)
    p = payload
    if "<" not in p and "\\" not in p:
        return False
    return bool(_CALLED_ALERT_RE.search(p)
                or _ON_ATTR_RE.search(p)
                or "javascript:" in p.lower()
                or re.search(r"<\s*(script|svg|iframe|img|body|style)\b",
                             p, re.I)
                or "srcdoc" in p.lower())


def _payload_strings(doc: dict):
    """Yield literal payload strings from a template's http blocks.

    Covers the two shapes dast XSS templates actually use: named payload
    lists under ``http[*].payloads`` and literal fuzz lists under
    ``http[*].fuzzing[*].fuzz``.  Cross-references like ``{{execution}}``
    resolve through the named payloads already yielded, so template-level
    resolution is not duplicated here.
    """
    named: dict[str, list[str]] = {}
    named_literals: set[str] = set()
    for block in (doc.get("http") or []):
        if not isinstance(block, dict):
            continue
        pl = block.get("payloads") or {}
        if isinstance(pl, dict):
            for name, values in pl.items():
                if isinstance(values, list):
                    named[str(name)] = [v for v in values
                                        if isinstance(v, str)]
                    for v in values:
                        if isinstance(v, str):
                            named_literals.add(str(v).strip())
                            yield v
        for fz in (block.get("fuzzing") or []):
            if not isinstance(fz, dict):
                continue
            for entry in (fz.get("fuzz") or []):
                if not isinstance(entry, str):
                    continue
                entry = entry.strip()
                m = re.fullmatch(r"\{\{\s*([A-Za-z0-9_-]+)\s*\}\}", entry)
                # a {{name}} cross-reference resolves to the named
                # payloads, which were already yielded above -- re-yielding
                # would only inflate the duplicate/skip counters
                if m:
                    continue
                if entry in named_literals:
                    continue
                yield entry


def extract_payloads(path: str, limit: int = 500) -> dict:
    """Extract XSS-relevant literal payloads from nuclei dast templates.

    Returns ``{"payloads": [{payload, template, tags, severity}],
    "skipped": {"oob": n, "not_xss": n, "duplicates": n, "bad_files": n},
    "templates": files_seen}`` -- the skip counts exist so the operator
    can see what the bridge declined and why, not just what it took.
    """
    files = _iter_yaml_files(path)
    skipped = {"oob": 0, "not_xss": 0, "duplicates": 0, "bad_files": 0,
               "placeholders": 0}
    seen: set[str] = set()
    out: list[dict] = []
    for fp in files:
        try:
            doc = _load_yaml_file(fp)
        except Exception:
            skipped["bad_files"] += 1
            continue
        if not isinstance(doc, dict):
            skipped["bad_files"] += 1
            continue
        info = doc.get("info") or {}
        for raw in _payload_strings(doc):
            p = _CONTROL_CHARS_RE.sub("", str(raw).strip())
            if not p or len(p) > _MAX_PAYLOAD_LEN:
                continue
            if _INTERACTSH_RE.search(p):
                skipped["oob"] += 1
                continue
            if _NUCLEI_DSL_RE.search(p):
                skipped["placeholders"] += 1
                continue
            if not is_xss_relevant(info, p):
                skipped["not_xss"] += 1
                continue
            key = " ".join(p.split())
            if key in seen:
                skipped["duplicates"] += 1
                continue
            seen.add(key)
            out.append({
                "payload": p,
                "template": str(doc.get("id")
                                or os.path.splitext(os.path.basename(fp))[0]),
                "tags": str(info.get("tags") or ""),
                "severity": str(info.get("severity") or ""),
            })
            if len(out) >= limit:
                _log.warning("nuclei-dast: payload limit %d hit", limit)
                return {"payloads": out, "skipped": skipped,
                        "templates": len(files)}
    return {"payloads": out, "skipped": skipped, "templates": len(files)}


def merge_into_custom(custom: list[str], extracted: dict,
                      limit: int = 500) -> list[str]:
    """Operator wordlist first, then bridge payloads, dedup'd, bounded.

    Pure function (CLI/test shared): the merge order is the priority
    order -- an explicit operator file outranks community imports.
    """
    out = list(custom)
    seen = {" ".join(c.split()) for c in out}
    for rec in (extracted or {}).get("payloads", []):
        p = rec["payload"]
        key = " ".join(p.split())
        if key in seen:
            continue
        if len(out) >= limit:
            break
        seen.add(key)
        out.append(p)
    return out
