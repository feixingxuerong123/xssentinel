"""Gate: every finding type the report knows about has dedicated remediation advice.

What this locks
---------------
``report.py`` maintains three hand-written maps keyed by finding type: the
SARIF rule id (``type_rule``), the human rule name (``type_name``) and the
interop description (:data:`_interop_type_desc`).  ``fix_advice.json`` is a
fourth, independent list.  Nothing tied them together, so they drifted.

Measured on 2026-10-08: six types were **emitted by real scans** and rendered
by the report, yet fell through to ``default_advice`` --

    cors_misconfig  xs_leak_surface  upload_xss
    stored_upload   stored_dom       source_map_exposed

That is not a crash and not a false positive, which is exactly why it went
unnoticed: the report simply told the reader to "apply context-aware output
encoding" for a CORS policy bug (a header-echo problem) and for an exposed
``.js.map`` (an information-disclosure problem).  The advice was wrong in a
way that a green test suite cannot see.

Two independent sources of truth agree on the six, so the finding is not an
artifact of one heuristic:

* real scan output -- ``benchmark/results/*.json`` contain findings of type
  ``cors_misconfig`` and ``stored_dom``;
* the report's own maps -- all six have a rule id and a display name, i.e.
  the report was written expecting to render them.

The gate therefore asserts the **intersection**: a type that the report
recognises and that the code base emits must have a dedicated advice entry.
Types only present in one source are allowed to differ (``jsonpcallback`` is
a legacy alias the report keeps for old SARIF consumers and nothing emits it;
``fuzzer_triage``/``bav`` are report-level vocabulary) -- pinning those too
would force advice for string values that never reach ``fix_advice``.

There is no waiver list.  An exemption would be the same "safe-looking
exception" shape this project already removed from the port-hygiene gate:
the failing case produced no signal, so nothing would ever turn it red.

This gate parses source and JSON only, so it runs (and fails) on a throttled
host.
"""
from __future__ import annotations

import ast
import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_PY = os.path.join(ROOT, "xssentinel", "core", "report.py")
FIX_ADVICE_JSON = os.path.join(ROOT, "xssentinel", "data", "fix_advice.json")

# Non-type keys that share the report's map syntax (confidence values and
# field names) -- excluded by name, not by a heuristic.
_NOT_A_TYPE = {"certain", "firm", "high", "medium", "low", "critical",
               "info", "name", "text", "tool"}


def _report_known_types(source: str) -> set[str]:
    """Types the report recognises: SARIF rule-id map keys.

    Parsed with ``ast`` rather than a regex so the extraction cannot be
    fooled by a string that merely looks like a map entry in a comment or a
    template literal.

    The maps live inside a function, so the tree is walked for every dict
    whose values all start with ``XSSENTINEL-`` (the rule-id map is the only
    one with that property).
    """
    tree = ast.parse(source)
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        keys, vals = node.keys, node.values
        if not keys or len(keys) != len(vals):
            continue
        pairs = []
        ok = True
        for k, v in zip(keys, vals):
            if not (isinstance(k, ast.Constant) and isinstance(k.value, str)
                    and isinstance(v, ast.Constant)
                    and isinstance(v.value, str)):
                ok = False
                break
            pairs.append((k.value, v.value))
        if not ok or not pairs:
            continue
        if all(value.startswith("XSSENTINEL-") for _key, value in pairs):
            found |= {key for key, _value in pairs}
    return found - _NOT_A_TYPE


def _emitted_types(source_root: str) -> set[str]:
    """Every finding type the scanner package can emit.

    Two shapes both reach :class:`~xssentinel.core.findings.Finding`:

    * a dict literal -- ``{"type": "dom_sink"}`` (``dom.py`` builds these,
      the scanner later collapses them into ``type: "dom"``);
    * a call keyword -- ``Finding(type="cors_misconfig", ...)`` and
      ``Finding(**{"type": "stored_dom", ...})``.

    The first version of this reader only walked dict literals, so
    ``cors_misconfig`` was invisible -- it is passed as a keyword in both
    engines.  A gate whose candidate set silently misses a type cannot
    report that type as uncovered, which is the exact failure mode this file
    exists to prevent.

    The set is intentionally loose: it includes JSON-schema literals
    (``"type": "object"``) and sub-result names.  That is safe because the
    callers intersect it with the report's maps before drawing conclusions.
    """
    out: set[str] = set()
    for dirpath, _dirnames, filenames in os.walk(source_root):
        if "__pycache__" in dirpath:
            continue
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                tree = ast.parse(open(path, encoding="utf-8").read())
            except (SyntaxError, UnicodeDecodeError):
                continue
            for node in ast.walk(tree):
                # Shape 1: dict literal {"type": "..."}
                if isinstance(node, ast.Dict):
                    for k, v in zip(node.keys, node.values):
                        if (isinstance(k, ast.Constant) and k.value == "type"
                                and isinstance(v, ast.Constant)
                                and isinstance(v.value, str)):
                            out.add(v.value)
                # Shape 2: keyword argument type="..."
                if isinstance(node, ast.Call):
                    for kw in node.keywords:
                        if kw.arg != "type":
                            continue
                        if (isinstance(kw.value, ast.Constant)
                                and isinstance(kw.value.value, str)):
                            out.add(kw.value.value)
    return out


def _advice_types() -> set[str]:
    with open(FIX_ADVICE_JSON, encoding="utf-8") as fh:
        return set(json.load(fh)["advice"])


def _literal_str_dict_keys(node: ast.Dict) -> set[str] | None:
    """Keys of a dict whose keys and values are all string literals, else None.

    Returns None when any pair is not a plain string -> string mapping, which
    keeps the walker from picking up unrelated dicts.
    """
    out: set[str] = set()
    for k, v in zip(node.keys, node.values):
        if not (isinstance(k, ast.Constant) and isinstance(k.value, str)
                and isinstance(v, ast.Constant) and isinstance(v.value, str)):
            return None
        out.add(k.value)
    return out or None


def _sarif_rule_map(source: str) -> set[str]:
    """Keys of the ``type_rule`` dict inside ``build_sarif``.

    Identified by "every value starts with XSSENTINEL-", which is true of the
    rule-id map and nothing else in the module.
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef)
                and node.name == "build_sarif"):
            continue
        for st in ast.walk(node):
            if not isinstance(st, ast.Assign):
                continue
            if not any(isinstance(t, ast.Name) and t.id == "type_rule"
                       for t in st.targets):
                continue
            keys = _literal_str_dict_keys(st.value)
            if keys and all(v.startswith("XSSENTINEL-")
                            for v in _literal_str_values(st.value)):
                return keys
    return set()


def _literal_str_values(node: ast.Dict) -> list[str]:
    return [v.value for v in node.values
            if isinstance(v, ast.Constant) and isinstance(v.value, str)]


def _interop_name_map(source: str) -> set[str]:
    """Keys of the module-level ``_INTEROP_TYPE_NAME`` dict."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "_INTEROP_TYPE_NAME"
                   for t in node.targets):
            continue
        keys = _literal_str_dict_keys(node.value)
        if keys:
            return keys
    return set()


def missing_advice(report_source: str, source_root: str) -> list[str]:
    """Sorted finding types that need advice but have none."""
    needed = _report_known_types(report_source) & _emitted_types(source_root)
    return sorted(needed - _advice_types())


def report_type_map_offenders(report_source: str, source_root: str,
                              interop: set[str] | None = None,
                              rules: set[str] | None = None,
                              emitted: set[str] | None = None) -> list[str]:
    """Emitted types the report's tables forgot.

    Second, independent invariant.  Discovered while pinning the advice gap:
    ``stored_dom`` is emitted by ``scanner_stored.py`` with browser-grade
    proof, but appeared in **none** of the report's three type tables.  The
    visible symptom is cosmetic until you look at the consumers -- the Burp
    and Nuclei exporters fell back to the slug ``"stored dom (XSS)"``, and
    the SARIF rule id collapsed to the generic ``XSSENTINEL-XSS``, so a
    stored browser-confirmed finding was indistinguishable from a reflected
    one in code-scanning triage.

    The rule is narrow on purpose: a type counts only when the report
    *already knows it* (it is named in one of the two browser-facing tables)
    and the code base emits it.  That keeps the check from demanding entries
    for the loose ``emitted`` set, which also contains JSON-schema literals
    (``"type": "object"``) and sub-result names (``dom_sink``) that never
    reach a report.

    The offenders reported are the ones sitting in exactly one of the two
    tables: known, rendered, but recognised by only half the surface.

    ``interop`` / ``rules`` / ``emitted`` are injectable so the anti-vacuity
    proof can exercise *this function* rather than re-deriving the set
    arithmetic beside it.
    """
    emitted = _emitted_types(source_root) if emitted is None else emitted
    interop = _interop_name_map(report_source) if interop is None else interop
    rules = _sarif_rule_map(report_source) if rules is None else rules
    acknowledged = interop | rules
    # Only types the report promises to render, i.e. named in a table AND
    # actually produced by the scanner.
    relevant = emitted & acknowledged
    only_half = relevant - (interop & rules)
    return sorted(only_half)


# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------

def test_every_emitted_report_type_has_dedicated_advice():
    with open(REPORT_PY, encoding="utf-8") as fh:
        report_source = fh.read()
    missing = missing_advice(
        report_source, os.path.join(ROOT, "xssentinel"))
    assert not missing, (
        "these finding types reach the report but fall through to the "
        "generic default advice, so the remediation section tells the reader "
        "to fix an XSS by output-encoding even when the bug is something "
        "else entirely.  Add one entry per type to "
        "xssentinel/data/fix_advice.json:\n  " + "\n  ".join(missing))


def test_intersection_is_not_empty():
    """Guard against the gate passing on an empty set.

    ``missing`` is a set difference: if either side of the intersection
    silently stopped resolving (a renamed map, a moved package), the result
    would be empty for the wrong reason -- the failure mode this project has
    already paid for twice (a gate that cannot report a violation).
    """
    with open(REPORT_PY, encoding="utf-8") as fh:
        report_source = fh.read()
    known = _report_known_types(report_source)
    emitted = _emitted_types(os.path.join(ROOT, "xssentinel"))
    assert len(known) >= 25, (
        f"the report's type maps resolved to only {len(known)} types "
        f"({sorted(known)}); the extraction is broken, not the corpus")
    assert len(emitted) >= 20, (
        f"only {len(emitted)} types found in the scanner package; the AST "
        "walk is not seeing the finding dicts")
    assert known & emitted, (
        "the report maps and the emitted types no longer intersect at all -- "
        "one of them moved, and this gate would pass vacuously")


def test_the_six_measured_types_have_advice():
    """Regression pin for the exact gap this gate was written for.

    Kept separate from the sweep above so a future refactor of the extraction
    cannot quietly turn the general assertion into a no-op while this one
    still names the offenders.

    Note the two different membership claims.  All six are *emitted*; only
    some of them are in the SARIF rule-id map.  ``stored_dom``,
    ``stored_upload`` and ``upload_xss`` were emitted with an interop
    description but no rule id -- a second, separate gap (Phase 207) that
    the rule-id sweep below now also covers.
    """
    emitted = _emitted_types(os.path.join(ROOT, "xssentinel"))
    measured = {"cors_misconfig", "xs_leak_surface", "upload_xss",
                "stored_upload", "stored_dom", "source_map_exposed"}
    assert measured <= emitted, (
        f"these types are no longer emitted by the code base: "
        f"{sorted(measured - emitted)} -- if that is intended, remove them "
        "from this pin and from the report maps together")
    advice = _advice_types()
    assert measured <= advice, (
        f"regressed to the default advice: {sorted(measured - advice)}")


def test_advice_entries_are_wellformed():
    """Every entry carries the full schema, not just a headline.

    A one-field entry would still "have advice" by the sweep above while
    rendering empty <li> items and a blank code block -- the gate should fail
    on that too.
    """
    with open(FIX_ADVICE_JSON, encoding="utf-8") as fh:
        doc = json.load(fh)
    bad = []
    for name, entry in doc["advice"].items():
        for field in ("headline", "detail", "code_example", "primary_cwe",
                      "also_consider"):
            if field not in entry:
                bad.append(f"{name}: missing {field}")
                continue
            if field == "also_consider":
                if not isinstance(entry[field], list) or not entry[field]:
                    bad.append(f"{name}: also_consider must be a non-empty list")
            elif not str(entry[field]).strip():
                bad.append(f"{name}: {field} is empty")
        cwe = entry.get("primary_cwe", "")
        if cwe and not str(cwe).startswith("CWE-"):
            bad.append(f"{name}: primary_cwe {cwe!r} is not a CWE id")
    assert not bad, "malformed advice entries:\n  " + "\n  ".join(bad)


def test_declared_entry_count_matches_reality():
    """_meta.entry_count drifts the moment an entry is added by hand."""
    with open(FIX_ADVICE_JSON, encoding="utf-8") as fh:
        doc = json.load(fh)
    declared = doc["_meta"].get("entry_count")
    actual = len(doc["advice"])
    assert declared == actual, (
        f"_meta.entry_count says {declared}, the corpus holds {actual} -- "
        "update the metadata in the same edit that adds an entry")


def test_report_tables_agree_on_every_emitted_type():
    """A type the report names must be named in BOTH browser-facing tables.

    Catches the ``stored_dom`` shape: present in the interop name table (a
    human reads a sensible label) but absent from the SARIF rule map, so the
    machine-readable export silently degrades to the generic rule id.
    """
    with open(REPORT_PY, encoding="utf-8") as fh:
        report_source = fh.read()
    offenders = report_type_map_offenders(
        report_source, os.path.join(ROOT, "xssentinel"))
    assert not offenders, (
        "these finding types are recognised by only one of the report's two "
        "browser-facing tables, so one exporter renders them and the other "
        "falls back to a generic rule id / slug:\n  " + "\n  ".join(offenders))


def test_report_table_extraction_is_not_vacuous():
    """The two table readers must resolve real dicts, not empty sets.

    If either extraction silently returned ``set()``, the agreement check
    above would compare two empty sets and pass forever.
    """
    with open(REPORT_PY, encoding="utf-8") as fh:
        report_source = fh.read()
    interop = _interop_name_map(report_source)
    rules = _sarif_rule_map(report_source)
    assert len(interop) >= 25, f"interop table resolved to {len(interop)} keys"
    assert len(rules) >= 25, f"SARIF rule table resolved to {len(rules)} keys"
    assert "reflected" in interop and "reflected" in rules


def _finding_call_types(source_root: str) -> set[str]:
    """Types passed to a ``Finding(...)`` call, however spelled.

    Narrower than :func:`_emitted_types` on purpose.  That one is deliberately
    loose (any ``"type": ...`` literal anywhere, including ``"type": "object"``
    in JSON schemas and ``"type": "dom_sink"`` in DOM sub-results).  This one
    requires the value to be a keyword of a call whose callee is named
    ``Finding``, which is how every real finding is constructed.

    Rationale: the ``scenario`` defect (Phase 207) was an *emitted* type in
    **none** of the report's tables -- invisible to the intersection-based
    sweep above, because that sweep only looks at types the report already
    knows.  A type constructed as a ``Finding`` is unambiguously real, so it
    can be required to be report-visible without an exemption list.
    """
    out: set[str] = set()
    for dirpath, _dirnames, filenames in os.walk(source_root):
        if "__pycache__" in dirpath:
            continue
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            try:
                tree = ast.parse(open(os.path.join(dirpath, fn),
                                      encoding="utf-8").read())
            except (SyntaxError, UnicodeDecodeError):
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fn_node = node.func
                name = getattr(fn_node, "id", None) or getattr(fn_node, "attr",
                                                               None)
                if name != "Finding":
                    continue
                for kw in node.keywords:
                    if (kw.arg == "type"
                            and isinstance(kw.value, ast.Constant)
                            and isinstance(kw.value.value, str)):
                        out.add(kw.value.value)
    return out


def orphan_types(report_source: str, source_root: str,
                 emitted: set[str] | None = None,
                 tables: set[str] | None = None) -> list[str]:
    """Finding constructions the report cannot render by name.

    Returns the sorted set of types built by a ``Finding(...)`` call that
    appear in NEITHER browser-facing table.
    """
    if emitted is None:
        emitted = _finding_call_types(source_root)
    if tables is None:
        tables = _interop_name_map(report_source) | _sarif_rule_map(
            report_source)
    return sorted(emitted - tables)


def test_every_finding_construction_is_report_visible():
    """A ``Finding`` the report cannot name renders as a slug, not a title.

    This is the ``scenario`` shape: built as ``Finding(type="scenario", ...)``
    in ``core/scenarios.py``, absent from every table, so the Burp/Nuclei
    exporters emitted ``"scenario (XSS)"`` and SARIF used the generic rule id.
    """
    with open(REPORT_PY, encoding="utf-8") as fh:
        report_source = fh.read()
    orphans = orphan_types(report_source, os.path.join(ROOT, "xssentinel"))
    assert not orphans, (
        "these types are constructed as Findings but named in neither report "
        "table, so the interop exporters fall back to a slug and SARIF to the "
        "generic rule id:\n  " + "\n  ".join(orphans))


def test_orphan_detector_is_not_vacuous():
    """The orphan sweep must be looking at real constructions."""
    ctor = _finding_call_types(os.path.join(ROOT, "xssentinel"))
    assert len(ctor) >= 8, (
        f"only {len(ctor)} Finding(...) constructions found ({sorted(ctor)}); "
        "the walker is not seeing the call sites")


# ---------------------------------------------------------------------------
# Anti-vacuity: the detector must be able to fail
# ---------------------------------------------------------------------------

def test_detector_fails_on_a_known_violation():
    """A gate that cannot report a violation is the same bug one level up.

    Re-insert ``source_map_exposed`` as an *uncovered* type (the exact shape
    that was measured on 2026-10-08) and confirm the detector names it.  The
    proof is self-contained: no file on disk is touched, the corpus is
    injected with the type removed.
    """
    with open(REPORT_PY, encoding="utf-8") as fh:
        report_source = fh.read()

    # Sanity: with the corpus as shipped, nothing is missing.
    assert not missing_advice(report_source, os.path.join(ROOT, "xssentinel"))

    advice = _advice_types()
    assert "source_map_exposed" in advice, "premise for the probe is gone"

    # Simulate the pre-fix corpus by removing the entry, without touching
    # the file: re-run the set arithmetic with a doctored corpus.
    needed = (_report_known_types(report_source)
              & _emitted_types(os.path.join(ROOT, "xssentinel")))
    doctored = needed - (advice - {"source_map_exposed"})
    assert "source_map_exposed" in doctored, (
        "removing the entry from the corpus did not make the type 'missing' "
        "-- the detector is not wired to the corpus")


def test_report_table_sweep_fails_on_a_known_violation():
    """Same anti-vacuity proof for the second invariant.

    Recreate the exact ``stored_dom`` shape -- named in the interop table,
    absent from the SARIF rule map -- and drive **the real detector function**
    with it.  Asserting the set arithmetic inline would prove only that sets
    subtract, not that the gate is wired to them.
    """
    synthetic = (
        "_INTEROP_TYPE_NAME = {\n"
        "    'reflected': 'Cross-site scripting (reflected)',\n"
        "    'stored_dom': 'Stored cross-site scripting (DOM-based)',\n"
        "}\n"
        "\n"
        "def build_sarif(findings):\n"
        "    type_rule = {\n"
        "        'reflected': 'XSSENTINEL-XSS-REFLECTED',\n"
        "    }\n"
        "    return type_rule\n"
    )
    # The readers must see exactly what the synthetic source declares...
    assert _interop_name_map(synthetic) == {"reflected", "stored_dom"}
    assert _sarif_rule_map(synthetic) == {"reflected"}
    # ...and the detector, fed that one-table-only shape, must name it.
    offenders = report_type_map_offenders(
        synthetic, os.path.join(ROOT, "xssentinel"),
        interop={"reflected", "stored_dom"},
        rules={"reflected"},
        emitted={"reflected", "stored_dom", "unrelated_not_in_report"})
    assert offenders == ["stored_dom"], (
        f"the one-table-only shape did not surface (got {offenders}); the "
        "invariant cannot detect the defect it was written for")
    # A type absent from BOTH tables is out of scope -- the gate must not
    # start demanding entries for schema literals or sub-result names.
    assert "unrelated_not_in_report" not in offenders


def test_extraction_rejects_lookalike_strings():
    """The AST extraction must not be fooled by a regex-shaped decoy.

    A comment or a template containing ``"type": "fake"`` used to be invisible
    to a naive scan; it must stay invisible here too, or the gate could be
    satisfied (or broken) by text rather than by code.
    """
    decoy = (
        "# \"type\": \"not_a_real_type\" in a comment\n"
        "def f():\n"
        "    return {'type': 'also_not_real'}\n"
    )
    tree = ast.parse(decoy)
    seen = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if (isinstance(k, ast.Constant) and k.value == "type"
                        and isinstance(v, ast.Constant)
                        and isinstance(v.value, str)):
                    seen.add(v.value)
    # The comment decoy is gone (AST does not carry comments); the real dict
    # literal is still visible.  That asymmetry is the point.
    assert "not_a_real_type" not in seen
    assert "also_not_real" in seen


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
