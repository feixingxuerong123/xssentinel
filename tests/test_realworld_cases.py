# -*- coding: utf-8 -*-
"""Phase 352: the real-world regression corpus stays a fixed, honest list.

The corpus is only useful if its shape cannot silently drift: a case added
without a ground truth, a duplicate URL, or an unpinned app version would
turn the comparison table into a different experiment.  This gate pins those
properties without running a scan (the scan itself is opt-in; the target is
a Docker application, not part of the unit gate).
"""
from __future__ import annotations

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES = os.path.join(ROOT, "benchmark", "realworld", "cases.json")


def _load():
    with open(CASES, encoding="utf-8") as fh:
        return json.load(fh)


def test_apps_are_pinned():
    """Every app block must be digest-pinned; the Juice Shop pin stays hard.

    v2 switched ``_meta["app"]`` to ``_meta["apps"]`` (the runner reads the
    plural shape) and added DVWA.  A re-pin is a different experiment and
    must be loud: Juice Shop's version is asserted exactly, DVWA only via
    its inline ``@sha256:`` digest (its upstream tag is :latest by design).
    """
    apps = _load()["_meta"]["apps"]
    assert set(apps) == {"juice", "juice_unsafe", "dvwa", "bwapp", "selfhosted"}
    for key, app in apps.items():
        assert app["version"], key
        assert app["base_url"].startswith("http://"), key
        if key == "selfhosted":
            # Local-source target: pinned by the in-repo file + start command,
            # not by a container digest.
            assert app["image"].startswith("local source"), key
            assert app.get("start"), key
            continue
        digest = app.get("image_digest") or app["image"].partition("@")[2]
        assert digest.startswith("sha256:"), f"{key}: image must be digest-pinned"
    for key in ("juice", "juice_unsafe"):
        assert apps[key]["version"] == "20.2.0", key
        assert apps[key]["image"] == "bkimminich/juice-shop:v20.2.0", key


def test_cases_reference_known_apps():
    cases = _load()["cases"]
    known = set(_load()["_meta"]["apps"])
    for c in cases:
        assert c.get("app") in known, c["id"]


def test_cases_have_endpoint_level_ground_truth_and_unique_urls():
    cases = _load()["cases"]
    assert len(cases) >= 7
    ids = [c["id"] for c in cases]
    # v2.1 has multiple apps: "/" is a different resource on Juice Shop and
    # the self-hosted lab, so uniqueness is per (app, url), not global.
    targets = [(c.get("app"), c["url"]) for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case id"
    assert len(targets) == len(set(targets)), "duplicate (app, url)"
    for c in cases:
        assert c["ground_truth"] in ("vulnerable", "safe"), c
        assert c.get("source") and c.get("evidence"), c
    vuln = [c for c in cases if c["ground_truth"] == "vulnerable"]
    safe = [c for c in cases if c["ground_truth"] == "safe"]
    assert len(vuln) >= 3 and len(safe) >= 4


def test_dom_cases_are_hash_routes_and_controls_are_not():
    cases = _load()["cases"]
    by_id = {c["id"]: c for c in cases}
    for cid in ("js-dom-search-iframe", "js-dom-search-onerror",
                "js-dom-search-script-tag"):
        assert "/#/search" in by_id[cid]["url"], cid
    for cid in ("js-root", "js-api-search", "js-track-order"):
        assert "/#/" not in by_id[cid]["url"], cid
