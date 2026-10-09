"""Phase 209: a template SSTI finding must be attributable to our input.

Found by scanning a REAL application (OWASP Juice Shop 20.2.0) instead of a
fixture of our own.  The scan emitted exactly one finding off 74 crawled
endpoints: ``template_ssti_dot``, severity **critical**, at
``/redirect?to=`` -- and the mechanism was a substring test.

``detect_rendered`` asked whether ``49`` appears in the response of a
``{{7*7}}`` probe.  Juice Shop does not render templates server-side: it
reflected the probe *verbatim* inside a 406 error page, and that page's one
and only ``49`` was a stack-trace line number (``route.js:149:13``).  The
evidence string then claimed the probe had "rendered to 49".

The fix is a control request: re-send the same parameter with a digits-free
value.  A ``49`` that shows up when our input contains no digits at all was
produced by the page, not by an engine.

Why these tests are load-bearing rather than decorative: delete the control
request from ``_scan_template`` and ``test_stack_trace_49_is_not_a_render``
fails, because the layer then believes the coincidence again.  Every case
here was written against the two responses measured from the live target.
"""
from __future__ import annotations

from xssentinel.core import template as tpl_mod
from xssentinel.core.scanner import Scanner

PROBE = "{{7*7}}"
CONTROL = tpl_mod.CONTROL_VALUE
# The confirm payload the layer sends once it believes an engine renders
# input.  It is per-framework, so it is read from the corpus instead of
# hardcoded -- a corpus edit must move the test, not silently break it.
ANGULARJS_CONFIRM = next(c for fw, _p, _v, c in tpl_mod.TEMPLATES
                         if fw == "AngularJS")

TRACE = ('<li>    at Route.dispatch '
         '(D:\\app\\node_modules\\express\\lib\\router\\route.js:149:13)</li>')


class _Resp:
    def __init__(self, text: str):
        self.text = text
        self.headers = {}


class _RecordingRequester:
    """Faithful stand-in for ``Requester.request``.

    Only ``text`` and ``headers`` are read by the layer; the call log is what
    lets a test assert that the control request actually went out.
    """

    def __init__(self, page):
        self._page = page
        self.calls: list[tuple] = []

    def request(self, method, url, params=None, data=None, **kwargs):
        self.calls.append((method, url, params, data))
        return _Resp(self._page(params, data))


def _sent_value(params, data):
    if data:
        return next(iter(data.values()), "")
    return next(iter((params or {}).values()), "")


def _scanner() -> Scanner:
    return Scanner(max_payloads=6, max_transforms=4, advanced_layers=True)


def _run_layer(scanner, requester, param_value_on_entry="apple"):
    scanner.findings.clear()
    # ``data`` is a dict at every real call site (_run_advanced_layers), and
    # _set_param does dict(data) unconditionally -- passing None here would
    # test a shape the product never produces.
    scanner._scan_template(
        requester, "http://target.invalid/redirect", "GET",
        {"to": param_value_on_entry}, {}, "to", False, "")
    return scanner.findings


# ---------------------------------------------------------------- control --

def test_stack_trace_49_is_not_a_render():
    """The measured Juice Shop shape: verbatim probe + coincidental "49"."""
    def page(params, data):
        v = _sent_value(params, data)
        # Error page: echoes the input into <title> and carries a stack trace
        # whose line number contains 49.  Same shape for probe and control.
        return f"<title>Unrecognized target URL: {v}</title>{TRACE}"

    sc, req = _scanner(), _RecordingRequester(page)
    findings = _run_layer(sc, req)
    assert findings == [], (
        "a template finding here is the Phase 209 false positive: the probe "
        "was reflected verbatim and '49' came from a line number")
    assert len(req.calls) == 2, (
        "the layer must ask once for the render and once for the control")


def test_genuine_render_still_fires():
    """The self-test fixture shape: the engine replaces the probe with 49."""
    def page(params, data):
        v = _sent_value(params, data)
        rendered = v.replace("{{7*7}}", "49").replace("{{ 7*7 }}", "49")
        return f"<div>{rendered}</div>"

    sc, req = _scanner(), _RecordingRequester(page)
    findings = _run_layer(sc, req)
    assert len(findings) == 1, "a real render must not be gated away"
    f = findings[0]
    d = f.data  # Finding is a thin kwargs wrapper (findings.py:129)
    assert d["type"].startswith("template_ssti_")
    assert d["severity"] == "critical"
    assert len(req.calls) == 3  # probe, control, confirm
    assert req.calls[2][2] == {"to": ANGULARJS_CONFIRM}, \
        "stage 2 must go out with the framework's confirm payload"


def test_control_request_failure_is_not_a_passed_control():
    """No attribution -> no claim.  A failed control is not evidence."""

    class _FailingOnSecond(_RecordingRequester):
        def __init__(self, page):
            super().__init__(page)
            self._n = 0

        def request(self, method, url, params=None, data=None, **kwargs):
            self._n += 1
            if self._n == 2:
                self.calls.append((method, url, params, data))
                raise OSError("connection reset")
            return super().request(method, url, params, data, **kwargs)

    def page(params, data):
        return f"<div>{_sent_value(params, data).replace('{{7*7}}', '49')}</div>"

    req = _FailingOnSecond(page)
    sc = _scanner()
    assert _run_layer(sc, req) == []
    assert len(req.calls) == 2, "probe + failed control, no confirm payload sent"


# ------------------------------------------------------------------ units --

def test_detect_rendered_without_control_keeps_old_semantics():
    assert tpl_mod.detect_rendered("value 49 here", "49") is True
    assert tpl_mod.detect_rendered("no digits", "49") is False


def test_detect_rendered_suppressed_when_control_also_shows_value():
    assert tpl_mod.detect_rendered("route.js:149:13", "49",
                                   control_text="route.js:149:13") is False


def test_detect_rendered_allowed_when_value_is_ours_alone():
    assert tpl_mod.detect_rendered("got 49", "49", control_text="got 0") is True


def test_exploitable_frameworks_threads_the_control():
    with_coincidence = f"<title>{PROBE}</title>{TRACE}"
    assert tpl_mod.exploitable_frameworks(with_coincidence), \
        "without the control this is exactly how the FP happened"
    assert tpl_mod.exploitable_frameworks(with_coincidence,
                                          f"<title>{CONTROL}</title>{TRACE}") == []


def test_control_value_contains_no_digits():
    """The control's whole argument is that it cannot produce the value."""
    assert not any(ch.isdigit() for ch in CONTROL)
    assert "{" not in CONTROL and "<" not in CONTROL


# ---------------------------------------------------------------- finding --

def test_finding_carries_a_confidence_and_an_honest_evidence_line():
    """`confidence` used to be absent -> null in the JSON report.

    Phase 198 recorded the same defect class for the polyglot fallback: a
    layer that appends Finding(...) itself bypasses ``_record``, so any key it
    forgets reaches consumers as None.
    """
    def page(params, data):
        v = _sent_value(params, data)
        return f"<div>{v.replace('{{7*7}}', '49')}</div>"

    sc = _scanner()
    findings = _run_layer(sc, _RecordingRequester(page))
    assert len(findings) == 1
    f = findings[0]
    assert f.data["confidence"] in ("medium", "firm", "high")
    assert "control" in f.data["evidence"]
    assert "rendered to 49" not in f.data["evidence"], \
        "the evidence line must describe what was measured, not a hardcoded claim"
