"""Credential egress guard: operator secrets never follow a page-chosen redirect.

Measured on this machine (requests 2.32.5 / urllib3 2.6.3 / aiohttp 3.13.3),
not assumed from the spec:

* A 302 to another host *does* drop ``Authorization`` and a header-named
  ``Cookie`` -- but only because urllib3 compares **host strings**, so
  ``localhost -> 127.0.0.1`` counts as cross-host while
  ``host:8080 -> host:9090`` does not.
* A custom ``X-Api-Key`` header reaches the redirect target intact.
* A cookie the operator passed to ``--cookie`` (no domain) reaches it intact too.
* aiohttp forwards both headers *and* jar cookies, unconditionally.

So a scanned page picks which origins receive the operator's credentials --
the same class of defect as the one disclosed for Dalfox as
GHSA-mph2-gf5w-6f9f ("a scanned page could choose where Dalfox sent the
operator's -H headers and --cookies").  The page under test is by definition
not the party to trust with them.

Policy, one rule for both engines: **credentials ride only on origins the
operator named.** Every top-level request names its origin; a hop reached
only because a response said ``Location:`` does not, and arrives without
them.  Same-origin redirects are untouched, which is the overwhelming
majority in practice (apps redirect within themselves).  Browser-shaped
headers (User-Agent, Accept, sec-fetch-*) survive cross-origin so a chain
still looks like a browser rather than like a scanner.

Detection semantics are untouched: the redirect is followed and its body
parsed exactly as before -- only the credential material is withheld.
"""
from __future__ import annotations

import threading
from urllib.parse import urlparse

# Never sent cross-origin, whoever set them: they exist to authenticate.
CREDENTIAL_HEADERS = frozenset({
    "authorization", "cookie", "proxy-authorization", "x-api-key", "api-key",
    "x-auth-token", "x-access-token", "x-csrf-token", "x-xsrf-token", "token",
})

# Operator headers that are NOT credentials: withholding them from a redirect
# would change how the hop looks to the server (a missing User-Agent is a
# scanner tell) without protecting anything.
BROWSER_SHAPED_HEADERS = frozenset({
    "user-agent", "accept", "accept-language", "accept-encoding",
    "accept-datetime", "cache-control", "connection", "content-length",
    "content-type", "dnt", "te", "transfer-encoding",
    "upgrade-insecure-requests", "sec-ch-ua", "sec-ch-ua-mobile",
    "sec-ch-ua-platform", "sec-fetch-dest", "sec-fetch-mode",
    "sec-fetch-site", "sec-fetch-user",
})

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def origin(url) -> tuple:
    """Normalize a URL to the (scheme, host, port) tuple browsers call an origin.

    Returns ``()`` for anything without a host (a bare path, ``file:``, a
    malformed URL); callers treat that as "cannot compare".
    """
    try:
        parts = urlparse(str(url))
    except (ValueError, TypeError):
        return ()
    host = (parts.hostname or "").lower()
    if not host:
        return ()
    scheme = (parts.scheme or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is None:
        port = _DEFAULT_PORTS.get(scheme, 0)
    return (scheme, host, port)


def same_origin(a, b) -> bool:
    """Whether two URLs share an origin.

    Unparseable input counts as same-origin: a guard that scrubbed on
    "unknown" would drop credentials from ordinary requests it cannot
    classify, which is a false-negative generator, not a security win.
    """
    oa, ob = origin(a), origin(b)
    if not oa or not ob:
        return True
    return oa == ob


class EgressPolicy:
    """Track which origins the operator named, and strip secrets from the rest."""

    def __init__(self, operator_headers=None, extra_secrets=None,
                 stop_at_boundary: bool = False):
        secrets = set(CREDENTIAL_HEADERS)
        for name in operator_headers or ():
            if name.lower() not in BROWSER_SHAPED_HEADERS:
                secrets.add(name.lower())
        secrets.update(n.lower() for n in (extra_secrets or ()))
        self.secrets = frozenset(secrets)
        # Opt-in authorization boundary: do not FOLLOW a redirect that leaves a
        # named origin at all.  Without it the guard only withholds credentials
        # and the payloads still reach a host nobody scoped -- which is the
        # other half of "only test what you were authorized to test".
        self.stop_at_boundary = bool(stop_at_boundary)
        #: Redirect targets the boundary refused (reported, never silent).
        self.boundary_stops: list = []
        # Origins named by a top-level request.  Lock-guarded: the sync engine
        # scans with N threads over clones that share one policy instance.
        self._explicit = set()
        self._lock = threading.Lock()
        #: Hops that arrived without credentials because of this guard.
        self.blocks = 0

    def note(self, url) -> None:
        """Record that the operator -- not a ``Location:`` header -- named this origin."""
        org = origin(url)
        if org:
            with self._lock:
                self._explicit.add(org)

    def is_named(self, url) -> bool:
        """Whether credentials may go to ``url``'s origin.

        Unknown/unparseable origins pass (see :func:`same_origin`).  Before any
        origin has been named the guard is inert -- a caller that issues
        requests without going through :meth:`note` must not have its headers
        eaten by an empty allowlist.
        """
        org = origin(url)
        if not org:
            return True
        with self._lock:
            return not self._explicit or org in self._explicit

    def scrub(self, headers, url) -> list:
        """Take every credential header off ``headers`` if ``url`` is unnamed.

        ``headers`` is mutated in place (requests' CaseInsensitiveDict and
        aiohttp's CIMultiDict both support ``del``).  Returns the names
        removed; ``[]`` means the origin was named and nothing moved.
        """
        if self.is_named(url):
            return []
        removed = [name for name in list(headers) if name.lower() in self.secrets]
        for name in removed:
            del headers[name]
        if removed:
            self.blocks += 1
        return removed

    def note_stop(self, url) -> str:
        """Record a redirect the authorization boundary refused to follow."""
        target = str(url)
        if len(self.boundary_stops) < 20 and target not in self.boundary_stops:
            self.boundary_stops.append(target)
        return target
