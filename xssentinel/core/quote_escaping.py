# -*- coding: utf-8 -*-
"""Single definition of the addslashes / quote-escaping probe contract.

Both pipelines used to hand-write the same two tokens, the same probe
payload and the same response regex.  A drift in either copy silently
changes what "quote escaping" means in one engine only -- the "same
contract written twice" family this repo keeps getting caught by.

I/O deliberately stays in each engine (sync uses ``Requester``, async uses
``aiohttp`` behind a semaphore/throttle).  Only the bytes we send and the
rule that reads them live here, so neither side can re-interpret them.
"""
from __future__ import annotations

import re
import secrets


def build_quote_probe():
    """Return ``(t1, t2, payload)`` for one addslashes probe.

    Two distinct tokens let a single-quoted and a double-quoted shape be
    told apart in the response; :func:`quote_escaping_detected` checks both.
    """
    t1 = "xssq_" + secrets.token_hex(3)
    t2 = "xssq_" + secrets.token_hex(3)
    payload = "<script>alert('%s');alert(\"%s\")</script>" % (t1, t2)
    return t1, t2, payload


def quote_escaping_detected(text, t1, t2):
    """True when the response shows a backslash inserted before a quote.

    ``addslashes`` puts a literal backslash before the quote, turning
    ``alert('tok')`` into a JS syntax error, while the unquoted /
    double-quoted / backtick shapes still execute.  The signal is that
    literal backslash measured on the raw response text, bound to *our*
    tokens -- not a guess about the filter's name and not a page feature.
    """
    text = text or ""
    return bool(re.search(r"\\+['\"]" + re.escape(t1), text)
                or re.search(r"\\+['\"]" + re.escape(t2), text))
