"""Phase 288: the archive (zip-slip) write carrier on scan_stored_dom.

Pure-logic tests: a fake host (the StoredBlindMixin needs req / _add /
_bump / coverage / verbose), a recording requester that captures the
multipart ``files=`` payload, and a fake DOM engine replaying analyze()
results.  No network, no subprocess, no Playwright.

Locks the contract the OWASP Juice Shop challenge #4 flow depends on
(measured live 2026-10-21, dev/_p287_row4.py):
  * the write becomes a real multipart ZIP upload whose single entry is
    the operator-given traversal path VERBATIM (``../`` intact),
  * the multipart filename stays clean -- the traversal lives only in
    the entry name, so nothing depends on how requests encodes ``../``,
  * the payload is the FILE's bytes (first probe = the ``</script>``
    breakout shape, because the target inlines the file into HTML),
  * companion --stored-extra fields ride as form data alongside the file,
  * archive mode REPLACES the form/JSON body writes (a zip endpoint does
    not parse them) and never fires without the opt-in flag,
  * the emitted finding records the carrier (param ``<field>[content]``,
    proof.archive_entry) and is graded browser-executed on a dialog hit.
"""
from __future__ import annotations

import io
import zipfile

from xssentinel.core.scanner_stored import (StoredBlindMixin,
                                            _ARCHIVE_BREAKOUT_BASE,
                                            _build_archive_zip)

DIALOG_HIT = [{"sink": "dialog", "snippet": "alert('xssv_tok')"}]


class _FakeEngine:
    def __init__(self, hits):
        self._hits = hits
        self.calls = []

    def available(self):
        return True

    def analyze(self, url, marker=None, dialog_token=None,
                click_selector=None, url_probes=True):
        self.calls.append((url, marker, dialog_token, url_probes))
        return list(self._hits)


class _FakeCoverage:
    def touch_layer(self, *a, **k):
        pass


class _RecordingReq:
    """Requester stand-in that keeps the multipart ``files=`` payload."""

    def __init__(self):
        self.calls = []

    def request(self, method, url, params=None, data=None, json=None,
                files=None, headers=None):
        self.calls.append({"method": method, "url": url, "data": data,
                           "json": json, "files": files,
                           "headers": headers})
        return object()  # truthy response stand-in

    def invalidate(self, url):
        pass


class _Host(StoredBlindMixin):
    def __init__(self, engine):
        self.req = _RecordingReq()
        self.engine = engine
        self.findings = []
        self.verbose = False
        self.max_payloads = 5
        self.max_transforms = 3
        self.coverage = _FakeCoverage()
        self.auth_headers: dict = {}
        self.auth_cookies: list = []
        self.auth_local_storage: dict = {}

    def _add(self, finding):
        self.findings.append(finding)

    def _bump(self):
        pass

    def _resolve_dom_engine(self):
        return self.engine


def _uploaded_zips(req):
    """[(field, multipart_filename, zipfile.ZipFile)] for every multipart
    call the recording requester saw."""
    out = []
    for c in req.calls:
        files = c.get("files") or {}
        for field, (fname, blob, mime) in files.items():
            assert mime == "application/zip"
            out.append((field, fname, zipfile.ZipFile(io.BytesIO(blob))))
    return out


# ---------------------------------------------------------------------------
# helper
# ---------------------------------------------------------------------------

def test_build_archive_zip_keeps_the_entry_name_verbatim():
    blob = _build_archive_zip("../../app/views/promo.pug", b"PAYLOAD")
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        assert z.namelist() == ["../../app/views/promo.pug"]
        assert z.read("../../app/views/promo.pug") == b"PAYLOAD"


# ---------------------------------------------------------------------------
# carrier behaviour
# ---------------------------------------------------------------------------

def test_archive_carrier_uploads_traversal_zip_and_confirms():
    eng = _FakeEngine(DIALOG_HIT)
    host = _Host(eng)
    ok = host.scan_stored_dom(
        "http://t/file-upload", view_url="http://t/promotion",
        param="file", archive_entry="../assets/promo_subtitle.vtt",
        extra_fields={"rating": "5"})
    assert ok is True
    assert len(host.findings) == 1
    f = host.findings[0].data
    assert f["type"] == "stored_dom"
    assert f["severity"] == "high" and f["confidence"] == "high"
    assert f["evidence_class"] == "browser-executed"
    assert f["headless"]["outcome"] == "fired"
    # the carrier is recorded, not the text param that was never sent
    assert f["param"] == "file[content]"
    assert f["proof"]["archive_entry"] == "../assets/promo_subtitle.vtt"
    assert "archive upload" in f["detail"]

    zips = _uploaded_zips(host.req)
    assert zips, "no multipart upload was sent"
    field, fname, z = zips[0]
    assert field == "file"
    # the traversal lives ONLY in the entry name; the multipart filename
    # stays clean (Juice Shop measurement: the extractor never sees the
    # multipart layer's encoding of ``../`` because it is not there).
    assert ".." not in fname and "/" not in fname
    assert z.namelist() == ["../assets/promo_subtitle.vtt"]
    entry = z.read("../assets/promo_subtitle.vtt").decode("utf-8")
    token = f["proof"]["token"]
    assert token in entry
    # companion fields ride as form data alongside the file
    first = host.req.calls[0]
    assert first["data"] == {"rating": "5"}
    # a zip endpoint does not parse a form/JSON body: the archive carrier
    # REPLACES the body writes, so no json= write ever happens.
    assert all(c["json"] is None for c in host.req.calls)


def test_first_archive_probe_is_the_breakout_shape():
    """The file the target inlines into HTML only executes through a
    ``</script>`` breakout, so that shape is probed FIRST (the corpus has
    no such base -- Phase 288 comment in scanner_stored.py)."""
    eng = _FakeEngine(DIALOG_HIT)
    host = _Host(eng)
    host.scan_stored_dom("http://t/file-upload",
                         view_url="http://t/promotion", param="file",
                         archive_entry="../assets/promo_subtitle.vtt")
    zips = _uploaded_zips(host.req)
    assert zips, "no multipart upload was sent"
    _field, _fname, z = zips[0]
    entry = z.read(z.namelist()[0]).decode("utf-8")
    assert entry.startswith("</script><script>alert(")
    # and the constant the loop prepends is that same shape
    assert _ARCHIVE_BREAKOUT_BASE["payload"].startswith("</script>")


def test_no_archive_flag_never_uploads_files():
    """Default behaviour is byte-identical: without the opt-in flag the
    stored-DOM flow never sends a multipart body."""
    eng = _FakeEngine(DIALOG_HIT)
    host = _Host(eng)
    host.scan_stored_dom("http://t/write", view_url="http://t/view",
                         param="comment")
    assert host.findings, "sanity: the plain flow still confirms"
    assert all(c["files"] is None for c in host.req.calls)


def test_custom_file_field_is_used():
    eng = _FakeEngine(DIALOG_HIT)
    host = _Host(eng)
    host.scan_stored_dom("http://t/file-upload",
                         view_url="http://t/promotion", param="file",
                         archive_entry="../x.vtt", file_field="attachment")
    zips = _uploaded_zips(host.req)
    assert zips and zips[0][0] == "attachment"
    f = host.findings[0].data
    assert f["param"] == "attachment[content]"


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------

def test_cli_parses_archive_flags():
    from xssentinel.__main__ import build_parser
    args = build_parser().parse_args([
        "--stored-inject", "http://t/file-upload",
        "--stored-view", "http://t/promotion",
        "--stored-dom",
        "--stored-archive-entry", "../assets/promo_subtitle.vtt",
        "--stored-file-field", "attachment",
    ])
    assert args.stored_archive_entry == "../assets/promo_subtitle.vtt"
    assert args.stored_file_field == "attachment"
    # defaults: unset entry, field name "file"
    args2 = build_parser().parse_args(["--stored-inject", "http://t/w"])
    assert args2.stored_archive_entry is None
    assert args2.stored_file_field == "file"
