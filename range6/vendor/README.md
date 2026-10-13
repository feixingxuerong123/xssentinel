# range6 vendored builds

Pinned upstream releases, fetched from the npm registry tarballs recorded
in each version's `integrity.txt` (tarball URL + sha512 of the exact
bytes).  Only the browser build (`purify.min.js`) is kept -- the CJS/ES
entry points and the coverage build serve no purpose in a range whose
consumer is a browser.

| Version | Why it is here |
|---|---|
| `2.0.7` | **Vulnerable twin.** Last release before 2.0.8, i.e. inside CVE-2020-26870's range (mXSS: the sanitized output re-parses in the browser into a live element the sanitizer's tree never contained). Measured in Chromium: the namespace-confusion PoC produces a real dialog (`dev/_r6_mxss_premise.py`). |
| `3.4.17` | **Safe twin.** The vendor's current release at vendoring time; every published advisory in `core/sanitizer_bypass.py`'s table is closed by 3.4.16. The identical PoC is stripped (measured, same probe). |

Re-fetch reproducibly with `python dev/fetch_range6_vendor.py`; it
rewrites these directories and the integrity pins from the registry.

Do not copy these script tags into a real page: 2.0.7 is a known-vulnerable
build, and the tags deliberately carry no SRI so the range does not trip
`sri_bypass`'s cross-origin-script rule for unrelated reasons.
