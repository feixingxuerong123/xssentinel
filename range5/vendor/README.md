# range5 vendored framework bundles

Upstream release tarballs pulled from `registry.npmjs.org` (unpkg is
unreachable from the author's host).  Vendored so the range runs
offline and in CI without a package manager.

Fetched by `dev/fetch_range5_vendor.py`.

| npm package | version | directory | files |
|---|---|---|---|
| `lit` | 3.3.3 | `vendor/lit/` | 39 |
| `lit-html` | 3.3.3 | `vendor/lit-html/` | 61 |
| `lit-element` | 4.2.2 | `vendor/lit-element/` | 15 |
| `@lit/reactive-element` | 2.1.2 | `vendor/reactive-element/` | 30 |
