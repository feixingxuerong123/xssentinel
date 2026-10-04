"""GraphQL introspection input-source (Phase 195, absorbed from the inQL /
Graphw00py recon step).

``--gql ENDPOINT`` introspects a GraphQL API and turns the schema into
what an XSS scanner actually needs: NAMES.  The argument names of
mutations (``comment``, ``author``, ``content``, ...) and the input-field
names of their input objects are exactly the parameters the application
later renders -- the same names the param miner brute-guesses from a
static 313-word list.  Introspection hands them to us for free, so they
are merged into the mining wordlist and the endpoint itself becomes a
scan target.

Scope discipline mirrors the other imports: the operator named the
endpoint; the introspection response contains no URLs to probe, so there
is nothing to partition -- the endpoint's own host is the authorization.

Boundaries: the response is untrusted JSON parsed with the stdlib parser;
caps bound the collected names; GraphQL ``errors`` responses raise rather
than yield an empty list (callers surface the error, same as the HAR
importer).
"""
from __future__ import annotations

import json

__all__ = ["gql_param_candidates", "INTROSPECTION_QUERY"]

_MAX_RESPONSE = 8 * 1024 * 1024

# Standard introspection, bounded to what we read: type names, fields,
# args and inputFields with their leaf type names.  No descriptions, no
# deprecation data, no enums' values.
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind
      name
      fields {
        name
        args { name type { kind name ofType { kind name ofType { name } } } }
      }
      inputFields { name type { kind name ofType { kind name } } }
    }
  }
}
"""

_META_PREFIX = "__"
_BUILTIN_TYPES = {
    "String", "Int", "Float", "Boolean", "ID", "Date", "DateTime",
    "JSON", "Upload", "BigInt", "Byte", "Time", "Cursor",
}


def _leaf_type_name(t: dict) -> str:
    """Peel NON_NULL/LIST wrappers down to the leaf type's name."""
    while isinstance(t, dict):
        if t.get("name"):
            return str(t["name"])
        t = t.get("ofType")
    return ""


def _string_scalar(t: dict) -> bool:
    """True when the argument accepts plain strings (String/ID/JSON...)."""
    name = _leaf_type_name(t)
    return (name in ("String", "ID", "JSON") or name not in _BUILTIN_TYPES
            and name != "")


def gql_param_candidates(endpoint: str, timeout: int = 15,
                         max_names: int = 200, fetch=None) -> list[str]:
    """Introspect ``endpoint`` -> ordered, deduped parameter-name candidates.

    Order encodes yield: mutation arguments first (they are WRITE
    injection points), then input-object fields, then query arguments,
    then plain field names.  Duplicates and GraphQL meta names
    (``__schema``) are dropped; the result is capped at ``max_names``.

    Raises on unreachable endpoints, non-JSON responses, GraphQL-level
    errors, or a schema without any query type.
    """
    if fetch is not None:                      # injectable for tests
        text = fetch(endpoint, INTROSPECTION_QUERY)
    else:
        import requests
        r = requests.post(
            endpoint, json={"query": INTROSPECTION_QUERY}, timeout=timeout,
            headers={"User-Agent": "xssentinel-gql/1.0",
                     "Content-Type": "application/json"},
            stream=True)
        r.raise_for_status()
        text = r.raw.read(_MAX_RESPONSE + 1, decode_content=True).decode(
            "utf-8", errors="replace")[:_MAX_RESPONSE]
    try:
        resp = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"GraphQL endpoint returned non-JSON: {e}") from e
    if not isinstance(resp, dict):
        raise ValueError("GraphQL response is not an object")
    if resp.get("errors") and not resp.get("data"):
        raise ValueError(f"GraphQL introspection failed: "
                         f"{resp['errors'][0].get('message', '?')[:200]}")
    data = resp.get("data") or {}
    schema = data.get("__schema") or {}
    types = schema.get("types") or []
    if not types:
        raise ValueError("GraphQL response has no __schema.types")

    by_name = {t.get("name"): t for t in types
               if isinstance(t, dict) and t.get("name")}
    mut_name = (schema.get("mutationType") or {}).get("name")
    qry_name = (schema.get("queryType") or {}).get("name")
    if not qry_name:
        raise ValueError("GraphQL schema has no queryType")

    def _args_of(type_name: str | None) -> list[str]:
        t = by_name.get(type_name) or {}
        out = []
        for f in (t.get("fields") or []):
            for a in (f.get("args") or []):
                if _string_scalar(a.get("type") or {}):
                    out.append(str(a.get("name") or ""))
        return out

    def _input_fields(type_name: str | None) -> list[str]:
        t = by_name.get(type_name) or {}
        if (t.get("kind") or "") != "INPUT_OBJECT":
            return []
        return [str(i.get("name") or "") for i in
                (t.get("inputFields") or [])]

    ordered: list[str] = []

    def _add(names) -> None:
        for n in names:
            if not n or n.startswith(_META_PREFIX) or n in ordered:
                continue
            ordered.append(n)

    # mutation arguments: the write-side injection points
    for t in types:
        if t.get("name") == mut_name and t.get("kind") == "OBJECT":
            for f in (t.get("fields") or []):
                _add([str(a.get("name") or "") for a in
                      (f.get("args") or [])
                      if _string_scalar(a.get("type") or {})])
    # input-object fields referenced anywhere
    for t in types:
        if t.get("kind") == "INPUT_OBJECT":
            _add(_input_fields(t.get("name")))
    # query arguments, then plain field names (weakest signal last)
    _add(_args_of(qry_name))
    for t in types:
        if t.get("name") == qry_name and t.get("kind") == "OBJECT":
            _add([str(f.get("name") or "") for f in
                  (t.get("fields") or [])])
    return ordered[:max_names]
