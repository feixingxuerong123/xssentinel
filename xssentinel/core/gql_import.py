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

__all__ = ["gql_param_candidates", "gql_mutation_targets",
           "INTROSPECTION_QUERY"]

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


def _introspect(endpoint: str, timeout: int, fetch=None) -> dict:
    """One introspection round-trip -> the ``__schema`` dict.

    Raises on unreachable endpoints, non-JSON responses, GraphQL-level
    errors, or a schema without types.  Shared by the wordlist and the
    mutation-target builders so one request serves both.
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
    if not (schema.get("types") or []):
        raise ValueError("GraphQL response has no __schema.types")
    return schema


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
    schema = _introspect(endpoint, timeout, fetch)
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


def _arg_type(t: dict) -> tuple[str, bool]:
    """Peel wrappers -> (leaf type name, is_non_null)."""
    non_null = False
    while isinstance(t, dict):
        if t.get("kind") == "NON_NULL":
            non_null = True
        if t.get("name"):
            return str(t["name"]), non_null
        t = t.get("ofType")
    return "", non_null


_SAMPLES = {"Int": 1, "Float": 1.0, "Boolean": True}


def gql_mutation_targets(endpoint: str, timeout: int = 15,
                         max_mutations: int = 25, fetch=None) -> list[dict]:
    """Introspect ``endpoint`` -> one scan-target spec per string-arg mutation.

    Modern GraphQL carries arguments in a plain ``variables`` JSON object,
    which is exactly the JSON-carrier mode the scanner already probes
    leaf-by-leaf (``json_leaf_paths`` / ``_set_json_leaf``): each emitted
    target's body is ``{"query": <template with $vars>, "variables":
    {arg: sample}}`` and the L1 loop injects the full payload ladder into
    every String/ID leaf -- no GraphQL-specific injection machinery
    needed.

    The query template declares every REQUIRED argument (with a
    type-appropriate sample, so the mutation actually executes) plus the
    optional String/ID arguments (the probe targets).  The selection set
    is ``{ __typename }`` -- valid on every object return type without
    knowing the schema's shape.

    Returns scan-target dicts aligned with the cli_runner spec format
    (url/method/data/cookies/headers); ``data`` is the JSON string (the
    CLI's ``_run_scan`` auto-parses `{`-leading bodies into JSON-carrier
    mode).  Capped at ``max_mutations``, deduped by field name.
    """
    schema = _introspect(endpoint, timeout, fetch)
    types = schema.get("types") or []
    by_name = {t.get("name"): t for t in types
               if isinstance(t, dict) and t.get("name")}
    mut_name = (schema.get("mutationType") or {}).get("name")
    if not mut_name:
        return []
    mut_type = by_name.get(mut_name) or {}

    targets: list[dict] = []
    seen: set[str] = set()
    for field in (mut_type.get("fields") or []):
        fname = str(field.get("name") or "")
        if not fname or fname.startswith("__") or fname in seen:
            continue
        args = field.get("args") or []
        string_args = [a for a in args
                       if _arg_type(a.get("type") or {})[0]
                       in ("String", "ID", "JSON")]
        if not string_args:
            continue                      # nothing probeable to inject
        seen.add(fname)

        var_defs: list[str] = []
        passthrough: list[str] = []
        variables: dict = {}
        for a in args:
            aname = str(a.get("name") or "")
            leaf, non_null = _arg_type(a.get("type") or {})
            if leaf in ("String", "ID", "JSON"):
                var_defs.append(f"${aname}: "
                                f"{'String' if leaf == 'JSON' else leaf}")
                passthrough.append(f"{aname}: ${aname}")
                variables[aname] = "probe"
            elif non_null:
                # required non-string args get type-appropriate samples so
                # the mutation executes and the string probes are reached
                sample = _SAMPLES.get(leaf)
                if sample is None:
                    sample = "{}" if leaf not in _BUILTIN_TYPES else ""
                if sample == "" and non_null:
                    # an unknown required scalar we cannot fabricate --
                    # skip the whole mutation rather than ship a query
                    # that can only error
                    break
                var_defs.append(f"${aname}: {leaf}")
                passthrough.append(f"{aname}: ${aname}")
                variables[aname] = sample
        if not variables:
            continue
        if any(a[0] not in variables for a in
               [(str(a.get("name") or ""), ) for a in args
                if _arg_type(a.get("type") or {})[1]
                and str(a.get("name") or "") not in variables]):
            # a required argument we could not sample -- the template would
            # be rejected server-side before any probe lands
            continue

        template = (f"mutation {fname[0].upper()}{fname[1:]}("
                    + ", ".join(var_defs)
                    + f") {{ {fname}(" + ", ".join(passthrough)
                    + ") { __typename } }")
        targets.append({
            "url": endpoint,
            "method": "POST",
            "data": json.dumps({"query": template,
                                "variables": variables},
                               ensure_ascii=False),
            "cookies": [],
            "headers": [],
            "gql_mutation": fname,
        })
        if len(targets) >= max_mutations:
            break
    return targets
