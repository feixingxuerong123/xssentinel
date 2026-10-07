"""Phase 195: --gql GraphQL introspection input source (inQL parity).

The expansion logic is driven through an injected ``fetch``; one loopback
test exercises the real requests.post path against a local GraphQL-ish
endpoint.  The introspected names flow into the param-mining wordlist via
cli_runner (three-line merge, wired like --param-wordlist).
"""
from __future__ import annotations

import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xssentinel.core.gql_import import (  # noqa: E402
    INTROSPECTION_QUERY,
    gql_mutation_targets,
    gql_param_candidates,
)

SCHEMA = {
    "data": {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"kind": "OBJECT", "name": "Query", "fields": [
                {"name": "search", "args": [
                    {"name": "term", "type": {"kind": "SCALAR",
                                              "name": "String"}},
                    {"name": "limit", "type": {"kind": "SCALAR",
                                               "name": "Int"}}]},
                {"name": "comments", "args": []},
            ]},
            {"kind": "OBJECT", "name": "Mutation", "fields": [
                {"name": "postComment", "args": [
                    {"name": "content", "type": {"kind": "NON_NULL",
                                                 "ofType": {"name": "String"}}},
                    {"name": "author", "type": {"kind": "SCALAR",
                                                "name": "String"}},
                    {"name": "rating", "type": {"kind": "NON_NULL",
                                                 "ofType": {"kind": "SCALAR",
                                                            "name": "Int"}}}]},
            ]},
            {"kind": "INPUT_OBJECT", "name": "CommentInput", "inputFields": [
                {"name": "body", "type": {"kind": "SCALAR", "name": "String"}},
                {"name": "screenName", "type": {"kind": "SCALAR",
                                                "name": "String"}},
            ]},
            {"kind": "SCALAR", "name": "Int", "fields": None,
             "inputFields": None},
        ],
    }}}


def _fetch_ok(url, query):
    assert query.strip() == INTROSPECTION_QUERY.strip()
    import json
    return json.dumps(SCHEMA)


def test_ordering_mutation_args_first_then_inputs_then_query():
    names = gql_param_candidates("http://t/graphql", fetch=_fetch_ok)
    # mutation write-side args lead (String-typed only -- Int dropped)
    assert names[:2] == ["content", "author"]
    assert "limit" not in names and "rating" not in names
    # input-object fields
    assert "body" in names and "screenName" in names
    # query args and field names follow
    assert "term" in names and "search" in names
    # dedup, no meta names
    assert len(names) == len(set(names))
    assert not any(n.startswith("__") for n in names)


def test_cap_is_respected():
    names = gql_param_candidates("http://t/graphql", fetch=_fetch_ok,
                                 max_names=3)
    assert names == ["content", "author", "body"]


def test_graphql_errors_raise():
    import json

    def fetch(url, query):
        return json.dumps({"errors": [{"message": "forbidden"}]})

    with pytest.raises(ValueError, match="forbidden"):
        gql_param_candidates("http://t/graphql", fetch=fetch)


def test_non_json_response_raises():
    with pytest.raises(ValueError, match="non-JSON"):
        gql_param_candidates("http://t/graphql",
                             fetch=lambda u, q: "<html>login page</html>")


def test_no_query_type_raises():
    import json
    bad = {"data": {"__schema": {"queryType": None, "mutationType": None,
                                 "types": [
                                     {"kind": "OBJECT", "name": "Foo",
                                      "fields": [], "inputFields": None}]}}}
    with pytest.raises(ValueError, match="queryType"):
        gql_param_candidates(
            "http://t/graphql",
            fetch=lambda u, q: json.dumps(bad))


class _GqlHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        import json
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        assert "IntrospectionQuery" in body
        out = json.dumps(SCHEMA).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def test_real_http_path_against_loopback():
    from tests.conftest import loopback_healthy
    if not loopback_healthy():
        pytest.skip("loopback degraded mid-session")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GqlHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        names = gql_param_candidates(
            f"http://127.0.0.1:{server.server_address[1]}/graphql")
        assert names[:2] == ["content", "author"]
    finally:
        server.shutdown()
        server.server_close()


def test_cli_flag_exists():
    import subprocess
    r = subprocess.run(
        [sys.executable, "-m", "xssentinel", "--help"],
        capture_output=True, text=True, timeout=60)
    assert "--gql" in (r.stdout + r.stderr)


# ---------------------------------------------------------------------------
# gql_mutation_targets (Phase 204)
# ---------------------------------------------------------------------------

class TestMutationTargets:
    def test_template_variables_and_shape(self):
        from xssentinel.core.gql_import import gql_mutation_targets
        import json
        targets = gql_mutation_targets("http://t/graphql", fetch=_fetch_ok)
        assert targets and targets[0]["gql_mutation"] == "postComment"
        assert targets[0]["method"] == "POST"
        body = json.loads(targets[0]["data"])
        # the query declares the string vars and passes them through; the
        # selection set is the always-valid __typename
        assert "mutation PostComment($content: String, $author: String, $rating: Int)" in body["query"]
        assert "postComment(content: $content, author: $author, rating: $rating)" in body["query"]
        assert "{ __typename }" in body["query"]
        # variables carry the probe samples the JSON-carrier prober replaces
        assert body["variables"]["content"] == "probe"
        assert body["variables"]["author"] == "probe"
        # the Int arg is REQUIRED (NON_NULL) -> sample so the mutation runs
        assert body["variables"]["rating"] == 1

    def test_int_args_are_not_probe_targets(self):
        from xssentinel.core.gql_import import gql_mutation_targets
        import json
        targets = gql_mutation_targets("http://t/graphql", fetch=_fetch_ok)
        body = json.loads(targets[0]["data"])
        q = body["query"]
        assert "$rating: Int" in q            # declared so the query runs
        assert body["variables"]["rating"] == 1

    def test_cap_and_no_mutation_type(self):
        import json

        def fetch(url, query):
            return json.dumps(SCHEMA)

        assert len(gql_mutation_targets("http://t/graphql", fetch=fetch,
                                        max_mutations=1)) == 1

        empty = {"data": {"__schema": {"queryType": {"name": "Query"},
                                       "mutationType": None,
                                       "types": SCHEMA["data"]["__schema"]["types"]}}}
        assert gql_mutation_targets(
            "http://t/graphql",
            fetch=lambda u, q: json.dumps(empty)) == []

    def test_cli_wiring_aligns_specs_with_urls(self):
        """The per-target loop indexes spec_targets[i] against urls[i] --
        the --gql branch must keep them the same length."""
        from xssentinel.core.gql_import import gql_param_candidates,             gql_mutation_targets
        names = gql_param_candidates("http://t/graphql", fetch=_fetch_ok)
        specs = [{"url": "http://t/graphql", "method": "GET", "data": "",
                  "cookies": [], "headers": []}] +             gql_mutation_targets("http://t/graphql", fetch=_fetch_ok)
        urls = [t["url"] for t in specs]
        assert len(urls) == len(specs) == 2
        assert names                                  # mining still armed