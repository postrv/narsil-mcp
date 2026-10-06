# quick-xml applicability review for the 1.7.1 candidate

Reviewed on 2026-10-06. `quick-xml 0.37.5` remains an affected dependency.
The two exceptions in `.cargo/audit.toml` record unreachable affected parsing
paths in Narsil's current public API and binaries; they do not assert that the
dependency has been patched.

## Dependency and upstream status

The candidate resolves these paths:

- `oxigraph 0.5.8 -> oxrdfio 0.2.5 -> oxrdfxml 0.2.3 -> quick-xml 0.37.5`
- `oxigraph 0.5.8 -> sparesults 0.3.3 -> quick-xml 0.37.5`, also through
  `spareval 0.2.6`.

[RUSTSEC-2026-0194](https://rustsec.org/advisories/RUSTSEC-2026-0194.html)
concerns duplicate-attribute checking in XML readers.
[RUSTSEC-2026-0195](https://rustsec.org/advisories/RUSTSEC-2026-0195.html)
concerns namespace allocation in `NsReader`. Both are fixed in quick-xml
0.41.0. Neither advisory lists a CVE alias in the reviewed RustSec data.

The published Oxigraph 0.5.11 family still requires quick-xml `^0.37` in
oxrdfxml and sparesults, so a compatible lockfile update cannot select the fix.
Oxigraph's unreleased 0.6 development line includes the
[upgrade to quick-xml 0.41](https://github.com/oxigraph/oxigraph/commit/e115a6a8dd9213fdf89a20cb72494ab333878218).
That git dependency cannot provide a normal crates.io release dependency until
the corresponding crates are published. The fixed quick-xml MSRV (Rust 1.86)
is below the existing Oxigraph requirement (Rust 1.87).

## Reachability boundary

`KnowledgeGraph` in `src/persistence/graph.rs` owns a private Oxigraph store.
It exposes no raw store, parser, or configurable-format getter. Its only RDF
input methods, `load_ontology` and `import_turtle`, explicitly select
`RdfFormat::Turtle`. Its serializers select Turtle or N-Quads. CCG inputs use
JSON deserialization or decompressed N-Quads text, without an XML parser.

`query` and `ask` parse SPARQL queries and consume in-process result objects.
They do not accept SPARQL XML results. Both install `LocalOnlyServiceHandler`,
which rejects every external SERVICE evaluation. This replaces Oxigraph's
default service handler and prevents network/result-parser fallback even if
downstream Cargo feature unification enables `oxigraph/http-client`.

This explicit handler matters for the library: without it, an HTTP-enabled
downstream build could select sparesults' XML reader through remote SERVICE
results. Disabling HTTP only in the normal release feature set would not be a
sufficient library-wide argument. sparesults uses the plain XML reader rather
than `NsReader`; the namespace-allocation advisory additionally requires the
RDF/XML path in oxrdfxml, which Narsil does not expose.

## Regression and review requirements

The `test_external_service_query_is_rejected` and
`test_external_service_ask_is_rejected` unit tests exercise a benign URN service
name and require Narsil's rejection. They make no network request. Verify both
the usual graph build and a build with downstream HTTP feature unification:

```sh
cargo test --locked --features graph test_external_service -- --test-threads=1
cargo test --locked --features graph,oxigraph/http-client test_external_service -- --test-threads=1
```

Existing local-query tests remain in the full `native,neural,graph` suite.
The release workflow also runs the HTTP-feature regression.

Re-review these exceptions whenever graph input formats, exposed graph handles,
SERVICE handlers, or dependency versions change. Remove the exceptions after
upgrading to a compatible published Oxigraph family resolving quick-xml 0.41
or newer. The exceptions apply only to these two advisory IDs; other advisories
continue to fail `cargo audit`. Embedding applications that directly use their
own Oxigraph parsers or evaluators must assess those separate entrypoints.
