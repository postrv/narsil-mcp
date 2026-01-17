# CCG Example Files

This directory contains example Code Context Graph (CCG) files demonstrating each layer of the CCG specification.

## Files

| File | Layer | Format | Purpose |
|------|-------|--------|---------|
| `layer0-manifest.json` | L0 | JSON-LD | Repository overview (~2 KB) |
| `layer1-architecture.json` | L1 | JSON-LD | Module structure and public API (~20 KB) |
| `layer2-symbol-index.nq` | L2 | N-Quads | All symbols and call graph (~500 KB typical) |
| `layer3-full-detail.nq` | L3 | N-Quads | Security findings, taint flows, source snippets |

## Layer Hierarchy

```
L0: Manifest (JSON-LD, ~1-2 KB)
 |  - Repository identity
 |  - Symbol counts
 |  - Security summary
 |  - Layer URLs
 |
L1: Architecture (JSON-LD, ~10-50 KB)
 |  - Module hierarchy
 |  - Public API surface
 |  - Dependency graph
 |  - Detected patterns
 |
L2: Symbol Index (N-Quads gzipped, ~100-500 KB)
 |  - All symbol definitions
 |  - Full call graph
 |  - Type relationships
 |  - Complexity metrics
 |
L3: Full Detail (N-Quads gzipped, ~1-20 MB)
    - Everything from L2
    - Security findings
    - Taint analysis
    - Data flow graphs
    - Source snippets
```

## Usage

### Viewing JSON-LD Layers

```bash
# Pretty print Layer 0
cat layer0-manifest.json | jq .

# Pretty print Layer 1
cat layer1-architecture.json | jq .
```

### Querying RDF Layers

The N-Quads files can be loaded into any RDF triplestore:

```bash
# Using Oxigraph
oxigraph load --file layer2-symbol-index.nq --location /tmp/ccg-db

# Query with SPARQL
oxigraph query --location /tmp/ccg-db --query "
  PREFIX narsil: <https://narsilmcp.com/ontology/v1#>
  SELECT ?fn ?complexity WHERE {
    ?fn a narsil:Method ;
        narsil:complexity ?complexity .
    FILTER(?complexity > 5)
  }
"
```

### Using with narsil-mcp

```bash
# Export CCG for a repository
narsil-mcp --repos ./myproject --graph export_ccg

# Query the CCG with SPARQL
narsil-mcp query_ccg --query "
  SELECT ?finding ?severity WHERE {
    ?finding a narsil:Vulnerability ;
             narsil:severity ?severity .
    FILTER(?severity = 'HIGH')
  }
"
```

## Layer Selection Guide

| Query Type | Layers | Why |
|------------|--------|-----|
| "What does this repo do?" | L0 + L1 | Overview and architecture |
| "Show me the public API" | L0 + L1 | `publicAPI` in L1 |
| "What calls function X?" | L0 + L2 | Call graph edges in L2 |
| "Are there security issues?" | L0 | Summary in `security` |
| "Explain vulnerability at Y:Z" | L0 + L3 | Full finding details |
| "Show taint flow" | L3 | Taint analysis data |

## Production Notes

In production:
- L2 and L3 files are **gzipped** (`.nq.gz`)
- Files are served from `codecontextgraph.com/ccg/...`
- Access is controlled via WebACL (Triple-Heart Model)

## See Also

- [CCG Specification v0.2](../../docs/ccg-spec.md)
- [JSON-LD Schema](../../schema/ccg-v1.json)
- [Narsil Ontology](../../ontology/narsil.ttl)
- [CCG Access Control Ontology](../../ontology/ccg-acl.ttl)
