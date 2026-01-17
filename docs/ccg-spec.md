# Code Context Graph (CCG) Specification v0.2

**Version:** 0.2
**Status:** Draft
**Date:** January 2026
**Namespace:** `https://codecontextgraph.com/`
**License:** CC BY 4.0

---

## 1. Introduction

### 1.1 Purpose

A Code Context Graph (CCG) is a standardized, multi-layer RDF dataset that encapsulates comprehensive code intelligence for a software repository. CCGs are designed to:

1. **Maximize context efficiency** for LLMs with limited context windows
2. **Enable AI agent interoperability** through semantic RDF representation
3. **Support progressive detail retrieval** via a hierarchical layer architecture
4. **Provide machine-verifiable refactoring specifications** through CCG diffs

### 1.2 Design Principles

| Principle | Description |
|-----------|-------------|
| **Context-friendly** | Layer 0+1 always fits in LLM context windows (<50 KB) |
| **Progressive detail** | Retrieve only the layers needed for the task |
| **Semantic** | RDF/JSON-LD enables reasoning and cross-repo linking |
| **Compressible** | Gzip compression achieves ~10:1 ratio |
| **Queryable** | SPARQL queries against Layer 3 for complex analysis |
| **Access-controlled** | Triple-Heart Model for tiered access |

### 1.3 Terminology

| Term | Definition |
|------|------------|
| **CCG** | Code Context Graph - the complete multi-layer dataset |
| **Layer** | One of four hierarchical detail levels (L0-L3) |
| **Manifest** | Layer 0 - minimal repository metadata (~1-2 KB) |
| **Triple** | An RDF statement (subject, predicate, object) |
| **Named Graph** | An RDF graph with a URI identifier |
| **SPARQL** | Query language for RDF graphs |
| **Triple-Heart** | Three-tier access model (Public/Authenticated/Private) |

---

## 2. Layer Architecture

CCGs use a four-layer hierarchy to balance context efficiency with comprehensiveness:

```
+------------------------------------------------------------------+
|  LAYER 0: MANIFEST (~1-2 KB)           Always in context         |
|  - Repository identity                                            |
|  - Symbol and security summaries                                  |
|  - Layer URIs for progressive fetching                           |
+------------------------------------------------------------------+
|  LAYER 1: ARCHITECTURE (~10-50 KB)     Loaded by default         |
|  - Module/package hierarchy                                       |
|  - Public API surface                                             |
|  - Module dependency graph                                        |
+------------------------------------------------------------------+
|  LAYER 2: SYMBOL INDEX (~100-500 KB)   Selective retrieval       |
|  - All symbols with signatures                                    |
|  - Full call graph edges                                          |
|  - Complexity metrics                                             |
+------------------------------------------------------------------+
|  LAYER 3: FULL DETAIL (~1-20 MB)       SPARQL queries only       |
|  - Complete RDF dataset                                           |
|  - Source snippets                                                |
|  - Security findings with remediation                             |
|  - Data flow and taint analysis                                   |
+------------------------------------------------------------------+
```

### 2.1 Layer Size Estimates

| Repository Size | LOC | Triples (est.) | L0 | L1 | L2 | L3 (gzipped) |
|-----------------|-----|----------------|-----|-----|------|--------------|
| Tiny | 1K | 500 | 2 KB | 15 KB | 8 KB | 5 KB |
| Small | 5K | 2,500 | 2 KB | 17 KB | 26 KB | 25 KB |
| Medium | 50K | 25,000 | 2 KB | 50 KB | 79 KB | 250 KB |
| Large | 200K | 100,000 | 2 KB | 50 KB | 315 KB | 1 MB |
| Very Large | 1M | 500,000 | 2 KB | 50 KB | 1.5 MB | 5 MB |

**Key insight:** L0 + L1 always fits in context (~52 KB max), giving LLMs enough to understand any codebase's structure before fetching details.

---

## 3. Namespaces and Prefixes

CCG uses the following RDF namespaces:

```turtle
@prefix ccg: <https://codecontextgraph.com/ontology/v1#> .
@prefix narsil: <https://narsilmcp.com/ontology/v1#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
```

### 3.1 URI Patterns

| Entity | URI Pattern |
|--------|-------------|
| Repository | `https://codecontextgraph.com/repo/{host}/{owner}/{name}` |
| Commit | `https://codecontextgraph.com/repo/{host}/{owner}/{name}@{commit}` |
| File | `<repo-uri>/file/{path}` |
| Symbol | `<repo-uri>/sym/{qualified-name}` |
| Finding | `<repo-uri>/finding/{id}` |
| Layer | `<repo-uri>/layer/{0-3}` |

**Example:**
```
https://codecontextgraph.com/repo/github.com/postrv/narsil-mcp@abc123
https://codecontextgraph.com/repo/github.com/postrv/narsil-mcp@abc123/file/src/main.rs
https://codecontextgraph.com/repo/github.com/postrv/narsil-mcp@abc123/sym/CodeIntelEngine
```

---

## 4. Layer Specifications

### 4.1 Layer 0: Manifest

**Format:** JSON-LD
**Extension:** `.ccg.manifest.json`
**Size:** ~1-2 KB
**Purpose:** Quick repository overview that always fits in context

**Required Fields:**

```json
{
  "@context": "https://codecontextgraph.com/schema/v1",
  "@type": "ccg:Manifest",
  "@id": "<repository-uri>",

  "repository": {
    "name": "string (required)",
    "url": "string (required, URL)",
    "commit": "string (required, commit hash)",
    "analyzedAt": "string (required, ISO 8601 datetime)"
  },

  "languages": {
    "<language>": {
      "files": "integer",
      "loc": "integer"
    }
  },

  "symbols": {
    "total": "integer",
    "functions": "integer",
    "structs": "integer",
    "classes": "integer",
    "methods": "integer",
    "traits": "integer",
    "interfaces": "integer",
    "enums": "integer"
  },

  "security": {
    "critical": "integer",
    "high": "integer",
    "medium": "integer",
    "low": "integer",
    "info": "integer"
  },

  "quality": {
    "avgCyclomaticComplexity": "number",
    "maxCyclomaticComplexity": "integer",
    "hotspots": ["string (file paths)"]
  },

  "entryPoints": [
    {
      "symbol": "string",
      "file": "string",
      "line": "integer"
    }
  ],

  "layers": {
    "architecture": "string (URL to Layer 1)",
    "symbolIndex": "string (URL to Layer 2)",
    "fullDetail": "string (URL to Layer 3)",
    "sparqlEndpoint": "string (optional, SPARQL endpoint URL)"
  }
}
```

### 4.2 Layer 1: Architecture

**Format:** JSON-LD
**Extension:** `.ccg.arch.json`
**Size:** ~10-50 KB
**Purpose:** Understand codebase structure and public API

**Required Fields:**

```json
{
  "@context": "https://codecontextgraph.com/schema/v1",
  "@type": "ccg:Architecture",
  "@id": "<repository-uri>/layer/1",

  "modules": [
    {
      "name": "string",
      "path": "string",
      "purpose": "string (optional)",
      "exports": ["string (symbol names)"],
      "dependsOn": ["string (module names)"],
      "loc": "integer"
    }
  ],

  "publicAPI": [
    {
      "symbol": "string",
      "signature": "string",
      "doc": "string (optional, first 200 chars)"
    }
  ],

  "patterns": {
    "architectural": ["string (pattern names)"],
    "detected": [
      {
        "pattern": "string",
        "location": "string (optional)",
        "coverage": "string (optional)"
      }
    ]
  },

  "moduleDependencyGraph": {
    "nodes": ["string (module names)"],
    "edges": [["string (from)", "string (to)"]]
  }
}
```

### 4.3 Layer 2: Symbol Index

**Format:** N-Quads (gzipped)
**Extension:** `.ccg.index.nq.gz`
**Size:** ~100-500 KB (gzipped)
**Purpose:** Navigation and call graph analysis

**Content:**

Layer 2 contains RDF triples for all symbols:

```turtle
# Symbol definitions
<sym:McpServer> a narsil:Struct ;
    narsil:name "McpServer" ;
    narsil:definedIn <file:src/mcp/server.rs> ;
    narsil:startLine 25 ;
    narsil:endLine 180 ;
    narsil:isPublic true ;
    narsil:docComment "The main MCP server..." .

<sym:McpServer::new> a narsil:Method ;
    narsil:name "new" ;
    narsil:hasParent <sym:McpServer> ;
    narsil:signature "pub fn new(config: Config) -> Self" ;
    narsil:startLine 35 ;
    narsil:endLine 52 ;
    narsil:complexity 3 .

# Call graph edges
<sym:McpServer::run> narsil:calls <sym:McpServer::handle_request> .
<sym:McpServer::handle_request> narsil:calls <sym:dispatch> .

# Type relationships
<sym:McpServer> narsil:implements <trait:McpHandler> .
```

**Required Triple Patterns:**

| Subject | Predicate | Object |
|---------|-----------|--------|
| Symbol | `rdf:type` | Symbol class |
| Symbol | `narsil:name` | Name string |
| Symbol | `narsil:definedIn` | File URI |
| Symbol | `narsil:startLine` | Line number |
| Function | `narsil:signature` | Signature string |
| Function | `narsil:complexity` | Complexity integer |
| Function | `narsil:calls` | Called function |

### 4.4 Layer 3: Full Detail

**Format:** N-Quads (gzipped)
**Extension:** `.ccg.full.nq.gz`
**Size:** ~1-20 MB (gzipped)
**Purpose:** Complete analysis data for SPARQL queries

**Content:**

Layer 3 includes everything from Layer 2 plus:

```turtle
# Security findings
<finding:cwe-89-query.rs-234> a narsil:Vulnerability ;
    narsil:cweId "CWE-89" ;
    narsil:severity "MEDIUM" ;
    narsil:owaspCategory "A03:2021" ;
    narsil:inFile <file:src/query.rs> ;
    narsil:atLine 234 ;
    narsil:affectsSymbol <sym:execute_query> ;
    narsil:message "Potential SQL injection via user input" ;
    narsil:remediation "Use parameterized queries instead of string concatenation" .

# Taint flows
<taint:1> a narsil:TaintFlow ;
    narsil:source <sym:get_user_input> ;
    narsil:sink <sym:execute_query> ;
    narsil:path (<sym:get_user_input> <sym:process_request> <sym:execute_query>) .

# Source snippets (for complex functions)
<sym:complex_function> narsil:sourceSnippet """
pub fn complex_function(input: &str) -> Result<Output> {
    // ... source code ...
}
""" .

# Data flow analysis
<dfg:execute_query> a narsil:DataFlowGraph ;
    narsil:forSymbol <sym:execute_query> ;
    narsil:definesVar "query" ;
    narsil:usesVar "user_input" .
```

**Named Graphs (Required):**

| Graph | Content |
|-------|---------|
| `<repo:meta>` | Repository metadata |
| `<repo:structure>` | File and symbol hierarchy |
| `<repo:calls>` | Call graph relationships |
| `<repo:security>` | Security findings |

**Named Graphs (Optional):**

| Graph | Content |
|-------|---------|
| `<repo:types>` | Type inference results |
| `<repo:dataflow>` | Data flow analysis |
| `<repo:docs>` | Linked documentation |
| `<repo:history>` | Git history/blame |

---

## 5. Access Control (Triple-Heart Model)

CCG implements a three-tier access control model based on WebACL:

### 5.1 Access Tiers

| Tier | Name | Agent Class | Typical Access |
|------|------|-------------|----------------|
| Public | Red Heart | `foaf:Agent` | Layer 0 (Manifest) |
| Authenticated | Yellow Heart | `acl:AuthenticatedAgent` | Layers 0-1 |
| Private | Blue Heart | Specific `acl:agent` | Layers 0-3 |

### 5.2 WebACL Example

```turtle
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

# Public: Anyone can see manifest
<#public-manifest> a acl:Authorization ;
    acl:accessTo </ccg/github.com/org/repo/layer/0> ;
    acl:agentClass foaf:Agent ;
    acl:mode acl:Read .

# Authenticated: Any verified agent can see architecture
<#authenticated-arch> a acl:Authorization ;
    acl:accessTo </ccg/github.com/org/repo/layer/1> ;
    acl:agentClass acl:AuthenticatedAgent ;
    acl:mode acl:Read .

# Private: Only specific agents can see full detail
<#private-full> a acl:Authorization ;
    acl:accessTo </ccg/github.com/org/repo/layer/3> ;
    acl:agent <https://security-scanner.example.ai/#agent> ;
    acl:mode acl:Read .
```

### 5.3 Default Access Mapping

| Content | Default Tier | Rationale |
|---------|--------------|-----------|
| Layer 0 (Manifest) | Public | Discovery, basic stats |
| Layer 1 (Architecture) | Authenticated | API surface, no implementation |
| Layer 2 (Symbol Index) | Private | Detailed code structure |
| Layer 3 (Full Detail) | Private | Security findings, source code |

---

## 6. File Extensions and Distribution

### 6.1 File Extensions

| Layer | Extension | Format | Compression |
|-------|-----------|--------|-------------|
| 0 | `.ccg.manifest.json` | JSON-LD | None |
| 1 | `.ccg.arch.json` | JSON-LD | None |
| 2 | `.ccg.index.nq.gz` | N-Quads | Gzip |
| 3 | `.ccg.full.nq.gz` | N-Quads | Gzip |
| Bundle | `.ccg.zip` | ZIP archive | Contains all layers |

### 6.2 Bundle Structure

A CCG bundle (`.ccg.zip`) contains:

```
repo-name.ccg.zip/
  manifest.json         # Layer 0
  architecture.json     # Layer 1
  symbol-index.nq.gz    # Layer 2
  full-detail.nq.gz     # Layer 3
  acl.ttl               # Access control (optional)
  README.md             # Human-readable summary (optional)
```

### 6.3 Registry URLs

CCGs are published to `codecontextgraph.com` with the following URL pattern:

```
https://codecontextgraph.com/ccg/{host}/{owner}/{repo}@{commit}/manifest.json
https://codecontextgraph.com/ccg/{host}/{owner}/{repo}@{commit}/architecture.json
https://codecontextgraph.com/ccg/{host}/{owner}/{repo}@{commit}/symbol-index.nq.gz
https://codecontextgraph.com/ccg/{host}/{owner}/{repo}@{commit}/full-detail.nq.gz
```

**Latest version alias:**
```
https://codecontextgraph.com/ccg/{host}/{owner}/{repo}/latest/manifest.json
```

---

## 7. Layer Selection Strategy

### 7.1 Query-to-Layer Mapping

| Query Type | Layers Needed | Typical Size |
|------------|---------------|--------------|
| "What does this codebase do?" | L0 + L1 | ~20 KB |
| "List the modules and their dependencies" | L0 + L1 | ~20 KB |
| "Find all functions that call X" | L0 + L2 (call graph subset) | ~50 KB |
| "What is the signature of function Y?" | L0 + L2 (single symbol) | ~5 KB |
| "Explain vulnerability in file Z" | L0 + L3 (SPARQL) | ~10 KB result |
| "Show security summary" | L0 only | ~2 KB |
| "Show complete call graph" | Don't load; return viz URL | N/A |

### 7.2 Decision Algorithm

```
function selectLayers(query):
    # Always load manifest
    layers = [L0]

    if query.needs_structure or query.needs_overview:
        layers.append(L1)

    if query.needs_symbols or query.needs_callgraph:
        # Load L2 subset by filtering
        layers.append(L2_subset(query.scope))

    if query.needs_security or query.needs_source or query.needs_dataflow:
        # Use SPARQL against L3, don't load fully
        return sparql_query(query)

    return layers
```

### 7.3 Context Budget Management

For an LLM with 200K token context (~800 KB):

| Budget | Strategy |
|--------|----------|
| <10 KB | L0 only |
| <50 KB | L0 + L1 |
| <200 KB | L0 + L1 + L2 subset |
| >200 KB | SPARQL query, return results |

---

## 8. CCG Diff Format

CCG diffs enable objective verification of refactoring completion.

### 8.1 Diff Structure

```json
{
  "@context": "https://codecontextgraph.com/schema/v1",
  "@type": "ccg:Diff",
  "base": "ccg:github.com/org/repo@abc123",
  "target": "ccg:refactor/description",

  "changes": {
    "modules": {
      "added": [{"name": "string", "path": "string", "purpose": "string"}],
      "removed": [{"name": "string", "path": "string"}],
      "renamed": [{"old": "string", "new": "string"}]
    },
    "symbols": {
      "moved": [{"symbol": "string", "from": "string", "to": "string"}],
      "renamed": [{"old": "string", "new": "string"}],
      "added": ["string"],
      "removed": ["string"]
    },
    "dependencies": {
      "added": [{"from": "string", "to": "string"}],
      "removed": [{"from": "string", "to": "string"}]
    }
  },

  "constraints": [
    {"type": "noCircularDeps"},
    {"type": "maxComplexity", "scope": "*", "value": 15},
    {"type": "mustExport", "module": "string", "symbols": ["string"]}
  ]
}
```

### 8.2 Constraint Types

| Constraint | Parameters | Description |
|------------|------------|-------------|
| `noCircularDeps` | - | Module graph must be acyclic |
| `maxComplexity` | `scope`, `value` | Cyclomatic complexity ceiling |
| `mustExport` | `module`, `symbols` | Required public API |
| `mustNotExport` | `module`, `symbols` | Forbidden public API |
| `noDirectCalls` | `from`, `to` | Module isolation |
| `mustCallThrough` | `from`, `to`, `via` | Enforce middleware |
| `layerViolation` | `layers` | Dependency direction |

### 8.3 Verification

Refactoring is complete when:
1. `diff.changes` are empty (all changes applied)
2. All `diff.constraints` are satisfied

```
verify(current_ccg, target_diff):
    for change in target_diff.changes:
        if not applied(current_ccg, change):
            return Failed(change)

    for constraint in target_diff.constraints:
        if not satisfied(current_ccg, constraint):
            return Failed(constraint)

    return Success
```

---

## 9. SPARQL Query Patterns

### 9.1 Common Queries

**Find all security findings:**
```sparql
PREFIX narsil: <https://narsilmcp.com/ontology/v1#>

SELECT ?finding ?severity ?file ?line ?message
WHERE {
  ?finding a narsil:Vulnerability ;
           narsil:severity ?severity ;
           narsil:inFile ?file ;
           narsil:atLine ?line ;
           narsil:message ?message .
}
ORDER BY DESC(?severity)
```

**Find callers of a function:**
```sparql
PREFIX narsil: <https://narsilmcp.com/ontology/v1#>

SELECT ?caller ?callerFile
WHERE {
  ?caller narsil:calls <sym:execute_query> ;
          narsil:definedIn ?callerFile .
}
```

**Find high-complexity functions:**
```sparql
PREFIX narsil: <https://narsilmcp.com/ontology/v1#>

SELECT ?fn ?complexity ?file
WHERE {
  ?fn a narsil:Function ;
      narsil:complexity ?complexity ;
      narsil:definedIn ?file .
  FILTER(?complexity > 15)
}
ORDER BY DESC(?complexity)
```

### 9.2 Query Templates

CCG implementations SHOULD provide parameterized templates:

| Template | Parameters | Description |
|----------|------------|-------------|
| `find_callers` | `symbol` | Find all callers of a function |
| `find_callees` | `symbol` | Find all functions called by |
| `find_by_severity` | `severity` | Security findings by severity |
| `find_by_cwe` | `cwe_id` | Security findings by CWE |
| `symbol_complexity` | `threshold` | Functions above complexity |
| `module_dependencies` | `module` | Dependencies of a module |

---

## 10. Implementation Conformance

### 10.1 Conformance Levels

| Level | Requirements |
|-------|--------------|
| **Basic** | Generate valid L0 manifest |
| **Standard** | Generate L0 + L1, valid JSON-LD |
| **Full** | Generate all layers, SPARQL queryable |
| **Extended** | Diffs, constraints, access control |

### 10.2 Validation

CCG documents MUST validate against:
- JSON-LD 1.1 specification (L0, L1)
- N-Quads syntax (L2, L3)
- CCG JSON Schema (layer structure)

### 10.3 Required Tools

Conformant implementations MUST provide:
- `export_ccg_manifest` - Generate Layer 0
- `get_ccg_manifest` - Retrieve and display Layer 0

Conformant implementations SHOULD provide:
- `export_ccg_architecture` - Generate Layer 1
- `export_ccg_index` - Generate Layer 2
- `export_ccg_full` - Generate Layer 3
- `export_ccg` - Generate all layers
- `query_ccg` - SPARQL query against Layer 3

---

## 11. References

### 11.1 Normative References

- [JSON-LD 1.1](https://www.w3.org/TR/json-ld11/)
- [RDF 1.1 N-Quads](https://www.w3.org/TR/n-quads/)
- [SPARQL 1.1 Query Language](https://www.w3.org/TR/sparql11-query/)
- [Web Access Control](https://solidproject.org/TR/wac)

### 11.2 Informative References

- [Narsil Code Intelligence Ontology](https://narsilmcp.com/ontology/v1)
- [CCG Access Control Ontology](https://codecontextgraph.com/acl/v1)
- [MCP (Model Context Protocol)](https://modelcontextprotocol.io/)

---

## Appendix A: JSON Schema Location

The authoritative JSON Schema for CCG is published at:
```
https://codecontextgraph.com/schema/v1
```

## Appendix B: Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1 | Dec 2025 | Initial draft |
| 0.2 | Jan 2026 | Multi-layer architecture, Triple-Heart access model, CCG diff format |

---

*"The graph is the spec. The spec is the graph."*
