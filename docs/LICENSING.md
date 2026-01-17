# Narsil Licensing Strategy: Open Core Model

> **Version:** 1.0
> **Last Updated:** January 2026
> **Related Documents:** [NARSIL_BACKEND_MASTER_PLAN.md](./NARSIL_BACKEND_MASTER_PLAN.md), [IMPLEMENTATION_PLAN.md](../IMPLEMENTATION_PLAN.md)

---

## Executive Summary

Narsil follows an **Open Core** licensing model, similar to GitLab, Grafana, and Elastic:

- **Open Source Core** (MIT): The MCP server, analysis tools, and CCG specification
- **Commercial Extensions** (Proprietary): Hosted services, enterprise features, and advanced tooling

This strategy maximizes adoption while protecting high-value IP for monetization.

---

## Repository Structure

### Public Repository: `narsil-mcp` (MIT License)

**Purpose:** Drive adoption, enable community contributions, establish CCG as the standard.

```
narsil-mcp/                         # MIT License - PUBLIC on GitHub
├── src/
│   ├── mcp/                        # All 76+ MCP tools
│   ├── parser.rs                   # 16+ language parsers
│   ├── index.rs                    # Local indexing
│   ├── cache/                      # Query caching
│   ├── cfg.rs                      # Control flow analysis
│   ├── dfg.rs                      # Data flow analysis
│   ├── taint.rs                    # Basic taint analysis
│   ├── security_rules.rs           # OWASP/CWE rules
│   ├── persistence/                # Local Oxigraph integration
│   │   ├── mod.rs
│   │   ├── graph.rs                # KnowledgeGraph struct
│   │   ├── transform.rs            # Symbol-to-RDF
│   │   └── sparql.rs               # Local SPARQL queries
│   └── ccg/                        # CCG generation (L0-L2)
│       ├── mod.rs
│       ├── schema.rs               # CCG types (open standard)
│       ├── layers.rs               # L0, L1, L2 generation
│       ├── export.rs               # JSON-LD/N-Quads export
│       └── import.rs               # Load published CCGs
├── ontology/
│   └── narsil.ttl                  # RDF ontology (open standard)
├── rules/                          # Security rules (community contributions)
├── docs/
│   └── ccg-spec.md                 # CCG specification (open standard)
├── schema/
│   └── ccg-v1.json                 # JSON-LD schema
└── LICENSE                         # MIT License
```

### Private Repository: `narsil-cloud` (Proprietary)

**Purpose:** Monetization through hosted services and enterprise features.

```
narsil-cloud/                       # Proprietary - PRIVATE
├── Cargo.toml                      # Depends on narsil-mcp
├── src/
│   ├── ccg/
│   │   ├── l3_generate.rs          # Full-detail L3 generation
│   │   ├── diff.rs                 # CCG diff computation
│   │   ├── constraints.rs          # Constraint verification
│   │   ├── target.rs               # Target CCG generation
│   │   └── progress.rs             # Refactoring progress tracking
│   ├── ldn/                        # Linked Data Notifications
│   │   ├── mod.rs
│   │   ├── inbox.rs                # W3C LDN inbox
│   │   └── send.rs                 # Outgoing notifications
│   ├── access/                     # Triple-Heart access control
│   │   ├── mod.rs
│   │   ├── webacl.rs               # WebACL implementation
│   │   └── tiers.rs                # Public/Authenticated/Private
│   ├── hosting/                    # Multi-tenant infrastructure
│   │   ├── mod.rs
│   │   ├── registry.rs             # CCG registry (R2 storage)
│   │   ├── api.rs                  # REST API
│   │   └── workers/                # Cloudflare Workers
│   ├── enterprise/                 # Enterprise features
│   │   ├── sso.rs                  # SAML/OIDC integration
│   │   ├── audit.rs                # Audit logging
│   │   └── teams.rs                # Team/org management
│   └── billing/                    # Subscription management
│       ├── mod.rs
│       └── stripe.rs               # Stripe integration
└── LICENSE                         # Proprietary - All Rights Reserved
```

---

## What's Open vs. Commercial

### Open Source (MIT) - `narsil-mcp`

| Component | Description | Rationale |
|-----------|-------------|-----------|
| **MCP Server** | All 76+ tools | Core value proposition, gets users hooked |
| **Language Parsers** | 16+ languages (expandable) | Community can contribute more |
| **Code Analysis** | CFG, DFG, call graphs, dead code | Fundamental features |
| **Security Scanning** | OWASP, CWE rules | Community improves rules |
| **Local Oxigraph** | RDF storage, SPARQL queries | Self-hosted option |
| **CCG Spec** | JSON-LD schema, ontology | Open standard drives adoption |
| **CCG L0-L2** | Manifest, architecture, symbol index | Useful locally, creates demand for L3 |
| **CCG Import** | Load published graphs | Interoperability |
| **CLI** | Command-line interface | Developer experience |
| **Query Caching** | Performance improvements | Benefits all users |

### Commercial (Proprietary) - `narsil-cloud`

| Component | Description | Rationale |
|-----------|-------------|-----------|
| **CCG L3 Generation** | Full-detail ~1-20MB graphs | Expensive compute, hosted value |
| **CCG Diff Verification** | "Definition of Done" tooling | High-value enterprise feature |
| **Constraint System** | `noDirectCalls`, `maxComplexity`, etc. | Refactoring assurance |
| **LDN Messaging** | Agent-to-agent notifications | Network effects, competitive moat |
| **Triple-Heart Access** | WebACL-based tiered access | Multi-tenant complexity |
| **Hosted Registry** | codecontextgraph.com storage | The actual service |
| **Enterprise Features** | SSO, audit logs, team management | Enterprise table stakes |
| **Analytics Dashboard** | Usage insights, trends | Insights monetization |
| **SLA & Support** | Guaranteed uptime, priority support | Enterprise contracts |

---

## Boundary Details

### Sprint 6: Oxigraph Integration (SPLIT)

**Open (narsil-mcp):**
- `KnowledgeGraph` struct with local Oxigraph store
- `narsil:` RDF ontology
- Symbol/call-graph/security-finding to RDF transformation
- `sparql_query` tool for local queries
- `--persist-graph` CLI flag

**Commercial (narsil-cloud):**
- Hosted graph storage with multi-tenant isolation
- Cross-repository SPARQL queries
- Graph federation across organizations
- Usage metering and quotas

### Sprint 7: CCG Standard (SPLIT)

**Open (narsil-mcp):**
- CCG JSON-LD schema and specification
- `export_ccg_manifest` tool (L0 ~2KB)
- `export_ccg_architecture` tool (L1 ~10-50KB)
- `export_ccg_index` tool (L2 ~100-500KB)
- `get_ccg_manifest` tool
- `export_ccg` tool (L0-L2 bundled)
- CCG import from registry URLs

**Commercial (narsil-cloud):**
- `export_ccg_full` tool (L3 ~1-20MB) - compute-intensive
- `query_ccg` tool against hosted L3 graphs
- CCG storage in registry
- CCG versioning and history

### Sprint 7b: CCG Diff (COMMERCIAL)

**All Commercial (narsil-cloud):**
- `compare_ccg` tool
- Constraint verification system
- `generate_target_ccg` tool
- `verify_ccg` tool
- `get_refactoring_progress` tool

### Sprint 8: Infrastructure (COMMERCIAL)

**All Commercial (narsil-cloud):**
- narsilmcp.com landing page (marketing)
- codecontextgraph.com registry
- GitHub Action for CCG publishing (uses open API)
- LDN inbox/outbox
- WebID authentication

---

## Dependency Relationship

```
┌─────────────────────────────────────────────────────────────┐
│                     narsil-cloud (Proprietary)               │
│                                                              │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────┐ │
│  │ L3 CCG     │ │ CCG Diff   │ │ LDN        │ │ Hosting  │ │
│  │ Generation │ │ + Verify   │ │ Messaging  │ │ Infra    │ │
│  └────────────┘ └────────────┘ └────────────┘ └──────────┘ │
│                           │                                  │
│                           │ depends on                       │
│                           ▼                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                narsil-mcp (MIT, git dependency)       │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            │ published as
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    GitHub: narsil-mcp (PUBLIC)               │
│                                                              │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────┐ │
│  │ 76+ MCP    │ │ 16+        │ │ Local      │ │ CCG      │ │
│  │ Tools      │ │ Languages  │ │ Oxigraph   │ │ L0-L2    │ │
│  └────────────┘ └────────────┘ └────────────┘ └──────────┘ │
│                                                              │
│  MIT License - Free to use, modify, distribute              │
└─────────────────────────────────────────────────────────────┘
```

---

## License Text

### narsil-mcp LICENSE (MIT)

```
MIT License

Copyright (c) 2025 Laurence Shouldice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### narsil-cloud LICENSE (Proprietary)

```
Copyright (c) 2025 Laurence Shouldice. All Rights Reserved.

This software and associated documentation files (the "Software") are
proprietary and confidential. Unauthorized copying, modification, distribution,
or use of this Software, via any medium, is strictly prohibited.

The Software is licensed, not sold. Use of the Software requires a valid
commercial license agreement.

For licensing inquiries, contact: [licensing email]
```

---

## FAQ

### Can I use narsil-mcp in my commercial product?

**Yes.** The MIT license allows commercial use, modification, and distribution. You must include the copyright notice and license text.

### Can I self-host narsil-mcp?

**Yes.** The open source version includes everything needed for local use, including Oxigraph integration and L0-L2 CCG generation.

### What do I get with a commercial license?

- L3 full-detail CCG generation
- CCG diff and constraint verification
- Hosted CCG registry storage
- LDN agent-to-agent messaging
- Enterprise features (SSO, audit, teams)
- SLA guarantees and support

### Can I contribute to narsil-mcp?

**Yes, please!** Contributions to the open source repository are welcome under the MIT license. See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

### Will open source features ever become commercial?

**No.** Once a feature is released as MIT, it stays MIT. We may add commercial enhancements (e.g., hosted versions), but the open source version remains free.

---

## Comparisons to Other Open Core Projects

| Project | Open Source | Commercial |
|---------|-------------|------------|
| **GitLab** | GitLab CE (MIT) | GitLab EE (enterprise features) |
| **Grafana** | Grafana (AGPL) | Grafana Cloud, Enterprise |
| **Elastic** | Elasticsearch (SSPL) | Elastic Cloud, X-Pack |
| **Redis** | Redis (BSD) | Redis Enterprise |
| **Narsil** | narsil-mcp (MIT) | narsil-cloud (proprietary) |

---

## Contact

- **Open Source Issues:** github.com/[org]/narsil-mcp/issues
- **Commercial Inquiries:** [sales email]
- **Security Reports:** [security email]
