# Repository Structure: Open Core Separation

> **Version:** 1.0
> **Last Updated:** January 2026
> **Related Documents:** [LICENSING.md](./LICENSING.md), [NARSIL_BACKEND_MASTER_PLAN.md](./NARSIL_BACKEND_MASTER_PLAN.md)

---

## Overview

This document defines the physical repository structure for the Narsil open core model.

**Two Repositories:**
1. `narsil-mcp` - Public, MIT licensed, drives adoption
2. `narsil-cloud` - Private, proprietary, generates revenue

---

## Repository 1: narsil-mcp (PUBLIC)

**GitHub:** `github.com/[org]/narsil-mcp`
**License:** MIT
**Visibility:** Public

### Directory Structure

```
narsil-mcp/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                  # Build, test, clippy
│   │   ├── release.yml             # Cargo publish, GitHub releases
│   │   └── security.yml            # Dependency scanning
│   ├── ISSUE_TEMPLATE/
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── CODEOWNERS
│
├── src/
│   ├── main.rs                     # CLI entry point
│   ├── lib.rs                      # Library exports
│   ├── mcp.rs                      # MCP server implementation
│   │
│   ├── parser.rs                   # Language parsers (16+)
│   ├── index.rs                    # Indexing infrastructure
│   │
│   ├── cache/                      # Query caching (Sprint 1)
│   │   ├── mod.rs
│   │   ├── invalidation.rs
│   │   └── query_cache.rs
│   │
│   ├── cfg.rs                      # Control flow graphs
│   ├── dfg.rs                      # Data flow analysis
│   ├── dead_code.rs                # Dead code detection (Sprint 2)
│   ├── taint.rs                    # Taint analysis
│   ├── type_inference.rs           # Type inference (Sprint 5)
│   │
│   ├── security_rules.rs           # Security rule engine
│   │
│   ├── persistence/                # Local Oxigraph (Sprint 6 - OPEN part)
│   │   ├── mod.rs
│   │   ├── graph.rs                # KnowledgeGraph struct
│   │   ├── transform.rs            # Symbol-to-RDF
│   │   └── sparql.rs               # Local SPARQL queries
│   │
│   └── ccg/                        # CCG generation (Sprint 7 - OPEN part)
│       ├── mod.rs
│       ├── schema.rs               # CCG types, JSON-LD structures
│       ├── layers.rs               # L0, L1, L2 generation only
│       ├── export.rs               # JSON-LD, N-Quads export
│       └── import.rs               # Load CCGs from URLs
│
├── ontology/
│   ├── narsil.ttl                  # Core RDF ontology
│   └── ccg.ttl                     # CCG-specific ontology
│
├── rules/                          # Security rules (YAML)
│   ├── owasp.yaml
│   ├── cwe.yaml
│   ├── rust.yaml
│   ├── python.yaml
│   ├── javascript.yaml
│   ├── go.yaml                     # Sprint 4
│   ├── java.yaml                   # Sprint 4
│   ├── csharp.yaml                 # Sprint 4
│   ├── kotlin.yaml                 # Sprint 4
│   ├── config.yaml                 # Sprint 4
│   └── iac.yaml                    # Sprint 4
│
├── schema/
│   └── ccg-v1.json                 # JSON-LD schema for CCG
│
├── docs/
│   ├── ccg-spec.md                 # CCG specification (open standard)
│   ├── LICENSING.md                # This licensing strategy doc
│   ├── REPO_STRUCTURE.md           # This document
│   ├── CONTRIBUTING.md             # Contribution guidelines
│   ├── SECURITY.md                 # Security policy
│   └── NARSIL_BACKEND_MASTER_PLAN.md  # Strategic context (public parts)
│
├── examples/
│   ├── ccg-l0-example.json         # Example L0 manifest
│   ├── ccg-l1-example.json         # Example L1 architecture
│   └── ccg-l2-example.nq.gz        # Example L2 symbol index
│
├── tests/
│   ├── integration/
│   ├── fixtures/
│   └── security_fixtures/
│
├── Cargo.toml
├── LICENSE                         # MIT License
├── README.md
├── CLAUDE.md                       # AI assistant context
└── IMPLEMENTATION_PLAN.md          # Sprint tracking (OPEN sprints)
```

### Key Files

#### Cargo.toml (excerpt)
```toml
[package]
name = "narsil-mcp"
version = "0.2.0"
edition = "2021"
license = "MIT"
description = "MCP server for code intelligence with CCG support"
repository = "https://github.com/[org]/narsil-mcp"

[dependencies]
# ... existing dependencies ...
oxigraph = "0.4"
sophia = "0.8"                      # RDF/SPARQL utilities
```

#### lib.rs (public API)
```rust
//! narsil-mcp: MCP server for code intelligence
//!
//! # Feature Flags
//! - `oxigraph`: Enable RDF graph persistence (default: enabled)
//! - `ccg`: Enable CCG generation (default: enabled)

pub mod cache;
pub mod ccg;
pub mod persistence;
// ... etc
```

---

## Repository 2: narsil-cloud (PRIVATE)

**GitHub:** `github.com/[org]/narsil-cloud` (private)
**License:** Proprietary
**Visibility:** Private

### Directory Structure

```
narsil-cloud/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                  # Build, test
│   │   ├── deploy-staging.yml      # Deploy to staging
│   │   └── deploy-prod.yml         # Deploy to production
│   └── CODEOWNERS
│
├── src/
│   ├── main.rs                     # Service entry point
│   ├── lib.rs                      # Library (for testing)
│   │
│   ├── ccg/                        # Commercial CCG features
│   │   ├── mod.rs
│   │   ├── l3_generate.rs          # Full-detail L3 generation
│   │   ├── diff.rs                 # CCG diff computation
│   │   ├── constraints.rs          # Constraint verification
│   │   ├── target.rs               # Target CCG generation from description
│   │   └── progress.rs             # Refactoring progress tracking
│   │
│   ├── ldn/                        # Linked Data Notifications
│   │   ├── mod.rs
│   │   ├── inbox.rs                # W3C LDN inbox implementation
│   │   ├── outbox.rs               # Outgoing notifications
│   │   └── webid.rs                # WebID authentication
│   │
│   ├── access/                     # Triple-Heart access control
│   │   ├── mod.rs
│   │   ├── webacl.rs               # WebACL implementation
│   │   └── tiers.rs                # Public/Authenticated/Private
│   │
│   ├── hosting/                    # Multi-tenant infrastructure
│   │   ├── mod.rs
│   │   ├── registry.rs             # CCG registry (R2 backend)
│   │   ├── storage.rs              # Per-layer storage
│   │   ├── api.rs                  # REST API handlers
│   │   └── workers/                # Cloudflare Workers
│   │       ├── ccg_upload.rs
│   │       ├── ccg_fetch.rs
│   │       └── badge.rs            # shields.io-style badges
│   │
│   ├── enterprise/                 # Enterprise features
│   │   ├── mod.rs
│   │   ├── sso.rs                  # SAML/OIDC integration
│   │   ├── audit.rs                # Audit logging
│   │   ├── teams.rs                # Team/org management
│   │   └── quotas.rs               # Usage quotas
│   │
│   └── billing/                    # Subscription management
│       ├── mod.rs
│       ├── stripe.rs               # Stripe integration
│       └── usage.rs                # Usage metering
│
├── infrastructure/                 # IaC
│   ├── terraform/
│   │   ├── cloudflare.tf           # Cloudflare config
│   │   ├── r2.tf                   # R2 bucket setup
│   │   └── dns.tf                  # DNS records
│   └── kubernetes/                 # K8s manifests (if needed)
│
├── landing-page/                   # narsilmcp.com (or separate repo)
│   └── ...
│
├── tests/
│   ├── integration/
│   └── e2e/
│
├── Cargo.toml
├── LICENSE                         # Proprietary license
└── README.md                       # Internal docs
```

### Key Files

#### Cargo.toml
```toml
[package]
name = "narsil-cloud"
version = "0.1.0"
edition = "2021"
license = "LicenseRef-Proprietary"
publish = false                     # Never publish to crates.io

[dependencies]
# Open source core as git dependency
narsil-mcp = { git = "https://github.com/[org]/narsil-mcp", tag = "v0.2.0" }

# Commercial-only dependencies
stripe-rust = "0.22"
axum = "0.7"
tower = "0.4"
jsonwebtoken = "9"
```

#### Dependency on narsil-mcp
```rust
// src/ccg/l3_generate.rs
use narsil_mcp::ccg::{CcgSchema, Layer};
use narsil_mcp::persistence::KnowledgeGraph;

pub fn generate_l3(graph: &KnowledgeGraph) -> Layer {
    // Uses open source types, adds proprietary logic
    // ...
}
```

---

## Migration Path

### Phase 1: Current State (narsil-mcp monorepo)

Everything is currently in `narsil-mcp`. No changes yet.

### Phase 2: Prepare for Split

1. **Ensure clean boundaries** - Sprint 1-5, Sprint 9 stay fully open
2. **Mark SPLIT sprints** - Sprint 6 and 7 have clear open/commercial boundaries
3. **Document public API** - `lib.rs` exports only open source features

### Phase 3: Create narsil-cloud

1. Create private `narsil-cloud` repository
2. Add `narsil-mcp` as git dependency
3. Implement commercial features (Sprint 7b, 8)
4. Set up CI/CD for deployment

### Phase 4: Maintain Separation

1. All new open source features go to `narsil-mcp`
2. All commercial features go to `narsil-cloud`
3. `narsil-cloud` always depends on a tagged version of `narsil-mcp`
4. Releases coordinated but independent

---

## Branching Strategy

### narsil-mcp (Public)

```
main                    # Stable, releases tagged here
├── develop             # Integration branch
├── feature/sprint-1-*  # Sprint 1 features
├── feature/sprint-2-*  # Sprint 2 features
└── ...
```

### narsil-cloud (Private)

```
main                    # Production
├── staging             # Pre-production testing
├── develop             # Integration
├── feature/sprint-7b-* # Commercial CCG diff
├── feature/sprint-8-*  # Infrastructure
└── ...
```

---

## Release Coordination

### narsil-mcp Releases

1. Semantic versioning: `MAJOR.MINOR.PATCH`
2. Git tags: `v0.2.0`, `v0.3.0`, etc.
3. Changelog in `CHANGELOG.md`
4. Published to crates.io

### narsil-cloud Releases

1. Internal versioning (not published)
2. Depends on specific narsil-mcp tag
3. Deployed to codecontextgraph.com
4. Rolling releases with canary deployment

### Dependency Updates

```toml
# narsil-cloud/Cargo.toml

# For development: track main branch
narsil-mcp = { git = "https://github.com/[org]/narsil-mcp", branch = "main" }

# For production: pin to tag
narsil-mcp = { git = "https://github.com/[org]/narsil-mcp", tag = "v0.2.0" }
```

---

## CI/CD Considerations

### narsil-mcp CI

```yaml
# .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --all-features
      - run: cargo clippy --all-targets -- -D warnings
```

### narsil-cloud CI

```yaml
# .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      # SSH key for private narsil-mcp access (if needed)
      - uses: webfactory/ssh-agent@v0.8.0
        with:
          ssh-private-key: ${{ secrets.DEPLOY_KEY }}
      - run: cargo test
      - run: cargo clippy -- -D warnings

  deploy-staging:
    needs: test
    if: github.ref == 'refs/heads/staging'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./deploy.sh staging
```

---

## Security Considerations

### Secrets Management

| Secret | Location | Purpose |
|--------|----------|---------|
| `CRATES_IO_TOKEN` | narsil-mcp | Publishing to crates.io |
| `CLOUDFLARE_API_TOKEN` | narsil-cloud | Deployments |
| `STRIPE_SECRET_KEY` | narsil-cloud | Billing |
| `R2_ACCESS_KEY` | narsil-cloud | CCG storage |

### Access Control

| Repository | Access |
|------------|--------|
| narsil-mcp | Public read, maintainers write |
| narsil-cloud | Team members only |

---

## Checklist for Split

- [ ] Ensure MIT LICENSE file is in narsil-mcp root
- [ ] Create narsil-cloud private repository
- [ ] Set up deploy keys for cross-repo dependency
- [ ] Configure CI/CD for both repositories
- [ ] Update narsil-mcp README with "Commercial features" section
- [ ] Create CONTRIBUTING.md for open source contributions
- [ ] Set up issue templates for feature requests
- [ ] Configure Dependabot for both repos
- [ ] Set up release automation
