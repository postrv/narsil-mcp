# narsil-mcp Improvement Plan

> A strategic roadmap to maximize value, adoption, and stickiness of narsil-mcp

## Executive Summary

narsil-mcp is a technically impressive project with strong foundations:
- 76 MCP tools, 16 languages, 359 tests
- Excellent performance (~2 GiB/s parsing)
- Security-hardened with 111 built-in rules
- Professional CI/CD pipeline

**Current State:** Production-ready v1.0 with minimal community adoption (44 stars).

**Primary Goal:** Create a clear path to real value quickly by focusing on:
1. Reducing friction to first success
2. Showcasing compelling use cases
3. Building community and trust

---

## Priority Matrix

| Priority | Category | Impact | Effort |
|----------|----------|--------|--------|
| P0 | Quick Wins (do now) | High | Low |
| P1 | Value Demonstration | Very High | Medium |
| P2 | Community Building | High | Medium |
| P3 | Feature Polish | Medium | High |

---

## P0: Quick Wins (This Week)

### 1. Add Missing Open Source Files
**Impact:** Builds trust and professionalism for potential contributors/adopters

- [ ] **SECURITY.md** - Vulnerability disclosure process
- [ ] **CONTRIBUTING.md** - How to contribute
- [ ] **CODE_OF_CONDUCT.md** - Community standards
- [ ] **docs/IMPLEMENTATION_ROADMAP.md** - Referenced in README but doesn't exist

### 2. Fix Documentation Gaps
**Impact:** Reduces friction for new users

- [ ] Add demo GIF/video to README (first impression matters)
- [ ] Create `examples/` directory with real-world scenarios
- [ ] Add "Quick Start" section with 3-minute success path
- [ ] Document privacy implications of neural search (API calls)

### 3. Improve Error Messages
**Impact:** Reduces user frustration

- [ ] Add actionable suggestions in error outputs
- [ ] Include help URLs in error messages
- [ ] Add `--diagnose` flag for troubleshooting

---

## P1: Value Demonstration (Next 2 Weeks)

### 4. Create Compelling Use Cases
**Impact:** Shows why users should care

**Use Case 1: Security Audit Workflow**
```bash
# One command security audit for your codebase
narsil-mcp --repos . --output-format sarif | upload-to-github-security
```
- Create `examples/security-audit/` with GitHub Actions integration
- Show SARIF output for GitHub Security tab integration

**Use Case 2: Code Review Assistant**
```markdown
# Claude prompt: "Review this PR using narsil-mcp"
- Find all changes via get_modified_files
- Check for security issues with scan_security
- Identify complexity hotspots with get_complexity
- Trace taint flows in changed code
```
- Create `examples/code-review/` with sample prompts

**Use Case 3: Codebase Onboarding**
```markdown
# Claude prompt: "Help me understand this codebase"
- Get project structure and key entry points
- Identify main abstractions via call graph
- Find similar code patterns I should follow
```
- Create `examples/onboarding/` with guided tour

### 5. Publish npm Package for WASM
**Impact:** Enables browser-based demos and wider reach

- [ ] Set up npm publishing in release workflow
- [ ] Create `@narsil-mcp/wasm` package on npm
- [ ] Add live demo playground (CodeSandbox/StackBlitz)

### 6. GitHub Actions Integration
**Impact:** Captures CI/CD use case - sticky adoption

Create `narsil-mcp-action` for:
- Security scanning in PRs
- SBOM generation on releases
- Dependency vulnerability alerts

```yaml
# .github/workflows/security.yml
- uses: postrv/narsil-mcp-action@v1
  with:
    scan: security
    fail-on: high
```

---

## P2: Community Building (Next Month)

### 7. Create Community Infrastructure
**Impact:** Builds sustainable adoption

- [ ] Set up GitHub Discussions (Q&A, Show & Tell)
- [ ] Create Discord server for real-time help
- [ ] Add "Built with narsil-mcp" showcase section
- [ ] Create X/Twitter presence for updates

### 8. Content Marketing
**Impact:** Drives discovery

- [ ] Write blog post: "How I Found 47 Security Vulnerabilities in 5 Minutes"
- [ ] Create comparison benchmark vs other tools
- [ ] Record YouTube demo video
- [ ] Submit to Hacker News, r/rust, r/programming

### 9. Integration Partnerships
**Impact:** Ecosystem presence

- [ ] Submit to MCP server registry/marketplace
- [ ] Create Raycast extension
- [ ] Create Alfred workflow
- [ ] Integration with popular editors beyond current 4

---

## P3: Feature Polish (Ongoing)

### 10. UX Improvements

**Interactive CLI Mode**
```bash
$ narsil-mcp interactive
narsil> search "authentication"
narsil> call-graph login
narsil> security-scan src/auth/
```

**Progress Indicators**
- Add progress bars during indexing
- Show estimated time remaining
- Display file count processed

**Project Initialization**
```bash
$ narsil-mcp init
✓ Detected: Rust project with 147 files
✓ Created: .narsil.toml
✓ Configured for: Claude Desktop
? Enable features: [x] Git  [x] Call Graph  [ ] Neural Search
```

### 11. Security Enhancements

- [ ] Add audit logging for all tool invocations
- [ ] Implement rate limiting for remote repo access
- [ ] Add sandbox mode for untrusted repositories
- [ ] Support SLSA provenance for releases

### 12. Performance Optimizations

- [ ] Lazy loading of language parsers (reduce startup time)
- [ ] Memory-mapped symbol index (reduce memory for large repos)
- [ ] Parallel file parsing for initial index
- [ ] Incremental call graph updates

### 13. Additional Language Support

Priority based on user demand:
- [ ] Scala
- [ ] Elixir
- [ ] Zig
- [ ] Lua
- [ ] Haskell

---

## Metrics to Track

### Adoption Metrics
| Metric | Current | 30-Day Goal | 90-Day Goal |
|--------|---------|-------------|-------------|
| GitHub Stars | 44 | 200 | 1,000 |
| Forks | 3 | 20 | 100 |
| npm Downloads | 0 | 500 | 5,000 |
| Discord Members | 0 | 50 | 300 |

### Usage Metrics (if telemetry added, opt-in)
- Most used tools
- Average index size
- Languages indexed
- Feature flag usage

---

## Implementation Order

### Week 1: Foundation
1. Add SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md
2. Create examples/ directory with 3 use cases
3. Add demo GIF to README
4. Fix docs/IMPLEMENTATION_ROADMAP.md reference

### Week 2: Visibility
1. Publish npm package
2. Create GitHub Action
3. Submit to MCP registries
4. Write first blog post

### Week 3: Community
1. Set up GitHub Discussions
2. Create Discord server
3. Post to Hacker News
4. Engage on X/Twitter

### Week 4+: Iterate
1. Respond to community feedback
2. Add requested features
3. Fix reported issues
4. Build partnerships

---

## Risk Mitigation

### Risk: Low adoption despite efforts
**Mitigation:** Focus on one niche (security scanning) and dominate it

### Risk: Competition from larger players
**Mitigation:** Emphasize privacy-first, offline-capable differentiator

### Risk: Maintenance burden
**Mitigation:**
- Accept only high-value PRs
- Automate everything possible
- Build contributor community

---

## Success Criteria

**Short-term (1 month):**
- [ ] 200+ GitHub stars
- [ ] 10+ contributors
- [ ] Featured in 2+ newsletters/blogs

**Medium-term (3 months):**
- [ ] 1,000+ GitHub stars
- [ ] Used by 5+ notable projects
- [ ] Stable community (20+ Discord active)

**Long-term (1 year):**
- [ ] De facto MCP server for code intelligence
- [ ] Enterprise adoption
- [ ] Sustainable open source project

---

## Appendix: Detailed Findings

### Code Completeness: ✅ Excellent
- No TODOs/FIXMEs in codebase
- 359 passing tests with good coverage
- Well-structured modular architecture
- Comprehensive error handling

### Feature Completeness: ✅ Very Good
- 76 MCP tools covering most use cases
- 16 languages supported
- Security, supply chain, and advanced analysis
- WASM build available

### Security: ✅ Good
- Path traversal vulnerabilities fixed
- Secret redaction in outputs
- File size limits
- Read-only by default
- cargo audit in CI

**Gaps:**
- No rate limiting
- No audit logging
- No SECURITY.md

### Privacy: ✅ Good
- Fully local by default
- Neural search requires external API (documented)
- No telemetry

**Gaps:**
- Privacy implications of neural search not prominent

### UX: ⚠️ Needs Work
- One-click installer works well
- IDE configs provided
- Missing interactive mode
- No progress indicators
- Error messages could be more helpful

### Adoption: ⚠️ Early Stage
- 44 stars, 3 forks
- No community presence
- No examples directory
- No demo video
- Not on MCP registries
