# narsil-xref

narsil-xref is a fork of [narsil-mcp](https://github.com/postrv/narsil-mcp)
with a different goal: correct cross-references (definitions, references,
callers and callees) in large local repositories, C and C++ first, for AI
coding agents. One SSE server per profile in `config.yaml` keeps the index of
that profile's repositories in memory, and every agent session uses it instead
of indexing again. narsil-mcp offers a broad set of analysis tools instead.
[Differences from narsil-mcp](#differences-from-narsil-mcp) lists what
changed.

## What it does

narsil-xref is an MCP (Model Context Protocol) server. It indexes local
repositories and answers an AI coding agent's questions about symbols,
references, call graphs and git history.

- Index: tree-sitter parses each file and extracts functions, types and
  methods. Tantivy, a full-text search library, ranks keyword search.
  `--persist` saves the index, so a restart re-parses only changed files.
- `--call-graph`: callers, callees and call paths between functions.
- `--git`: blame, file and symbol history, commit diffs, branch state.
- `--lsp`: hover, types, definitions and references from a language
  server: clangd and ccls for C and C++, rust-analyzer, pyright,
  typescript-language-server and gopls. For C and C++, GNU Global (gtags)
  adds references when `global` is on `PATH`; `--gtags-generate` builds
  its database. The results of tree-sitter, clangd, ccls and gtags are
  compared, so a reference one backend misses can come from another.
- `--transport sse`: one server per config profile keeps the index in
  memory. A stdio session that the editor starts forwards its requests to
  that server instead of indexing again.

## Install

Prebuilt binaries exist for Linux on x86_64 and aarch64, as a tarball and
as a `.deb` package, on the
[releases page](https://github.com/bsbernd/narsil-xref/releases).

```bash
curl -fsSL https://raw.githubusercontent.com/bsbernd/narsil-xref/main/install.sh | bash
```

From source, into `~/.local/bin`:

```bash
git clone https://github.com/bsbernd/narsil-xref.git
cd narsil-xref
bash setup.sh             # add --systemd to install the systemd user units
```

`--lsp` and gtags use only the servers found on `PATH` (`clangd`, `ccls`,
`global`, ...); each one is optional.

## Run

```bash
narsil-xref --repos . --git --call-graph --persist --watch --lsp
```

`--watch` re-indexes files when they change. An MCP client starts the
server from its config, for example `.mcp.json` in the project root:

```json
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": ["--repos", ".", "--git", "--call-graph", "--persist", "--lsp"]
    }
  }
}
```

With the systemd units from `setup.sh --systemd`, one SSE server per
profile starts on the first connection:

```bash
systemctl --user enable --now narsil-xref@dev.socket
```

[README_SSE.md](README_SSE.md) describes the SSE server, how stdio
sessions find it, and the memory watchdog that restarts it above
`--memory-hard-limit`.

## Configuration

Settings come from, highest priority first: command-line options,
`NARSIL_*` environment variables, `.narsil.yaml` in the repository,
`~/.config/narsil-xref/config.yaml`.

A profile in `config.yaml` names a set of repositories and options:

```yaml
version: "1.0"
profiles:
  dev:
    repos:
      - ~/src/api
      - ~/src/web
    git: true
    call_graph: true
    persist: true
    expose: [code, git]
```

```bash
narsil-xref --profile dev
narsil-xref config show        # effective configuration
```

[docs/configuration.md](docs/configuration.md) lists every setting.

## Tools

`narsil-xref tools list` prints every tool with its description.
`--expose code,git` offers only those tool groups to the client; each
offered tool's description costs context in every request.
[docs/tools.md](docs/tools.md) describes the tools and groups.

## Languages

Symbols are extracted from Rust, Python, JavaScript, TypeScript, Go, C,
C++, Java, C#, Bash, Ruby, Kotlin, PHP, Swift, Verilog/SystemVerilog,
Scala, Lua, Haskell, Elixir, Clojure, Dart, Julia, R, Perl, Zig, Erlang,
Elm, Fortran, PowerShell, Nix and Groovy.

## Visualization

`cargo build --release --features frontend` embeds a web UI that draws
call graphs; [docs/frontend.md](docs/frontend.md) explains it.

## Differences from narsil-mcp

Removed:

- security scanning and taint analysis
- supply-chain analysis (SBOM, licences, dependency and upgrade checks)
- the code context graph (CCG) export and the RDF/SPARQL knowledge graph
- neural embeddings
- remote GitHub repositories
- the WASM build
- the lint tools (dead code, dead stores, uninitialized variables, type inference)
- the import-graph and chunk/similarity retrieval tools
- tool presets and editor detection

Added or fixed:

- C and C++ symbols and call graphs from tree-sitter, clangd, ccls and gtags
  are checked against each other
- call graph fixes: incoming calls survive file updates, call sites match by
  line and name, functions inside parse errors are kept
- one SSE server per config profile, which stdio sessions of the editors
  delegate to, with systemd socket activation and a memory watchdog

Most of these changes could go back to narsil-mcp, but that would probably be
a lot of work. Most code changes since the fork were generated by an AI coding
agent.

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## License

Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or MIT
([LICENSE-MIT](LICENSE-MIT)), at your option.
