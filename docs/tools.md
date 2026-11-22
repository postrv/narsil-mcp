# Tool reference

narsil-xref exposes 42 MCP tools. This page says what each one answers, which
group it belongs to, and which ones not to trust.

Tool schemas cost context on **every** request, not once per session: the MCP
protocol is stateless, so the client re-sends the whole tool block with each
turn. `--expose` selects which groups ship, so a session that only navigates
source does not carry the analysis tools' schemas in its context window all
day.

## Choosing groups

```console
$ narsil-xref --expose code,git            # recommended default
$ narsil-xref --expose code                # navigation only
$ narsil-xref --expose code,git,analysis   # when you want metrics and graphs
```

Comma-separated and composable. `base` is always included. An empty `--expose`
exposes every registered tool.

Groups can also be set without touching the command line, which matters when
the invocation comes from an editor plugin. First match wins:

| where | example |
|---|---|
| `--expose` flag | `narsil-xref --expose code,git` |
| `NARSIL_EXPOSE` env | `NARSIL_EXPOSE=code,git` |
| the selected profile | `profiles: { dev: { expose: [code, git] } }` |
| top-level config | `expose: [code, git]` in `config.yaml` |

The last one is the machine-wide default. Note that a stdio instance which
delegates to a running SSE daemon (see `--transport sse`) serves the
**daemon's** tool list — its own `--expose` cannot apply, and it says so in a
warning.

### What `--expose` does and does not do

It filters `tools/list` — what a client is told about — and `tools/call`
refuses anything outside the groups, so the two agree. The refusal names the
group and says not to retry:

```
Tool 'get_complexity' is not available on this server: its group 'analysis' is
not exposed (this server serves: base, code, git). This is a fixed server
configuration, not a transient failure — do not retry 'get_complexity', and
expect every other 'analysis' tool to be unavailable too. To enable it, add
'analysis' to --expose or to `expose:` in config.yaml and restart the server.
```

Clients are also told when the set changes. The server advertises
`"tools": {"listChanged": true}`, and after the stdio proxy transparently
reconnects to a restarted daemon it emits
`notifications/tools/list_changed` to the client, which re-reads `tools/list`.

That one path is the only place a client's view can go stale without it
noticing — the tool set is fixed for a process lifetime, so nothing polls or
diffs anything. The notification is a single ~60-byte line per reconnect, and
it is skipped entirely when the request that hit the restart was itself a
`tools/list`, since that reply already carries the new list.

One limit worth knowing: the HTTP `/tools/call` route used by the
visualization frontend is unaffected; it is a local UI surface, not an MCP
client. So `--expose` is a context-window budget with a guard rail, not an
access-control boundary.

| group | tools | in the recommended default? |
|---|---|---|
| `base` | 8 | always |
| `code` | 20 | yes |
| `git` | 9 | yes |
| `analysis` | 5 | no — derived from source you can already read |

The line between `code` and the opt-in `analysis` group is **retrieval
versus restatement**. A tool belongs in `code` when it answers something the
caller cannot work out from source it is already holding — where a symbol
lives, who calls it, what the LSP knows. A tool belongs in `analysis` when its
answer is derivable from code already in view: a complexity number, a listing
of the branches in a function you are reading. Paying schema bytes on every
request to offer the second kind is a bad trade.

Two tools sit in `code` despite looking like analysis. `get_call_graph` returns
callers, callees and metrics in one round trip instead of two calls, and
`get_reaching_definitions` answers "where did this value come from" across a
function too long to hold in view — both are retrieval in substance.

### `base` — which repos, and is the index fresh

Always exposed. Without these a client cannot name a repository or recover from
a stale index. If a navigation call returns nothing unexpectedly, `reindex` is
the documented first move.

### `code` — what is this code

The bulk of everyday use: symbols, references, search, file text, LSP lookups,
call edges per-symbol and as a graph, def-use chains. Seven of these tools
carry 87% of all recorded traffic.

### `git` — why is it like this

Blame, file and symbol history, commit diffs, branch state, contributors.
Belongs in the default: with git tools absent an agent told to use narsil for
blame finds nothing and falls back to raw `git`, which is what routing it here
was meant to prevent.

### `analysis` — derived from code you can already read

Complexity metrics, connectivity hotspots, and per-function control and data
flow, plus `get_code_graph`, which only the HTTP frontend calls. A model
holding the source can work all of this out unaided, so it is off by default.

Enable it deliberately, and read the caveats first — two of them return wrong
answers today: `get_function_hotspots` ranks std method names (`len`,
`is_empty`) as the codebase's most-connected functions, and `get_data_flow`
takes ~13 s for one function and emits the false positives described below.
`get_complexity` is correct.

## Tools by group

<!-- BEGIN GENERATED: narsil-xref tools list --format markdown -->

### `base`

| tool | required args | what it answers |
|---|---|---|
| `discover_repos` | path | Auto-discover repositories in a directory by detecting VCS roots and project markers |
| `forget_repo` | — | Drop a repository from the index, freeing the memory and the on-disk store it held |
| `get_incremental_status` | — | Get status of incremental indexing including Merkle tree root hash, file counts, and change statistics |
| `get_index_status` | — | Get status of the search index and enabled features |
| `get_metrics` | — | Get performance metrics including tool execution times, indexing statistics, and server uptime |
| `list_repos` | — | List indexed repositories (path, file/line counts) |
| `reindex` | — | Re-index one repository or all of them |
| `validate_repo` | path | Check whether a path is a repository narsil can index, before adding it |

### `code`

| tool | required args | what it answers |
|---|---|---|
| `find_call_path` | from, to | Find the call path between two functions |
| `find_references` | symbol | Every reference to a symbol, unioning LSP hits with text matches |
| `find_symbol_usages` | symbol | Usages of a symbol including its imports and re-exports, cross-language aware for JS/TS |
| `find_symbols` | — | Find structs, classes, enums, interfaces, functions and methods by name pattern or kind |
| `get_call_graph` | — | Callers, callees and complexity for one function in a single call, or the whole repository's graph |
| `get_callees` | function | Find functions called by a given function |
| `get_callers` | function | Find functions that call a given function |
| `get_dependencies` | path | Imports and module dependencies of one source file |
| `get_excerpt` | path | Context around a list of specific line numbers, expanded to function or class boundaries |
| `get_export_map` | path | Get the export map for a file or module showing all exported symbols and their types |
| `get_file` | path | File contents, optionally one contiguous start_line..end_line range |
| `get_hover_info` | path, line, character | Get hover information (type info, documentation) for a symbol at a specific position |
| `get_project_structure` | — | Get the directory structure and key files of a repository |
| `get_reaching_definitions` | path, function | Get reaching definitions analysis - which variable assignments reach each point in the code |
| `get_symbol_definition` | symbol | Get the full definition of a symbol with surrounding context |
| `get_type_info` | path, line, character | Get precise type information for a symbol |
| `go_to_definition` | path, line, character | Find the definition location of a symbol at a specific position |
| `hybrid_search` | query | Fuses keyword ranking with TF-IDF similarity (Reciprocal Rank Fusion) |
| `search_code` | query | Keyword and phrase search across code — the default when you know the terms to look for |
| `semantic_search` | query | Ranked search for a natural-language description of code, using BM25 with code-aware tokenization |

### `git`

| tool | required args | what it answers |
|---|---|---|
| `get_blame` | path | Get git blame information for a file |
| `get_branch_info` | — | Get current branch name and repository status |
| `get_commit_diff` | commit | Get the diff for a specific commit |
| `get_commit_range` | base | List commits in base..branch and their merge-base, oldest first |
| `get_contributors` | — | Get contributors to a file or repository |
| `get_file_history` | path | Get git commit history for a file |
| `get_hotspots` | — | Find code hotspots - files with high churn and complexity |
| `get_modified_files` | — | Get list of modified files in the working tree |
| `get_recent_changes` | — | Get recent commits across the repository |
| `get_symbol_history` | symbol | Get commits that modified a specific symbol/function |

### `analysis`

| tool | required args | what it answers |
|---|---|---|
| `get_code_graph` | — | Whole-repo graph data as raw JSON for the visualization frontend |
| `get_complexity` | function | Get complexity metrics (cyclomatic, cognitive) for a function |
| `get_control_flow` | path, function | Get the control flow graph (CFG) for a function, showing basic blocks, branches, and loops |
| `get_data_flow` | path, function | Get data flow analysis for a function, showing variable definitions and uses |
| `get_function_hotspots` | — | Find highly connected functions (potential refactoring targets) based on call graph analysis |
<!-- END GENERATED -->

## Paging

Result size is capped per tool. Which argument does the capping is not
consistent, so check before assuming:

| argument | tools |
|---|---|
| `limit` | `find_references`, `find_symbols`, `get_callers`, `get_callees`, `get_contributors` |
| `offset` | `find_references`, `get_callers`, `get_callees`, `get_contributors` |
| `max_results` | `search_code`, `semantic_search`, `hybrid_search` |

Everything else is capped by defaults it does not let you change. A response
over 48 KB is truncated on a line boundary by the response budget with a notice
naming what was dropped.

## While an index is updating

A branch switch, a `reindex` and the initial index all rebuild a repo's index.
For as long as that lasts, a tool that reads the index answers with JSON-RPC
error **-32001** and a message starting `EAGAIN: index update in progress` —
retry the same request rather than treating the failure as an answer. The
alternative would be a reply mixing both branches, or an empty one, with
nothing to distinguish it from the truth.

The base and git groups are never refused, so `get_index_status`, `list_repos`,
`reindex` and the git tools still work while a rebuild is running. A request
that names no `repo` reads every indexed repo, so one repo mid-update is enough
to refuse it.

## Caveats

Behaviour verified by measurement, not read off the descriptions. Each is
tracked in `../../CLAUDE-narsil-xref.issues`.

**`get_data_flow` — false positives, both C and Rust.** The dataflow engine
does not seed function parameters as definitions and treats a write that
escapes the function (an out-parameter, a value moved into a struct literal)
as never read. The engine's def-use chains are fine — the seeding and the
escape modelling are not.

**`get_code_graph` — should not be reachable over MCP.** Its own description
says "HTTP-only tool, not available via MCP"; calling it returns ~714 KB of raw
JSON that only the response budget keeps from flooding the session. The HTTP
`/graph` route is its real caller.

**`get_branch_info` — grows with the branch.** Prints one line per ahead-commit
and per working-tree entry, uncapped: 15 KB on a branch 187 commits ahead.

## Keeping this current

The section between the `BEGIN GENERATED` and `END GENERATED` markers is
produced from the tool registry:

```console
$ narsil-xref tools list --format markdown > /tmp/tools.md
```

Everything outside the markers is hand-written. CI checks that the generated
block matches the registry, the same way `make autofmt-check` guards
formatting — a tool added to `tool_metadata.rs` without a group assignment
fails the build rather than silently becoming unreachable.
