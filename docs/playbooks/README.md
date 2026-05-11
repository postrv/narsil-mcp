# narsil-mcp Playbooks

Practical guides showing how AI assistants use narsil-mcp's code intelligence tools.

## How It Works

narsil-mcp is an **MCP server** - it gives AI assistants like Claude direct access to code intelligence tools. When you chat with Claude about your codebase, Claude automatically calls these tools to:

- Navigate and understand code
- Search for patterns and symbols
- Analyze dependencies and call graphs
- Scan for security vulnerabilities
- Track git history and blame

**You don't need plugins, agents, or skills.** The MCP protocol is built into Claude Desktop, Claude Code, VS Code (Copilot), Cursor, and other tools. You just configure the server once, and Claude gains 90 code intelligence capabilities.

## Quick Example

**You say:** "How does authentication work in this project?"

**Claude automatically:**
1. Calls `search_code` with query "authentication"
2. Calls `find_symbols` to find auth-related classes/functions
3. Calls `get_callers` to see what calls the auth functions
4. Calls `get_file` to read the relevant source code
5. Synthesizes an answer with specific file/line references

You never see the tool calls - Claude just answers with accurate, grounded information.

## Playbooks

### Getting Started
- **[Quick Start](getting-started.md)** - Install, configure, verify it's working

### Workflows
Step-by-step guides for common development tasks:

| Workflow | Description | Key Tools Used |
|----------|-------------|----------------|
| [Understand a Codebase](workflows/understand-codebase.md) | Explore an unfamiliar project | `get_project_structure`, `find_symbols`, `search_code`, `get_dependencies` |
| [Fix a Bug](workflows/fix-a-bug.md) | Debug and trace issues | `search_code`, `get_callers`, `get_control_flow`, `trace_taint` |
| [Security Audit](workflows/security-audit.md) | Find vulnerabilities | `scan_security`, `check_owasp_top10`, `trace_taint`, `check_dependencies` |
| [Code Review](workflows/code-review.md) | Review changes effectively | `get_modified_files`, `get_blame`, `get_callers`, `get_complexity` |

### Tool Chains
See exactly which tools Claude calls for different tasks:

| Task | Tool Chain |
|------|------------|
| "What does this function do?" | `find_symbols` → `get_symbol_definition` → `get_callers` |
| "Find where X is used" | `find_references` → `find_symbol_usages` → `get_excerpt` |
| "Is this code secure?" | `scan_security` → `trace_taint` → `suggest_fix` |
| "Who wrote this?" | `get_blame` → `get_symbol_history` → `get_contributors` |

### Integrations
Setup guides for each supported platform:

- [Claude Desktop](integrations/claude-desktop.md)
- [Claude Code (CLI)](integrations/claude-code.md)
- [VS Code with Copilot](integrations/vscode-copilot.md)
- [Cursor](integrations/cursor.md)

## Common Questions

### "Is this a plugin/agent/skill?"

No - it's a **server** that speaks the MCP protocol. Think of it like a language server (LSP) but for AI assistants instead of editors. The AI client (Claude) connects to it and gains new capabilities.

### "When does Claude call these tools?"

Claude decides when to use tools based on your questions. Examples:

| You Ask | Claude Uses |
|---------|-------------|
| "What functions are in auth.py?" | `find_symbols` |
| "Find all SQL queries" | `search_code` |
| "What calls this function?" | `get_callers` |
| "Is there any XSS risk?" | `check_owasp_top10`, `trace_taint` |
| "Show me the git history" | `get_file_history`, `get_blame` |

### "Do I need to tell Claude to use specific tools?"

No. Claude automatically picks the right tools based on context. But you can be specific if you want:
- "Use the call graph to show what calls `handleAuth`"
- "Run an OWASP scan on the API routes"
- "Generate an SBOM for this project"

### "What makes this different from just reading files?"

narsil-mcp gives Claude **semantic understanding**:

| Without narsil-mcp | With narsil-mcp |
|-------------------|-----------------|
| Claude reads raw text | Claude understands symbols, types, relationships |
| "grep for function name" | Cross-reference aware symbol search |
| No call graph awareness | "What calls X?" / "What does X call?" |
| Manual security review | Automated OWASP/CWE scanning with taint analysis |
| Limited git context | Blame, history, hotspots, contributor analysis |

## Next Steps

1. **[Install narsil-mcp](../INSTALL.md)** - via Homebrew, npm, cargo, or binary
2. **[Configure for your editor](getting-started.md)** - Claude Desktop, VS Code, Cursor
3. **Try a workflow** - start with [Understand a Codebase](workflows/understand-codebase.md)
