# WebAssembly (Browser) Usage

This is an experimental source-only integration. `@narsil-mcp/wasm` is not
published on npm, and the native CLI 1.7.1 release does not qualify or publish
the WASM build. The build script generates a local `pkg/` package with separate
version metadata; the examples below describe that experimental interface.

## Features

**Available in WASM:**
- Multi-language parsing (Rust, Python, JS, TS, Go, C, C++, Java, C#)
- Symbol extraction (functions, classes, structs, etc.)
- Full-text search with BM25 ranking
- TF-IDF code similarity search
- In-memory file storage

**Not available in WASM** (requires native build):
- Git integration
- File system watching
- LSP integration
- Neural embeddings (API calls)
- Index persistence

## Building the WASM Module

The WASM build requires a C compiler that supports WASM targets (for tree-sitter and compression libraries).

### Prerequisites

```bash
# Install Rust WASM target and wasm-pack
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

# Install WASM-compatible C toolchain (choose one):
# Option 1: Using Emscripten (recommended)
brew install emscripten  # macOS
# or: sudo apt install emscripten  # Ubuntu

# Option 2: Using WASI SDK
# Download from https://github.com/WebAssembly/wasi-sdk/releases
```

### Build Commands

```bash
# Build for web (browsers)
./scripts/build-wasm.sh

# Build for bundlers (webpack, vite, etc.)
./scripts/build-wasm.sh bundler

# Build for Node.js
./scripts/build-wasm.sh nodejs

# Output will be in pkg/
```

### Build Targets

| Target | Use Case | Output |
|--------|----------|--------|
| `web` | Direct browser usage, CDN | ES modules with init() |
| `bundler` | Webpack, Vite, Rollup | ES modules for bundlers |
| `nodejs` | Node.js applications | CommonJS modules |
| `deno` | Deno runtime | ES modules for Deno |

## Installation

After a successful local build, consume the generated `pkg/` directory from
your application. There is no public npm package to install. Validate the local
package and its exports for your chosen build target before using the examples.

## Basic Usage (JavaScript/TypeScript)

```typescript
import { CodeIntelClient } from '@narsil-mcp/wasm';

// Create and initialize the client
const client = new CodeIntelClient();
await client.init();

// Index files
client.indexFile('src/main.rs', rustSourceCode);
client.indexFile('src/lib.py', pythonSourceCode);

// Find symbols
const symbols = client.findSymbols('Handler');
const classes = client.findSymbols(null, 'class');

// Search code
const results = client.search('error handling');

// Find similar code
const similar = client.findSimilar('fn process_request(req: Request) -> Response');

// Get statistics
console.log(client.stats()); // { files: 2, symbols: 15, embeddings: 12 }
```

## React Example

```tsx
import { useEffect, useState } from 'react';
import { CodeIntelClient, Symbol } from '@narsil-mcp/wasm';

function CodeExplorer({ files }: { files: Record<string, string> }) {
  const [client, setClient] = useState<CodeIntelClient | null>(null);
  const [symbols, setSymbols] = useState<Symbol[]>([]);

  useEffect(() => {
    const init = async () => {
      const c = new CodeIntelClient();
      await c.init();

      // Index all files
      for (const [path, content] of Object.entries(files)) {
        c.indexFile(path, content);
      }

      setClient(c);
      setSymbols(c.findSymbols());
    };
    init();
  }, [files]);

  return (
    <ul>
      {symbols.map(s => (
        <li key={`${s.file_path}:${s.name}`}>
          {s.kind}: {s.name} ({s.file_path}:{s.start_line})
        </li>
      ))}
    </ul>
  );
}
```

## Low-Level API (WasmCodeIntel)

For more control, use the low-level `WasmCodeIntel` class directly:

```typescript
import init, { WasmCodeIntel } from '@narsil-mcp/wasm';

await init();  // Initialize WASM module

const engine = new WasmCodeIntel();
engine.index_file('main.rs', code);

// Returns JSON strings - parse them yourself
const symbolsJson = engine.find_symbols(null, 'function');
const symbols = JSON.parse(symbolsJson);
```

## API Reference

| Method | Description | Returns |
|--------|-------------|---------|
| `indexFile(path, content)` | Index a single file | `boolean` |
| `indexFiles(files)` | Bulk index `[{path, content}]` | `number` (count) |
| `findSymbols(pattern?, kind?)` | Find symbols by pattern/kind | `Symbol[]` |
| `search(query, maxResults?)` | Full-text search with BM25 | `SearchResult[]` |
| `findSimilar(code, maxResults?)` | TF-IDF similarity search | `SimilarCode[]` |
| `getFile(path)` | Get file content | `string \| null` |
| `symbolAt(path, line)` | Get symbol at line | `Symbol \| null` |
| `symbolsInFile(path)` | List symbols in file | `Symbol[]` |
| `listFiles()` | List indexed file paths | `string[]` |
| `stats()` | Get engine statistics | `Stats` |
| `clear()` | Clear all indexed data | `void` |

## TypeScript Types

```typescript
interface Symbol {
  name: string;
  kind: string;  // 'function' | 'class' | 'struct' | etc.
  file_path: string;
  start_line: number;
  end_line: number;
  signature?: string;
  doc_comment?: string;
}

interface SearchResult {
  file: string;
  start_line: number;
  end_line: number;
  content: string;
  score: number;
}

interface Stats {
  files: number;
  symbols: number;
  embeddings: number;
}
```

**Supported Symbol Kinds:** `function`, `method`, `class`, `struct`, `enum`, `interface`, `trait`, `type`, `module`, `namespace`, `constant`, `variable`

## Bundle Size

~2-3MB gzipped (includes tree-sitter parsers for all languages)

## Troubleshooting

### Build Errors

If you see errors about missing C compilers or tree-sitter during WASM build:

```bash
# macOS
xcode-select --install
brew install emscripten

# Ubuntu/Debian
sudo apt install build-essential emscripten
```

### Module Loading Errors

Ensure you're using the correct target for your environment:
- Browser: Use `web` target
- Bundler (webpack/vite): Use `bundler` target
- Node.js: Use `nodejs` target
