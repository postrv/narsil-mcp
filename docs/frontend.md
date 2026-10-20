# Visualization Frontend

narsil-xref includes an optional web-based visualization frontend for exploring call graphs, import dependencies, and code structure interactively.

## Quick Start

### Option 1: Embedded Frontend (Recommended)

Build with the `frontend` feature to embed the visualization UI in the binary:

```bash
# Build with embedded frontend
cargo build --release --features frontend

# Run with HTTP server (MCP server still works on stdio)
./target/release/narsil-xref --repos ~/project --http --call-graph

# Open http://localhost:3000 in your browser
```

The MCP server runs on stdio while the HTTP server runs in the background, so you can use both editor integration and the visualization simultaneously.

### Option 2: Development Mode

For frontend development, run the backend and frontend separately:

```bash
# Terminal 1: Start the API server
./target/release/narsil-xref --repos ~/project --http --call-graph

# Terminal 2: Start the frontend dev server
cd frontend
npm install
npm run dev
# Frontend runs on http://localhost:5173, connects to API on :3000
```

## Features

- **Interactive graph visualization** with Cytoscape.js
- **Multiple views**: call graph, import graph, symbol references, hybrid, control flow
- **Complexity metrics overlay** with color coding
- **Security vulnerability highlighting**
- **Depth control** and focused exploration (double-click to drill down)
- **Multiple layout algorithms** (hierarchical, breadth-first, circle, concentric)
- **File-based clustering**
- **Node details panel** with code excerpts

## HTTP API Endpoints

When `--http` is enabled:

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Server health check |
| `GET /tools` | List available tools |
| `POST /tools/call` | Execute any MCP tool |
| `GET /graph?repo=...&view=call&depth=3` | Get graph visualization data |

### Graph Endpoint Parameters

```
GET /graph?repo=myrepo&view=call&depth=3&function=main
```

| Parameter | Description | Default |
|-----------|-------------|---------|
| `repo` | Repository name | Required |
| `view` | Graph type: `call`, `import`, `symbol`, `hybrid`, `control_flow` | `call` |
| `depth` | Maximum depth to traverse | `3` |
| `function` | Focus on specific function (optional) | - |

## Configuration

### HTTP Port

```bash
# Use custom port (default: 3000)
narsil-xref --repos ~/project --http --http-port 8080
```

### With Editor Integration

The HTTP server runs alongside the MCP server on stdio:

```json
{
  "mcpServers": {
    "narsil-xref": {
      "command": "narsil-xref",
      "args": [
        "--repos", ".",
        "--git",
        "--call-graph",
        "--http",
        "--http-port", "3000"
      ]
    }
  }
}
```

This allows you to:
1. Use narsil-xref tools in your editor via MCP
2. Open `http://localhost:3000` to visualize the same data

## Build Sizes

| Feature | Description | Size |
|---------|-------------|------|
| `native` (default) | Full MCP server with all tools | ~30MB |
| `frontend` | + Embedded visualization web UI | ~31MB |

## Frontend Development

The frontend is a React application using:
- **Cytoscape.js** for graph rendering
- **Vite** for development server
- **TypeScript** for type safety

```bash
cd frontend
npm install
npm run dev      # Development server
npm run build    # Production build
npm run preview  # Preview production build
```

### Building Embedded Frontend

When you build with `--features frontend`, the production frontend assets are embedded in the binary using `rust-embed`. To update the embedded assets:

```bash
# Build frontend
cd frontend
npm run build

# Rebuild the binary to embed new assets
cargo build --release --features frontend
```

## Troubleshooting

### CORS Errors

The HTTP server includes CORS headers for local development. If you're accessing from a different origin, ensure the frontend is connecting to the correct API URL.

### Graph Not Loading

1. Ensure `--call-graph` flag is enabled for call graph views
2. Check that the repository is indexed (`list_repos` tool)
3. Verify the function exists (`find_symbols` tool)
