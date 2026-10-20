# Integration Tests for narsil-xref

This directory contains comprehensive end-to-end integration tests for the MCP (Model Context Protocol) server.

## Overview

The integration tests verify the full JSON-RPC protocol flow by:
1. Starting actual MCP server processes
2. Creating temporary test repositories with sample code
3. Sending JSON-RPC requests over stdin/stdout
4. Validating responses and behavior

## Test Structure

### Test Helper Classes

- **`TestMcpServer`**: Manages the MCP server process lifecycle, handles JSON-RPC communication
- **`TestRepo`**: Creates temporary directories with test code files (Rust, Python, TypeScript)

### Test Categories

#### 1. Protocol Tests
- `test_initialize_protocol`: Tests MCP initialization handshake
- `test_tools_list`: Verifies all tools are properly exposed

#### 2. Core Functionality Tests
- `test_list_repos`: Repository listing and metadata
- `test_get_project_structure`: Directory tree generation
- `test_find_symbols_rust`: Symbol extraction from Rust code
- `test_find_symbols_python`: Symbol extraction from Python code
- `test_find_symbols_typescript`: Symbol extraction from TypeScript code
- `test_get_symbol_definition`: Symbol definition retrieval with context
- `test_search_code`: Code search functionality
- `test_get_file`: File content retrieval
- `test_get_file_with_line_range`: Partial file retrieval
- `test_find_references`: Symbol reference finding
- `test_get_dependencies`: Import/dependency analysis
- `test_reindex`: Repository re-indexing

#### 3. Error Handling Tests
- `test_error_invalid_json`: Invalid JSON-RPC payloads
- `test_error_unknown_method`: Non-existent methods
- `test_error_missing_required_param`: Missing required parameters
- `test_error_nonexistent_repo`: References to non-existent repositories
- `test_error_nonexistent_file`: References to non-existent files

#### 4. Edge Cases
- `test_empty_repository`: Empty repository handling
- `test_large_file`: Performance with large files (1000+ functions)
- `test_file_with_syntax_errors`: Resilience to syntax errors
- `test_gitignore_respected`: .gitignore compliance
- `test_multiple_languages`: Multi-language repository support

#### 5. Advanced Features
- `test_symbol_filtering_by_pattern`: Name pattern filtering
- `test_symbol_filtering_by_file_pattern`: File glob pattern filtering
- `test_concurrent_requests`: Multiple sequential requests
- `test_search_with_file_pattern`: Search with file filtering

## Running the Tests

### Run all integration tests
```bash
cargo test --test integration_tests
```

### Run with single thread (recommended for debugging)
```bash
cargo test --test integration_tests -- --test-threads=1
```

### Run specific test
```bash
cargo test --test integration_tests test_find_symbols_rust
```

### Run with output
```bash
cargo test --test integration_tests -- --nocapture
```

## Test Fixtures

Each test creates temporary repositories with sample code:

### Rust Example
```rust
pub struct User {
    pub name: String,
    pub age: u32,
}

pub fn process_user(user: &User) -> bool {
    true
}
```

### Python Example
```python
class Calculator:
    def add(self, a, b):
        return a + b

def multiply(x, y):
    return x * y
```

### TypeScript Example
```typescript
interface User {
    name: string;
    email: string;
}

class UserService {
    getUser(id: ID): User {
        return { name: "test", email: "test@example.com" };
    }
}
```

## Requirements

- The `narsil-xref` binary must be built before running tests
- Tests use the `tempfile` crate for isolated test fixtures
- Each test spawns a fresh server process to ensure isolation

## Build Before Testing

```bash
# Build the binary first
cargo build --bin narsil-xref

# Then run tests
cargo test --test integration_tests
```

## Test Timing

- Tests run sequentially to avoid port conflicts and resource contention
- Each test includes a 2-3 second sleep to allow indexing to complete
- Total test suite takes approximately 50-60 seconds

## Coverage

The integration tests cover:
- âœ… All 9 MCP tools (list_repos, get_project_structure, find_symbols, etc.)
- âœ… JSON-RPC protocol compliance
- âœ… Multi-language parsing (Rust, Python, TypeScript, JavaScript, Go, C, C++, Java)
- âœ… Error handling and edge cases
- âœ… Search and filtering capabilities
- âœ… File system operations (.gitignore, large files, syntax errors)

## Continuous Integration

These tests are suitable for CI/CD pipelines:
```yaml
- name: Run integration tests
  run: |
    cargo build --bin narsil-xref
    cargo test --test integration_tests -- --test-threads=1
```

## Debugging Failed Tests

If tests fail:

1. Check the binary builds successfully:
   ```bash
   cargo build --bin narsil-xref
   ```

2. Run individual tests with output:
   ```bash
   cargo test --test integration_tests test_name -- --nocapture
   ```

3. Check for stderr output (server logs) during test execution

4. Verify tree-sitter grammars are properly installed (Cargo.toml dependencies)

## Adding New Tests

To add a new test:

1. Create a test function with `#[test]` annotation
2. Use `TestRepo::new()` to create a temporary repository
3. Add test files using `repo.add_rust_file()`, `repo.add_python_file()`, etc.
4. Start server with `TestMcpServer::start_with_repo()`
5. Wait for indexing: `std::thread::sleep(Duration::from_secs(2))`
6. Call tools and assert on responses

Example:
```rust
#[test]
fn test_my_feature() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file("src/lib.rs", "pub fn hello() {}")?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let response = server.call_tool("find_symbols", json!({
        "repo": repo.path().file_name().unwrap().to_str().unwrap(),
        "symbol_type": "function"
    }))?;

    assert!(response["error"].is_null());
    Ok(())
}
```

## Known Limitations

- Tests use polling (sleep) rather than proper synchronization for indexing completion
- Some tests may be sensitive to timing on slow machines
- TypeScript/TSX support depends on tree-sitter-typescript grammar availability
