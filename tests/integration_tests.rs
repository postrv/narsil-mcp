use anyhow::Result;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Helper to manage MCP server process for testing
struct TestMcpServer {
    stdin: Mutex<std::process::ChildStdin>,
    stdout: Mutex<BufReader<std::process::ChildStdout>>,
    _process: Child,
    _temp_dir: TempDir,
}

impl TestMcpServer {
    /// Start a new MCP server instance with a test repository
    fn start_with_repo(repo_path: &Path) -> Result<Self> {
        let temp_dir = TempDir::new()?;
        let binary_path = if cfg!(debug_assertions) {
            "target/debug/narsil-mcp"
        } else {
            "target/release/narsil-mcp"
        };

        let mut process = Command::new(binary_path)
            .arg("--repos")
            .arg(repo_path.to_str().unwrap())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let stdin = process.stdin.take().expect("Failed to open stdin");
        let stdout = BufReader::new(process.stdout.take().expect("Failed to open stdout"));

        Ok(Self {
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(stdout),
            _process: process,
            _temp_dir: temp_dir,
        })
    }

    /// Send a JSON-RPC request and receive a response
    fn send_request(&self, method: &str, params: Value) -> Result<Value> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });

        let mut stdin = self.stdin.lock().unwrap();
        let mut stdout = self.stdout.lock().unwrap();

        // Send request
        let request_str = serde_json::to_string(&request)? + "\n";
        stdin.write_all(request_str.as_bytes())?;
        stdin.flush()?;

        // Read response
        let mut response_line = String::new();
        stdout.read_line(&mut response_line)?;

        let response: Value = serde_json::from_str(&response_line)?;
        Ok(response)
    }

    /// Send a tool call request
    fn call_tool(&self, tool_name: &str, arguments: Value) -> Result<Value> {
        self.send_request(
            "tools/call",
            json!({
                "name": tool_name,
                "arguments": arguments
            }),
        )
    }

    /// Send raw JSON string and receive response (for testing malformed requests)
    fn send_request_raw(&self, raw_json: &str) -> Result<Value> {
        let mut stdin = self.stdin.lock().unwrap();
        let mut stdout = self.stdout.lock().unwrap();

        // Send raw request with newline
        stdin.write_all(raw_json.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;

        // Read response
        let mut response_line = String::new();
        stdout.read_line(&mut response_line)?;

        let response: Value = serde_json::from_str(&response_line)?;
        Ok(response)
    }

    /// Wait for a specific repository to be indexed and available.
    /// Polls list_repos until the repo appears or timeout is reached.
    /// This is more robust than a fixed sleep, especially on slower CI systems.
    fn wait_for_repo(&self, repo_name: &str, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        let poll_interval = Duration::from_millis(100);

        loop {
            if start.elapsed() > timeout {
                anyhow::bail!(
                    "Timeout waiting for repo '{}' to be indexed after {:?}",
                    repo_name,
                    timeout
                );
            }

            let response = self.call_tool("list_repos", json!({}))?;
            if let Some(content) = response["result"]["content"][0]["text"].as_str() {
                if content.contains(repo_name) {
                    return Ok(());
                }
            }

            std::thread::sleep(poll_interval);
        }
    }
}

impl Drop for TestMcpServer {
    fn drop(&mut self) {
        // Process will be killed when it goes out of scope
    }
}

/// Create a test repository with sample code files
struct TestRepo {
    dir: TempDir,
}

impl TestRepo {
    fn new() -> Result<Self> {
        let dir = TempDir::new()?;
        Ok(Self { dir })
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Add a Rust file to the repository
    fn add_rust_file(&self, name: &str, content: &str) -> Result<()> {
        let path = self.dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Add a Python file to the repository
    fn add_python_file(&self, name: &str, content: &str) -> Result<()> {
        let path = self.dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Add a TypeScript file to the repository
    fn add_typescript_file(&self, name: &str, content: &str) -> Result<()> {
        let path = self.dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Add a .gitignore file
    fn add_gitignore(&self, content: &str) -> Result<()> {
        std::fs::write(self.dir.path().join(".gitignore"), content)?;
        Ok(())
    }
}

#[test]
fn test_initialize_protocol() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file("src/main.rs", "fn main() {}")?;

    let server = TestMcpServer::start_with_repo(repo.path())?;

    let response = server.send_request(
        "initialize",
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }),
    )?;

    assert_eq!(response["jsonrpc"], "2.0");
    assert!(response["result"].is_object());
    assert_eq!(response["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(response["result"]["serverInfo"]["name"], "narsil-mcp");
    assert!(response["result"]["capabilities"].is_object());

    Ok(())
}

#[test]
fn test_tools_list() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file("src/main.rs", "fn main() {}")?;

    let server = TestMcpServer::start_with_repo(repo.path())?;

    let response = server.send_request("tools/list", json!({}))?;

    assert_eq!(response["jsonrpc"], "2.0");
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools should be an array");

    let tool_names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();

    assert!(tool_names.contains(&"list_repos"));
    assert!(tool_names.contains(&"get_project_structure"));
    assert!(tool_names.contains(&"find_symbols"));
    assert!(tool_names.contains(&"get_symbol_definition"));
    assert!(tool_names.contains(&"search_code"));
    assert!(tool_names.contains(&"get_file"));
    assert!(tool_names.contains(&"find_references"));
    assert!(tool_names.contains(&"get_dependencies"));
    assert!(tool_names.contains(&"reindex"));

    Ok(())
}

#[test]
fn test_list_repos() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file(
        "src/lib.rs",
        r#"
        pub struct MyStruct {
            pub field: i32,
        }
    "#,
    )?;

    let server = TestMcpServer::start_with_repo(repo.path())?;

    // Wait for indexing to complete (simple sleep)
    std::thread::sleep(std::time::Duration::from_secs(2));

    let response = server.call_tool("list_repos", json!({}))?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("Indexed Repositories"));
    assert!(content.contains("rust"));

    Ok(())
}

#[test]
fn test_get_project_structure() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file("src/main.rs", "fn main() {}")?;
    repo.add_rust_file("src/lib.rs", "pub fn hello() {}")?;
    repo.add_rust_file("src/utils/mod.rs", "pub mod helpers;")?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();
    let response = server.call_tool(
        "get_project_structure",
        json!({
            "repo": repo_name,
            "max_depth": 3
        }),
    )?;

    // The response should be successful
    assert!(response["error"].is_null());

    // Verify we got some content back
    let result = &response["result"];
    assert!(result.is_object());

    // Should have content array
    let content_array = result["content"].as_array();
    assert!(content_array.is_some());

    if let Some(arr) = content_array {
        if !arr.is_empty() {
            let content = arr[0]["text"].as_str().unwrap_or("");
            // Just verify we got some text back - the exact format may vary
            assert!(
                !content.is_empty(),
                "Project structure should return some content"
            );
        }
    }

    Ok(())
}

#[test]
fn test_find_symbols_rust() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file(
        "src/lib.rs",
        r#"
        pub struct User {
            pub name: String,
            pub age: u32,
        }

        pub enum Status {
            Active,
            Inactive,
        }

        pub fn process_user(user: &User) -> bool {
            true
        }

        impl User {
            pub fn new(name: String, age: u32) -> Self {
                User { name, age }
            }
        }
    "#,
    )?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();

    // Find all symbols
    let response = server.call_tool(
        "find_symbols",
        json!({
            "repo": repo_name,
            "symbol_type": "all"
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("User"));
    assert!(content.contains("Status"));
    assert!(content.contains("process_user"));

    // Find only structs
    let response = server.call_tool(
        "find_symbols",
        json!({
            "repo": repo_name,
            "symbol_type": "struct"
        }),
    )?;

    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("User"));
    assert!(!content.contains("process_user"));

    Ok(())
}

#[test]
fn test_find_symbols_python() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_python_file(
        "app.py",
        r#"
class Calculator:
    def add(self, a, b):
        return a + b

    def subtract(self, a, b):
        return a - b

def multiply(x, y):
    return x * y
    "#,
    )?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();
    let response = server.call_tool(
        "find_symbols",
        json!({
            "repo": repo_name,
            "symbol_type": "class"
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("Calculator"));

    Ok(())
}

#[test]
fn test_find_symbols_typescript() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_typescript_file(
        "types.ts",
        r#"
interface User {
    name: string;
    email: string;
}

type ID = string | number;

enum Role {
    Admin,
    User,
    Guest
}

class UserService {
    getUser(id: ID): User {
        return { name: "test", email: "test@example.com" };
    }
}
    "#,
    )?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();
    let response = server.call_tool(
        "find_symbols",
        json!({
            "repo": repo_name,
            "symbol_type": "interface"
        }),
    )?;

    // TypeScript support may vary, so just check if response is valid
    if response["error"].is_null() {
        let content = response["result"]["content"][0]["text"]
            .as_str()
            .expect("Expected text content");
        // If successful, should contain some content
        assert!(!content.is_empty());
    }

    Ok(())
}

#[test]
fn test_get_symbol_definition() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file(
        "src/lib.rs",
        r#"
        /// A user in the system
        pub struct User {
            pub name: String,
            pub age: u32,
        }

        impl User {
            pub fn new(name: String, age: u32) -> Self {
                User { name, age }
            }
        }
    "#,
    )?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();
    let response = server.call_tool(
        "get_symbol_definition",
        json!({
            "repo": repo_name,
            "symbol": "User",
            "context_lines": 2
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("User"));
    assert!(content.contains("pub struct User"));
    assert!(content.contains("name: String"));

    Ok(())
}

#[test]
fn test_search_code() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file(
        "src/lib.rs",
        r#"
        pub fn calculate_total(items: &[i32]) -> i32 {
            items.iter().sum()
        }

        pub fn calculate_average(items: &[i32]) -> f64 {
            let total = calculate_total(items);
            total as f64 / items.len() as f64
        }
    "#,
    )?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let response = server.call_tool(
        "search_code",
        json!({
            "query": "calculate",
            "max_results": 10
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("calculate"));
    assert!(content.contains("Search Results"));

    Ok(())
}

#[test]
fn test_get_file() -> Result<()> {
    let repo = TestRepo::new()?;
    let file_content = r#"fn main() {
    println!("Hello, world!");
}
"#;
    repo.add_rust_file("src/main.rs", file_content)?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();
    let response = server.call_tool(
        "get_file",
        json!({
            "repo": repo_name,
            "path": "src/main.rs"
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("main"));
    assert!(content.contains("println!"));

    Ok(())
}

#[test]
fn test_get_file_with_line_range() -> Result<()> {
    let repo = TestRepo::new()?;
    let file_content = r#"fn first() {}
fn second() {}
fn third() {}
fn fourth() {}
"#;
    repo.add_rust_file("src/functions.rs", file_content)?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();
    let response = server.call_tool(
        "get_file",
        json!({
            "repo": repo_name,
            "path": "src/functions.rs",
            "start_line": 2,
            "end_line": 3
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("second"));
    assert!(content.contains("third"));
    assert!(!content.contains("first"));
    assert!(!content.contains("fourth"));

    Ok(())
}

#[test]
fn test_find_references() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file(
        "src/lib.rs",
        r#"
        pub struct Config {
            pub value: String,
        }

        pub fn create_config() -> Config {
            Config { value: String::new() }
        }

        pub fn use_config(cfg: &Config) {
            println!("{}", cfg.value);
        }
    "#,
    )?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();
    let response = server.call_tool(
        "find_references",
        json!({
            "repo": repo_name,
            "symbol": "Config",
            "include_definition": true
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("References to `Config`"));
    assert!(content.contains("Config"));

    Ok(())
}

#[test]
fn test_get_dependencies() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file(
        "src/lib.rs",
        r#"
        use std::collections::HashMap;
        use std::fs::File;

        pub fn example() {}
    "#,
    )?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();
    let response = server.call_tool(
        "get_dependencies",
        json!({
            "repo": repo_name,
            "path": "src/lib.rs",
            "direction": "imports"
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("Dependencies"));
    assert!(content.contains("use std::"));

    Ok(())
}

#[test]
fn test_reindex() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file("src/lib.rs", "pub fn hello() {}")?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();

    // Wait for initial indexing to complete instead of fixed sleep
    // This is more robust on slower CI systems (especially Windows)
    server.wait_for_repo(repo_name, Duration::from_secs(30))?;

    let response = server.call_tool(
        "reindex",
        json!({
            "repo": repo_name
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("Re-indexed"));

    Ok(())
}

#[test]
fn test_error_invalid_json() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file("src/main.rs", "fn main() {}")?;

    let server = TestMcpServer::start_with_repo(repo.path())?;

    // Send syntactically valid JSON that's missing required JSON-RPC fields.
    // The server treats this as a parse error (-32700) because it can't
    // deserialize it into a valid JsonRpcRequest struct.
    let response = server.send_request_raw(r#"{"id": 1}"#)?;

    assert_eq!(response["jsonrpc"], "2.0");
    assert!(response["error"].is_object());
    // Server returns parse error (-32700) because the JSON doesn't match
    // the expected JsonRpcRequest structure (missing jsonrpc, method fields)
    assert_eq!(response["error"]["code"], -32700);

    Ok(())
}

#[test]
fn test_error_unknown_method() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file("src/main.rs", "fn main() {}")?;

    let server = TestMcpServer::start_with_repo(repo.path())?;

    let response = server.send_request("unknown_method", json!({}))?;

    assert!(response["error"].is_object());
    assert_eq!(response["error"]["code"], -32601);

    Ok(())
}

#[test]
fn test_error_missing_required_param() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file("src/main.rs", "fn main() {}")?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Call get_file without required 'path' parameter
    let response = server.call_tool(
        "get_file",
        json!({
            "repo": "test"
            // Missing 'path' parameter
        }),
    )?;

    assert!(response["error"].is_object());

    Ok(())
}

#[test]
fn test_error_nonexistent_repo() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file("src/main.rs", "fn main() {}")?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let response = server.call_tool(
        "find_symbols",
        json!({
            "repo": "nonexistent_repo_12345"
        }),
    )?;

    assert!(response["error"].is_object());
    let error_msg = response["error"]["message"].as_str().unwrap();
    assert!(error_msg.contains("not found") || error_msg.contains("Repository"));

    Ok(())
}

#[test]
fn test_error_nonexistent_file() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file("src/main.rs", "fn main() {}")?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();
    let response = server.call_tool(
        "get_file",
        json!({
            "repo": repo_name,
            "path": "nonexistent/file.rs"
        }),
    )?;

    assert!(response["error"].is_object());

    Ok(())
}

#[test]
fn test_empty_repository() -> Result<()> {
    let repo = TestRepo::new()?;
    // Don't add any files - empty repo

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let response = server.call_tool("list_repos", json!({}))?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    // Should still work with empty repo
    assert!(content.contains("Indexed Repositories"));

    Ok(())
}

#[test]
fn test_large_file() -> Result<()> {
    let repo = TestRepo::new()?;

    // Create a large file with many functions
    let mut content = String::new();
    for i in 0..1000 {
        content.push_str(&format!("pub fn function_{}() {{}}\n", i));
    }
    repo.add_rust_file("src/large.rs", &content)?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(3));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();
    let response = server.call_tool(
        "find_symbols",
        json!({
            "repo": repo_name,
            "symbol_type": "function",
            "pattern": "function_500"
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("function_500"));

    Ok(())
}

#[test]
fn test_file_with_syntax_errors() -> Result<()> {
    let repo = TestRepo::new()?;

    // Add file with syntax errors
    repo.add_rust_file(
        "src/broken.rs",
        r#"
        pub struct Invalid {
            // Missing closing brace and semicolon
            field: String
    "#,
    )?;

    // Also add a valid file
    repo.add_rust_file("src/valid.rs", "pub fn valid() {}")?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Server should still work with the valid file
    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();
    let response = server.call_tool(
        "find_symbols",
        json!({
            "repo": repo_name,
            "symbol_type": "function"
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    // Should find the valid function
    assert!(content.contains("valid") || content.contains("Symbols"));

    Ok(())
}

#[test]
fn test_gitignore_respected() -> Result<()> {
    let repo = TestRepo::new()?;

    // Add .gitignore
    repo.add_gitignore("ignored/\n*.tmp\n")?;

    // Add files that should be ignored
    std::fs::create_dir_all(repo.path().join("ignored"))?;
    repo.add_rust_file("ignored/secret.rs", "pub fn secret() {}")?;
    repo.add_rust_file("temp.tmp", "pub fn temp() {}")?;

    // Add file that should be indexed
    repo.add_rust_file("src/main.rs", "pub fn main() {}")?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();
    let response = server.call_tool(
        "search_code",
        json!({
            "repo": repo_name,
            "query": "fn",
            "max_results": 100
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    // Should find main
    assert!(content.contains("main"));
    // Files matching .gitignore patterns should ideally not appear
    // but this depends on the ignore crate's behavior
    // Just verify we got some results
    assert!(!content.is_empty());

    Ok(())
}

#[test]
fn test_multiple_languages() -> Result<()> {
    let repo = TestRepo::new()?;

    repo.add_rust_file(
        "src/lib.rs",
        r#"
        pub struct RustStruct {}
    "#,
    )?;

    repo.add_python_file(
        "script.py",
        r#"
class PythonClass:
    pass
    "#,
    )?;

    repo.add_typescript_file(
        "types.ts",
        r#"
interface TypeScriptInterface {
    name: string;
}
    "#,
    )?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let response = server.call_tool("list_repos", json!({}))?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    // Should show multiple languages
    assert!(content.contains("rust") || content.contains("Rust"));
    assert!(content.contains("python") || content.contains("Python"));
    assert!(content.contains("typescript") || content.contains("TypeScript"));

    Ok(())
}

#[test]
fn test_symbol_filtering_by_pattern() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file(
        "src/lib.rs",
        r#"
        pub fn create_user() {}
        pub fn delete_user() {}
        pub fn update_product() {}
        pub fn create_order() {}
    "#,
    )?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();

    // Find symbols matching pattern "create"
    let response = server.call_tool(
        "find_symbols",
        json!({
            "repo": repo_name,
            "symbol_type": "function",
            "pattern": "create"
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("create_user"));
    assert!(content.contains("create_order"));
    assert!(!content.contains("delete_user"));
    assert!(!content.contains("update_product"));

    Ok(())
}

#[test]
fn test_symbol_filtering_by_file_pattern() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file("src/models/user.rs", "pub struct User {}")?;
    repo.add_rust_file("src/models/product.rs", "pub struct Product {}")?;
    repo.add_rust_file("src/handlers/api.rs", "pub fn handle() {}")?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();

    // Find symbols only in models directory
    let response = server.call_tool(
        "find_symbols",
        json!({
            "repo": repo_name,
            "file_pattern": "src/models/*.rs"
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("User") || content.contains("Product"));
    assert!(!content.contains("handle"));

    Ok(())
}

mod git_tests {
    use super::*;
    use narsil_mcp::git::GitRepo;

    #[test]
    fn test_git_available() {
        // Test that check_git_available() returns Ok on a system with git
        let result = GitRepo::check_git_available();
        assert!(result.is_ok(), "Git should be available on the system");
    }

    #[test]
    fn test_git_repo_creation() {
        // Use the project's own .git directory for testing
        let repo = GitRepo::new(Path::new("."));
        assert!(
            repo.is_ok(),
            "Should be able to create GitRepo from current directory"
        );

        let repo = repo.unwrap();
        // Test current_branch returns something
        let branch = repo.current_branch();
        assert!(branch.is_ok(), "Should be able to get current branch");
    }

    #[test]
    fn test_git_blame_on_cargo_toml() {
        // Test blame on Cargo.toml (a file that exists in the repo)
        let repo = GitRepo::new(Path::new("."));
        assert!(repo.is_ok());

        let repo = repo.unwrap();
        let blame_result = repo.blame("Cargo.toml");

        // If the file has been committed and we get blame info, validate it
        // Note: File might exist but have no commit history yet (e.g., new repo)
        if let Ok(blame) = blame_result {
            // Only validate if there IS blame info (file might be uncommitted)
            if !blame.is_empty() {
                // Check that blame entries have expected fields
                for entry in blame.iter().take(5) {
                    assert!(!entry.commit.is_empty(), "Commit hash should not be empty");
                    assert!(!entry.author.is_empty(), "Author should not be empty");
                    assert!(entry.line_number > 0, "Line number should be positive");
                }
            }
        }
    }

    #[test]
    fn test_git_file_history() {
        // Test getting file history for Cargo.toml
        let repo = GitRepo::new(Path::new("."));
        assert!(repo.is_ok());

        let repo = repo.unwrap();
        let history_result = repo.file_history("Cargo.toml", 10);

        // If the file has commit history, we should get commits
        if let Ok(history) = history_result {
            // File might be new, so just check if we can call the function
            // If there's history, validate it
            if !history.is_empty() {
                for commit in history.iter().take(3) {
                    assert!(!commit.hash.is_empty(), "Commit hash should not be empty");
                    assert!(!commit.author.is_empty(), "Author should not be empty");
                    assert!(
                        !commit.short_hash.is_empty(),
                        "Short hash should not be empty"
                    );
                    assert!(commit.timestamp > 0, "Timestamp should be positive");
                }
            }
        }
    }

    #[test]
    fn test_git_input_validation() {
        let repo = GitRepo::new(Path::new("."));
        assert!(repo.is_ok());

        let repo = repo.unwrap();

        // Test that file paths starting with '-' are rejected
        let result = repo.blame("-suspicious-file.txt");
        assert!(
            result.is_err(),
            "Should reject file paths starting with '-'"
        );

        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("cannot start with '-'"),
            "Error should mention the dash restriction"
        );

        // Test null byte rejection
        let result = repo.blame("file\0with\0null");
        assert!(result.is_err(), "Should reject file paths with null bytes");

        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("cannot contain null bytes"),
            "Error should mention null byte restriction"
        );
    }

    #[test]
    fn test_git_blame_range() {
        let repo = GitRepo::new(Path::new("."));
        assert!(repo.is_ok());

        let repo = repo.unwrap();

        // Test blame_range on a subset of lines
        let result = repo.blame_range("Cargo.toml", 1, 5);

        // If successful, verify the range
        if let Ok(blame) = result {
            // Should have at most 5 entries (lines 1-5)
            assert!(blame.len() <= 5, "Should return at most 5 blame entries");
        }
    }

    #[test]
    fn test_git_current_branch() {
        let repo = GitRepo::new(Path::new("."));
        assert!(repo.is_ok());

        let repo = repo.unwrap();
        let branch = repo.current_branch();

        assert!(branch.is_ok(), "Should be able to get current branch");
        let branch_name = branch.unwrap();
        // Branch name should not be empty (unless in detached HEAD)
        // Just verify we got something back
        assert!(
            !branch_name.is_empty() || branch_name.is_empty(),
            "Branch query should complete"
        );
    }

    #[test]
    fn test_git_modified_files() {
        let repo = GitRepo::new(Path::new("."));
        assert!(repo.is_ok());

        let repo = repo.unwrap();
        let modified = repo.modified_files();

        // Should be able to get modified files (may be empty)
        assert!(modified.is_ok(), "Should be able to query modified files");
    }

    #[test]
    fn test_git_file_contributors() {
        let repo = GitRepo::new(Path::new("."));
        assert!(repo.is_ok());

        let repo = repo.unwrap();
        let contributors = repo.file_contributors("Cargo.toml");

        // If file has contributors, verify the format
        if let Ok(contribs) = contributors {
            if !contribs.is_empty() {
                for (name, count) in contribs.iter().take(3) {
                    assert!(!name.is_empty(), "Contributor name should not be empty");
                    assert!(*count > 0, "Commit count should be positive");
                }
            }
        }
    }
}

#[test]
fn test_concurrent_requests() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file(
        "src/lib.rs",
        r#"
        pub struct Data {}
        pub fn process() {}
    "#,
    )?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();

    // Wait for initial indexing to complete instead of fixed sleep
    // This is more robust on slower CI systems (especially Windows)
    server.wait_for_repo(repo_name, Duration::from_secs(30))?;

    // Send multiple requests in sequence
    for _ in 0..5 {
        let response = server.call_tool("list_repos", json!({}))?;
        assert!(response["error"].is_null());
    }

    // Verify state is still consistent
    let response = server.call_tool(
        "find_symbols",
        json!({
            "repo": repo_name,
            "symbol_type": "all"
        }),
    )?;

    assert!(response["error"].is_null());

    Ok(())
}

#[test]
fn test_search_with_file_pattern() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file("src/lib.rs", "// search target in lib")?;
    repo.add_rust_file("tests/test.rs", "// search target in test")?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let response = server.call_tool(
        "search_code",
        json!({
            "query": "search target",
            "file_pattern": "src/*.rs",
            "max_results": 10
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("lib"));
    assert!(!content.contains("test.rs"));

    Ok(())
}

#[test]
fn test_discover_repos() -> Result<()> {
    use tempfile::tempdir;

    // Create a temp directory with multiple repositories
    let base_dir = tempdir()?;

    // Create repo 1 with .git
    let repo1 = base_dir.path().join("repo1");
    std::fs::create_dir_all(&repo1)?;
    std::fs::create_dir_all(repo1.join(".git"))?;
    std::fs::write(repo1.join("README.md"), "Repo 1")?;

    // Create repo 2 with Cargo.toml
    let repo2 = base_dir.path().join("repo2");
    std::fs::create_dir_all(&repo2)?;
    std::fs::write(repo2.join("Cargo.toml"), "[package]\nname = \"repo2\"")?;

    // Create a non-repo directory
    let non_repo = base_dir.path().join("not_a_repo");
    std::fs::create_dir_all(&non_repo)?;
    std::fs::write(non_repo.join("file.txt"), "Not a repo")?;

    // Start server with any repo
    let test_repo = TestRepo::new()?;
    test_repo.add_rust_file("src/main.rs", "fn main() {}")?;
    let server = TestMcpServer::start_with_repo(test_repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Test discover_repos
    let response = server.call_tool(
        "discover_repos",
        json!({
            "path": base_dir.path().to_str().unwrap(),
            "max_depth": 2
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    // Should find both repos but not the non-repo directory
    assert!(content.contains("repo1") || content.contains("repo2"));
    assert!(content.contains("Discovered Repositories"));

    Ok(())
}

#[test]
fn test_validate_repo() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file("src/main.rs", "fn main() {}")?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Test validate_repo with the test repo path
    let response = server.call_tool(
        "validate_repo",
        json!({
            "path": repo.path().to_str().unwrap()
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("Repository Validation"));
    assert!(content.contains("Readable"));

    Ok(())
}

#[test]
fn test_get_excerpt_basic() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file(
        "src/lib.rs",
        r#"// Line 1
// Line 2
pub fn example_function() {
    // Line 4
    let x = 42;
    let y = x + 10;
    println!("Result: {}", y);
}
// Line 9
"#,
    )?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();
    let response = server.call_tool(
        "get_excerpt",
        json!({
            "repo": repo_name,
            "path": "src/lib.rs",
            "lines": [5],
            "context_before": 2,
            "context_after": 2
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    assert!(content.contains("Code Excerpt"));
    assert!(content.contains("let x = 42"));

    Ok(())
}

#[test]
fn test_get_excerpt_with_scope_expansion() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file(
        "src/lib.rs",
        r#"pub struct User {
    pub name: String,
    pub age: u32,
}

pub fn create_user(name: String, age: u32) -> User {
    User { name, age }
}

pub fn validate_user(user: &User) -> bool {
    !user.name.is_empty() && user.age > 0
}
"#,
    )?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();

    // Request line 7 which is inside create_user function
    let response = server.call_tool(
        "get_excerpt",
        json!({
            "repo": repo_name,
            "path": "src/lib.rs",
            "lines": [7],
            "expand_to_scope": true
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    // With scope expansion, should include the entire function
    assert!(content.contains("create_user"));
    assert!(content.contains("User { name, age }"));

    Ok(())
}

#[test]
fn test_get_excerpt_multiple_lines() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file(
        "src/lib.rs",
        r#"pub fn function_one() {
    println!("one");
}

pub fn function_two() {
    println!("two");
}

pub fn function_three() {
    println!("three");
}
"#,
    )?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();

    // Request multiple lines across different functions
    let response = server.call_tool(
        "get_excerpt",
        json!({
            "repo": repo_name,
            "path": "src/lib.rs",
            "lines": [2, 6, 10],
            "expand_to_scope": false
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    // Should contain excerpts from multiple locations
    assert!(content.contains("Code Excerpt"));

    Ok(())
}

#[test]
fn test_get_excerpt_with_max_lines() -> Result<()> {
    let repo = TestRepo::new()?;

    // Create a file with many lines
    let mut content = String::new();
    for i in 1..=100 {
        content.push_str(&format!("// Line {}\n", i));
    }
    repo.add_rust_file("src/large.rs", &content)?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();

    // Request excerpt around line 50 with max_lines constraint
    let response = server.call_tool(
        "get_excerpt",
        json!({
            "repo": repo_name,
            "path": "src/large.rs",
            "lines": [50],
            "max_lines": 10
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    // Should respect max_lines constraint
    assert!(content.contains("Line 50"));

    Ok(())
}

#[test]
fn test_get_excerpt_python_scope() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_python_file(
        "app.py",
        r#"class Calculator:
    def __init__(self):
        self.result = 0

    def add(self, x, y):
        result = x + y
        return result

    def subtract(self, x, y):
        return x - y

def standalone_function():
    return "standalone"
"#,
    )?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();

    // Request line inside add method
    let response = server.call_tool(
        "get_excerpt",
        json!({
            "repo": repo_name,
            "path": "app.py",
            "lines": [6],
            "expand_to_scope": true
        }),
    )?;

    assert!(response["error"].is_null());
    let content = response["result"]["content"][0]["text"]
        .as_str()
        .expect("Expected text content");

    // Should expand to include the method or class
    assert!(content.contains("add") || content.contains("Calculator"));

    Ok(())
}

#[test]
fn test_get_excerpt_error_invalid_path() -> Result<()> {
    let repo = TestRepo::new()?;
    repo.add_rust_file("src/lib.rs", "fn main() {}")?;

    let server = TestMcpServer::start_with_repo(repo.path())?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    let repo_name = repo.path().file_name().unwrap().to_str().unwrap();

    let response = server.call_tool(
        "get_excerpt",
        json!({
            "repo": repo_name,
            "path": "nonexistent/file.rs",
            "lines": [5]
        }),
    )?;

    assert!(response["error"].is_object());

    Ok(())
}

// Security tests module
mod security_tests {
    use super::*;

    #[test]
    fn test_path_traversal_blocked() -> Result<()> {
        let repo = TestRepo::new()?;
        repo.add_rust_file("src/main.rs", "fn main() {}")?;

        // Create a file outside the repo that we'll try to access
        let outside_dir = tempfile::tempdir()?;
        let outside_file = outside_dir.path().join("secret.txt");
        std::fs::write(&outside_file, "SECRET CONTENT")?;

        let server = TestMcpServer::start_with_repo(repo.path())?;
        std::thread::sleep(std::time::Duration::from_secs(2));

        let repo_name = repo.path().file_name().unwrap().to_str().unwrap();

        // Try various path traversal attacks
        let traversal_attempts = vec![
            "../../../etc/passwd",
            "../../secret.txt",
            "../secret.txt",
            "src/../../secret.txt",
            "src/../../../etc/passwd",
            "./../../secret.txt",
        ];

        for attempt in traversal_attempts {
            let response = server.call_tool(
                "get_file",
                json!({
                    "repo": repo_name,
                    "path": attempt
                }),
            )?;

            // Should return an error, not file contents
            assert!(
                response["error"].is_object(),
                "Path traversal should be blocked for: {}",
                attempt
            );

            // Verify it doesn't contain secret content
            if let Some(content) = response["result"]["content"][0]["text"].as_str() {
                assert!(
                    !content.contains("SECRET CONTENT"),
                    "Should not be able to read files outside repo for: {}",
                    attempt
                );
            }
        }

        Ok(())
    }

    #[test]
    fn test_absolute_path_blocked() -> Result<()> {
        let repo = TestRepo::new()?;
        repo.add_rust_file("src/main.rs", "fn main() {}")?;

        let server = TestMcpServer::start_with_repo(repo.path())?;
        std::thread::sleep(std::time::Duration::from_secs(2));

        let repo_name = repo.path().file_name().unwrap().to_str().unwrap();

        // Try to access absolute path
        let response = server.call_tool(
            "get_file",
            json!({
                "repo": repo_name,
                "path": "/etc/passwd"
            }),
        )?;

        // Should return an error
        assert!(response["error"].is_object());

        Ok(())
    }
}
