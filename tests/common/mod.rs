//! Common test utilities for narsil-mcp integration testing.
//!
//! This module provides shared infrastructure for testing:
//! - `TestHarness` - manages MCP server processes
//! - `TestRepo` - creates temporary repositories with test files
//! - Assertion macros for common patterns
//! - Fixture loading utilities

use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Unique request ID generator for JSON-RPC
static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Test harness that manages an MCP server instance and test repository
pub struct TestHarness {
    server: TestMcpServer,
    repo: TestRepo,
    metrics: TestMetrics,
}

impl TestHarness {
    /// Create a new test harness with an empty repository
    pub fn new() -> Result<Self> {
        let repo = TestRepo::new()?;
        let server = TestMcpServer::start_with_repo(repo.path())?;
        Ok(Self {
            server,
            repo,
            metrics: TestMetrics::new(),
        })
    }

    /// Create a harness with a pre-built fixture
    pub fn with_fixture(fixture_name: &str) -> Result<Self> {
        let repo = TestRepo::from_fixture(fixture_name)?;
        let server = TestMcpServer::start_with_repo(repo.path())?;
        Ok(Self {
            server,
            repo,
            metrics: TestMetrics::new(),
        })
    }

    /// Create a harness with multiple features enabled
    pub fn with_features(features: &[&str]) -> Result<Self> {
        let repo = TestRepo::new()?;
        let server = TestMcpServer::start_with_features(repo.path(), features)?;
        Ok(Self {
            server,
            repo,
            metrics: TestMetrics::new(),
        })
    }

    /// Get the test repository
    pub fn repo(&self) -> &TestRepo {
        &self.repo
    }

    /// Add a file to the repository
    pub fn add_file(&self, path: &str, content: &str) -> Result<PathBuf> {
        self.repo.add_file(path, content)
    }

    /// Trigger reindexing after adding files
    pub fn reindex(&self) -> Result<Value> {
        self.call_tool("reindex", json!({}))
    }

    /// Initialize the MCP protocol
    pub fn initialize(&self) -> Result<Value> {
        self.server.send_request(
            "initialize",
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"}
            }),
        )
    }

    /// List available tools
    pub fn list_tools(&self) -> Result<Value> {
        self.server.send_request("tools/list", json!({}))
    }

    /// Call a tool and return the result
    pub fn call_tool(&self, name: &str, arguments: Value) -> Result<Value> {
        let start = Instant::now();
        let result = self.server.call_tool(name, arguments);
        self.metrics.record_call(name, start.elapsed());
        result
    }

    /// Call a tool and extract the text content from the response
    pub fn call_tool_text(&self, name: &str, arguments: Value) -> Result<String> {
        let response = self.call_tool(name, arguments)?;
        extract_text_content(&response)
    }

    /// Get test metrics
    pub fn metrics(&self) -> &TestMetrics {
        &self.metrics
    }

    /// Get the repository name as registered with the server
    pub fn repo_name(&self) -> String {
        self.repo
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string()
    }
}

/// Manages an MCP server process for testing
pub struct TestMcpServer {
    stdin: Mutex<std::process::ChildStdin>,
    stdout: Mutex<BufReader<std::process::ChildStdout>>,
    _process: Child,
}

impl TestMcpServer {
    /// Start a new MCP server with the given repository path
    pub fn start_with_repo(repo_path: &Path) -> Result<Self> {
        Self::start_with_features(repo_path, &[])
    }

    /// Start a new MCP server with specific features enabled
    pub fn start_with_features(repo_path: &Path, features: &[&str]) -> Result<Self> {
        let binary_path = get_binary_path();

        let mut args = vec!["--repos".to_string(), repo_path.to_string_lossy().to_string()];

        for feature in features {
            args.push(format!("--{}", feature));
        }

        let mut process = Command::new(binary_path)
            .args(&args)
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
        })
    }

    /// Send a JSON-RPC request and receive a response
    pub fn send_request(&self, method: &str, params: Value) -> Result<Value> {
        let id = REQUEST_ID.fetch_add(1, Ordering::SeqCst);
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
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

    /// Call a tool with the given arguments
    pub fn call_tool(&self, tool_name: &str, arguments: Value) -> Result<Value> {
        self.send_request(
            "tools/call",
            json!({
                "name": tool_name,
                "arguments": arguments
            }),
        )
    }

    /// Wait for a specific repository to be indexed and available.
    /// Polls list_repos until the repo appears or timeout is reached.
    /// This is more robust than a fixed sleep, especially on slower CI systems.
    pub fn wait_for_repo(&self, repo_name: &str, timeout: Duration) -> Result<()> {
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

/// Test repository builder
pub struct TestRepo {
    dir: TempDir,
    files: Vec<PathBuf>,
}

impl TestRepo {
    /// Create a new empty test repository
    pub fn new() -> Result<Self> {
        let dir = TempDir::new()?;
        Ok(Self {
            dir,
            files: Vec::new(),
        })
    }

    /// Create a test repository from a fixture
    pub fn from_fixture(fixture_name: &str) -> Result<Self> {
        let mut repo = Self::new()?;

        match fixture_name {
            "rust_basic" => {
                repo.add_rust_basic()?;
            }
            "python_basic" => {
                repo.add_python_basic()?;
            }
            "typescript_basic" => {
                repo.add_typescript_basic()?;
            }
            "multi_language" => {
                repo.add_rust_basic()?;
                repo.add_python_basic()?;
                repo.add_typescript_basic()?;
            }
            "security_samples" => {
                repo.add_security_samples()?;
            }
            "call_graph_samples" => {
                repo.add_call_graph_samples()?;
            }
            "large_codebase" => {
                repo.add_large_codebase()?;
            }
            _ => {
                anyhow::bail!("Unknown fixture: {}", fixture_name);
            }
        }

        Ok(repo)
    }

    /// Get the repository path
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Get the list of files added to the repository
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// Add a file to the repository
    pub fn add_file(&self, relative_path: &str, content: &str) -> Result<PathBuf> {
        let path = self.dir.path().join(relative_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, content)?;
        Ok(path)
    }

    /// Add a .gitignore file
    pub fn add_gitignore(&self, content: &str) -> Result<()> {
        self.add_file(".gitignore", content)?;
        Ok(())
    }

    // Fixture builders

    fn add_rust_basic(&mut self) -> Result<()> {
        self.add_file(
            "src/lib.rs",
            r#"//! A simple library for testing.

/// A greeting function
pub fn greet(name: &str) -> String {
    format!("Hello, {}!", name)
}

/// Adds two numbers
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

/// A simple struct
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    /// Creates a new point
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }

    /// Calculates distance from origin
    pub fn distance_from_origin(&self) -> f64 {
        (self.x * self.x + self.y * self.y).sqrt()
    }
}

/// An example trait
pub trait Drawable {
    fn draw(&self);
}

/// An enumeration
pub enum Color {
    Red,
    Green,
    Blue,
    Rgb(u8, u8, u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_greet() {
        assert_eq!(greet("World"), "Hello, World!");
    }

    #[test]
    fn test_add() {
        assert_eq!(add(2, 3), 5);
    }
}
"#,
        )?;

        self.add_file(
            "src/main.rs",
            r#"use mylib::{greet, Point};

fn main() {
    println!("{}", greet("Rust"));

    let p = Point::new(3.0, 4.0);
    println!("Distance: {}", p.distance_from_origin());
}
"#,
        )?;

        Ok(())
    }

    fn add_python_basic(&mut self) -> Result<()> {
        self.add_file(
            "src/main.py",
            r#"""Main module for Python testing."""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class User:
    """Represents a user in the system."""
    name: str
    email: str
    age: Optional[int] = None


class UserService:
    """Service for managing users."""

    def __init__(self):
        self.users: List[User] = []

    def add_user(self, user: User) -> None:
        """Add a user to the system."""
        self.users.append(user)

    def find_by_email(self, email: str) -> Optional[User]:
        """Find a user by email address."""
        for user in self.users:
            if user.email == email:
                return user
        return None

    def get_all_users(self) -> List[User]:
        """Get all registered users."""
        return self.users.copy()


def validate_email(email: str) -> bool:
    """Validate an email address format."""
    return "@" in email and "." in email


def main():
    """Main entry point."""
    service = UserService()
    user = User("John", "john@example.com", 30)
    service.add_user(user)
    print(f"Added user: {user.name}")


if __name__ == "__main__":
    main()
"#,
        )?;

        self.add_file(
            "src/utils.py",
            r#"""Utility functions."""

def format_name(first: str, last: str) -> str:
    """Format a full name."""
    return f"{first} {last}"


def calculate_average(numbers: list) -> float:
    """Calculate the average of a list of numbers."""
    if not numbers:
        return 0.0
    return sum(numbers) / len(numbers)
"#,
        )?;

        Ok(())
    }

    fn add_typescript_basic(&mut self) -> Result<()> {
        self.add_file(
            "src/index.ts",
            r#"/**
 * Main entry point for TypeScript testing.
 */

import { UserService, User } from './user';

interface Config {
    apiUrl: string;
    timeout: number;
    retries: number;
}

type Status = 'pending' | 'active' | 'inactive';

enum LogLevel {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
}

class Application {
    private config: Config;
    private userService: UserService;

    constructor(config: Config) {
        this.config = config;
        this.userService = new UserService();
    }

    async start(): Promise<void> {
        console.log(`Starting with API: ${this.config.apiUrl}`);
    }

    getStatus(): Status {
        return 'active';
    }
}

function greet(name: string): string {
    return `Hello, ${name}!`;
}

const add = (a: number, b: number): number => a + b;

export { Application, Config, Status, LogLevel, greet, add };
"#,
        )?;

        self.add_file(
            "src/user.ts",
            r#"/**
 * User module for TypeScript testing.
 */

export interface User {
    id: number;
    name: string;
    email: string;
    createdAt: Date;
}

export class UserService {
    private users: User[] = [];
    private nextId: number = 1;

    addUser(name: string, email: string): User {
        const user: User = {
            id: this.nextId++,
            name,
            email,
            createdAt: new Date(),
        };
        this.users.push(user);
        return user;
    }

    findById(id: number): User | undefined {
        return this.users.find(u => u.id === id);
    }

    findByEmail(email: string): User | undefined {
        return this.users.find(u => u.email === email);
    }

    getAllUsers(): User[] {
        return [...this.users];
    }

    deleteUser(id: number): boolean {
        const index = this.users.findIndex(u => u.id === id);
        if (index >= 0) {
            this.users.splice(index, 1);
            return true;
        }
        return false;
    }
}
"#,
        )?;

        Ok(())
    }

    fn add_security_samples(&mut self) -> Result<()> {
        // SQL Injection sample
        self.add_file(
            "src/vulnerable_sql.py",
            r#"""Vulnerable SQL examples for testing."""

def search_users_unsafe(conn, name):
    """VULNERABLE: Direct string interpolation in SQL."""
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return conn.execute(query)


def search_users_safe(conn, name):
    """SAFE: Parameterized query."""
    query = "SELECT * FROM users WHERE name = ?"
    return conn.execute(query, (name,))
"#,
        )?;

        // XSS sample
        self.add_file(
            "src/vulnerable_xss.js",
            r#"/**
 * XSS vulnerability examples.
 */

// VULNERABLE: Direct insertion of user input
function displayMessage(userInput) {
    document.getElementById('output').innerHTML = userInput;
}

// SAFE: Using textContent
function displayMessageSafe(userInput) {
    document.getElementById('output').textContent = userInput;
}

// VULNERABLE: Template literal XSS
app.get('/search', (req, res) => {
    res.send(`<h1>Results for: ${req.query.q}</h1>`);
});

// SAFE: Escaped output
const escape = require('escape-html');
app.get('/search-safe', (req, res) => {
    res.send(`<h1>Results for: ${escape(req.query.q)}</h1>`);
});
"#,
        )?;

        // Command injection sample
        self.add_file(
            "src/vulnerable_command.rs",
            r#"//! Command injection examples.

use std::process::Command;

/// VULNERABLE: Direct command interpolation
fn run_ping_unsafe(host: &str) {
    let cmd = format!("ping -c 1 {}", host);
    Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .spawn()
        .expect("failed");
}

/// SAFE: Argument passing
fn run_ping_safe(host: &str) {
    Command::new("ping")
        .args(["-c", "1", host])
        .spawn()
        .expect("failed");
}
"#,
        )?;

        // Hardcoded secrets
        self.add_file(
            "src/secrets.py",
            r#"""Hardcoded secrets examples."""

# VULNERABLE: Hardcoded API key
API_KEY = "sk-1234567890abcdef"

# VULNERABLE: Hardcoded password
DATABASE_PASSWORD = "super_secret_password"

# SAFE: Environment variable
import os
SAFE_API_KEY = os.environ.get("API_KEY")
"#,
        )?;

        Ok(())
    }

    fn add_call_graph_samples(&mut self) -> Result<()> {
        self.add_file(
            "src/call_chain.rs",
            r#"//! Call graph test samples.

fn entry_point() {
    middle_function();
}

fn middle_function() {
    helper_a();
    helper_b();
}

fn helper_a() {
    leaf_function();
}

fn helper_b() {
    leaf_function();
}

fn leaf_function() {
    // No outgoing calls
}

fn recursive_function(n: i32) {
    if n > 0 {
        recursive_function(n - 1);
    }
}

fn mutual_a() {
    mutual_b();
}

fn mutual_b() {
    mutual_a();
}
"#,
        )?;

        Ok(())
    }

    fn add_large_codebase(&mut self) -> Result<()> {
        // Generate a large number of files for performance testing
        for i in 0..100 {
            let content = format!(
                r#"//! Module {i}

pub fn function_{i}_a(x: i32) -> i32 {{
    x + {i}
}}

pub fn function_{i}_b(x: i32) -> i32 {{
    function_{i}_a(x) * 2
}}

pub struct Struct{i} {{
    pub field_a: i32,
    pub field_b: String,
}}

impl Struct{i} {{
    pub fn new() -> Self {{
        Self {{
            field_a: {i},
            field_b: String::from("module_{i}"),
        }}
    }}

    pub fn process(&self) -> i32 {{
        function_{i}_a(self.field_a)
    }}
}}
"#
            );
            self.add_file(&format!("src/module_{}.rs", i), &content)?;
        }

        // Add a main file that imports all modules
        let mut imports = String::new();
        for i in 0..100 {
            imports.push_str(&format!("mod module_{};\n", i));
        }
        self.add_file("src/lib.rs", &imports)?;

        Ok(())
    }
}

/// Test metrics for performance tracking
pub struct TestMetrics {
    calls: Mutex<HashMap<String, Vec<Duration>>>,
}

impl TestMetrics {
    fn new() -> Self {
        Self {
            calls: Mutex::new(HashMap::new()),
        }
    }

    fn record_call(&self, tool: &str, duration: Duration) {
        let mut calls = self.calls.lock().unwrap();
        calls
            .entry(tool.to_string())
            .or_default()
            .push(duration);
    }

    /// Get average duration for a tool
    pub fn average_duration(&self, tool: &str) -> Option<Duration> {
        let calls = self.calls.lock().unwrap();
        calls.get(tool).map(|durations| {
            let total: Duration = durations.iter().sum();
            total / durations.len() as u32
        })
    }

    /// Get all recorded metrics
    pub fn all_metrics(&self) -> HashMap<String, (usize, Duration)> {
        let calls = self.calls.lock().unwrap();
        calls
            .iter()
            .map(|(tool, durations)| {
                let count = durations.len();
                let avg = durations.iter().sum::<Duration>() / count as u32;
                (tool.clone(), (count, avg))
            })
            .collect()
    }
}

// Helper functions

fn get_binary_path() -> PathBuf {
    let path = if cfg!(debug_assertions) {
        "target/debug/narsil-mcp"
    } else {
        "target/release/narsil-mcp"
    };
    PathBuf::from(path)
}

/// Extract text content from a JSON-RPC tool response
pub fn extract_text_content(response: &Value) -> Result<String> {
    let result = response
        .get("result")
        .ok_or_else(|| anyhow::anyhow!("No result in response"))?;

    if let Some(content) = result.get("content") {
        if let Some(arr) = content.as_array() {
            for item in arr {
                if let Some(text) = item.get("text") {
                    return Ok(text.as_str().unwrap_or("").to_string());
                }
            }
        }
    }

    // Try isError case
    if let Some(is_error) = result.get("isError") {
        if is_error.as_bool() == Some(true) {
            if let Some(content) = result.get("content") {
                if let Some(arr) = content.as_array() {
                    for item in arr {
                        if let Some(text) = item.get("text") {
                            anyhow::bail!("Tool error: {}", text.as_str().unwrap_or(""));
                        }
                    }
                }
            }
        }
    }

    anyhow::bail!("Could not extract text content from response")
}

/// Check if a response indicates success
pub fn is_success(response: &Value) -> bool {
    response.get("result").is_some() && response.get("error").is_none()
}

/// Check if a response indicates an error
pub fn is_error(response: &Value) -> bool {
    response.get("error").is_some()
}

// Assertion macros

/// Assert that symbols contain a specific name
#[macro_export]
macro_rules! assert_symbols_contain {
    ($symbols:expr, $name:expr) => {
        assert!(
            $symbols.iter().any(|s| s.name == $name),
            "Expected to find symbol '{}' in {:?}",
            $name,
            $symbols.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
    };
}

/// Assert that a response is successful
#[macro_export]
macro_rules! assert_success {
    ($response:expr) => {
        assert!(
            $crate::common::is_success(&$response),
            "Expected success but got: {:?}",
            $response
        );
    };
}

/// Assert that a response is an error
#[macro_export]
macro_rules! assert_error {
    ($response:expr) => {
        assert!(
            $crate::common::is_error(&$response),
            "Expected error but got: {:?}",
            $response
        );
    };
}

/// Assert that text content contains a substring
#[macro_export]
macro_rules! assert_content_contains {
    ($response:expr, $substring:expr) => {{
        let text = $crate::common::extract_text_content(&$response)
            .expect("Failed to extract text content");
        assert!(
            text.contains($substring),
            "Expected content to contain '{}' but got: {}",
            $substring,
            text
        );
    }};
}
