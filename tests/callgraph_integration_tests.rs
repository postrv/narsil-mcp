use narsil_mcp::callgraph::CallGraph;
use narsil_mcp::parser::LanguageParser;
use std::path::Path;

#[test]
fn test_rust_call_graph_simple() {
    let parser = LanguageParser::new().unwrap();
    let call_graph = CallGraph::new();

    // Simple Rust file with function calls
    let rust_code = r#"
fn main() {
    println!("Hello");
    helper();
}

fn helper() {
    worker();
}

fn worker() {
    println!("Working");
}
"#;

    // Parse the file
    let tree = parser
        .parse_to_tree(Path::new("test.rs"), rust_code)
        .unwrap();

    // Build call graph
    let files = vec![("test.rs".to_string(), rust_code.to_string(), tree)];

    call_graph.build_from_files(&files).unwrap();

    // Verify call graph structure (targets are now qualified keys: "file::name")
    let main_callees = call_graph.get_callees("main");
    assert_eq!(main_callees.len(), 1);
    assert!(
        main_callees[0].target.ends_with("::helper"),
        "expected target ending with ::helper, got: {}",
        main_callees[0].target
    );

    let helper_callees = call_graph.get_callees("helper");
    assert_eq!(helper_callees.len(), 1);
    assert!(
        helper_callees[0].target.ends_with("::worker"),
        "expected target ending with ::worker, got: {}",
        helper_callees[0].target
    );

    let worker_callers = call_graph.get_callers("worker");
    assert_eq!(worker_callers.len(), 1);
    assert!(
        worker_callers[0].target.ends_with("::helper"),
        "expected target ending with ::helper, got: {}",
        worker_callers[0].target
    );
}

#[test]
fn test_python_call_graph() {
    let parser = LanguageParser::new().unwrap();
    let call_graph = CallGraph::new();

    let python_code = r#"
def main():
    print("Hello")
    helper()

def helper():
    worker()

def worker():
    print("Working")
"#;

    let tree = parser
        .parse_to_tree(Path::new("test.py"), python_code)
        .unwrap();

    let files = vec![("test.py".to_string(), python_code.to_string(), tree)];

    call_graph.build_from_files(&files).unwrap();

    // Verify call edges - main calls helper (and also print, which is detected)
    let main_callees = call_graph.get_callees("main");
    assert!(
        !main_callees.is_empty(),
        "main should have at least one callee"
    );
    let calls_helper = main_callees.iter().any(|e| e.target.ends_with("::helper"));
    assert!(
        calls_helper,
        "main should call helper, got: {:?}",
        main_callees.iter().map(|e| &e.target).collect::<Vec<_>>()
    );
}

#[test]
fn test_javascript_call_graph() {
    let parser = LanguageParser::new().unwrap();
    let call_graph = CallGraph::new();

    let js_code = r#"
function main() {
    console.log("Hello");
    helper();
}

function helper() {
    worker();
}

function worker() {
    console.log("Working");
}
"#;

    let tree = parser.parse_to_tree(Path::new("test.js"), js_code).unwrap();

    let files = vec![("test.js".to_string(), js_code.to_string(), tree)];

    call_graph.build_from_files(&files).unwrap();

    // Verify call graph - main calls helper (and also console.log, which is detected)
    let main_callees = call_graph.get_callees("main");
    assert!(
        !main_callees.is_empty(),
        "main should have at least one callee"
    );
    let calls_helper = main_callees.iter().any(|e| e.target.ends_with("::helper"));
    assert!(
        calls_helper,
        "main should call helper, got: {:?}",
        main_callees.iter().map(|e| &e.target).collect::<Vec<_>>()
    );

    // Test transitive callees
    let transitive = call_graph.get_transitive_callees("main", 10);
    assert!(transitive.len() >= 2); // Should find helper and worker
}

#[test]
fn test_cross_file_calls() {
    let parser = LanguageParser::new().unwrap();
    let call_graph = CallGraph::new();

    // File 1: main.rs
    let file1 = r#"
mod utils;

fn main() {
    utils::helper();
}
"#;

    // File 2: utils.rs
    let file2 = r#"
pub fn helper() {
    internal_worker();
}

fn internal_worker() {
    println!("Working");
}
"#;

    let tree1 = parser.parse_to_tree(Path::new("main.rs"), file1).unwrap();
    let tree2 = parser.parse_to_tree(Path::new("utils.rs"), file2).unwrap();

    let files = vec![
        ("main.rs".to_string(), file1.to_string(), tree1),
        ("utils.rs".to_string(), file2.to_string(), tree2),
    ];

    call_graph.build_from_files(&files).unwrap();

    // Verify helper is called
    let helper_callers = call_graph.get_callers("helper");
    assert!(!helper_callers.is_empty());
}

#[test]
fn test_cross_file_scoped_call_resolution() {
    let parser = LanguageParser::new().unwrap();
    let call_graph = CallGraph::new();

    // File 1: main.rs - calls App::run()
    let main_code = r#"
fn main() {
    App::run();
}
"#;

    // File 2: src/app/mod.rs - defines run()
    let app_code = r#"
pub fn run() {
    println!("app running");
}
"#;

    // File 3: src/agents/mod.rs - also defines run()
    let agents_code = r#"
pub fn run() {
    println!("agents running");
}
"#;

    let tree1 = parser
        .parse_to_tree(Path::new("main.rs"), main_code)
        .unwrap();
    let tree2 = parser
        .parse_to_tree(Path::new("src/app/mod.rs"), app_code)
        .unwrap();
    let tree3 = parser
        .parse_to_tree(Path::new("src/agents/mod.rs"), agents_code)
        .unwrap();

    let files = vec![
        ("main.rs".to_string(), main_code.to_string(), tree1),
        ("src/app/mod.rs".to_string(), app_code.to_string(), tree2),
        (
            "src/agents/mod.rs".to_string(),
            agents_code.to_string(),
            tree3,
        ),
    ];

    call_graph.build_from_files(&files).unwrap();

    // App::run() in main should resolve to src/app/mod.rs::run, not agents
    let main_callees = call_graph.get_callees("main");
    assert!(
        !main_callees.is_empty(),
        "main should have at least one callee"
    );

    let run_call = main_callees.iter().find(|e| e.target.ends_with("::run"));
    assert!(run_call.is_some(), "main should call some ::run function");
    assert_eq!(
        run_call.unwrap().target,
        "src/app/mod.rs::run",
        "App::run() should resolve to src/app/mod.rs::run via scope hint"
    );
}

#[test]
fn test_extract_scope_from_scoped_call() {
    let parser = LanguageParser::new().unwrap();
    let call_graph = CallGraph::new();

    // Code with a scoped call
    let code = r#"
fn caller() {
    utils::helper();
}

fn helper() {
    println!("local helper");
}
"#;

    let tree = parser.parse_to_tree(Path::new("test.rs"), code).unwrap();
    let files = vec![("test.rs".to_string(), code.to_string(), tree)];

    call_graph.build_from_files(&files).unwrap();

    // The call to utils::helper() should have scope_hint populated
    let caller_callees = call_graph.get_callees("caller");
    assert!(
        !caller_callees.is_empty(),
        "caller should have at least one callee"
    );

    // Find the edge targeting helper
    let helper_edge = caller_callees
        .iter()
        .find(|e| e.target.ends_with("::helper") || e.target == "helper");
    assert!(
        helper_edge.is_some(),
        "caller should call helper, got: {:?}",
        caller_callees.iter().map(|e| &e.target).collect::<Vec<_>>()
    );

    let edge = helper_edge.unwrap();
    assert_eq!(
        edge.scope_hint,
        Some("utils".to_string()),
        "scope_hint should capture 'utils' from utils::helper()"
    );
}

#[test]
fn test_find_call_path_deterministic_with_ambiguous_names() {
    let parser = LanguageParser::new().unwrap();
    let call_graph = CallGraph::new();

    // main calls App::start(), two modules define start()
    let main_code = r#"
fn main() {
    App::start();
}
"#;

    let app_code = r#"
pub fn start() {
    work();
}

fn work() {
    println!("working");
}
"#;

    let other_code = r#"
pub fn start() {
    println!("other start");
}
"#;

    let tree1 = parser
        .parse_to_tree(Path::new("main.rs"), main_code)
        .unwrap();
    let tree2 = parser
        .parse_to_tree(Path::new("src/app/mod.rs"), app_code)
        .unwrap();
    let tree3 = parser
        .parse_to_tree(Path::new("src/other/mod.rs"), other_code)
        .unwrap();

    let files = vec![
        ("main.rs".to_string(), main_code.to_string(), tree1),
        ("src/app/mod.rs".to_string(), app_code.to_string(), tree2),
        (
            "src/other/mod.rs".to_string(),
            other_code.to_string(),
            tree3,
        ),
    ];

    call_graph.build_from_files(&files).unwrap();

    // find_call_path should give consistent results
    let path1 = call_graph.find_call_path("main", "work");
    let path2 = call_graph.find_call_path("main", "work");
    assert_eq!(path1, path2, "find_call_path must be deterministic");

    // Should find the path: main -> src/app/mod.rs::start -> src/app/mod.rs::work
    assert!(path1.is_some(), "Should find a path from main to work");
    let path = path1.unwrap();
    assert!(
        path.iter()
            .any(|p| p.contains("app") && p.contains("start")),
        "Path should go through app::start, got: {:?}",
        path
    );
}
