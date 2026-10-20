use narsil_xref::callgraph::CallGraph;
use narsil_xref::parser::LanguageParser;
use narsil_xref::response_budget::ListWindow;
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

#[test]
fn test_c_static_function_call_graph() {
    let parser = LanguageParser::new().unwrap();
    let call_graph = CallGraph::new();

    // Reproduces the niova-block bug: static C functions in the same TU
    // with a 3-step call chain. find_call_path returned "No path found"
    // and get_callees/get_callers both returned 0 for all three functions.
    let c_code = r#"
static int leaf_func(int x, int y);

static int
mid_func(int x)
{
    return leaf_func(x, x + 1);
}

static int
top_func(void)
{
    return mid_func(42);
}

static int
leaf_func(int x, int y)
{
    return x + y;
}
"#;

    let tree = parser.parse_to_tree(Path::new("test.c"), c_code).unwrap();
    let files = vec![("test.c".to_string(), c_code.to_string(), tree)];
    call_graph.build_from_files(&files).unwrap();

    // top_func should call mid_func
    let top_callees = call_graph.get_callees("top_func");
    assert!(
        !top_callees.is_empty(),
        "top_func should have callees (found 0)"
    );
    assert!(
        top_callees.iter().any(|e| e.target.ends_with("::mid_func")),
        "top_func should call mid_func, got: {:?}",
        top_callees.iter().map(|e| &e.target).collect::<Vec<_>>()
    );

    // mid_func should call leaf_func
    let mid_callees = call_graph.get_callees("mid_func");
    assert!(
        !mid_callees.is_empty(),
        "mid_func should have callees (found 0)"
    );
    assert!(
        mid_callees
            .iter()
            .any(|e| e.target.ends_with("::leaf_func")),
        "mid_func should call leaf_func, got: {:?}",
        mid_callees.iter().map(|e| &e.target).collect::<Vec<_>>()
    );

    // leaf_func should have mid_func as caller
    let leaf_callers = call_graph.get_callers("leaf_func");
    assert!(
        !leaf_callers.is_empty(),
        "leaf_func should have callers (found 0)"
    );

    // find_call_path should resolve the 3-step chain
    let path = call_graph.find_call_path("top_func", "leaf_func");
    assert!(
        path.is_some(),
        "find_call_path(top_func -> leaf_func) returned None"
    );
    let path = path.unwrap();
    assert_eq!(path.len(), 3, "expected 3-step path, got: {:?}", path);
}

#[test]
fn test_c_cross_file_static_call_graph() {
    let parser = LanguageParser::new().unwrap();
    let call_graph = CallGraph::new();

    // Simulates the niop_co_submit_and_wait pattern: function defined in
    // another file, called from a static function in nclient.c-style file.
    let nclient_code = r#"
static int
rchunk_func(int *niops, int n)
{
    return submit_and_wait(niops, n);
}

static int
iterate_func(int x)
{
    return rchunk_func(&x, 1);
}

static void
top_co(void)
{
    iterate_func(99);
}
"#;

    let niop_code = r#"
int submit_and_wait(int *niops, int n)
{
    return n;
}
"#;

    let tree1 = parser
        .parse_to_tree(Path::new("src/nclient.c"), nclient_code)
        .unwrap();
    let tree2 = parser
        .parse_to_tree(Path::new("src/niop.c"), niop_code)
        .unwrap();

    let files = vec![
        ("src/nclient.c".to_string(), nclient_code.to_string(), tree1),
        ("src/niop.c".to_string(), niop_code.to_string(), tree2),
    ];
    call_graph.build_from_files(&files).unwrap();

    // The 3-step cross-file path must be found
    let path = call_graph.find_call_path("top_co", "submit_and_wait");
    assert!(
        path.is_some(),
        "find_call_path(top_co -> submit_and_wait) returned None"
    );

    // submit_and_wait must show rchunk_func as a caller
    let callers = call_graph.get_callers("submit_and_wait");
    assert!(
        !callers.is_empty(),
        "submit_and_wait should have callers (found 0)"
    );
}

#[test]
fn test_c_typedef_return_type_call_graph() {
    // Reproduces the exact niova-block pattern:
    //   nclient_write_co        → static niova_task_co_ctx (typedef void)
    //   niop_co_submit_and_wait → niova_task_co_int_ctx    (typedef int, no static)
    //
    // tree-sitter-c sees these as type_identifier (not primitive_type).
    // If the call graph misidentifies the function_definition node due to
    // the custom return type, get_callees and get_callers both return 0.
    let parser = LanguageParser::new().unwrap();
    let call_graph = CallGraph::new();

    let nclient_code = r#"
typedef void    niova_task_co_ctx;
typedef int     niova_task_co_int_ctx;

static niova_task_co_int_ctx
rchunk_submit(int *niops, int n)
{
    return niop_co_submit_and_wait(niops, n);
}

static niova_task_co_int_ctx
iterate_and_submit(int x)
{
    return rchunk_submit(&x, 1);
}

static niova_task_co_ctx
write_co(void)
{
    iterate_and_submit(99);
}
"#;

    let niop_code = r#"
typedef int     niova_task_co_int_ctx;

niova_task_co_int_ctx
niop_co_submit_and_wait(int *niops, int n)
{
    return n;
}
"#;

    let tree1 = parser
        .parse_to_tree(Path::new("src/nclient.c"), nclient_code)
        .unwrap();
    let tree2 = parser
        .parse_to_tree(Path::new("src/niop.c"), niop_code)
        .unwrap();

    let files = vec![
        ("src/nclient.c".to_string(), nclient_code.to_string(), tree1),
        ("src/niop.c".to_string(), niop_code.to_string(), tree2),
    ];
    call_graph.build_from_files(&files).unwrap();

    // write_co (typedef void return) must have outgoing edges
    let write_co_callees = call_graph.get_callees("write_co");
    assert!(
        !write_co_callees.is_empty(),
        "write_co (typedef void return) should have callees — got 0 (static typedef return type bug?)"
    );

    // niop_co_submit_and_wait (typedef int return, no static) must have callers
    let callers = call_graph.get_callers("niop_co_submit_and_wait");
    assert!(
        !callers.is_empty(),
        "niop_co_submit_and_wait should have callers — got 0"
    );

    // The full 3-step path must be resolvable
    let path = call_graph.find_call_path("write_co", "niop_co_submit_and_wait");
    assert!(
        path.is_some(),
        "find_call_path(write_co -> niop_co_submit_and_wait) returned None"
    );
}

#[test]
fn test_c_syscall_define_call_graph() {
    // Linux SYSCALL_DEFINEn expands to a function via macros, but tree-sitter-c
    // sees the unexpanded macro as a call_expression followed by a sibling body.
    // The syscall entry point must still appear as a node named after the syscall
    // (its first macro argument), and the calls in its body must be attributed to
    // it — not dropped.
    let parser = LanguageParser::new().unwrap();
    let call_graph = CallGraph::new();

    let code = r#"
static int io_submit_sqes(void *ctx, unsigned n) { return 0; }
static int helper_fn(int x) { return x; }

SYSCALL_DEFINE6(io_uring_enter, unsigned int, fd, u32, to_submit,
		u32, min_complete, u32, flags, const void __user *, argp,
		size_t, argsz)
{
	int ret;
	ret = io_submit_sqes(ctx, to_submit);
	helper_fn(ret);
	return ret;
}
"#;

    let tree = parser
        .parse_to_tree(Path::new("io_uring/io_uring.c"), code)
        .unwrap();
    let files = vec![("io_uring/io_uring.c".to_string(), code.to_string(), tree)];
    call_graph.build_from_files(&files).unwrap();

    // The syscall body's calls are attributed to io_uring_enter.
    let callees = call_graph.get_callees("io_uring_enter");
    assert!(
        callees
            .iter()
            .any(|e| e.target.ends_with("::io_submit_sqes")),
        "io_uring_enter should call io_submit_sqes — got {:?}",
        callees.iter().map(|e| &e.target).collect::<Vec<_>>()
    );
    assert!(
        callees.iter().any(|e| e.target.ends_with("::helper_fn")),
        "io_uring_enter should call helper_fn"
    );

    // io_submit_sqes must show the syscall entry point as a caller.
    let callers = call_graph.get_callers("io_submit_sqes");
    assert!(
        callers
            .iter()
            .any(|e| e.target.ends_with("::io_uring_enter")),
        "io_submit_sqes should be called by io_uring_enter — got {:?}",
        callers.iter().map(|e| &e.target).collect::<Vec<_>>()
    );
}

#[test]
fn test_c_preprocessor_split_if_is_a_degraded_region() {
    // Split opening braces make the parser absorb later definitions into ERROR.
    let parser = LanguageParser::new().unwrap();
    let call_graph = CallGraph::new();

    let code = r#"
int damaged(int value)
{
#if FEATURE
    if (value > 0) {
#else
    if (value > 1) {
#endif
        record(value);
    }

    return external(value);
}

static int caller(int value)
{
    return damaged(value);
}

static int later_function(int value)
{
    return caller(value) + unrelated(value);
}
"#;

    let tree = parser.parse_to_tree(Path::new("sample.c"), code).unwrap();
    let files = vec![("sample.c".to_string(), code.to_string(), tree)];
    call_graph.build_from_files(&files).unwrap();

    assert!(
        call_graph.get_callees("damaged").is_empty(),
        "the parser cannot identify the damaged function body"
    );

    let callees = call_graph.get_callees("caller");
    assert_eq!(callees.len(), 1);
    assert_eq!(callees[0].target, "damaged");
    let callers = call_graph.get_callers("damaged");
    assert_eq!(callers.len(), 1);
    assert_eq!(callers[0].target, "sample.c::caller");
    let callers = call_graph.get_callers("unrelated");
    assert_eq!(callers.len(), 1);
    assert_eq!(callers[0].target, "sample.c::later_function");

    let (regions, files) = call_graph
        .degraded_summary()
        .expect("the split-if body should be recorded as a degraded region");
    assert_eq!(regions, 1);
    assert_eq!(files, 1);
}

#[test]
fn test_c_call_graph_without_parse_errors_has_no_degraded_regions() {
    let parser = LanguageParser::new().unwrap();
    let call_graph = CallGraph::new();

    let code = r#"
static int helper(int x) { return x; }
static int caller(int x) { return helper(x); }
"#;

    let tree = parser.parse_to_tree(Path::new("clean.c"), code).unwrap();
    let files = vec![("clean.c".to_string(), code.to_string(), tree)];
    call_graph.build_from_files(&files).unwrap();

    assert!(call_graph.degraded_summary().is_none());
}

/// Build a repo where `hot` has `count` callers spread over two files.
fn write_hot_function_repo(root: &std::path::Path, count: usize) -> std::io::Result<()> {
    std::fs::create_dir_all(root.join("src"))?;
    std::fs::write(root.join("src/hot.rs"), "pub fn hot() {}\n")?;
    for (file, range) in [("src/a.rs", 0..count / 2), ("src/b.rs", count / 2..count)] {
        let mut body = String::new();
        for idx in range {
            body.push_str(&format!("pub fn caller_{}() {{ hot(); }}\n", idx));
        }
        std::fs::write(root.join(file), body)?;
    }
    Ok(())
}

async fn hot_function_engine(
    repo: &std::path::Path,
    index_dir: &std::path::Path,
) -> narsil_xref::index::CodeIntelEngine {
    use narsil_xref::index::{CodeIntelEngine, EngineOptions};

    let options = EngineOptions {
        call_graph_enabled: true,
        ..Default::default()
    };
    let engine =
        CodeIntelEngine::with_options(index_dir.to_path_buf(), vec![repo.to_path_buf()], options)
            .await
            .expect("engine");

    // with_options returns before the index exists; the server does this on a
    // background task and the call-graph tools refuse to answer until it runs.
    engine
        .complete_initialization()
        .await
        .expect("initialization");
    engine
}

/// A capped caller list must still say how many there are and how to get the
/// rest — a truncated list that reads as complete is worse than a long one.
#[tokio::test]
async fn get_callers_caps_and_reports_the_total() {
    let repo = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_hot_function_repo(repo.path(), 60).unwrap();
    let engine = hot_function_engine(repo.path(), index_dir.path()).await;

    let output = engine
        .get_callers(
            repo.path().to_str().unwrap(),
            "hot",
            false,
            5,
            None,
            ListWindow::new(0, narsil_xref::response_budget::DEFAULT_LIST_LIMIT),
        )
        .await
        .unwrap();

    assert!(output.contains("Found 60 direct callers"), "{}", output);
    let listing = output.split("## Remaining callers by file").next().unwrap();
    assert_eq!(listing.matches("\n- `").count(), 50, "{}", output);
    assert!(output.contains("Showing 50 of 60"), "{}", output);
    assert!(output.contains("get_callers(limit=0)"), "{}", output);
    assert!(output.contains("src/b.rs"), "{}", output);
}

/// The rendered page is cached, so a limit=0 caller must not be served the
/// capped answer produced for an earlier default-limit call.
#[tokio::test]
async fn get_callers_limit_zero_is_not_served_the_cached_page() {
    let repo = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_hot_function_repo(repo.path(), 60).unwrap();
    let engine = hot_function_engine(repo.path(), index_dir.path()).await;
    let repo_arg = repo.path().to_str().unwrap();

    let capped = engine
        .get_callers(repo_arg, "hot", false, 5, None, ListWindow::new(0, 50))
        .await
        .unwrap();
    assert!(capped.contains("Showing 50 of 60"));

    let full = engine
        .get_callers(repo_arg, "hot", false, 5, None, ListWindow::new(0, 0))
        .await
        .unwrap();
    assert_eq!(full.matches("\n- `").count(), 60, "{}", full);
    assert!(!full.contains("Showing"), "{}", full);
}

/// A repo with one C file whose only function has an `if` split across
/// #if/#else/#endif — tree-sitter cannot see this function or its calls at
/// all, so get_callers/get_callees must say the call graph may be incomplete
/// rather than presenting an empty or partial answer as exhaustive.
fn write_preprocessor_split_repo(root: &std::path::Path) -> std::io::Result<()> {
    std::fs::write(
        root.join("reply.c"),
        r#"
static int send_msg(int fd, int len) { return 0; }

int send_reply_nofree(int req, int error, int len)
{
	int out;

#if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 32
	const char *str = "err";
	if ((str == 0 && error != 0) || error > 0) {
#else
	if (error <= -1000 || error > 0) {
#endif
		error = -1;
	}

	return send_msg(req, len);
}
"#,
    )
}

#[tokio::test]
async fn get_callers_and_get_callees_report_unparsed_regions() {
    let repo = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_preprocessor_split_repo(repo.path()).unwrap();
    let engine = hot_function_engine(repo.path(), index_dir.path()).await;
    let repo_arg = repo.path().to_str().unwrap();

    let callers = engine
        .get_callers(
            repo_arg,
            "send_msg",
            false,
            5,
            None,
            ListWindow::new(0, narsil_xref::response_budget::DEFAULT_LIST_LIMIT),
        )
        .await
        .unwrap();
    assert!(
        callers.contains("could not be parsed by tree-sitter"),
        "{}",
        callers
    );

    let callees = engine
        .get_callees(
            repo_arg,
            "send_reply_nofree",
            false,
            5,
            None,
            ListWindow::new(0, narsil_xref::response_budget::DEFAULT_LIST_LIMIT),
        )
        .await
        .unwrap();
    assert!(
        callees.contains("could not be parsed by tree-sitter"),
        "{}",
        callees
    );
}

/// A repo with no unparsed regions must not carry the degraded-region
/// footnote — the note is only for a genuine coverage gap.
#[tokio::test]
async fn get_callers_omits_the_degraded_note_when_the_graph_is_complete() {
    let repo = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_hot_function_repo(repo.path(), 2).unwrap();
    let engine = hot_function_engine(repo.path(), index_dir.path()).await;

    let output = engine
        .get_callers(
            repo.path().to_str().unwrap(),
            "hot",
            false,
            5,
            None,
            ListWindow::new(0, narsil_xref::response_budget::DEFAULT_LIST_LIMIT),
        )
        .await
        .unwrap();
    assert!(!output.contains("could not be parsed by tree-sitter"), "{}", output);
}
