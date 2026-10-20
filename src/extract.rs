//! Intelligent code excerpt extraction
//!
//! Extracts relevant code snippets with appropriate context for AI consumption.

use std::collections::HashSet;

/// Configuration for excerpt extraction
#[derive(Debug, Clone)]
pub struct ExcerptConfig {
    /// Lines of context before the match
    pub context_before: usize,

    /// Lines of context after the match
    pub context_after: usize,

    /// Maximum excerpt length in lines
    pub max_lines: usize,

    /// Include line numbers
    pub include_line_numbers: bool,

    /// Merge overlapping excerpts
    pub merge_overlapping: bool,

    /// Expand to include complete syntactic units (functions, classes)
    pub expand_to_scope: bool,
}

impl Default for ExcerptConfig {
    fn default() -> Self {
        Self {
            context_before: 5,
            context_after: 5,
            max_lines: 50,
            include_line_numbers: true,
            merge_overlapping: true,
            expand_to_scope: true,
        }
    }
}

/// A code excerpt with metadata
#[derive(Debug, Clone)]
pub struct Excerpt {
    /// The extracted code
    pub content: String,

    /// Starting line (1-indexed)
    pub start_line: usize,

    /// Ending line (1-indexed)
    pub end_line: usize,

    /// Lines that matched the query (stored for potential highlighting)
    pub _match_lines: Vec<usize>,

    /// Relevance score (0-1)
    pub relevance: f32,
}

/// Extract excerpts from source code around match locations
pub fn extract_excerpts(
    source: &str,
    match_lines: &[usize],
    config: &ExcerptConfig,
) -> Vec<Excerpt> {
    let lines: Vec<&str> = source.lines().collect();
    let total_lines = lines.len();

    if match_lines.is_empty() || total_lines == 0 {
        return vec![];
    }

    // Calculate ranges for each match
    let mut ranges: Vec<(usize, usize, Vec<usize>)> = match_lines
        .iter()
        .map(|&line| {
            let start = line.saturating_sub(config.context_before + 1);
            let end = (line + config.context_after).min(total_lines);
            (start, end, vec![line])
        })
        .collect();

    // Merge overlapping ranges if configured
    if config.merge_overlapping {
        ranges = merge_ranges(ranges);
    }

    // Extract excerpts
    ranges
        .into_iter()
        .map(|(start, end, matches)| {
            let (final_start, final_end) = if config.expand_to_scope {
                expand_to_scope(&lines, start, end)
            } else {
                (start, end)
            };

            // Limit to max lines
            let (mut clamped_start, mut clamped_end) =
                clamp_range(final_start, final_end, &matches, config.max_lines);

            // Scope expansion is a heuristic and can settle on a scope that
            // ends before the requested line. Losing the scope is a worse
            // answer; losing the requested line is no answer at all.
            let keeps_matches = matches
                .iter()
                .all(|&line| clamped_start < line && line <= clamped_end);
            if !keeps_matches {
                let (window_start, window_end) =
                    clamp_range(start, end, &matches, config.max_lines);
                clamped_start = window_start;
                clamped_end = window_end;
            }

            let content = format_excerpt(
                &lines[clamped_start..clamped_end],
                clamped_start,
                &matches,
                config.include_line_numbers,
            );

            let relevance = calculate_relevance(&matches, clamped_start, clamped_end);

            Excerpt {
                content,
                start_line: clamped_start + 1,
                end_line: clamped_end,
                _match_lines: matches,
                relevance,
            }
        })
        .collect()
}

/// Merge overlapping or adjacent ranges
fn merge_ranges(mut ranges: Vec<(usize, usize, Vec<usize>)>) -> Vec<(usize, usize, Vec<usize>)> {
    if ranges.is_empty() {
        return ranges;
    }

    ranges.sort_by_key(|(start, _, _)| *start);

    let mut merged = vec![ranges[0].clone()];

    for (start, end, matches) in ranges.into_iter().skip(1) {
        let last = merged.last_mut().unwrap();

        // If ranges overlap or are adjacent, merge them
        if start <= last.1 + 1 {
            last.1 = last.1.max(end);
            last.2.extend(matches);
        } else {
            merged.push((start, end, matches));
        }
    }

    merged
}

/// Expand range to include complete syntactic scope (function, class, etc.)
fn expand_to_scope(lines: &[&str], start: usize, end: usize) -> (usize, usize) {
    let mut new_start = start;
    let mut new_end = end;
    let mut in_scope = false;

    // Scan backwards for a scope that reaches past `end`. One that closes
    // earlier is a sibling the scan walked over, not the enclosing scope.
    for candidate in (0..=start).rev() {
        if !is_scope_start(lines[candidate]) {
            continue;
        }

        let scope_end = match brace_scope_end(lines, candidate) {
            Some(brace_end) => brace_end,
            None => expand_by_indentation(lines, candidate, end).1,
        };

        if scope_end >= end {
            new_start = candidate;
            new_end = scope_end;
            in_scope = true;
            break;
        }
    }

    // Also expand for Python-style indentation-based scopes
    if !in_scope {
        let (py_start, py_end) = expand_by_indentation(lines, start, end);
        new_start = new_start.min(py_start);
        new_end = new_end.max(py_end);
    }

    (new_start, new_end.min(lines.len()))
}

/// End of the brace scope opened at `scope_start`, exclusive. `None` when no
/// brace ever opens — an indentation-based scope, or a line that only looked
/// like a scope start.
fn brace_scope_end(lines: &[&str], scope_start: usize) -> Option<usize> {
    let mut brace_count: i32 = 0;
    let mut opened = false;

    for (i, line) in lines.iter().enumerate().skip(scope_start) {
        brace_count += line.chars().filter(|&c| c == '{').count() as i32;
        brace_count -= line.chars().filter(|&c| c == '}').count() as i32;

        if brace_count > 0 {
            opened = true;
        } else if opened {
            return Some(i + 1);
        }
    }

    if opened {
        Some(lines.len())
    } else {
        None
    }
}

/// Check if a line starts a scope (function, class, etc.)
fn is_scope_start(line: &str) -> bool {
    let trimmed = line.trim_start();

    // Common patterns
    let patterns = [
        "fn ",
        "pub fn ",
        "async fn ",
        "pub async fn ",
        "def ",
        "async def ",
        "class ",
        "struct ",
        "enum ",
        "impl ",
        "trait ",
        "interface ",
        "function ",
        "func ",
        "module ",
        "namespace ",
    ];

    if !patterns.iter().any(|p| trimmed.starts_with(p)) {
        return false;
    }

    // A keyword alone names a type as easily as it opens a scope:
    // `struct my_holder items[2];` is a local variable, not a definition.
    // The body has to start somewhere — a brace here, or a `:` for Python.
    trimmed.contains('{') || trimmed.ends_with(':')
}

/// Expand scope based on indentation (for Python, YAML, etc.)
fn expand_by_indentation(lines: &[&str], start: usize, end: usize) -> (usize, usize) {
    if start >= lines.len() {
        return (start, end);
    }

    let base_indent = get_indent(lines[start]);
    let mut new_start = start;
    let mut new_end = end;

    // Find the start of this indentation level
    for i in (0..start).rev() {
        let indent = get_indent(lines[i]);
        if indent < base_indent && !lines[i].trim().is_empty() {
            new_start = i;
            break;
        }
    }

    // Find the end of this indentation level
    for (i, line) in lines.iter().enumerate().skip(end) {
        let indent = get_indent(line);
        if indent < base_indent && !line.trim().is_empty() {
            new_end = i;
            break;
        }
    }

    (new_start, new_end)
}

/// Get the indentation level of a line
fn get_indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Clamp range to max lines, keeping matches centered
fn clamp_range(start: usize, end: usize, matches: &[usize], max_lines: usize) -> (usize, usize) {
    let current_lines = end - start;

    if current_lines <= max_lines {
        return (start, end);
    }

    // Find the center of matches
    let match_center = matches.iter().sum::<usize>() / matches.len().max(1);

    // Center the window around the matches
    let half = max_lines / 2;
    let new_start = match_center.saturating_sub(half);
    let new_end = new_start + max_lines;

    // Adjust if we went past the end
    if new_end > end {
        let overflow = new_end - end;
        (new_start.saturating_sub(overflow), end)
    } else {
        (new_start.max(start), new_end)
    }
}

/// Format an excerpt with optional line numbers
fn format_excerpt(
    lines: &[&str],
    start_offset: usize,
    matches: &[usize],
    include_line_numbers: bool,
) -> String {
    let match_set: HashSet<_> = matches.iter().collect();

    lines
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let line_num = start_offset + i + 1;
            let marker = if match_set.contains(&line_num) {
                "→"
            } else {
                " "
            };

            if include_line_numbers {
                format!("{} {:4} │ {}", marker, line_num, line)
            } else {
                format!("{} {}", marker, line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether `text` carries the signature of UTF-8 that was read as cp1252 and
/// re-encoded: the leading byte of a multi-byte sequence surfaces as a Latin-1
/// supplement character (`â`, `ð`, `Ã`). Every excerpt narsil returned was
/// mangled that way once, in the source literals themselves.
#[cfg(test)]
pub(crate) fn is_double_encoded(text: &str) -> bool {
    text.chars().any(|ch| ('\u{c0}'..='\u{ff}').contains(&ch))
}

/// Check if a file path appears to be a test file.
///
/// Used by the `exclude_tests` search and symbol options.
///
/// # Examples
/// ```
/// use narsil_xref::extract::is_test_file;
/// assert!(is_test_file("tests/integration_tests.rs"));
/// assert!(is_test_file("src/foo_test.rs"));
/// assert!(!is_test_file("src/main.rs"));
/// ```
pub fn is_test_file(path: &str) -> bool {
    let path_lower = path.to_lowercase();

    // Directory patterns that indicate test code
    if path_lower.contains("/tests/")
        || path_lower.contains("/test/")
        || path_lower.contains("/__tests__/")
        || path_lower.contains("/fixtures/")
        || path_lower.contains("/testdata/")
        || path_lower.contains("/test_data/")
        || path_lower.contains("/mocks/")
        || path_lower.contains("/__mocks__/")
        || path_lower.contains("/spec/")
        || path_lower.starts_with("test/")
        || path_lower.starts_with("tests/")
        // Also catch test-fixtures at start of path or after a slash
        || path_lower.starts_with("test-fixtures/")
        || path_lower.contains("/test-fixtures/")
        // Security test sample directories
        || path_lower.contains("/security/vulnerable")
        || path_lower.contains("/vulnerable/")
    {
        return true;
    }

    // File name patterns
    let file_name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Rust test files
    if file_name.ends_with("_test.rs") || file_name.ends_with("_tests.rs") {
        return true;
    }

    // JavaScript/TypeScript test files
    if file_name.ends_with(".test.js")
        || file_name.ends_with(".test.ts")
        || file_name.ends_with(".test.jsx")
        || file_name.ends_with(".test.tsx")
        || file_name.ends_with(".spec.js")
        || file_name.ends_with(".spec.ts")
        || file_name.ends_with(".spec.jsx")
        || file_name.ends_with(".spec.tsx")
    {
        return true;
    }

    // Python test files
    if file_name.starts_with("test_") || file_name.ends_with("_test.py") {
        return true;
    }

    // Go test files
    if file_name.ends_with("_test.go") {
        return true;
    }

    // Java test files
    if file_name.ends_with("test.java") && file_name != "test.java" {
        return true;
    }

    // Files explicitly named as vulnerable samples
    if file_name.starts_with("vulnerable.") || file_name.starts_with("insecure.") {
        return true;
    }

    false
}

pub(crate) fn is_comment_only_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//")
        || trimmed.starts_with("///")
        || trimmed.starts_with("//!")
        || trimmed.starts_with('*')
        || trimmed.starts_with('#')
}

/// Calculate relevance score based on match density
fn calculate_relevance(matches: &[usize], start: usize, end: usize) -> f32 {
    let range_size = (end - start).max(1) as f32;
    let match_count = matches.len() as f32;

    // Higher score for denser matches
    let density = match_count / range_size;

    // Normalize to 0-1
    (density * 10.0).min(1.0)
}

/// Extract the most relevant excerpt from multiple candidates
pub fn select_best_excerpt(excerpts: &[Excerpt], max_count: usize) -> Vec<&Excerpt> {
    let mut sorted: Vec<_> = excerpts.iter().collect();
    sorted.sort_by(|a, b| {
        b.relevance
            .partial_cmp(&a.relevance)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    sorted.truncate(max_count);
    sorted
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: the gutter and the match marker were stored double-encoded
    /// in this file, so every excerpt came back with `â”‚` in place of `│`.
    #[test]
    fn excerpt_gutter_is_not_double_encoded() {
        let excerpt = format_excerpt(&["fn main() {}", "let x = 1;"], 0, &[1], true);
        assert!(excerpt.contains('│'), "gutter missing: {}", excerpt);
        assert!(excerpt.contains('→'), "match marker missing: {}", excerpt);
        assert!(!is_double_encoded(&excerpt), "mojibake: {}", excerpt);
    }

    #[test]
    fn test_extract_excerpt() {
        let source = r#"
fn main() {
    println!("Hello");
    let x = 42;
    println!("World");
}
"#;

        let config = ExcerptConfig {
            context_before: 1,
            context_after: 1,
            ..Default::default()
        };

        let excerpts = extract_excerpts(source, &[4], &config);
        assert!(!excerpts.is_empty());
        assert!(excerpts[0].content.contains("42"));
    }

    #[test]
    fn scope_expansion_starts_brace_scan_at_scope_start() {
        let source = [
            "fn main() {",
            "    if true {",
            "        work();",
            "    }",
            "}",
        ];

        assert_eq!(expand_to_scope(&source, 2, 3), (0, 5));
    }

    /// Regression: a request for one line was answered with a different line
    /// two hundred lines above it — a local variable declaration that the
    /// scope heuristic took for a scope start.
    #[test]
    fn excerpt_keeps_the_requested_line_when_scope_expansion_misfires() {
        let mut source = String::from("struct my_holder items[2];\n");
        for filler in 0..40 {
            source.push_str(&format!("\tcall_{}();\n", filler));
        }
        source.push_str("\tthe_requested_line();\n");

        let requested = source.lines().count();
        let config = ExcerptConfig {
            context_before: 20,
            context_after: 30,
            max_lines: 100,
            ..Default::default()
        };

        let excerpts = extract_excerpts(&source, &[requested], &config);
        assert_eq!(excerpts.len(), 1);
        assert!(
            excerpts[0].content.contains("the_requested_line"),
            "requested line {} missing from excerpt: {}",
            requested,
            excerpts[0].content
        );
        assert!(excerpts[0].start_line <= requested);
        assert!(requested <= excerpts[0].end_line);
    }

    #[test]
    fn local_declaration_is_not_a_scope_start() {
        assert!(!is_scope_start("\tstruct my_holder items[2];"));
        assert!(!is_scope_start(
            "\tstruct my_queue *queue = get_queue(dev, id);"
        ));
        assert!(!is_scope_start("\tenum my_flags flags;"));

        assert!(is_scope_start("struct my_session {"));
        assert!(is_scope_start("fn main() {"));
        assert!(is_scope_start("def handler(self):"));
    }

    /// A scope that closes before the requested range is a sibling: the scan
    /// has to keep going back for the one that encloses it.
    #[test]
    fn scope_expansion_skips_a_sibling_scope() {
        let source = [
            "impl Engine {",
            "    fn first() {",
            "        work();",
            "    }",
            "",
            "    fn second() {",
            "        target();",
            "    }",
            "}",
        ];

        assert_eq!(expand_to_scope(&source, 6, 7), (5, 8));
    }

    #[test]
    fn test_merge_ranges() {
        let ranges = vec![(0, 5, vec![2]), (4, 10, vec![7]), (15, 20, vec![17])];

        let merged = merge_ranges(ranges);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].0, 0);
        assert_eq!(merged[0].1, 10);
    }

    #[test]
    fn test_is_test_file_directories() {
        // Test directory patterns (must have slash before directory name)
        assert!(is_test_file("project/tests/integration_tests.rs"));
        assert!(is_test_file("src/test/java/MyTest.java"));
        assert!(is_test_file("src/__tests__/Component.test.js"));
        assert!(is_test_file("project/fixtures/sample_data.py"));
        assert!(is_test_file("project/testdata/input.json"));
        assert!(is_test_file("project/test_data/expected.txt"));
        assert!(is_test_file("src/mocks/api.js"));
        assert!(is_test_file("src/__mocks__/fs.js"));
        assert!(is_test_file("project/spec/helpers/test_helper.rb"));
    }

    #[test]
    fn test_is_test_file_rust() {
        assert!(is_test_file("src/foo_test.rs"));
        assert!(is_test_file("src/integration_tests.rs"));
        assert!(!is_test_file("src/main.rs"));
        assert!(!is_test_file("src/lib.rs"));
        assert!(!is_test_file("src/testing.rs")); // Contains "test" but not a test file
    }

    #[test]
    fn test_is_test_file_javascript() {
        assert!(is_test_file("component.test.js"));
        assert!(is_test_file("utils.test.ts"));
        assert!(is_test_file("component.spec.js"));
        assert!(is_test_file("utils.spec.ts"));
        assert!(is_test_file("App.test.tsx"));
        assert!(is_test_file("App.spec.jsx"));
        assert!(!is_test_file("src/index.js"));
        assert!(!is_test_file("src/contest.js")); // Contains "test" substring
    }

    #[test]
    fn test_is_test_file_python() {
        assert!(is_test_file("test_utils.py"));
        assert!(is_test_file("test_api.py"));
        assert!(is_test_file("utils_test.py"));
        assert!(!is_test_file("src/main.py"));
        assert!(!is_test_file("contest.py")); // Starts with "con", ends with "test"
    }

    #[test]
    fn test_is_test_file_go() {
        assert!(is_test_file("main_test.go"));
        assert!(is_test_file("utils_test.go"));
        assert!(!is_test_file("main.go"));
    }

    #[test]
    fn test_is_test_file_java() {
        assert!(is_test_file("UserServiceTest.java"));
        assert!(is_test_file("ApiTest.java"));
        assert!(!is_test_file("Test.java")); // Just "Test.java" is often a valid class
        assert!(!is_test_file("Main.java"));
    }

    #[test]
    fn test_is_test_file_negative_cases() {
        // Should NOT match these
        assert!(!is_test_file("src/main.rs"));
        assert!(!is_test_file("src/lib.rs"));
        assert!(!is_test_file("src/testing_utils.rs")); // Contains "testing" but not test file pattern
        assert!(!is_test_file("app/contest.js")); // Contains "test" substring
        assert!(!is_test_file("src/latest_results.py")); // Contains "test" substring
    }

    #[test]
    fn test_is_test_file_test_fixtures() {
        // Test new test-fixtures patterns
        assert!(is_test_file("test-fixtures/security/vulnerable.php"));
        assert!(is_test_file("test-fixtures/sample.rs"));
        assert!(is_test_file("/path/to/test-fixtures/vulnerable.go"));
        assert!(is_test_file("project/test-fixtures/data.json"));
        // Security test sample directories
        assert!(is_test_file("src/security/vulnerable.ts"));
        assert!(is_test_file("project/vulnerable/sample.py"));
        // Files named vulnerable.*
        assert!(is_test_file("vulnerable.php"));
        assert!(is_test_file("src/vulnerable.java"));
        assert!(is_test_file("insecure.go"));
        assert!(is_test_file("path/to/insecure.rb"));
    }
}
