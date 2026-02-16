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
            let (clamped_start, clamped_end) =
                clamp_range(final_start, final_end, &matches, config.max_lines);

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

    // Track brace/bracket balance
    let mut brace_count = 0;
    let mut in_scope = false;

    // Scan backwards to find scope start
    for i in (0..=start).rev() {
        let line = lines[i];

        // Look for scope-starting keywords
        if is_scope_start(line) {
            new_start = i;
            in_scope = true;

            // Count opening braces
            brace_count += line.chars().filter(|&c| c == '{').count() as i32;
            brace_count -= line.chars().filter(|&c| c == '}').count() as i32;
            break;
        }
    }

    // If we found a scope start, scan forward to find the end
    if in_scope {
        for (i, line) in lines.iter().enumerate().skip(start) {
            brace_count += line.chars().filter(|&c| c == '{').count() as i32;
            brace_count -= line.chars().filter(|&c| c == '}').count() as i32;

            if brace_count <= 0 {
                new_end = i + 1;
                break;
            }
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

    patterns.iter().any(|p| trimmed.starts_with(p))
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
                "â†’"
            } else {
                " "
            };

            if include_line_numbers {
                format!("{} {:4} â”‚ {}", marker, line_num, line)
            } else {
                format!("{} {}", marker, line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
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
    fn test_merge_ranges() {
        let ranges = vec![(0, 5, vec![2]), (4, 10, vec![7]), (15, 20, vec![17])];

        let merged = merge_ranges(ranges);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].0, 0);
        assert_eq!(merged[0].1, 10);
    }
}
