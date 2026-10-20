//! Benchmarks for code parsing performance.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// Benchmark parsing a Rust file
fn bench_parse_rust(c: &mut Criterion) {
    let small_file = r#"
        fn hello() {
            println!("Hello, World!");
        }
    "#;

    let medium_file = generate_rust_file(50);
    let large_file = generate_rust_file(500);

    let mut group = c.benchmark_group("parse_rust");

    group.throughput(Throughput::Bytes(small_file.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("small", small_file.len()),
        &small_file,
        |b, code| {
            b.iter(|| parse_rust_code(black_box(code)));
        },
    );

    group.throughput(Throughput::Bytes(medium_file.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("medium", medium_file.len()),
        &medium_file,
        |b, code| {
            b.iter(|| parse_rust_code(black_box(code)));
        },
    );

    group.throughput(Throughput::Bytes(large_file.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("large", large_file.len()),
        &large_file,
        |b, code| {
            b.iter(|| parse_rust_code(black_box(code)));
        },
    );

    group.finish();
}

/// Benchmark parsing Python
fn bench_parse_python(c: &mut Criterion) {
    let code = generate_python_file(100);

    c.bench_function("parse_python_100_functions", |b| {
        b.iter(|| parse_python_code(black_box(&code)));
    });
}

/// Benchmark parsing TypeScript
fn bench_parse_typescript(c: &mut Criterion) {
    let code = generate_typescript_file(100);

    c.bench_function("parse_typescript_100_functions", |b| {
        b.iter(|| parse_typescript_code(black_box(&code)));
    });
}

/// Benchmark multi-language parsing
fn bench_parse_mixed(c: &mut Criterion) {
    let rust_code = generate_rust_file(100);
    let python_code = generate_python_file(100);
    let ts_code = generate_typescript_file(100);

    c.bench_function("parse_mixed_languages", |b| {
        b.iter(|| {
            parse_rust_code(black_box(&rust_code));
            parse_python_code(black_box(&python_code));
            parse_typescript_code(black_box(&ts_code));
        });
    });
}

// Helper functions to generate test code

fn generate_rust_file(num_functions: usize) -> String {
    let mut code = String::from("//! Generated Rust file for benchmarking\n\n");

    for i in 0..num_functions {
        code.push_str(&format!(
            r#"
/// Function {i} documentation
pub fn function_{i}(arg: i32) -> i32 {{
    let x = arg + {i};
    let y = x * 2;
    if y > 100 {{
        y - 50
    }} else {{
        y + 50
    }}
}}

/// Struct {i}
pub struct Struct{i} {{
    pub field_a: i32,
    pub field_b: String,
    field_c: Option<i32>,
}}

impl Struct{i} {{
    pub fn new(a: i32, b: String) -> Self {{
        Self {{
            field_a: a,
            field_b: b,
            field_c: None,
        }}
    }}

    pub fn process(&self) -> i32 {{
        self.field_a + self.field_c.unwrap_or(0)
    }}
}}

"#
        ));
    }

    code
}

fn generate_python_file(num_functions: usize) -> String {
    let mut code = String::from("\"\"\"Generated Python file for benchmarking.\"\"\"\n\n");

    for i in 0..num_functions {
        code.push_str(&format!(
            r#"
def function_{i}(arg: int) -> int:
    """Function {i} documentation."""
    x = arg + {i}
    y = x * 2
    if y > 100:
        return y - 50
    else:
        return y + 50


class Class{i}:
    """Class {i} documentation."""

    def __init__(self, a: int, b: str):
        self.field_a = a
        self.field_b = b
        self._field_c = None

    def process(self) -> int:
        return self.field_a + (self._field_c or 0)

"#
        ));
    }

    code
}

fn generate_typescript_file(num_functions: usize) -> String {
    let mut code = String::from("// Generated TypeScript file for benchmarking\n\n");

    for i in 0..num_functions {
        code.push_str(&format!(
            r#"
/**
 * Function {i} documentation
 */
export function function_{i}(arg: number): number {{
    const x = arg + {i};
    const y = x * 2;
    if (y > 100) {{
        return y - 50;
    }} else {{
        return y + 50;
    }}
}}

/**
 * Interface {i}
 */
export interface Interface{i} {{
    fieldA: number;
    fieldB: string;
    fieldC?: number;
}}

/**
 * Class {i}
 */
export class Class{i} implements Interface{i} {{
    fieldA: number;
    fieldB: string;
    fieldC?: number;

    constructor(a: number, b: string) {{
        this.fieldA = a;
        this.fieldB = b;
    }}

    process(): number {{
        return this.fieldA + (this.fieldC ?? 0);
    }}
}}

"#
        ));
    }

    code
}

// Stub functions - these would call the actual parser
// In real implementation, these would use the narsil_xref library

fn parse_rust_code(code: &str) -> usize {
    // Placeholder - would use tree-sitter-rust
    code.matches("fn ").count()
}

fn parse_python_code(code: &str) -> usize {
    // Placeholder - would use tree-sitter-python
    code.matches("def ").count()
}

fn parse_typescript_code(code: &str) -> usize {
    // Placeholder - would use tree-sitter-typescript
    code.matches("function ").count()
}

criterion_group!(
    benches,
    bench_parse_rust,
    bench_parse_python,
    bench_parse_typescript,
    bench_parse_mixed,
);
criterion_main!(benches);
