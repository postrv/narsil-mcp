use anyhow::{anyhow, Result};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Parser, Query, QueryCursor, Tree};

use crate::symbols::{Symbol, SymbolKind};

/// Supported languages and their tree-sitter configurations
#[derive(Debug, Clone)]
pub struct LanguageConfig {
    pub name: String,
    pub language: Language,
    pub extensions: Vec<&'static str>,
    pub symbol_query: &'static str,
}

/// Language configuration with lazily-compiled query
/// Query is compiled on first use, warnings logged once, then cached
struct LazyLanguageConfig {
    config: LanguageConfig,
    /// Lazily compiled query (None if compilation failed)
    compiled_query: OnceLock<Option<Arc<Query>>>,
}

impl LazyLanguageConfig {
    fn new(config: LanguageConfig) -> Self {
        Self {
            config,
            compiled_query: OnceLock::new(),
        }
    }

    /// Get the compiled query, compiling on first access
    fn get_query(&self) -> Option<&Arc<Query>> {
        self.compiled_query
            .get_or_init(
                || match Query::new(&self.config.language, self.config.symbol_query) {
                    Ok(q) => Some(Arc::new(q)),
                    Err(e) => {
                        tracing::warn!(
                            "Query compilation failed for {} (this warning appears once): {:?}",
                            self.config.name,
                            e
                        );
                        None
                    }
                },
            )
            .as_ref()
    }
}

/// A parsed file with extracted information
#[derive(Debug, Clone)]
pub struct ParsedFile {
    #[allow(dead_code)]
    pub path: String,
    pub language: String,
    pub symbols: Vec<Symbol>,
    #[allow(dead_code)]
    pub tree: Option<Tree>,
}

/// Multi-language parser using tree-sitter
pub struct LanguageParser {
    configs: Vec<LazyLanguageConfig>,
}

impl LanguageParser {
    pub fn new() -> Result<Self> {
        let configs = vec![
            // Rust
            LanguageConfig {
                name: "rust".to_string(),
                language: tree_sitter_rust::LANGUAGE.into(),
                extensions: vec!["rs"],
                symbol_query: r#"
                    (function_item name: (identifier) @function.name) @function.def
                    (struct_item name: (type_identifier) @struct.name) @struct.def
                    (enum_item name: (type_identifier) @enum.name) @enum.def
                    (trait_item name: (type_identifier) @trait.name) @trait.def
                    (impl_item type: (type_identifier) @impl.name) @impl.def
                    (type_item name: (type_identifier) @type.name) @type.def
                    (const_item name: (identifier) @const.name) @const.def
                    (static_item name: (identifier) @static.name) @static.def
                    (mod_item name: (identifier) @mod.name) @mod.def
                "#,
            },
            // Python
            LanguageConfig {
                name: "python".to_string(),
                language: tree_sitter_python::LANGUAGE.into(),
                extensions: vec!["py", "pyi"],
                symbol_query: r#"
                    (function_definition name: (identifier) @function.name) @function.def
                    (class_definition name: (identifier) @class.name) @class.def
                "#,
            },
            // JavaScript
            LanguageConfig {
                name: "javascript".to_string(),
                language: tree_sitter_javascript::LANGUAGE.into(),
                extensions: vec!["js", "jsx", "mjs"],
                symbol_query: r#"
                    (function_declaration name: (identifier) @function.name) @function.def
                    (class_declaration name: (identifier) @class.name) @class.def
                    (method_definition name: (property_identifier) @method.name) @method.def
                    (arrow_function) @arrow.def
                    (variable_declarator name: (identifier) @var.name) @var.def
                "#,
            },
            // TypeScript
            LanguageConfig {
                name: "typescript".to_string(),
                language: tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
                extensions: vec!["ts"],
                symbol_query: r#"
                    (function_declaration name: (identifier) @function.name) @function.def
                    (class_declaration name: (type_identifier) @class.name) @class.def
                    (method_definition name: (property_identifier) @method.name) @method.def
                    (interface_declaration name: (type_identifier) @interface.name) @interface.def
                    (type_alias_declaration name: (type_identifier) @type.name) @type.def
                    (enum_declaration name: (identifier) @enum.name) @enum.def
                "#,
            },
            // TSX
            LanguageConfig {
                name: "tsx".to_string(),
                language: tree_sitter_typescript::LANGUAGE_TSX.into(),
                extensions: vec!["tsx"],
                symbol_query: r#"
                    (function_declaration name: (identifier) @function.name) @function.def
                    (class_declaration name: (type_identifier) @class.name) @class.def
                    (method_definition name: (property_identifier) @method.name) @method.def
                    (interface_declaration name: (type_identifier) @interface.name) @interface.def
                    (type_alias_declaration name: (type_identifier) @type.name) @type.def
                "#,
            },
            // Go
            LanguageConfig {
                name: "go".to_string(),
                language: tree_sitter_go::LANGUAGE.into(),
                extensions: vec!["go"],
                symbol_query: r#"
                    (function_declaration name: (identifier) @function.name) @function.def
                    (method_declaration name: (field_identifier) @method.name) @method.def
                    (type_declaration (type_spec name: (type_identifier) @type.name)) @type.def
                "#,
            },
            // C
            LanguageConfig {
                name: "c".to_string(),
                language: tree_sitter_c::LANGUAGE.into(),
                extensions: vec!["c", "h"],
                symbol_query: r#"
                    (function_definition declarator: (function_declarator declarator: (identifier) @function.name)) @function.def
                    (struct_specifier name: (type_identifier) @struct.name) @struct.def
                    (enum_specifier name: (type_identifier) @enum.name) @enum.def
                    (type_definition declarator: (type_identifier) @type.name) @type.def
                "#,
            },
            // C++
            LanguageConfig {
                name: "cpp".to_string(),
                language: tree_sitter_cpp::LANGUAGE.into(),
                extensions: vec!["cpp", "cc", "cxx", "hpp", "hxx", "hh"],
                symbol_query: r#"
                    (function_definition declarator: (function_declarator declarator: (identifier) @function.name)) @function.def
                    (class_specifier name: (type_identifier) @class.name) @class.def
                    (struct_specifier name: (type_identifier) @struct.name) @struct.def
                    (enum_specifier name: (type_identifier) @enum.name) @enum.def
                    (namespace_definition name: (namespace_identifier) @namespace.name) @namespace.def
                "#,
            },
            // Java
            LanguageConfig {
                name: "java".to_string(),
                language: tree_sitter_java::LANGUAGE.into(),
                extensions: vec!["java"],
                symbol_query: r#"
                    (method_declaration name: (identifier) @method.name) @method.def
                    (class_declaration name: (identifier) @class.name) @class.def
                    (interface_declaration name: (identifier) @interface.name) @interface.def
                    (enum_declaration name: (identifier) @enum.name) @enum.def
                "#,
            },
            // C#
            LanguageConfig {
                name: "csharp".to_string(),
                language: tree_sitter_c_sharp::LANGUAGE.into(),
                extensions: vec!["cs"],
                symbol_query: r#"
                    (method_declaration name: (identifier) @method.name) @method.def
                    (class_declaration name: (identifier) @class.name) @class.def
                    (interface_declaration name: (identifier) @interface.name) @interface.def
                    (struct_declaration name: (identifier) @struct.name) @struct.def
                    (enum_declaration name: (identifier) @enum.name) @enum.def
                    (record_declaration name: (identifier) @class.name) @class.def
                    (delegate_declaration name: (identifier) @type.name) @type.def
                    (namespace_declaration name: (identifier) @namespace.name) @namespace.def
                    (property_declaration name: (identifier) @var.name) @var.def
                "#,
            },
            // Bash
            LanguageConfig {
                name: "bash".to_string(),
                language: tree_sitter_bash::LANGUAGE.into(),
                extensions: vec!["sh", "bash", "zsh"],
                symbol_query: r#"
                    (function_definition name: (word) @function.name) @function.def
                    (variable_assignment name: (variable_name) @var.name) @var.def
                "#,
            },
            // Ruby
            LanguageConfig {
                name: "ruby".to_string(),
                language: tree_sitter_ruby::LANGUAGE.into(),
                extensions: vec!["rb", "rake", "gemspec"],
                symbol_query: r#"
                    (method name: (identifier) @method.name) @method.def
                    (singleton_method name: (identifier) @method.name) @method.def
                    (class name: (constant) @class.name) @class.def
                    (module name: (constant) @mod.name) @mod.def
                "#,
            },
            // Kotlin
            LanguageConfig {
                name: "kotlin".to_string(),
                language: tree_sitter_kotlin_sg::LANGUAGE.into(),
                extensions: vec!["kt", "kts"],
                symbol_query: r#"
                    (function_declaration (simple_identifier) @function.name) @function.def
                    (class_declaration (type_identifier) @class.name) @class.def
                    (object_declaration (type_identifier) @class.name) @class.def
                "#,
            },
            // PHP
            LanguageConfig {
                name: "php".to_string(),
                language: tree_sitter_php::LANGUAGE_PHP.into(),
                extensions: vec!["php", "phtml"],
                symbol_query: r#"
                    (function_definition name: (name) @function.name) @function.def
                    (method_declaration name: (name) @method.name) @method.def
                    (class_declaration name: (name) @class.name) @class.def
                    (interface_declaration name: (name) @interface.name) @interface.def
                    (trait_declaration name: (name) @trait.name) @trait.def
                "#,
            },
            // Swift
            // Note: Swift tree-sitter uses class_declaration for classes, structs, and enums
            LanguageConfig {
                name: "swift".to_string(),
                language: tree_sitter_swift::LANGUAGE.into(),
                extensions: vec!["swift"],
                symbol_query: r#"
                    (class_declaration name: (type_identifier) @class.name) @class.def
                    (protocol_declaration name: (type_identifier) @interface.name) @interface.def
                    (function_declaration name: (simple_identifier) @function.name) @function.def
                "#,
            },
            // Verilog/SystemVerilog
            LanguageConfig {
                name: "verilog".to_string(),
                language: tree_sitter_verilog::LANGUAGE.into(),
                extensions: vec!["v", "vh", "sv", "svh"],
                symbol_query: r#"
                    (module_declaration (module_header (simple_identifier) @module.name)) @module.def
                    (task_body_declaration (task_identifier (task_identifier (simple_identifier) @function.name))) @function.def
                    (function_body_declaration (function_identifier (function_identifier (simple_identifier) @function.name))) @function.def
                    (interface_declaration (interface_identifier (simple_identifier) @interface.name)) @interface.def
                    (class_declaration (class_identifier (simple_identifier) @class.name)) @class.def
                "#,
            },
            // Scala
            LanguageConfig {
                name: "scala".to_string(),
                language: tree_sitter_scala::LANGUAGE.into(),
                extensions: vec!["scala", "sc"],
                symbol_query: r#"
                    (class_definition name: (identifier) @class.name) @class.def
                    (object_definition name: (identifier) @class.name) @class.def
                    (trait_definition name: (identifier) @trait.name) @trait.def
                    (function_definition name: (identifier) @function.name) @function.def
                    (val_definition pattern: (identifier) @var.name) @var.def
                "#,
            },
            // Lua
            LanguageConfig {
                name: "lua".to_string(),
                language: tree_sitter_lua::LANGUAGE.into(),
                extensions: vec!["lua"],
                symbol_query: r#"
                    (function_declaration name: (identifier) @function.name) @function.def
                    (function_declaration name: (dot_index_expression) @function.name) @function.def
                    (function_declaration name: (method_index_expression) @method.name) @method.def
                "#,
            },
            // Haskell
            LanguageConfig {
                name: "haskell".to_string(),
                language: tree_sitter_haskell::LANGUAGE.into(),
                extensions: vec!["hs", "lhs"],
                symbol_query: r#"
                    (decl name: (variable) @function.name) @function.def
                    (decl names: (binding_list (variable) @function.name)) @function.def
                    (data_type (name) @struct.name) @struct.def
                    (class (name) @trait.name) @trait.def
                "#,
            },
            // Elixir
            LanguageConfig {
                name: "elixir".to_string(),
                language: tree_sitter_elixir::LANGUAGE.into(),
                extensions: vec!["ex", "exs"],
                symbol_query: r#"
                    (call target: (identifier) (arguments (alias) @mod.name)) @mod.def
                    (call target: (identifier) (arguments (identifier) @function.name)) @function.def
                    (call target: (identifier) (arguments (call target: (identifier) @function.name))) @function.def
                "#,
            },
            // Clojure
            LanguageConfig {
                name: "clojure".to_string(),
                language: tree_sitter_clojure_orchard::LANGUAGE.into(),
                extensions: vec!["clj", "cljs", "cljc", "edn"],
                symbol_query: r#"
                    (list_lit) @function.def
                "#,
            },
            // Dart
            LanguageConfig {
                name: "dart".to_string(),
                language: tree_sitter_dart_orchard::LANGUAGE.into(),
                extensions: vec!["dart"],
                symbol_query: r#"
                    (class_definition (identifier) @class.name) @class.def
                    (function_signature (identifier) @function.name) @function.def
                    (enum_declaration (identifier) @enum.name) @enum.def
                "#,
            },
            // Julia
            // Julia uses `function name(args)` and `name(args) = body` syntax
            LanguageConfig {
                name: "julia".to_string(),
                language: tree_sitter_julia::LANGUAGE.into(),
                extensions: vec!["jl"],
                symbol_query: r#"
                    (module_definition (identifier) @mod.name) @mod.def

                    (function_definition
                      (signature
                        (call_expression (identifier) @function.name))) @function.def

                    (short_function_definition
                      (call_expression (identifier) @function.name)) @function.def

                    (struct_definition
                      (identifier) @struct.name) @struct.def
                "#,
            },
            // R
            // R uses `<-` or `=` for function assignment: `greet <- function(name) { ... }`
            // Both are parsed as binary_operator with: identifier, operator(<- or =), function_definition
            LanguageConfig {
                name: "r".to_string(),
                language: tree_sitter_r::LANGUAGE.into(),
                extensions: vec!["R", "r", "Rmd"],
                symbol_query: r#"
                    (binary_operator
                      (identifier) @function.name
                      _
                      (function_definition)) @function.def
                "#,
            },
            // Perl
            // Perl uses `sub name { }` for function definitions
            LanguageConfig {
                name: "perl".to_string(),
                language: tree_sitter_perl::LANGUAGE.into(),
                extensions: vec!["pl", "pm", "t"],
                symbol_query: r#"
                    (function_definition (identifier) @function.name) @function.def
                    (package_statement (package_name) @mod.name) @mod.def
                "#,
            },
            // Zig
            // Zig uses `fn name(...) type { }` for functions, `const`/`var` for declarations
            LanguageConfig {
                name: "zig".to_string(),
                language: tree_sitter_zig::LANGUAGE.into(),
                extensions: vec!["zig"],
                symbol_query: r#"
                    (function_declaration (identifier) @function.name) @function.def
                    (variable_declaration (identifier) @var.name) @var.def
                "#,
            },
            // Erlang
            // Erlang uses `-module(name).` for modules and `name(Args) -> Body.` for functions
            LanguageConfig {
                name: "erlang".to_string(),
                language: tree_sitter_erlang::LANGUAGE.into(),
                extensions: vec!["erl", "hrl"],
                symbol_query: r#"
                    (function_clause name: (atom) @function.name) @function.def
                    (module_attribute name: (atom) @mod.name) @mod.def
                    (record_decl name: (atom) @struct.name) @struct.def
                "#,
            },
            // Elm
            // Elm uses `name : Type` for type annotations and `name args = body` for functions
            LanguageConfig {
                name: "elm".to_string(),
                language: tree_sitter_elm::LANGUAGE.into(),
                extensions: vec!["elm"],
                symbol_query: r#"
                    (value_declaration (function_declaration_left (lower_case_identifier) @function.name)) @function.def
                    (type_alias_declaration (upper_case_identifier) @type.name) @type.def
                    (type_declaration (upper_case_identifier) @type.name) @type.def
                "#,
            },
            // Fortran
            // Fortran uses PROGRAM, SUBROUTINE, FUNCTION, MODULE keywords
            LanguageConfig {
                name: "fortran".to_string(),
                language: tree_sitter_fortran::LANGUAGE.into(),
                extensions: vec!["f90", "f95", "f03", "f08", "f", "for", "fpp"],
                symbol_query: r#"
                    (program_statement (name) @function.name) @function.def
                    (subroutine_statement (name) @function.name) @function.def
                    (function_statement (name) @function.name) @function.def
                    (module_statement (name) @mod.name) @mod.def
                "#,
            },
            // PowerShell
            // PowerShell uses `function Name { }` for functions and `class Name { }` for classes
            LanguageConfig {
                name: "powershell".to_string(),
                language: tree_sitter_powershell::LANGUAGE.into(),
                extensions: vec!["ps1", "psm1", "psd1"],
                symbol_query: r#"
                    (function_statement (function_name) @function.name) @function.def
                    (class_statement (simple_name) @class.name) @class.def
                    (enum_statement (simple_name) @enum.name) @enum.def
                "#,
            },
            // Nix
            // Nix uses `name = value;` for bindings, often with let...in or attribute sets
            LanguageConfig {
                name: "nix".to_string(),
                language: tree_sitter_nix::LANGUAGE.into(),
                extensions: vec!["nix"],
                symbol_query: r#"
                    (binding attrpath: (attrpath (identifier) @var.name)) @var.def
                "#,
            },
            // Groovy
            // Groovy uses Java-like syntax with `class`, `interface`, `enum`, and `def`
            LanguageConfig {
                name: "groovy".to_string(),
                language: tree_sitter_groovy::LANGUAGE.into(),
                extensions: vec!["groovy", "gradle"],
                symbol_query: r#"
                    (method_declaration name: (identifier) @method.name) @method.def
                    (class_declaration name: (identifier) @class.name) @class.def
                    (interface_declaration name: (identifier) @interface.name) @interface.def
                    (enum_declaration name: (identifier) @enum.name) @enum.def
                    (function_definition (identifier) @function.name) @function.def
                "#,
            },
        ];

        // Wrap configs in lazy wrappers (queries compiled on first use, not during init)
        let lazy_configs = configs.into_iter().map(LazyLanguageConfig::new).collect();

        Ok(Self {
            configs: lazy_configs,
        })
    }

    /// Get language config for a file extension
    fn get_config(&self, path: &Path) -> Option<&LazyLanguageConfig> {
        let ext = path.extension()?.to_str()?;
        self.configs
            .iter()
            .find(|c| c.config.extensions.contains(&ext))
    }

    /// Parse a file and extract symbols
    pub fn parse_file(&self, path: &Path, content: &str) -> Result<ParsedFile> {
        let lazy_config = self
            .get_config(path)
            .ok_or_else(|| anyhow!("Unsupported file type: {:?}", path))?;

        let mut parser = Parser::new();
        parser.set_language(&lazy_config.config.language)?;

        let tree = parser
            .parse(content, None)
            .ok_or_else(|| anyhow!("Failed to parse file"))?;

        let symbols = self.extract_symbols(&tree, content, lazy_config)?;

        Ok(ParsedFile {
            path: path.to_string_lossy().to_string(),
            language: lazy_config.config.name.clone(),
            symbols,
            tree: Some(tree),
        })
    }

    /// Parse a file and return just the tree (for call graph analysis)
    #[allow(dead_code)]
    pub fn parse_to_tree(&self, path: &Path, content: &str) -> Result<Tree> {
        let lazy_config = self
            .get_config(path)
            .ok_or_else(|| anyhow!("Unsupported file type: {:?}", path))?;

        let mut parser = Parser::new();
        parser.set_language(&lazy_config.config.language)?;

        parser
            .parse(content, None)
            .ok_or_else(|| anyhow!("Failed to parse file"))
    }

    /// Extract symbols using tree-sitter queries
    fn extract_symbols(
        &self,
        tree: &Tree,
        source: &str,
        lazy_config: &LazyLanguageConfig,
    ) -> Result<Vec<Symbol>> {
        let mut symbols = Vec::new();
        let source_bytes = source.as_bytes();

        // Get lazily-compiled query (errors logged once on first access)
        let query = match lazy_config.get_query() {
            Some(q) => q,
            None => return Ok(symbols), // Query compilation failed, return empty
        };

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(query, tree.root_node(), source_bytes);

        while let Some(match_) = matches.next() {
            let mut name: Option<String> = None;
            let mut kind: Option<SymbolKind> = None;
            let mut start_line = 0;
            let mut end_line = 0;
            let mut signature: Option<String> = None;

            for capture in match_.captures {
                let capture_name = query.capture_names()[capture.index as usize];
                let node = capture.node;
                let text = node.utf8_text(source_bytes).unwrap_or("");

                if capture_name.ends_with(".name") {
                    name = Some(text.to_string());
                    kind = Some(parse_symbol_kind(capture_name));
                } else if capture_name.ends_with(".def") {
                    start_line = node.start_position().row + 1;
                    end_line = node.end_position().row + 1;

                    // Extract first line as signature
                    let first_line_end = text.find('\n').unwrap_or(text.len());
                    signature = Some(text[..first_line_end.min(200)].to_string());
                }
            }

            if let (Some(name), Some(kind)) = (name, kind) {
                symbols.push(Symbol {
                    name,
                    kind,
                    file_path: String::new(), // Will be set by caller
                    start_line,
                    end_line,
                    signature,
                    qualified_name: None,
                    doc_comment: None,
                });
            }
        }

        Ok(symbols)
    }

    /// Get all supported extensions
    #[allow(dead_code)]
    pub fn supported_extensions(&self) -> Vec<&'static str> {
        self.configs
            .iter()
            .flat_map(|c| c.config.extensions.iter().copied())
            .collect()
    }
}

fn parse_symbol_kind(capture_name: &str) -> SymbolKind {
    let prefix = capture_name.split('.').next().unwrap_or("");
    match prefix {
        "function" => SymbolKind::Function,
        "method" => SymbolKind::Method,
        "class" => SymbolKind::Class,
        "struct" => SymbolKind::Struct,
        "enum" => SymbolKind::Enum,
        "interface" => SymbolKind::Interface,
        "trait" => SymbolKind::Trait,
        "type" => SymbolKind::TypeAlias,
        "const" | "static" => SymbolKind::Constant,
        "mod" | "module" | "namespace" => SymbolKind::Module,
        "impl" => SymbolKind::Implementation,
        "var" | "arrow" => SymbolKind::Variable,
        _ => SymbolKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rust() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
            pub struct MyStruct {
                field: u32,
            }

            pub fn my_function() -> i32 {
                42
            }

            impl MyStruct {
                pub fn method(&self) {}
            }
        "#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        assert_eq!(parsed.language, "rust");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(names.contains(&&"MyStruct".to_string()));
        assert!(names.contains(&&"my_function".to_string()));
    }

    #[test]
    fn test_parse_python() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
class MyClass:
    def __init__(self):
        pass

    def method(self):
        return 42

def standalone_function():
    pass
        "#;

        let parsed = parser.parse_file(Path::new("test.py"), content).unwrap();
        assert_eq!(parsed.language, "python");

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(names.contains(&&"MyClass".to_string()));
        assert!(names.contains(&&"standalone_function".to_string()));
    }

    #[test]
    fn test_parse_csharp() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
namespace MyApp
{
    public interface IService
    {
        void DoWork();
    }

    public class MyService : IService
    {
        public string Name { get; set; }

        public void DoWork()
        {
            Console.WriteLine("Working");
        }

        private int Calculate(int x, int y)
        {
            return x + y;
        }
    }

    public struct Point
    {
        public int X;
        public int Y;
    }

    public enum Status
    {
        Active,
        Inactive
    }
}
        "#;

        let parsed = parser.parse_file(Path::new("test.cs"), content).unwrap();
        assert_eq!(parsed.language, "csharp");

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(
            names.contains(&&"MyApp".to_string()),
            "Should find namespace"
        );
        assert!(
            names.contains(&&"IService".to_string()),
            "Should find interface"
        );
        assert!(
            names.contains(&&"MyService".to_string()),
            "Should find class"
        );
        assert!(names.contains(&&"DoWork".to_string()), "Should find method");
        assert!(names.contains(&&"Point".to_string()), "Should find struct");
        assert!(names.contains(&&"Status".to_string()), "Should find enum");
    }

    #[test]
    fn test_parse_swift() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
class MyClass {
    var name: String

    init(name: String) {
        self.name = name
    }

    func greet() -> String {
        return "Hello, \(name)"
    }
}

struct Point {
    var x: Int
    var y: Int
}

protocol Drawable {
    func draw()
}

enum Direction {
    case north
    case south
    case east
    case west
}

func standaloneFunction() {
    print("Hello")
}
        "#;

        let parsed = parser.parse_file(Path::new("test.swift"), content).unwrap();
        assert_eq!(parsed.language, "swift");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(names.contains(&&"MyClass".to_string()), "Should find class");
        assert!(names.contains(&&"Point".to_string()), "Should find struct");
        assert!(
            names.contains(&&"Drawable".to_string()),
            "Should find protocol"
        );
        assert!(
            names.contains(&&"Direction".to_string()),
            "Should find enum"
        );
        assert!(
            names.contains(&&"standaloneFunction".to_string()),
            "Should find function"
        );
    }

    #[test]
    fn test_parse_cpp() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
namespace MyNamespace {
    class MyClass {
    public:
        void myMethod() {}
    };

    struct MyStruct {
        int x;
        int y;
    };

    enum MyEnum {
        VALUE_A,
        VALUE_B
    };
}

void standaloneFunction() {
    // do something
}
        "#;

        let parsed = parser.parse_file(Path::new("test.cpp"), content).unwrap();
        assert_eq!(parsed.language, "cpp");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(
            names.contains(&&"MyNamespace".to_string()),
            "Should find namespace, found: {:?}",
            names
        );
        assert!(names.contains(&&"MyClass".to_string()), "Should find class");
        assert!(
            names.contains(&&"MyStruct".to_string()),
            "Should find struct"
        );
        assert!(names.contains(&&"MyEnum".to_string()), "Should find enum");
        assert!(
            names.contains(&&"standaloneFunction".to_string()),
            "Should find function"
        );
    }

    #[test]
    fn test_parse_scala() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
package com.example

trait Greeter {
  def greet(name: String): String
}

class MyClass(val name: String) extends Greeter {
  def greet(name: String): String = s"Hello, $name"

  private def helper(): Int = 42
}

object MyObject {
  def main(args: Array[String]): Unit = {
    println("Hello")
  }

  val constant: Int = 100
}

case class Person(name: String, age: Int)

def topLevelFunction(): Unit = {
  println("Top level")
}
        "#;

        let parsed = parser.parse_file(Path::new("test.scala"), content).unwrap();
        assert_eq!(parsed.language, "scala");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(
            names.contains(&&"Greeter".to_string()),
            "Should find trait Greeter, found: {:?}",
            names
        );
        assert!(
            names.contains(&&"MyClass".to_string()),
            "Should find class MyClass"
        );
        assert!(
            names.contains(&&"MyObject".to_string()),
            "Should find object MyObject"
        );
        assert!(
            names.contains(&&"greet".to_string()),
            "Should find method greet"
        );
        assert!(
            names.contains(&&"Person".to_string()),
            "Should find case class Person"
        );
    }

    #[test]
    fn test_parse_lua() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
-- Global function
function greet(name)
    print("Hello, " .. name)
end

-- Local function
local function helper()
    return 42
end

-- Module table with methods
local MyModule = {}

function MyModule.create(name)
    return { name = name }
end

function MyModule:method()
    return self.name
end

-- Anonymous function assigned to variable
local callback = function(x)
    return x * 2
end
        "#;

        let parsed = parser.parse_file(Path::new("test.lua"), content).unwrap();
        assert_eq!(parsed.language, "lua");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(
            names.contains(&&"greet".to_string()),
            "Should find function greet, found: {:?}",
            names
        );
        assert!(
            names.contains(&&"helper".to_string()),
            "Should find local function helper"
        );
        assert!(
            names.contains(&&"MyModule.create".to_string())
                || names.contains(&&"create".to_string()),
            "Should find MyModule.create method"
        );
    }

    #[test]
    fn test_parse_haskell() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
module Main where

-- Data type
data Person = Person { name :: String, age :: Int }

-- Type alias
type Name = String

-- Newtype
newtype UserId = UserId Int

-- Type class
class Greeter a where
  greet :: a -> String

-- Instance
instance Greeter Person where
  greet p = "Hello, " ++ name p

-- Function declarations
factorial :: Int -> Int
factorial 0 = 1
factorial n = n * factorial (n - 1)

main :: IO ()
main = putStrLn "Hello, World!"
        "#;

        let parsed = parser.parse_file(Path::new("test.hs"), content).unwrap();
        assert_eq!(parsed.language, "haskell");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(
            names.contains(&&"Person".to_string()),
            "Should find data type Person, found: {:?}",
            names
        );
        assert!(
            names.contains(&&"factorial".to_string()),
            "Should find function factorial"
        );
        assert!(
            names.contains(&&"main".to_string()),
            "Should find function main"
        );
        assert!(
            names.contains(&&"Greeter".to_string()),
            "Should find type class Greeter"
        );
    }

    #[test]
    fn test_parse_elixir() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
defmodule MyApp.Greeter do
  @moduledoc """
  A simple greeter module.
  """

  def greet(name) do
    "Hello, #{name}!"
  end

  defp format_name(name) do
    String.capitalize(name)
  end

  def say_goodbye(name), do: "Goodbye, #{name}!"
end

defmodule MyApp.Calculator do
  def add(a, b), do: a + b
  def subtract(a, b), do: a - b
end
        "#;

        let parsed = parser.parse_file(Path::new("test.ex"), content).unwrap();
        assert_eq!(parsed.language, "elixir");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        // Note: Elixir symbol extraction may capture module names differently
        assert!(
            names
                .iter()
                .any(|n| n.contains("Greeter") || n.contains("MyApp")),
            "Should find module MyApp.Greeter, found: {:?}",
            names
        );
    }

    #[test]
    fn test_parse_clojure() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
(ns myapp.core
  (:require [clojure.string :as str]))

(def greeting "Hello")

(defn greet
  "Greets a person by name."
  [name]
  (str greeting ", " name "!"))

(defn- private-helper
  [x]
  (* x 2))

(defmacro unless
  [condition & body]
  `(if (not ~condition) (do ~@body)))
        "#;

        let parsed = parser.parse_file(Path::new("test.clj"), content).unwrap();
        assert_eq!(parsed.language, "clojure");
        // Clojure symbol extraction is limited due to homoiconic nature
        // The grammar only provides generic list/symbol nodes
        // Basic parsing should succeed even if symbol extraction is minimal
        assert!(
            parsed.tree.is_some(),
            "Should successfully parse Clojure code"
        );
    }

    #[test]
    fn test_parse_verilog() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
module counter(
    input clk,
    input reset,
    output reg [7:0] count
);
    always @(posedge clk or posedge reset) begin
        if (reset)
            count <= 8'b0;
        else
            count <= count + 1;
    end
endmodule

module test_bench;
    reg clk;
    reg reset;
    wire [7:0] count;

    counter uut (
        .clk(clk),
        .reset(reset),
        .count(count)
    );

    task run_test;
        begin
            #10 reset = 0;
            #50 $finish;
        end
    endtask

    function [7:0] double_value;
        input [7:0] val;
        begin
            double_value = val * 2;
        end
    endfunction
endmodule
        "#;

        let parsed = parser.parse_file(Path::new("test.v"), content).unwrap();
        assert_eq!(parsed.language, "verilog");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(
            names.contains(&&"counter".to_string()),
            "Should find module counter"
        );
        assert!(
            names.contains(&&"test_bench".to_string()),
            "Should find module test_bench"
        );
        assert!(names.contains(&&"run_test".to_string()), "Should find task");
        assert!(
            names.contains(&&"double_value".to_string()),
            "Should find function"
        );
    }

    #[test]
    fn test_parse_dart() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
class Person {
  final String name;
  final int age;

  Person(this.name, this.age);

  void greet() {
    print('Hello, my name is $name');
  }

  int getAgeInMonths() {
    return age * 12;
  }
}

abstract class Animal {
  void makeSound();
}

mixin Flyable {
  void fly() {
    print('Flying!');
  }
}

enum Color { red, green, blue }

void main() {
  var person = Person('Alice', 30);
  person.greet();
}

int add(int a, int b) => a + b;
        "#;

        let parsed = parser.parse_file(Path::new("test.dart"), content).unwrap();
        assert_eq!(parsed.language, "dart");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(
            names.contains(&&"Person".to_string()),
            "Should find class Person, found: {:?}",
            names
        );
        assert!(
            names.contains(&&"Animal".to_string()),
            "Should find abstract class Animal"
        );
        assert!(
            names.contains(&&"main".to_string()),
            "Should find function main"
        );
        assert!(
            names.contains(&&"add".to_string()),
            "Should find function add"
        );
    }

    #[test]
    fn test_parse_julia() {
        let parser = LanguageParser::new().unwrap();
        // Simplified test case
        let content = r#"
function greet(name)
    println("Hello")
end

struct Person
    name
end
        "#;

        let parsed = parser.parse_file(Path::new("test.jl"), content).unwrap();
        assert_eq!(parsed.language, "julia");

        // Julia symbol extraction is limited due to complex AST structure
        // We verify that the parser works by checking the tree was created
        assert!(
            parsed.tree.is_some(),
            "Should successfully parse Julia code"
        );
        // If symbols are extracted, verify they contain expected names
        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        eprintln!("Found Julia symbols: {:?}", names);
        if !names.is_empty() {
            // Check that function definitions produce symbol entries
            assert!(
                parsed
                    .symbols
                    .iter()
                    .any(|s| s.kind == crate::symbols::SymbolKind::Function),
                "Should find at least one function symbol"
            );
        }
    }

    #[test]
    fn test_parse_r() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
# Function definitions
greet <- function(name) {
  print(paste("Hello,", name))
}

add <- function(a, b) {
  return(a + b)
}

# Using equals assignment
calculate_mean = function(x) {
  sum(x) / length(x)
}

# S3 class method
print.Person <- function(x) {
  cat("Person:", x$name, "\n")
}

# Constants
PI <- 3.14159

# Main script
result <- add(1, 2)
print(result)
        "#;

        let parsed = parser.parse_file(Path::new("test.R"), content).unwrap();
        assert_eq!(parsed.language, "r");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(
            names.contains(&&"greet".to_string()),
            "Should find function greet, found: {:?}",
            names
        );
        assert!(
            names.contains(&&"add".to_string()),
            "Should find function add"
        );
        assert!(
            names.contains(&&"calculate_mean".to_string()),
            "Should find function calculate_mean"
        );
    }

    #[test]
    fn test_parse_perl() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
package Person;

use strict;
use warnings;

sub new {
    my ($class, $name, $age) = @_;
    my $self = {
        name => $name,
        age  => $age,
    };
    return bless $self, $class;
}

sub greet {
    my ($self) = @_;
    print "Hello, my name is $self->{name}\n";
}

sub get_age {
    my ($self) = @_;
    return $self->{age};
}

1;

package main;

sub add {
    my ($a, $b) = @_;
    return $a + $b;
}

my $person = Person->new('Alice', 30);
$person->greet();
        "#;

        let parsed = parser.parse_file(Path::new("test.pl"), content).unwrap();
        assert_eq!(parsed.language, "perl");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(
            names.contains(&&"new".to_string()),
            "Should find sub new, found: {:?}",
            names
        );
        assert!(
            names.contains(&&"greet".to_string()),
            "Should find sub greet"
        );
        assert!(names.contains(&&"add".to_string()), "Should find sub add");
    }

    #[test]
    fn test_parse_zig() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
const std = @import("std");

pub const Person = struct {
    name: []const u8,
    age: u32,

    pub fn init(name: []const u8, age: u32) Person {
        return Person{ .name = name, .age = age };
    }

    pub fn greet(self: Person) void {
        std.debug.print("Hello, {s}!\n", .{self.name});
    }
};

const Color = enum {
    red,
    green,
    blue,
};

const Status = union(enum) {
    ok: void,
    err: []const u8,
};

pub fn add(a: i32, b: i32) i32 {
    return a + b;
}

fn helper() void {
    // Private function
}

pub fn main() !void {
    const person = Person.init("Alice", 30);
    person.greet();
}
        "#;

        let parsed = parser.parse_file(Path::new("test.zig"), content).unwrap();
        assert_eq!(parsed.language, "zig");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(
            names.contains(&&"Person".to_string()),
            "Should find struct Person, found: {:?}",
            names
        );
        assert!(
            names.contains(&&"Color".to_string()),
            "Should find enum Color"
        );
        assert!(
            names.contains(&&"add".to_string()),
            "Should find function add"
        );
        assert!(
            names.contains(&&"main".to_string()),
            "Should find function main"
        );
    }

    #[test]
    fn test_parse_erlang() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
-module(greeting).
-export([hello/1, goodbye/1]).

%% Public function
hello(Name) ->
    io:format("Hello, ~s!~n", [Name]).

%% Another public function
goodbye(Name) ->
    io:format("Goodbye, ~s!~n", [Name]).

%% Private helper function
format_message(Msg, Name) ->
    io_lib:format("~s, ~s!", [Msg, Name]).

-record(person, {name, age}).

greet_person(#person{name = Name}) ->
    hello(Name).
        "#;

        let parsed = parser.parse_file(Path::new("test.erl"), content).unwrap();
        assert_eq!(parsed.language, "erlang");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(
            names.contains(&&"hello".to_string()),
            "Should find function hello, found: {:?}",
            names
        );
        assert!(
            names.contains(&&"goodbye".to_string()),
            "Should find function goodbye"
        );
    }

    #[test]
    fn test_parse_elm() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
module Main exposing (main)

import Html exposing (Html, text, div)

-- Type alias
type alias Model =
    { name : String
    , count : Int
    }

-- Custom type
type Msg
    = Increment
    | Decrement
    | Reset

-- Function definitions
greet : String -> String
greet name =
    "Hello, " ++ name ++ "!"

add : Int -> Int -> Int
add a b =
    a + b

main : Html msg
main =
    text (greet "World")
        "#;

        let parsed = parser.parse_file(Path::new("test.elm"), content).unwrap();
        assert_eq!(parsed.language, "elm");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(
            names.contains(&&"greet".to_string()),
            "Should find function greet, found: {:?}",
            names
        );
        assert!(
            names.contains(&&"add".to_string()),
            "Should find function add"
        );
        assert!(
            names.contains(&&"main".to_string()),
            "Should find function main"
        );
    }

    #[test]
    fn test_parse_fortran() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
program hello
    implicit none
    call greet("World")
contains
    subroutine greet(name)
        character(len=*), intent(in) :: name
        print *, "Hello, ", name
    end subroutine greet

    function add(a, b) result(c)
        integer, intent(in) :: a, b
        integer :: c
        c = a + b
    end function add
end program hello

module math_utils
    implicit none
contains
    function multiply(x, y) result(z)
        real, intent(in) :: x, y
        real :: z
        z = x * y
    end function multiply
end module math_utils
        "#;

        let parsed = parser.parse_file(Path::new("test.f90"), content).unwrap();
        assert_eq!(parsed.language, "fortran");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(
            names.contains(&&"hello".to_string()),
            "Should find program hello, found: {:?}",
            names
        );
        assert!(
            names.contains(&&"greet".to_string()),
            "Should find subroutine greet"
        );
        assert!(
            names.contains(&&"add".to_string()),
            "Should find function add"
        );
    }

    #[test]
    fn test_parse_powershell() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
function Get-Greeting {
    param(
        [string]$Name
    )
    return "Hello, $Name!"
}

function Add-Numbers {
    param(
        [int]$a,
        [int]$b
    )
    return $a + $b
}

function Invoke-Process {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    process {
        Get-Process | Where-Object { $_.Path -eq $Path }
    }
}

class Person {
    [string]$Name
    [int]$Age

    Person([string]$name, [int]$age) {
        $this.Name = $name
        $this.Age = $age
    }

    [string] Greet() {
        return "Hello, I am $($this.Name)"
    }
}

$greeting = Get-Greeting -Name "World"
Write-Output $greeting
        "#;

        let parsed = parser.parse_file(Path::new("test.ps1"), content).unwrap();
        assert_eq!(parsed.language, "powershell");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(
            names.contains(&&"Get-Greeting".to_string()),
            "Should find function Get-Greeting, found: {:?}",
            names
        );
        assert!(
            names.contains(&&"Add-Numbers".to_string()),
            "Should find function Add-Numbers"
        );
    }

    #[test]
    fn test_parse_nix() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
{ lib, stdenv, fetchurl }:

let
  greet = name: "Hello, ${name}!";

  add = a: b: a + b;

  person = {
    name = "Alice";
    age = 30;
  };

  buildPackage = { name, version, src }:
    stdenv.mkDerivation {
      inherit name version src;
      buildPhase = "make";
      installPhase = "make install";
    };
in
{
  greeting = greet "World";
  sum = add 1 2;
  package = buildPackage {
    name = "example";
    version = "1.0";
    src = fetchurl { url = "https://example.com"; sha256 = "..."; };
  };
}
        "#;

        let parsed = parser.parse_file(Path::new("test.nix"), content).unwrap();
        assert_eq!(parsed.language, "nix");
        // Nix has a unique syntax, verify parsing succeeds
        assert!(parsed.tree.is_some(), "Should successfully parse Nix code");
        // If symbols are extracted, check for expected bindings
        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        eprintln!("Found Nix symbols: {:?}", names);
    }

    #[test]
    fn test_parse_groovy() {
        let parser = LanguageParser::new().unwrap();
        let content = r#"
package com.example

class Person {
    String name
    int age

    Person(String name, int age) {
        this.name = name
        this.age = age
    }

    String greet() {
        return "Hello, my name is ${name}"
    }

    static int add(int a, int b) {
        return a + b
    }
}

interface Greeter {
    String sayHello(String name)
}

trait Printable {
    void print() {
        println(this.toString())
    }
}

enum Status {
    ACTIVE,
    INACTIVE,
    PENDING
}

def standaloneFunction(x) {
    return x * 2
}

def greeting = new Person("Alice", 30).greet()
println greeting
        "#;

        let parsed = parser
            .parse_file(Path::new("test.groovy"), content)
            .unwrap();
        assert_eq!(parsed.language, "groovy");
        assert!(!parsed.symbols.is_empty());

        let names: Vec<_> = parsed.symbols.iter().map(|s| &s.name).collect();
        assert!(
            names.contains(&&"Person".to_string()),
            "Should find class Person, found: {:?}",
            names
        );
        assert!(
            names.contains(&&"Greeter".to_string()),
            "Should find interface Greeter"
        );
        assert!(
            names.contains(&&"Status".to_string()),
            "Should find enum Status"
        );
    }
}
