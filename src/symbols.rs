//! Symbol types and classification for code intelligence

use serde::{Deserialize, Serialize};

/// The kind of symbol (data structure, function, etc.)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolKind {
    // Data structures
    Struct,
    Class,
    Enum,
    Interface,
    Trait,
    TypeAlias,

    // Functions and methods
    Function,
    Method,
    Constructor,

    // Modules and namespaces
    Module,
    Namespace,
    Package,

    // Values
    Constant,
    Variable,
    Field,
    Parameter,

    // Special
    Implementation,
    Macro,
    Unknown,
}

impl SymbolKind {
    /// Check if this is a data structure type
    pub fn is_data_structure(&self) -> bool {
        matches!(
            self,
            SymbolKind::Struct
                | SymbolKind::Class
                | SymbolKind::Enum
                | SymbolKind::Interface
                | SymbolKind::Trait
                | SymbolKind::TypeAlias
        )
    }

    /// Check if this is a callable
    pub fn is_callable(&self) -> bool {
        matches!(
            self,
            SymbolKind::Function | SymbolKind::Method | SymbolKind::Constructor
        )
    }

    /// Get icon for display
    pub fn icon(&self) -> &'static str {
        match self {
            SymbolKind::Struct => "ðŸ“¦",
            SymbolKind::Class => "ðŸ›ï¸",
            SymbolKind::Enum => "ðŸ“‹",
            SymbolKind::Interface => "ðŸ“œ",
            SymbolKind::Trait => "ðŸ”§",
            SymbolKind::TypeAlias => "ðŸ·ï¸",
            SymbolKind::Function => "âš¡",
            SymbolKind::Method => "ðŸ”¹",
            SymbolKind::Constructor => "ðŸ”¨",
            SymbolKind::Module => "ðŸ“",
            SymbolKind::Namespace => "ðŸ“‚",
            SymbolKind::Package => "ðŸ“¦",
            SymbolKind::Constant => "ðŸ”’",
            SymbolKind::Variable => "ðŸ’¾",
            SymbolKind::Field => "ðŸ”·",
            SymbolKind::Parameter => "ðŸ“¥",
            SymbolKind::Implementation => "âš™ï¸",
            SymbolKind::Macro => "ðŸŽ¯",
            SymbolKind::Unknown => "â“",
        }
    }
}

/// A symbol extracted from source code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    /// The symbol name
    pub name: String,

    /// The kind of symbol
    pub kind: SymbolKind,

    /// File path relative to repository root
    pub file_path: String,

    /// Starting line number (1-indexed)
    pub start_line: usize,

    /// Ending line number (1-indexed, inclusive)
    pub end_line: usize,

    /// The symbol signature (e.g., function signature)
    pub signature: Option<String>,

    /// Fully qualified name (e.g., module::ClassName::method)
    pub qualified_name: Option<String>,

    /// Documentation comment
    pub doc_comment: Option<String>,
}

impl Symbol {
    /// Get the display name with kind icon
    pub fn display_name(&self) -> String {
        format!("{} {}", self.kind.icon(), self.name)
    }

    /// Get location string
    pub fn location(&self) -> String {
        format!("{}:{}-{}", self.file_path, self.start_line, self.end_line)
    }

    /// Get line count
    pub fn line_count(&self) -> usize {
        self.end_line.saturating_sub(self.start_line) + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_kind_classification() {
        assert!(SymbolKind::Struct.is_data_structure());
        assert!(SymbolKind::Class.is_data_structure());
        assert!(!SymbolKind::Function.is_data_structure());

        assert!(SymbolKind::Function.is_callable());
        assert!(SymbolKind::Method.is_callable());
        assert!(!SymbolKind::Struct.is_callable());
    }

    #[test]
    fn test_symbol_display() {
        let sym = Symbol {
            name: "MyStruct".to_string(),
            kind: SymbolKind::Struct,
            file_path: "src/lib.rs".to_string(),
            start_line: 10,
            end_line: 20,
            signature: Some("pub struct MyStruct".to_string()),
            qualified_name: Some("crate::MyStruct".to_string()),
            doc_comment: None,
        };

        assert_eq!(sym.location(), "src/lib.rs:10-20");
        assert_eq!(sym.line_count(), 11);
    }
}
