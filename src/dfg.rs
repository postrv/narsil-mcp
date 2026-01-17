//! Data Flow Graph (DFG) analysis module.
//!
//! This module provides data flow analysis for tracking variable definitions,
//! uses, and detecting data flow issues like uninitialized variables and dead stores.
//!
//! # Features
//! - Variable definition and use tracking
//! - Reaching definitions analysis
//! - Def-use chains
//! - Liveness analysis
//! - Dead store detection
//! - Uninitialized variable detection

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use tree_sitter::Tree;

use crate::cfg::{BlockId, ControlFlowGraph};

/// Unique identifier for a variable
pub type VarId = String;

/// Unique identifier for a definition
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct DefId {
    /// Variable being defined
    pub variable: VarId,
    /// Block where definition occurs
    pub block: BlockId,
    /// Line number
    pub line: usize,
    /// Unique index within the block
    pub index: usize,
}

impl DefId {
    pub fn new(variable: &str, block: BlockId, line: usize, index: usize) -> Self {
        Self {
            variable: variable.to_string(),
            block,
            line,
            index,
        }
    }
}

/// A variable definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Definition {
    /// Definition identifier
    pub id: DefId,
    /// Kind of definition
    pub kind: DefKind,
    /// Expression being assigned (simplified)
    pub expression: String,
    /// Variables used in the expression
    pub uses: Vec<VarId>,
}

/// Types of variable definitions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefKind {
    /// let x = ...
    Declaration,
    /// x = ...
    Assignment,
    /// Function parameter
    Parameter,
    /// For loop variable
    LoopVar,
    /// Pattern binding (match, if let)
    PatternBinding,
}

/// A variable use
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Use {
    /// Variable being used
    pub variable: VarId,
    /// Block where use occurs
    pub block: BlockId,
    /// Line number
    pub line: usize,
    /// Kind of use
    pub kind: UseKind,
}

/// Types of variable uses
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UseKind {
    /// Read in an expression
    Read,
    /// Passed as argument
    Argument,
    /// Used in return
    Return,
    /// Used in condition
    Condition,
    /// Address taken (&x)
    AddressTaken,
    /// Used in dereference (*x)
    Dereference,
}

/// Data flow facts for a basic block
#[derive(Debug, Clone, Default)]
pub struct BlockDataFlow {
    /// Definitions generated in this block
    pub gen: HashSet<DefId>,
    /// Definitions killed in this block
    pub kill: HashSet<DefId>,
    /// Definitions reaching the entry of this block
    pub reaching_in: HashSet<DefId>,
    /// Definitions reaching the exit of this block
    pub reaching_out: HashSet<DefId>,
    /// Variables live at entry
    pub live_in: HashSet<VarId>,
    /// Variables live at exit
    pub live_out: HashSet<VarId>,
    /// Variables used before defined in this block
    pub use_before_def: HashSet<VarId>,
    /// Variables defined in this block
    pub defined: HashSet<VarId>,
}

/// A def-use chain entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefUseChain {
    /// The definition
    pub definition: DefId,
    /// Uses of this definition
    pub uses: Vec<Use>,
    /// Is this definition ever used?
    pub is_used: bool,
}

/// Data flow analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowAnalysis {
    /// Function name
    pub function_name: String,
    /// File path
    pub file_path: String,
    /// All definitions
    pub definitions: Vec<Definition>,
    /// All uses
    pub uses: Vec<Use>,
    /// Def-use chains
    pub def_use_chains: Vec<DefUseChain>,
    /// Dead stores (definitions never used)
    pub dead_stores: Vec<DefId>,
    /// Potentially uninitialized uses
    pub uninitialized_uses: Vec<Use>,
    /// Variables that may be used after being moved (Rust-specific)
    pub use_after_move: Vec<Use>,
}

impl DataFlowAnalysis {
    pub fn new(function_name: &str, file_path: &str) -> Self {
        Self {
            function_name: function_name.to_string(),
            file_path: file_path.to_string(),
            definitions: Vec::new(),
            uses: Vec::new(),
            def_use_chains: Vec::new(),
            dead_stores: Vec::new(),
            uninitialized_uses: Vec::new(),
            use_after_move: Vec::new(),
        }
    }

    /// Format as markdown
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str(&format!(
            "# Data Flow Analysis: `{}`\n\n",
            self.function_name
        ));
        md.push_str(&format!("**File**: `{}`\n\n", self.file_path));

        // Summary
        md.push_str("## Summary\n\n");
        md.push_str(&format!("- **Definitions**: {}\n", self.definitions.len()));
        md.push_str(&format!("- **Uses**: {}\n", self.uses.len()));
        md.push_str(&format!("- **Dead Stores**: {}\n", self.dead_stores.len()));
        md.push_str(&format!(
            "- **Uninitialized Uses**: {}\n",
            self.uninitialized_uses.len()
        ));
        md.push_str(&format!(
            "- **Use After Move**: {}\n\n",
            self.use_after_move.len()
        ));

        // Dead stores
        if !self.dead_stores.is_empty() {
            md.push_str("## ⚠️ Dead Stores\n\n");
            md.push_str("*Variables assigned but never read:*\n\n");
            for def in &self.dead_stores {
                md.push_str(&format!(
                    "- `{}` at line {} (block {})\n",
                    def.variable, def.line, def.block
                ));
            }
            md.push('\n');
        }

        // Uninitialized uses
        if !self.uninitialized_uses.is_empty() {
            md.push_str("## ⚠️ Potentially Uninitialized Variables\n\n");
            for use_ in &self.uninitialized_uses {
                md.push_str(&format!(
                    "- `{}` at line {} ({:?})\n",
                    use_.variable, use_.line, use_.kind
                ));
            }
            md.push('\n');
        }

        // Use after move
        if !self.use_after_move.is_empty() {
            md.push_str("## ⚠️ Use After Move\n\n");
            md.push_str("*Variables used after being moved (Rust ownership violation):*\n\n");
            for use_ in &self.use_after_move {
                md.push_str(&format!(
                    "- `{}` at line {} (block {})\n",
                    use_.variable, use_.line, use_.block
                ));
            }
            md.push('\n');
        }

        // Def-use chains
        md.push_str("## Def-Use Chains\n\n");
        for chain in &self.def_use_chains {
            let status = if chain.is_used { "✓" } else { "⚠️" };
            md.push_str(&format!(
                "### {} `{}` (line {})\n\n",
                status, chain.definition.variable, chain.definition.line
            ));

            if chain.uses.is_empty() {
                md.push_str("*No uses found*\n\n");
            } else {
                for use_ in &chain.uses {
                    md.push_str(&format!("- Line {}: {:?}\n", use_.line, use_.kind));
                }
                md.push('\n');
            }
        }

        md
    }
}

/// Data flow graph analyzer
pub struct DfgAnalyzer<'a> {
    /// The control flow graph
    cfg: &'a ControlFlowGraph,
    /// Data flow facts per block
    block_facts: HashMap<BlockId, BlockDataFlow>,
    /// All definitions found
    definitions: Vec<Definition>,
    /// All uses found
    uses: Vec<Use>,
    /// Definition index counter per block
    def_counters: HashMap<BlockId, usize>,
}

impl<'a> DfgAnalyzer<'a> {
    pub fn new(cfg: &'a ControlFlowGraph) -> Self {
        Self {
            cfg,
            block_facts: HashMap::new(),
            definitions: Vec::new(),
            uses: Vec::new(),
            def_counters: HashMap::new(),
        }
    }

    /// Run the complete data flow analysis
    pub fn analyze(&mut self) -> DataFlowAnalysis {
        // Initialize block facts
        for &block_id in self.cfg.blocks.keys() {
            self.block_facts.insert(block_id, BlockDataFlow::default());
        }

        // Phase 1: Extract definitions and uses from each block
        self.extract_defs_and_uses();

        // Phase 2: Compute reaching definitions
        self.compute_reaching_definitions();

        // Phase 3: Compute liveness
        self.compute_liveness();

        // Phase 4: Build def-use chains
        let def_use_chains = self.build_def_use_chains();

        // Phase 5: Detect issues
        let dead_stores = self.find_dead_stores(&def_use_chains);
        let uninitialized_uses = self.find_uninitialized_uses();
        let use_after_move = self.find_use_after_move();

        DataFlowAnalysis {
            function_name: self.cfg.function_name.clone(),
            file_path: self.cfg.file_path.clone(),
            definitions: self.definitions.clone(),
            uses: self.uses.clone(),
            def_use_chains,
            dead_stores,
            uninitialized_uses,
            use_after_move,
        }
    }

    fn extract_defs_and_uses(&mut self) {
        // Simplified extraction - in real implementation would parse AST
        for (block_id, block) in &self.cfg.blocks {
            for stmt in &block.statements {
                match &stmt.kind {
                    crate::cfg::StatementKind::Assignment { variable } => {
                        let idx = self.next_def_index(*block_id);
                        let def_id = DefId::new(variable, *block_id, stmt.line, idx);

                        // Extract uses from expression
                        let uses = self.extract_uses_from_text(&stmt.text, *block_id, stmt.line);

                        self.definitions.push(Definition {
                            id: def_id.clone(),
                            kind: DefKind::Assignment,
                            expression: stmt.text.clone(),
                            uses: uses.iter().map(|u| u.variable.clone()).collect(),
                        });

                        // Add uses
                        self.uses.extend(uses);

                        // Update block facts
                        if let Some(facts) = self.block_facts.get_mut(block_id) {
                            facts.gen.insert(def_id);
                            facts.defined.insert(variable.clone());
                        }
                    }
                    crate::cfg::StatementKind::Call { function: _ } => {
                        // Function call may have uses
                        let uses = self.extract_uses_from_text(&stmt.text, *block_id, stmt.line);
                        self.uses.extend(uses);
                    }
                    crate::cfg::StatementKind::Return => {
                        let uses = self.extract_uses_from_text(&stmt.text, *block_id, stmt.line);
                        for mut use_ in uses {
                            use_.kind = UseKind::Return;
                            self.uses.push(use_);
                        }
                    }
                    crate::cfg::StatementKind::ControlFlow => {
                        // Condition uses
                        let uses = self.extract_uses_from_text(&stmt.text, *block_id, stmt.line);
                        for mut use_ in uses {
                            use_.kind = UseKind::Condition;
                            self.uses.push(use_);
                        }
                    }
                    crate::cfg::StatementKind::PatternBinding { variables } => {
                        // Each variable in the pattern binding is a definition
                        for variable in variables {
                            let idx = self.next_def_index(*block_id);
                            let def_id = DefId::new(variable, *block_id, stmt.line, idx);

                            self.definitions.push(Definition {
                                id: def_id.clone(),
                                kind: DefKind::PatternBinding,
                                expression: stmt.text.clone(),
                                uses: Vec::new(), // Pattern bindings don't have uses on RHS in this context
                            });

                            // Update block facts
                            if let Some(facts) = self.block_facts.get_mut(block_id) {
                                facts.gen.insert(def_id);
                                facts.defined.insert(variable.clone());
                            }
                        }
                    }
                    crate::cfg::StatementKind::Expression => {
                        // Extract uses from expression statements
                        let uses = self.extract_uses_from_text(&stmt.text, *block_id, stmt.line);
                        self.uses.extend(uses);
                    }
                    _ => {}
                }
            }
        }
    }

    fn extract_uses_from_text(&self, text: &str, block: BlockId, line: usize) -> Vec<Use> {
        // Simplified: extract identifiers that look like variable names
        let mut uses = Vec::new();
        let mut current_ident = String::new();

        for c in text.chars() {
            if c.is_alphanumeric() || c == '_' {
                current_ident.push(c);
            } else {
                if !current_ident.is_empty()
                    && current_ident
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_lowercase())
                    && !is_keyword(&current_ident)
                    && !is_type_constructor(&current_ident)
                {
                    uses.push(Use {
                        variable: current_ident.clone(),
                        block,
                        line,
                        kind: UseKind::Read,
                    });
                }
                current_ident.clear();
            }
        }

        // Don't forget last identifier
        if !current_ident.is_empty()
            && current_ident
                .chars()
                .next()
                .is_some_and(|c| c.is_lowercase())
            && !is_keyword(&current_ident)
            && !is_type_constructor(&current_ident)
        {
            uses.push(Use {
                variable: current_ident,
                block,
                line,
                kind: UseKind::Read,
            });
        }

        uses
    }

    fn next_def_index(&mut self, block: BlockId) -> usize {
        let counter = self.def_counters.entry(block).or_insert(0);
        let idx = *counter;
        *counter += 1;
        idx
    }

    fn compute_reaching_definitions(&mut self) {
        // Worklist algorithm for reaching definitions
        let mut worklist: VecDeque<BlockId> = self.cfg.blocks.keys().copied().collect();
        let all_defs: HashSet<DefId> = self.definitions.iter().map(|d| d.id.clone()).collect();

        while let Some(block_id) = worklist.pop_front() {
            // Compute IN as union of OUT of predecessors
            let mut new_in = HashSet::new();
            for pred in self.cfg.predecessors(block_id) {
                if let Some(pred_facts) = self.block_facts.get(&pred) {
                    new_in.extend(pred_facts.reaching_out.iter().cloned());
                }
            }

            // Compute OUT = GEN ∪ (IN - KILL)
            let gen = self
                .block_facts
                .get(&block_id)
                .map(|f| f.gen.clone())
                .unwrap_or_default();

            // KILL = all defs of same variable
            let kill: HashSet<DefId> = gen
                .iter()
                .flat_map(|d| {
                    let var = d.variable.clone();
                    let def_id = d.clone();
                    all_defs
                        .iter()
                        .filter(move |other| other.variable == var && **other != def_id)
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .collect();

            let new_out: HashSet<DefId> = gen
                .iter()
                .cloned()
                .chain(new_in.iter().filter(|d| !kill.contains(d)).cloned())
                .collect();

            // Update and check for changes
            if let Some(facts) = self.block_facts.get_mut(&block_id) {
                if facts.reaching_out != new_out {
                    facts.reaching_in = new_in;
                    facts.reaching_out = new_out;

                    // Add successors to worklist
                    for succ in self.cfg.successors(block_id) {
                        if !worklist.contains(&succ) {
                            worklist.push_back(succ);
                        }
                    }
                }
            }
        }
    }

    fn compute_liveness(&mut self) {
        // Backwards analysis for liveness
        let mut worklist: VecDeque<BlockId> = self.cfg.blocks.keys().copied().collect();

        // First pass: compute use-before-def for each block
        for (block_id, facts) in &mut self.block_facts {
            let block_uses: HashSet<VarId> = self
                .uses
                .iter()
                .filter(|u| u.block == *block_id)
                .map(|u| u.variable.clone())
                .collect();

            facts.use_before_def = block_uses.difference(&facts.defined).cloned().collect();
        }

        while let Some(block_id) = worklist.pop_front() {
            // LIVE_OUT = union of LIVE_IN of successors
            let mut new_live_out = HashSet::new();
            for succ in self.cfg.successors(block_id) {
                if let Some(succ_facts) = self.block_facts.get(&succ) {
                    new_live_out.extend(succ_facts.live_in.iter().cloned());
                }
            }

            // LIVE_IN = USE_BEFORE_DEF ∪ (LIVE_OUT - DEFINED)
            let use_before_def = self
                .block_facts
                .get(&block_id)
                .map(|f| f.use_before_def.clone())
                .unwrap_or_default();
            let defined = self
                .block_facts
                .get(&block_id)
                .map(|f| f.defined.clone())
                .unwrap_or_default();

            let new_live_in: HashSet<VarId> = use_before_def
                .iter()
                .cloned()
                .chain(
                    new_live_out
                        .iter()
                        .filter(|v| !defined.contains(*v))
                        .cloned(),
                )
                .collect();

            if let Some(facts) = self.block_facts.get_mut(&block_id) {
                if facts.live_in != new_live_in {
                    facts.live_in = new_live_in;
                    facts.live_out = new_live_out;

                    // Add predecessors to worklist
                    for pred in self.cfg.predecessors(block_id) {
                        if !worklist.contains(&pred) {
                            worklist.push_back(pred);
                        }
                    }
                }
            }
        }
    }

    fn build_def_use_chains(&self) -> Vec<DefUseChain> {
        let mut chains = Vec::new();

        for def in &self.definitions {
            let uses: Vec<Use> = self
                .uses
                .iter()
                .filter(|u| {
                    u.variable == def.id.variable && self.definition_reaches_use(&def.id, u)
                })
                .cloned()
                .collect();

            let is_used = !uses.is_empty();

            chains.push(DefUseChain {
                definition: def.id.clone(),
                uses,
                is_used,
            });
        }

        chains
    }

    fn definition_reaches_use(&self, def: &DefId, use_: &Use) -> bool {
        // Check if def is in reaching_in of use's block
        if let Some(facts) = self.block_facts.get(&use_.block) {
            if facts.reaching_in.contains(def) || facts.gen.contains(def) {
                // Also check line numbers if in same block
                if def.block == use_.block {
                    return def.line < use_.line;
                }
                return true;
            }
        }
        false
    }

    fn find_dead_stores(&self, chains: &[DefUseChain]) -> Vec<DefId> {
        chains
            .iter()
            .filter(|c| !c.is_used)
            .map(|c| c.definition.clone())
            .collect()
    }

    fn find_uninitialized_uses(&self) -> Vec<Use> {
        let mut uninitialized = Vec::new();

        // Get function parameters - they are implicitly defined at function entry
        let params: std::collections::HashSet<_> = self.cfg.parameters.iter().collect();

        for use_ in &self.uses {
            // Skip function parameters - they are implicitly defined
            if params.contains(&use_.variable) {
                continue;
            }

            // Check if any definition of this variable reaches this use
            let has_reaching_def = self.definitions.iter().any(|d| {
                d.id.variable == use_.variable && self.definition_reaches_use(&d.id, use_)
            });

            if !has_reaching_def {
                uninitialized.push(use_.clone());
            }
        }

        uninitialized
    }

    /// Find variables used after being moved (Rust ownership semantics)
    ///
    /// A variable is considered "moved" when:
    /// - It's assigned to another variable without a reference (&) or clone
    /// - It's passed to a function by value
    ///
    /// Copy types (primitives) are excluded from move detection.
    fn find_use_after_move(&self) -> Vec<Use> {
        let mut moved_vars: HashMap<String, usize> = HashMap::new(); // var -> move_line
        let mut use_after_move = Vec::new();

        // Process blocks in topological order (simplified: by block ID)
        let mut block_ids: Vec<_> = self.cfg.blocks.keys().copied().collect();
        block_ids.sort();

        for block_id in block_ids {
            if let Some(block) = self.cfg.blocks.get(&block_id) {
                for stmt in &block.statements {
                    // Check for moves in assignment expressions
                    if let crate::cfg::StatementKind::Assignment { variable: _ } = &stmt.kind {
                        // Check if RHS is a simple variable (potential move)
                        if let Some(moved_var) = self.extract_moved_variable(&stmt.text) {
                            if !is_copy_type(&moved_var) {
                                moved_vars.insert(moved_var, stmt.line);
                            }
                        }
                    }

                    // Check for uses of moved variables
                    let used_vars = self.extract_uses_from_text(&stmt.text, block_id, stmt.line);
                    for use_ in used_vars {
                        if let Some(&move_line) = moved_vars.get(&use_.variable) {
                            // Variable was moved before this use
                            if use_.line > move_line {
                                use_after_move.push(Use {
                                    variable: use_.variable.clone(),
                                    block: block_id,
                                    line: use_.line,
                                    kind: UseKind::Read,
                                });
                            }
                        }
                    }
                }
            }
        }

        use_after_move
    }

    /// Extract a potentially moved variable from an assignment expression
    /// Returns Some(var_name) if the RHS is a simple variable (not a reference, clone, or literal)
    fn extract_moved_variable(&self, text: &str) -> Option<String> {
        // Look for pattern: let x = y; or x = y; (where y is a variable, not &y or y.clone())
        let text = text.trim();

        // Extract RHS after '='
        let rhs = text
            .split_once('=')
            .map(|(_, r)| r.trim().trim_end_matches(';').trim())?;

        // Skip if RHS is:
        // - A reference (&)
        // - A clone call (.clone())
        // - A copy call (.copy())
        // - A literal (number, string, bool)
        // - A function call (contains '(')
        // - A field access or method chain (contains '.')
        // - A constructor (contains '{')
        if rhs.starts_with('&')
            || rhs.contains(".clone()")
            || rhs.contains(".copy()")
            || rhs.contains('(')
            || rhs.contains('.')
            || rhs.contains('{')
            || rhs.starts_with('"')
            || rhs.starts_with('\'')
            || rhs.parse::<f64>().is_ok()
            || rhs == "true"
            || rhs == "false"
        {
            return None;
        }

        // Check if RHS is a simple identifier
        if rhs.chars().all(|c| c.is_alphanumeric() || c == '_')
            && rhs
                .chars()
                .next()
                .is_some_and(|c| c.is_lowercase() || c == '_')
            && !is_keyword(rhs)
        {
            Some(rhs.to_string())
        } else {
            None
        }
    }
}

// Helper functions

/// Check if a variable name looks like a Copy type based on naming conventions
fn is_copy_type(var_name: &str) -> bool {
    // Heuristic: Variables with typical primitive-type suffixes are likely Copy
    // This is a simplification - proper type inference would need full type info
    let name_lower = var_name.to_lowercase();

    // Common patterns for Copy types
    name_lower.ends_with("_i32")
        || name_lower.ends_with("_i64")
        || name_lower.ends_with("_u32")
        || name_lower.ends_with("_u64")
        || name_lower.ends_with("_f32")
        || name_lower.ends_with("_f64")
        || name_lower.ends_with("_bool")
        || name_lower.ends_with("_char")
        || name_lower == "i"
        || name_lower == "j"
        || name_lower == "k"
        || name_lower == "n"
        || name_lower == "x"
        || name_lower == "y"
        || name_lower == "z"
        || name_lower == "count"
        || name_lower == "index"
        || name_lower == "len"
        || name_lower == "size"
        || name_lower == "offset"
        || name_lower == "result" // Often bool or numeric result
}

/// Check if a string is a keyword in any supported language.
///
/// Covers keywords from: Rust, Python, JavaScript/TypeScript, Go, Java, C#, Kotlin, C/C++
fn is_keyword(s: &str) -> bool {
    matches!(
        s,
        // Rust keywords
        "let"
            | "mut"
            | "fn"
            | "if"
            | "else"
            | "while"
            | "for"
            | "loop"
            | "match"
            | "return"
            | "break"
            | "continue"
            | "struct"
            | "enum"
            | "impl"
            | "trait"
            | "pub"
            | "use"
            | "mod"
            | "const"
            | "static"
            | "type"
            | "where"
            | "async"
            | "await"
            | "move"
            | "ref"
            | "self"
            | "Self"
            | "super"
            | "crate"
            | "true"
            | "false"
            | "in"
            | "as"
            | "dyn"
            | "extern"
            | "unsafe"
            // Python keywords
            | "def"
            | "class"
            | "import"
            | "from"
            | "and"
            | "or"
            | "not"
            | "is"
            | "None"
            | "True"
            | "False"
            | "try"
            | "except"
            | "finally"
            | "raise"
            | "with"
            | "lambda"
            | "pass"
            | "yield"
            | "global"
            | "nonlocal"
            | "assert"
            | "del"
            | "elif"
            // JavaScript/TypeScript keywords
            | "function"
            | "var"
            | "new"
            | "this"
            | "null"
            | "undefined"
            | "typeof"
            | "instanceof"
            | "delete"
            | "void"
            | "throw"
            | "catch"
            | "debugger"
            | "export"
            | "default"
            | "extends"
            | "implements"
            | "interface"
            | "package"
            // Note: "static" already defined in Rust section
            | "private"
            | "protected"
            | "public"
            | "abstract"
            | "final"
            | "native"
            | "synchronized"
            | "transient"
            | "volatile"
            | "arguments"
            | "eval"
            // Go keywords
            | "func"
            // Note: "package" already defined in JS/TS section
            | "defer"
            | "go"
            | "chan"
            | "select"
            | "case"
            | "fallthrough"
            | "range"
            | "map"
            | "nil"
            // Java keywords
            | "throws"
            | "boolean"
            | "byte"
            | "char"
            | "short"
            | "int"
            | "long"
            | "float"
            | "double"
            | "strictfp"
            // C# keywords
            | "namespace"
            | "using"
            | "virtual"
            | "override"
            | "sealed"
            | "internal"
            | "partial"
            | "readonly"
            | "event"
            | "delegate"
            | "params"
            | "out"
            | "checked"
            | "unchecked"
            | "lock"
            | "fixed"
            | "stackalloc"
            | "base"
            | "explicit"
            | "implicit"
            | "operator"
            // Kotlin keywords
            | "fun"
            | "val"
            | "object"
            | "data"
            | "when"
            | "companion"
            | "init"
            | "suspend"
            | "inline"
            | "reified"
            | "crossinline"
            | "noinline"
            | "tailrec"
            | "vararg"
            | "annotation"
            | "inner"
            | "open"
            | "lateinit"
            | "by"
            | "constructor"
            | "it"
            // C/C++ keywords
            | "sizeof"
            | "typedef"
            | "register"
            | "auto"
            | "template"
            | "typename"
            | "friend"
            | "mutable"
            | "constexpr"
            | "noexcept"
            | "decltype"
            | "nullptr"
            | "alignof"
            | "alignas"
            | "asm"
            | "union"
            | "goto"
            | "switch"
            | "do"
    )
}

/// Check if a name is a type constructor (should not be treated as a variable use)
fn is_type_constructor(s: &str) -> bool {
    matches!(
        s,
        // Option variants
        "Some" | "None" |
        // Result variants
        "Ok" | "Err" |
        // Common type names that might appear
        "Box" | "Vec" | "String" | "Option" | "Result" |
        // Iterator methods commonly appearing in patterns
        "iter" | "into_iter" |
        // Standard library types
        "Arc" | "Rc" | "Cell" | "RefCell" | "Mutex" | "RwLock"
    )
}

/// Analyze data flow for all functions in a file
pub fn analyze_file(tree: &Tree, source: &str, file_path: &str) -> Result<Vec<DataFlowAnalysis>> {
    // First build CFGs
    let cfgs = crate::cfg::analyze_function(tree, source, file_path)?;

    // Then analyze each CFG
    let mut analyses = Vec::new();
    for cfg in &cfgs {
        let mut analyzer = DfgAnalyzer::new(cfg);
        analyses.push(analyzer.analyze());
    }

    Ok(analyses)
}

/// Find all dead stores in a file
pub fn find_dead_stores(
    tree: &Tree,
    source: &str,
    file_path: &str,
) -> Result<Vec<(String, DefId)>> {
    let analyses = analyze_file(tree, source, file_path)?;

    let mut dead_stores = Vec::new();
    for analysis in analyses {
        for def in analysis.dead_stores {
            dead_stores.push((analysis.function_name.clone(), def));
        }
    }

    Ok(dead_stores)
}

/// Find all potentially uninitialized variable uses
pub fn find_uninitialized_vars(
    tree: &Tree,
    source: &str,
    file_path: &str,
) -> Result<Vec<(String, Use)>> {
    let analyses = analyze_file(tree, source, file_path)?;

    let mut uninit = Vec::new();
    for analysis in analyses {
        for use_ in analysis.uninitialized_uses {
            uninit.push((analysis.function_name.clone(), use_.clone()));
        }
    }

    Ok(uninit)
}

/// Find all use-after-move violations in a file (Rust ownership semantics)
pub fn find_use_after_move(
    tree: &Tree,
    source: &str,
    file_path: &str,
) -> Result<Vec<(String, Use)>> {
    let analyses = analyze_file(tree, source, file_path)?;

    let mut violations = Vec::new();
    for analysis in analyses {
        for use_ in analysis.use_after_move {
            violations.push((analysis.function_name.clone(), use_.clone()));
        }
    }

    Ok(violations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::*;

    fn create_simple_cfg() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new("test_func", "test.rs");

        // Entry block with assignment
        let mut entry = BasicBlock {
            id: 0,
            label: "entry".to_string(),
            start_line: 1,
            end_line: 3,
            terminator: Terminator::FallThrough,
            statements: Vec::new(),
            is_entry: true,
            is_exit: false,
        };
        entry.statements.push(Statement {
            line: 1,
            kind: StatementKind::Assignment {
                variable: "x".to_string(),
            },
            text: "let x = 5".to_string(),
        });
        entry.statements.push(Statement {
            line: 2,
            kind: StatementKind::Assignment {
                variable: "y".to_string(),
            },
            text: "let y = x + 1".to_string(),
        });
        cfg.add_block(entry);

        // Exit block with return
        let mut exit = BasicBlock {
            id: 1,
            label: "exit".to_string(),
            start_line: 4,
            end_line: 4,
            terminator: Terminator::Return,
            statements: Vec::new(),
            is_entry: false,
            is_exit: true,
        };
        exit.statements.push(Statement {
            line: 4,
            kind: StatementKind::Return,
            text: "return y".to_string(),
        });
        cfg.add_block(exit);

        cfg.add_edge(0, 1, EdgeKind::FallThrough);
        cfg
    }

    #[test]
    fn test_def_id_creation() {
        let def_id = DefId::new("x", 0, 10, 0);

        assert_eq!(def_id.variable, "x");
        assert_eq!(def_id.block, 0);
        assert_eq!(def_id.line, 10);
        assert_eq!(def_id.index, 0);
    }

    #[test]
    fn test_def_id_equality() {
        let def1 = DefId::new("x", 0, 10, 0);
        let def2 = DefId::new("x", 0, 10, 0);
        let def3 = DefId::new("y", 0, 10, 0);

        assert_eq!(def1, def2);
        assert_ne!(def1, def3);
    }

    #[test]
    fn test_definition_creation() {
        let def = Definition {
            id: DefId::new("x", 0, 1, 0),
            kind: DefKind::Declaration,
            expression: "5 + y".to_string(),
            uses: vec!["y".to_string()],
        };

        assert_eq!(def.id.variable, "x");
        assert_eq!(def.kind, DefKind::Declaration);
        assert_eq!(def.uses, vec!["y"]);
    }

    #[test]
    fn test_use_creation() {
        let use_ = Use {
            variable: "x".to_string(),
            block: 0,
            line: 5,
            kind: UseKind::Read,
        };

        assert_eq!(use_.variable, "x");
        assert_eq!(use_.block, 0);
        assert_eq!(use_.line, 5);
        assert_eq!(use_.kind, UseKind::Read);
    }

    #[test]
    fn test_use_kinds() {
        assert_ne!(UseKind::Read, UseKind::Argument);
        assert_ne!(UseKind::Return, UseKind::Condition);
        assert_eq!(UseKind::AddressTaken, UseKind::AddressTaken);
    }

    #[test]
    fn test_def_kinds() {
        assert_ne!(DefKind::Declaration, DefKind::Assignment);
        assert_ne!(DefKind::Parameter, DefKind::LoopVar);
        assert_eq!(DefKind::PatternBinding, DefKind::PatternBinding);
    }

    #[test]
    fn test_block_data_flow_default() {
        let facts = BlockDataFlow::default();

        assert!(facts.gen.is_empty());
        assert!(facts.kill.is_empty());
        assert!(facts.reaching_in.is_empty());
        assert!(facts.reaching_out.is_empty());
        assert!(facts.live_in.is_empty());
        assert!(facts.live_out.is_empty());
    }

    #[test]
    fn test_dfg_analyzer_creation() {
        let cfg = create_simple_cfg();
        let analyzer = DfgAnalyzer::new(&cfg);

        assert_eq!(analyzer.definitions.len(), 0);
        assert_eq!(analyzer.uses.len(), 0);
    }

    #[test]
    fn test_dfg_analysis_basic() {
        let cfg = create_simple_cfg();
        let mut analyzer = DfgAnalyzer::new(&cfg);

        let result = analyzer.analyze();

        assert_eq!(result.function_name, "test_func");
        assert_eq!(result.file_path, "test.rs");
    }

    #[test]
    fn test_def_use_chain_creation() {
        let chain = DefUseChain {
            definition: DefId::new("x", 0, 1, 0),
            uses: vec![Use {
                variable: "x".to_string(),
                block: 0,
                line: 2,
                kind: UseKind::Read,
            }],
            is_used: true,
        };

        assert!(chain.is_used);
        assert_eq!(chain.uses.len(), 1);
    }

    #[test]
    fn test_dead_store_detection() {
        // Create CFG with unused variable
        let mut cfg = ControlFlowGraph::new("test", "test.rs");

        let mut block = BasicBlock {
            id: 0,
            label: "entry".to_string(),
            start_line: 1,
            end_line: 2,
            terminator: Terminator::Return,
            statements: Vec::new(),
            is_entry: true,
            is_exit: true,
        };
        block.statements.push(Statement {
            line: 1,
            kind: StatementKind::Assignment {
                variable: "unused".to_string(),
            },
            text: "let unused = 5".to_string(),
        });
        cfg.add_block(block);

        let mut analyzer = DfgAnalyzer::new(&cfg);
        let result = analyzer.analyze();

        // Should detect dead store for 'unused'
        assert!(!result.dead_stores.is_empty());
    }

    #[test]
    fn test_is_keyword() {
        assert!(is_keyword("let"));
        assert!(is_keyword("fn"));
        assert!(is_keyword("if"));
        assert!(is_keyword("return"));
        assert!(!is_keyword("foo"));
        assert!(!is_keyword("bar"));
        assert!(!is_keyword("x"));
    }

    #[test]
    fn test_is_keyword_multi_language() {
        // Rust keywords (already tested above, but verify a few more)
        assert!(is_keyword("match"));
        assert!(is_keyword("impl"));
        assert!(is_keyword("trait"));

        // Python keywords
        assert!(is_keyword("def"));
        assert!(is_keyword("elif"));
        assert!(is_keyword("except"));
        assert!(is_keyword("lambda"));
        assert!(is_keyword("pass"));
        assert!(is_keyword("yield"));
        assert!(is_keyword("None"));
        assert!(is_keyword("True"));
        assert!(is_keyword("False"));

        // JavaScript/TypeScript keywords
        assert!(is_keyword("function"));
        assert!(is_keyword("var"));
        assert!(is_keyword("undefined"));
        assert!(is_keyword("null"));
        assert!(is_keyword("typeof"));
        assert!(is_keyword("instanceof"));
        assert!(is_keyword("new"));
        assert!(is_keyword("this"));
        assert!(is_keyword("export"));
        assert!(is_keyword("import"));
        assert!(is_keyword("default"));

        // Go keywords
        assert!(is_keyword("func"));
        assert!(is_keyword("package"));
        assert!(is_keyword("defer"));
        assert!(is_keyword("go"));
        assert!(is_keyword("chan"));
        assert!(is_keyword("select"));
        assert!(is_keyword("range"));
        assert!(is_keyword("nil"));

        // Java keywords
        assert!(is_keyword("class"));
        assert!(is_keyword("public"));
        assert!(is_keyword("private"));
        assert!(is_keyword("protected"));
        assert!(is_keyword("extends"));
        assert!(is_keyword("implements"));
        assert!(is_keyword("interface"));
        assert!(is_keyword("abstract"));
        assert!(is_keyword("final"));
        assert!(is_keyword("synchronized"));
        assert!(is_keyword("throws"));
        assert!(is_keyword("void"));

        // C# keywords
        assert!(is_keyword("namespace"));
        assert!(is_keyword("using"));
        assert!(is_keyword("virtual"));
        assert!(is_keyword("override"));
        assert!(is_keyword("sealed"));
        assert!(is_keyword("internal"));
        assert!(is_keyword("partial"));
        assert!(is_keyword("readonly"));
        assert!(is_keyword("event"));
        assert!(is_keyword("delegate"));

        // Kotlin keywords
        assert!(is_keyword("fun"));
        assert!(is_keyword("val"));
        assert!(is_keyword("object"));
        assert!(is_keyword("data"));
        assert!(is_keyword("when"));
        assert!(is_keyword("companion"));
        assert!(is_keyword("init"));
        assert!(is_keyword("suspend"));
        assert!(is_keyword("inline"));
        assert!(is_keyword("reified"));

        // C/C++ keywords
        assert!(is_keyword("void"));
        assert!(is_keyword("sizeof"));
        assert!(is_keyword("typedef"));
        assert!(is_keyword("extern"));
        assert!(is_keyword("register"));
        assert!(is_keyword("template"));
        assert!(is_keyword("typename"));
        assert!(is_keyword("virtual"));
        assert!(is_keyword("explicit"));
        assert!(is_keyword("friend"));
        assert!(is_keyword("operator"));

        // Non-keywords should still return false
        assert!(!is_keyword("foo"));
        assert!(!is_keyword("bar"));
        assert!(!is_keyword("myVariable"));
        assert!(!is_keyword("calculate"));
    }

    #[test]
    fn test_data_flow_analysis_new() {
        let analysis = DataFlowAnalysis::new("my_func", "my_file.rs");

        assert_eq!(analysis.function_name, "my_func");
        assert_eq!(analysis.file_path, "my_file.rs");
        assert!(analysis.definitions.is_empty());
        assert!(analysis.uses.is_empty());
        assert!(analysis.def_use_chains.is_empty());
        assert!(analysis.dead_stores.is_empty());
        assert!(analysis.uninitialized_uses.is_empty());
    }

    #[test]
    fn test_to_markdown_basic() {
        let analysis = DataFlowAnalysis::new("test", "test.rs");
        let md = analysis.to_markdown();

        assert!(md.contains("Data Flow Analysis: `test`"));
        assert!(md.contains("test.rs"));
        assert!(md.contains("Summary"));
    }

    #[test]
    fn test_to_markdown_with_dead_stores() {
        let mut analysis = DataFlowAnalysis::new("test", "test.rs");
        analysis.dead_stores.push(DefId::new("unused", 0, 5, 0));

        let md = analysis.to_markdown();

        assert!(md.contains("Dead Stores"));
        assert!(md.contains("unused"));
        assert!(md.contains("line 5"));
    }

    #[test]
    fn test_to_markdown_with_uninitialized() {
        let mut analysis = DataFlowAnalysis::new("test", "test.rs");
        analysis.uninitialized_uses.push(Use {
            variable: "uninit".to_string(),
            block: 0,
            line: 10,
            kind: UseKind::Read,
        });

        let md = analysis.to_markdown();

        assert!(md.contains("Uninitialized"));
        assert!(md.contains("uninit"));
    }

    #[test]
    fn test_reaching_definitions_simple() {
        let mut cfg = ControlFlowGraph::new("test", "test.rs");

        // Block 0: x = 5
        let mut b0 = BasicBlock {
            id: 0,
            label: "b0".to_string(),
            start_line: 1,
            end_line: 1,
            terminator: Terminator::FallThrough,
            statements: Vec::new(),
            is_entry: true,
            is_exit: false,
        };
        b0.statements.push(Statement {
            line: 1,
            kind: StatementKind::Assignment {
                variable: "x".to_string(),
            },
            text: "let x = 5".to_string(),
        });
        cfg.add_block(b0);

        // Block 1: use x
        let mut b1 = BasicBlock {
            id: 1,
            label: "b1".to_string(),
            start_line: 2,
            end_line: 2,
            terminator: Terminator::Return,
            statements: Vec::new(),
            is_entry: false,
            is_exit: true,
        };
        b1.statements.push(Statement {
            line: 2,
            kind: StatementKind::Return,
            text: "return x".to_string(),
        });
        cfg.add_block(b1);

        cfg.add_edge(0, 1, EdgeKind::FallThrough);

        let mut analyzer = DfgAnalyzer::new(&cfg);
        let result = analyzer.analyze();

        // x should be used and not dead
        assert!(
            result.dead_stores.is_empty() || !result.dead_stores.iter().any(|d| d.variable == "x")
        );
    }

    #[test]
    fn test_liveness_analysis() {
        let cfg = create_simple_cfg();
        let mut analyzer = DfgAnalyzer::new(&cfg);

        // Initialize
        for &block_id in cfg.blocks.keys() {
            analyzer
                .block_facts
                .insert(block_id, BlockDataFlow::default());
        }

        // After liveness, y should be live at entry of block 1 (exit)
        // x should be live at entry of block 0 (for use in y = x + 1)
        analyzer.extract_defs_and_uses();
        analyzer.compute_liveness();

        // Just verify computation completes without panic
    }

    #[test]
    fn test_extract_uses_from_text() {
        let cfg = create_simple_cfg();
        let analyzer = DfgAnalyzer::new(&cfg);

        let uses = analyzer.extract_uses_from_text("x + y * z", 0, 1);

        assert!(uses.iter().any(|u| u.variable == "x"));
        assert!(uses.iter().any(|u| u.variable == "y"));
        assert!(uses.iter().any(|u| u.variable == "z"));
    }

    #[test]
    fn test_extract_uses_filters_keywords() {
        let cfg = create_simple_cfg();
        let analyzer = DfgAnalyzer::new(&cfg);

        let uses = analyzer.extract_uses_from_text("let x = if true then y else z", 0, 1);

        // Should not include keywords
        assert!(!uses.iter().any(|u| u.variable == "let"));
        assert!(!uses.iter().any(|u| u.variable == "if"));
        // Should include variables
        assert!(uses.iter().any(|u| u.variable == "x"));
        assert!(uses.iter().any(|u| u.variable == "y"));
        assert!(uses.iter().any(|u| u.variable == "z"));
    }

    #[test]
    fn test_def_use_chain_unused() {
        let chain = DefUseChain {
            definition: DefId::new("unused", 0, 1, 0),
            uses: Vec::new(),
            is_used: false,
        };

        assert!(!chain.is_used);
        assert!(chain.uses.is_empty());
    }

    #[test]
    fn test_multiple_defs_same_variable() {
        let mut cfg = ControlFlowGraph::new("test", "test.rs");

        let mut block = BasicBlock {
            id: 0,
            label: "entry".to_string(),
            start_line: 1,
            end_line: 3,
            terminator: Terminator::Return,
            statements: Vec::new(),
            is_entry: true,
            is_exit: true,
        };

        // Two definitions of x
        block.statements.push(Statement {
            line: 1,
            kind: StatementKind::Assignment {
                variable: "x".to_string(),
            },
            text: "let x = 5".to_string(),
        });
        block.statements.push(Statement {
            line: 2,
            kind: StatementKind::Assignment {
                variable: "x".to_string(),
            },
            text: "x = 10".to_string(),
        });
        block.statements.push(Statement {
            line: 3,
            kind: StatementKind::Return,
            text: "return x".to_string(),
        });
        cfg.add_block(block);

        let mut analyzer = DfgAnalyzer::new(&cfg);
        let result = analyzer.analyze();

        // First definition of x should be dead (overwritten before use)
        // Second definition should be used
        assert_eq!(result.definitions.len(), 2);
    }

    #[test]
    fn test_branch_reaching_definitions() {
        let mut cfg = ControlFlowGraph::new("test", "test.rs");

        // Entry: x = 1
        let mut entry = BasicBlock {
            id: 0,
            label: "entry".to_string(),
            start_line: 1,
            end_line: 1,
            terminator: Terminator::Branch {
                condition: "cond".to_string(),
            },
            statements: Vec::new(),
            is_entry: true,
            is_exit: false,
        };
        entry.statements.push(Statement {
            line: 1,
            kind: StatementKind::Assignment {
                variable: "x".to_string(),
            },
            text: "let x = 1".to_string(),
        });
        cfg.add_block(entry);

        // Then: x = 2
        let mut then_block = BasicBlock {
            id: 1,
            label: "then".to_string(),
            start_line: 2,
            end_line: 2,
            terminator: Terminator::Jump,
            statements: Vec::new(),
            is_entry: false,
            is_exit: false,
        };
        then_block.statements.push(Statement {
            line: 2,
            kind: StatementKind::Assignment {
                variable: "x".to_string(),
            },
            text: "x = 2".to_string(),
        });
        cfg.add_block(then_block);

        // Merge: use x
        let mut merge = BasicBlock {
            id: 2,
            label: "merge".to_string(),
            start_line: 3,
            end_line: 3,
            terminator: Terminator::Return,
            statements: Vec::new(),
            is_entry: false,
            is_exit: true,
        };
        merge.statements.push(Statement {
            line: 3,
            kind: StatementKind::Return,
            text: "return x".to_string(),
        });
        cfg.add_block(merge);

        cfg.add_edge(0, 1, EdgeKind::TrueBranch);
        cfg.add_edge(0, 2, EdgeKind::FalseBranch);
        cfg.add_edge(1, 2, EdgeKind::FallThrough);

        let mut analyzer = DfgAnalyzer::new(&cfg);
        let result = analyzer.analyze();

        // Both definitions could reach the use
        assert_eq!(result.definitions.len(), 2);
    }

    #[test]
    fn test_loop_reaching_definitions() {
        let mut cfg = ControlFlowGraph::new("test", "test.rs");

        // Entry: x = 0
        let mut entry = BasicBlock {
            id: 0,
            label: "entry".to_string(),
            start_line: 1,
            end_line: 1,
            terminator: Terminator::FallThrough,
            statements: Vec::new(),
            is_entry: true,
            is_exit: false,
        };
        entry.statements.push(Statement {
            line: 1,
            kind: StatementKind::Assignment {
                variable: "x".to_string(),
            },
            text: "let x = 0".to_string(),
        });
        cfg.add_block(entry);

        // Loop header
        let header = BasicBlock {
            id: 1,
            label: "header".to_string(),
            start_line: 2,
            end_line: 2,
            terminator: Terminator::Branch {
                condition: "x < 10".to_string(),
            },
            statements: Vec::new(),
            is_entry: false,
            is_exit: false,
        };
        cfg.add_block(header);

        // Loop body: x = x + 1
        let mut body = BasicBlock {
            id: 2,
            label: "body".to_string(),
            start_line: 3,
            end_line: 3,
            terminator: Terminator::Jump,
            statements: Vec::new(),
            is_entry: false,
            is_exit: false,
        };
        body.statements.push(Statement {
            line: 3,
            kind: StatementKind::Assignment {
                variable: "x".to_string(),
            },
            text: "x = x + 1".to_string(),
        });
        cfg.add_block(body);

        // Exit
        let exit = BasicBlock {
            id: 3,
            label: "exit".to_string(),
            start_line: 4,
            end_line: 4,
            terminator: Terminator::Return,
            statements: Vec::new(),
            is_entry: false,
            is_exit: true,
        };
        cfg.add_block(exit);

        cfg.add_edge(0, 1, EdgeKind::FallThrough);
        cfg.add_edge(1, 2, EdgeKind::TrueBranch);
        cfg.add_edge(1, 3, EdgeKind::FalseBranch);
        cfg.add_edge(2, 1, EdgeKind::LoopBack);

        let mut analyzer = DfgAnalyzer::new(&cfg);
        let result = analyzer.analyze();

        // Two definitions of x
        assert_eq!(result.definitions.len(), 2);
    }

    // Phase A7: Integration tests for false positive reduction

    #[test]
    fn test_pattern_binding_creates_definition() {
        // Test that PatternBinding statements create proper definitions
        let mut cfg = ControlFlowGraph::new("test_pattern", "test.rs");

        // Entry block
        let entry = BasicBlock {
            id: 0,
            label: "entry".to_string(),
            start_line: 1,
            end_line: 1,
            terminator: Terminator::FallThrough,
            statements: Vec::new(),
            is_entry: true,
            is_exit: false,
        };
        cfg.add_block(entry);

        // Match arm block with pattern binding
        let mut match_arm = BasicBlock {
            id: 1,
            label: "match_arm".to_string(),
            start_line: 2,
            end_line: 3,
            terminator: Terminator::FallThrough,
            statements: Vec::new(),
            is_entry: false,
            is_exit: false,
        };
        match_arm.statements.push(Statement {
            line: 2,
            kind: StatementKind::PatternBinding {
                variables: vec!["value".to_string()],
            },
            text: "Some(value)".to_string(),
        });
        cfg.add_block(match_arm);

        // Exit
        let exit = BasicBlock {
            id: 2,
            label: "exit".to_string(),
            start_line: 4,
            end_line: 4,
            terminator: Terminator::Return,
            statements: Vec::new(),
            is_entry: false,
            is_exit: true,
        };
        cfg.add_block(exit);

        cfg.add_edge(0, 1, EdgeKind::FallThrough);
        cfg.add_edge(1, 2, EdgeKind::FallThrough);

        let mut analyzer = DfgAnalyzer::new(&cfg);
        let result = analyzer.analyze();

        // 'value' should be recognized as a definition
        assert!(
            result.definitions.iter().any(|d| d.id.variable == "value"),
            "Pattern binding 'value' should create a definition, found: {:?}",
            result
                .definitions
                .iter()
                .map(|d| &d.id.variable)
                .collect::<Vec<_>>()
        );

        // Definition should be of kind PatternBinding
        let value_def = result
            .definitions
            .iter()
            .find(|d| d.id.variable == "value")
            .expect("Should find value definition");
        assert_eq!(value_def.kind, DefKind::PatternBinding);
    }

    #[test]
    fn test_pattern_variable_not_uninitialized() {
        // Test that pattern-bound variables are NOT marked as uninitialized
        let mut cfg = ControlFlowGraph::new("test_no_fp", "test.rs");

        // Entry
        let entry = BasicBlock {
            id: 0,
            label: "entry".to_string(),
            start_line: 1,
            end_line: 1,
            terminator: Terminator::Branch {
                condition: "opt".to_string(),
            },
            statements: vec![Statement {
                line: 1,
                kind: StatementKind::ControlFlow,
                text: "match opt".to_string(),
            }],
            is_entry: true,
            is_exit: false,
        };
        cfg.add_block(entry);

        // Match arm with pattern binding + use
        let mut match_arm = BasicBlock {
            id: 1,
            label: "match_arm".to_string(),
            start_line: 2,
            end_line: 3,
            terminator: Terminator::FallThrough,
            statements: Vec::new(),
            is_entry: false,
            is_exit: false,
        };
        // Pattern binding: Some(x) creates definition for 'x'
        match_arm.statements.push(Statement {
            line: 2,
            kind: StatementKind::PatternBinding {
                variables: vec!["x".to_string()],
            },
            text: "Some(x)".to_string(),
        });
        // Expression using 'x': should NOT be uninitialized
        match_arm.statements.push(Statement {
            line: 3,
            kind: StatementKind::Expression,
            text: "println!(x + 1)".to_string(),
        });
        cfg.add_block(match_arm);

        // Exit
        let exit = BasicBlock {
            id: 2,
            label: "exit".to_string(),
            start_line: 4,
            end_line: 4,
            terminator: Terminator::Return,
            statements: Vec::new(),
            is_entry: false,
            is_exit: true,
        };
        cfg.add_block(exit);

        cfg.add_edge(0, 1, EdgeKind::TrueBranch);
        cfg.add_edge(0, 2, EdgeKind::FalseBranch);
        cfg.add_edge(1, 2, EdgeKind::FallThrough);

        let mut analyzer = DfgAnalyzer::new(&cfg);
        let result = analyzer.analyze();

        // 'x' should NOT appear in uninitialized uses since it's defined by the pattern
        let uninit_vars: Vec<&str> = result
            .uninitialized_uses
            .iter()
            .map(|u| u.variable.as_str())
            .collect();

        assert!(
            !uninit_vars.contains(&"x"),
            "Pattern variable 'x' should NOT be uninitialized. Uninitialized vars: {:?}",
            uninit_vars
        );
    }

    #[test]
    fn test_type_constructors_not_reported_as_uses() {
        // Verify that type constructors like Some, None, Ok, Err are filtered
        let mut cfg = ControlFlowGraph::new("test_type_constructors", "test.rs");

        let mut block = BasicBlock {
            id: 0,
            label: "entry".to_string(),
            start_line: 1,
            end_line: 2,
            terminator: Terminator::Return,
            statements: Vec::new(),
            is_entry: true,
            is_exit: true,
        };
        // Statement containing type constructors
        block.statements.push(Statement {
            line: 1,
            kind: StatementKind::Expression,
            text: "Some(value) Ok(result) Err(error) None".to_string(),
        });
        cfg.add_block(block);

        let mut analyzer = DfgAnalyzer::new(&cfg);
        let result = analyzer.analyze();

        let use_vars: Vec<&str> = result.uses.iter().map(|u| u.variable.as_str()).collect();

        // Type constructors should NOT appear as uses
        assert!(
            !use_vars
                .iter()
                .any(|&v| v == "Some" || v == "None" || v == "Ok" || v == "Err"),
            "Type constructors should be filtered. Uses found: {:?}",
            use_vars
        );

        // But actual variables should still be found
        assert!(use_vars.contains(&"value"), "Should find 'value' use");
        assert!(use_vars.contains(&"result"), "Should find 'result' use");
        assert!(use_vars.contains(&"error"), "Should find 'error' use");
    }

    #[test]
    fn test_for_loop_variable_not_uninitialized() {
        // Test for loop variables are properly recognized
        let mut cfg = ControlFlowGraph::new("test_for_loop", "test.rs");

        // Entry
        let entry = BasicBlock {
            id: 0,
            label: "entry".to_string(),
            start_line: 1,
            end_line: 1,
            terminator: Terminator::FallThrough,
            statements: Vec::new(),
            is_entry: true,
            is_exit: false,
        };
        cfg.add_block(entry);

        // For header
        let header = BasicBlock {
            id: 1,
            label: "for_header".to_string(),
            start_line: 2,
            end_line: 2,
            terminator: Terminator::Loop,
            statements: vec![Statement {
                line: 2,
                kind: StatementKind::ControlFlow,
                text: "for loop".to_string(),
            }],
            is_entry: false,
            is_exit: false,
        };
        cfg.add_block(header);

        // For body with pattern binding + use
        let mut body = BasicBlock {
            id: 2,
            label: "for_body".to_string(),
            start_line: 3,
            end_line: 4,
            terminator: Terminator::FallThrough,
            statements: Vec::new(),
            is_entry: false,
            is_exit: false,
        };
        body.statements.push(Statement {
            line: 3,
            kind: StatementKind::PatternBinding {
                variables: vec!["item".to_string()],
            },
            text: "for item".to_string(),
        });
        body.statements.push(Statement {
            line: 4,
            kind: StatementKind::Expression,
            text: "process(item)".to_string(),
        });
        cfg.add_block(body);

        // Exit
        let exit = BasicBlock {
            id: 3,
            label: "for_exit".to_string(),
            start_line: 5,
            end_line: 5,
            terminator: Terminator::Return,
            statements: Vec::new(),
            is_entry: false,
            is_exit: true,
        };
        cfg.add_block(exit);

        cfg.add_edge(0, 1, EdgeKind::FallThrough);
        cfg.add_edge(1, 2, EdgeKind::TrueBranch);
        cfg.add_edge(1, 3, EdgeKind::FalseBranch);
        cfg.add_edge(2, 1, EdgeKind::LoopBack);

        let mut analyzer = DfgAnalyzer::new(&cfg);
        let result = analyzer.analyze();

        // 'item' should be a definition
        assert!(
            result.definitions.iter().any(|d| d.id.variable == "item"),
            "Loop variable 'item' should be a definition"
        );

        // 'item' should NOT be uninitialized
        let uninit_vars: Vec<&str> = result
            .uninitialized_uses
            .iter()
            .map(|u| u.variable.as_str())
            .collect();

        assert!(
            !uninit_vars.contains(&"item"),
            "Loop variable 'item' should NOT be uninitialized. Uninit: {:?}",
            uninit_vars
        );
    }

    #[test]
    fn test_nested_pattern_bindings() {
        // Test nested patterns like Ok(Some(inner))
        let mut cfg = ControlFlowGraph::new("test_nested", "test.rs");

        let mut block = BasicBlock {
            id: 0,
            label: "match_arm".to_string(),
            start_line: 1,
            end_line: 2,
            terminator: Terminator::Return,
            statements: Vec::new(),
            is_entry: true,
            is_exit: true,
        };
        // Nested pattern binding with multiple variables
        block.statements.push(Statement {
            line: 1,
            kind: StatementKind::PatternBinding {
                variables: vec!["inner".to_string(), "second".to_string()],
            },
            text: "Ok(Some((inner, second)))".to_string(),
        });
        block.statements.push(Statement {
            line: 2,
            kind: StatementKind::Expression,
            text: "use(inner, second)".to_string(),
        });
        cfg.add_block(block);

        let mut analyzer = DfgAnalyzer::new(&cfg);
        let result = analyzer.analyze();

        // Both variables should be definitions
        assert!(
            result.definitions.iter().any(|d| d.id.variable == "inner"),
            "Should have 'inner' definition"
        );
        assert!(
            result.definitions.iter().any(|d| d.id.variable == "second"),
            "Should have 'second' definition"
        );

        // Neither should be uninitialized
        let uninit_vars: Vec<&str> = result
            .uninitialized_uses
            .iter()
            .map(|u| u.variable.as_str())
            .collect();

        assert!(
            !uninit_vars.contains(&"inner") && !uninit_vars.contains(&"second"),
            "Nested pattern variables should NOT be uninitialized. Uninit: {:?}",
            uninit_vars
        );
    }

    // ==== Multi-Language Dead Store Detection Tests ====

    #[test]
    fn test_go_dead_store_detection() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .unwrap();

        let source = r#"
package main

func example() int {
    unused := 5
    x := 10
    return x
}
"#;

        let tree = parser.parse(source, None).unwrap();
        let dead_stores = find_dead_stores(&tree, source, "test.go").unwrap();

        // Should detect 'unused' as a dead store
        assert!(
            dead_stores.iter().any(|(_, def)| def.variable == "unused"),
            "Go: Should detect 'unused' as dead store. Found: {:?}",
            dead_stores
        );
        // 'x' is used in return, should NOT be a dead store
        assert!(
            !dead_stores.iter().any(|(_, def)| def.variable == "x"),
            "Go: 'x' is used, should NOT be dead store"
        );
    }

    #[test]
    fn test_java_dead_store_detection() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .unwrap();

        let source = r#"
public class Test {
    public int example() {
        int unused = 5;
        int x = 10;
        return x;
    }
}
"#;

        let tree = parser.parse(source, None).unwrap();
        let dead_stores = find_dead_stores(&tree, source, "Test.java").unwrap();

        // Should detect 'unused' as a dead store
        assert!(
            dead_stores.iter().any(|(_, def)| def.variable == "unused"),
            "Java: Should detect 'unused' as dead store. Found: {:?}",
            dead_stores
        );
    }

    #[test]
    fn test_kotlin_dead_store_detection() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_kotlin_sg::LANGUAGE.into())
            .unwrap();

        let source = r#"
fun example(): Int {
    val unused = 5
    val x = 10
    return x
}
"#;

        let tree = parser.parse(source, None).unwrap();
        let dead_stores = find_dead_stores(&tree, source, "test.kt").unwrap();

        // Should detect 'unused' as a dead store
        assert!(
            dead_stores.iter().any(|(_, def)| def.variable == "unused"),
            "Kotlin: Should detect 'unused' as dead store. Found: {:?}",
            dead_stores
        );
    }

    #[test]
    fn test_python_dead_store_detection() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();

        let source = r#"
def example():
    unused = 5
    x = 10
    return x
"#;

        let tree = parser.parse(source, None).unwrap();
        let dead_stores = find_dead_stores(&tree, source, "test.py").unwrap();

        // Should detect 'unused' as a dead store
        assert!(
            dead_stores.iter().any(|(_, def)| def.variable == "unused"),
            "Python: Should detect 'unused' as dead store. Found: {:?}",
            dead_stores
        );
    }

    #[test]
    fn test_typescript_dead_store_detection() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .unwrap();

        let source = r#"
function example(): number {
    let unused = 5;
    let x = 10;
    return x;
}
"#;

        let tree = parser.parse(source, None).unwrap();
        let dead_stores = find_dead_stores(&tree, source, "test.ts").unwrap();

        // Should detect 'unused' as a dead store
        assert!(
            dead_stores.iter().any(|(_, def)| def.variable == "unused"),
            "TypeScript: Should detect 'unused' as dead store. Found: {:?}",
            dead_stores
        );
    }
}
