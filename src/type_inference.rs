//! Type inference for dynamic languages (Python, JavaScript, TypeScript)
//!
//! Uses Hindley-Milner style inference with:
//! - Flow-sensitive analysis (types can change through code)
//! - Gradual typing (mixing typed and untyped code)
//! - Built-in stubs for standard library

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tree_sitter::Node;

use crate::cfg::{BlockId, ControlFlowGraph, StatementKind};

/// Type variable identifier for inference
pub type TypeVarId = u32;

/// Inferred type representation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Type {
    // Primitive types
    /// Integer type (int in Python, number in JS)
    Int,
    /// Floating point type
    Float,
    /// String type
    String,
    /// Boolean type
    Bool,
    /// None/null/undefined
    None,
    /// Bytes type (Python)
    Bytes,

    // Composite types
    /// List/Array type
    List(Box<Type>),
    /// Dictionary/Object type
    Dict(Box<Type>, Box<Type>),
    /// Set type
    Set(Box<Type>),
    /// Tuple type
    Tuple(Vec<Type>),

    /// Callable/Function type
    Function { params: Vec<Type>, ret: Box<Type> },

    /// Object/class instance
    Instance {
        class_name: String,
        type_args: Vec<Type>,
    },

    /// Type variable (for inference)
    Var(TypeVarId),

    /// Union type (e.g., str | None)
    Union(Vec<Type>),

    /// Optional type (shorthand for T | None)
    Optional(Box<Type>),

    /// Unknown/any type
    Unknown,

    /// Never type (unreachable code)
    Never,

    /// Literal type (for literal inference)
    Literal(LiteralType),
}

/// Literal type values
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LiteralType {
    Int(i64),
    Float(String), // Use string to preserve precision
    String(String),
    Bool(bool),
}

impl Type {
    /// Check if this type is a subtype of another
    pub fn is_subtype_of(&self, other: &Type) -> bool {
        if self == other {
            return true;
        }

        match (self, other) {
            // Any type is subtype of Unknown
            (_, Type::Unknown) => true,
            // Never is subtype of everything
            (Type::Never, _) => true,
            // None is subtype of Optional
            (Type::None, Type::Optional(_)) => true,
            // T is subtype of Optional<T>
            (t, Type::Optional(inner)) => t.is_subtype_of(inner),
            // Int is subtype of Float (numeric widening)
            (Type::Int, Type::Float) => true,
            // Literal types are subtypes of their base types
            (Type::Literal(LiteralType::Int(_)), Type::Int) => true,
            (Type::Literal(LiteralType::Float(_)), Type::Float) => true,
            (Type::Literal(LiteralType::String(_)), Type::String) => true,
            (Type::Literal(LiteralType::Bool(_)), Type::Bool) => true,
            // List covariance
            (Type::List(a), Type::List(b)) => a.is_subtype_of(b),
            // Union subtyping - T is subtype of Union if T is subtype of any member
            (t, Type::Union(types)) => types.iter().any(|u| t.is_subtype_of(u)),
            // Union subtype - Union is subtype of T if all members are subtypes
            (Type::Union(types), t) => types.iter().all(|u| u.is_subtype_of(t)),
            _ => false,
        }
    }

    /// Simplify type (e.g., flatten nested unions)
    pub fn simplify(&self) -> Type {
        match self {
            Type::Union(types) => {
                let mut simplified: Vec<Type> = Vec::new();
                for t in types {
                    let t = t.simplify();
                    match t {
                        Type::Union(inner) => simplified.extend(inner),
                        _ => {
                            if !simplified.contains(&t) {
                                simplified.push(t);
                            }
                        }
                    }
                }
                if simplified.len() == 1 {
                    simplified.pop().unwrap()
                } else {
                    Type::Union(simplified)
                }
            }
            Type::Optional(inner) => {
                let inner = inner.simplify();
                if inner == Type::None {
                    Type::None
                } else {
                    Type::Optional(Box::new(inner))
                }
            }
            _ => self.clone(),
        }
    }

    /// Get human-readable type name
    pub fn display_name(&self) -> String {
        match self {
            Type::Int => "int".to_string(),
            Type::Float => "float".to_string(),
            Type::String => "str".to_string(),
            Type::Bool => "bool".to_string(),
            Type::None => "None".to_string(),
            Type::Bytes => "bytes".to_string(),
            Type::List(inner) => format!("list[{}]", inner.display_name()),
            Type::Dict(k, v) => format!("dict[{}, {}]", k.display_name(), v.display_name()),
            Type::Set(inner) => format!("set[{}]", inner.display_name()),
            Type::Tuple(types) => {
                let inner: Vec<String> = types.iter().map(|t| t.display_name()).collect();
                format!("tuple[{}]", inner.join(", "))
            }
            Type::Function { params, ret } => {
                let params: Vec<String> = params.iter().map(|t| t.display_name()).collect();
                format!("({}) -> {}", params.join(", "), ret.display_name())
            }
            Type::Instance {
                class_name,
                type_args,
            } => {
                if type_args.is_empty() {
                    class_name.clone()
                } else {
                    let args: Vec<String> = type_args.iter().map(|t| t.display_name()).collect();
                    format!("{}[{}]", class_name, args.join(", "))
                }
            }
            Type::Var(id) => format!("T{}", id),
            Type::Union(types) => {
                let inner: Vec<String> = types.iter().map(|t| t.display_name()).collect();
                inner.join(" | ")
            }
            Type::Optional(inner) => format!("{} | None", inner.display_name()),
            Type::Unknown => "Any".to_string(),
            Type::Never => "Never".to_string(),
            Type::Literal(lit) => match lit {
                LiteralType::Int(i) => format!("Literal[{}]", i),
                LiteralType::Float(f) => format!("Literal[{}]", f),
                LiteralType::String(s) => format!("Literal[\"{}\"]", s),
                LiteralType::Bool(b) => format!("Literal[{}]", b),
            },
        }
    }
}

/// Type constraint for unification
#[derive(Debug, Clone)]
pub enum Constraint {
    /// T1 = T2 (equality)
    Equal(Type, Type),
    /// T1 is subtype of T2
    Subtype(Type, Type),
    /// T has attribute attr of type T2
    HasAttr(Type, String, Type),
    /// T is callable with params returning ret
    Callable(Type, Vec<Type>, Type),
    /// T has method with signature
    HasMethod(Type, String, Vec<Type>, Type),
}

/// Type environment at a program point
#[derive(Debug, Clone, Default)]
pub struct TypeEnv {
    /// Variable name -> Type
    bindings: HashMap<String, Type>,
    /// Type variable substitutions
    substitutions: HashMap<TypeVarId, Type>,
    /// Fresh type variable counter
    next_var: TypeVarId,
    /// Scope stack (for nested scopes)
    scopes: Vec<HashMap<String, Type>>,
}

impl TypeEnv {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a fresh type variable
    pub fn fresh_var(&mut self) -> Type {
        let var = Type::Var(self.next_var);
        self.next_var += 1;
        var
    }

    /// Bind a variable to a type
    pub fn bind(&mut self, name: String, ty: Type) {
        self.bindings.insert(name, ty);
    }

    /// Look up a variable's type
    pub fn lookup(&self, name: &str) -> Option<&Type> {
        // Check current scope first
        self.bindings.get(name).or_else(|| {
            // Check parent scopes
            for scope in self.scopes.iter().rev() {
                if let Some(ty) = scope.get(name) {
                    return Some(ty);
                }
            }
            None
        })
    }

    /// Enter a new scope
    pub fn push_scope(&mut self) {
        self.scopes.push(std::mem::take(&mut self.bindings));
    }

    /// Exit current scope
    pub fn pop_scope(&mut self) {
        if let Some(parent) = self.scopes.pop() {
            self.bindings = parent;
        }
    }

    /// Apply substitutions to resolve type variables
    pub fn substitute(&self, ty: &Type) -> Type {
        match ty {
            Type::Var(id) => {
                if let Some(resolved) = self.substitutions.get(id) {
                    self.substitute(resolved)
                } else {
                    ty.clone()
                }
            }
            Type::List(inner) => Type::List(Box::new(self.substitute(inner))),
            Type::Dict(k, v) => {
                Type::Dict(Box::new(self.substitute(k)), Box::new(self.substitute(v)))
            }
            Type::Set(inner) => Type::Set(Box::new(self.substitute(inner))),
            Type::Tuple(types) => Type::Tuple(types.iter().map(|t| self.substitute(t)).collect()),
            Type::Union(types) => Type::Union(types.iter().map(|t| self.substitute(t)).collect()),
            Type::Optional(inner) => Type::Optional(Box::new(self.substitute(inner))),
            Type::Function { params, ret } => Type::Function {
                params: params.iter().map(|t| self.substitute(t)).collect(),
                ret: Box::new(self.substitute(ret)),
            },
            Type::Instance {
                class_name,
                type_args,
            } => Type::Instance {
                class_name: class_name.clone(),
                type_args: type_args.iter().map(|t| self.substitute(t)).collect(),
            },
            _ => ty.clone(),
        }
    }

    /// Add a type variable substitution
    pub fn add_substitution(&mut self, var: TypeVarId, ty: Type) {
        self.substitutions.insert(var, ty);
    }

    /// Get all variable bindings
    pub fn all_bindings(&self) -> HashMap<String, Type> {
        let mut all = HashMap::new();
        for scope in &self.scopes {
            all.extend(scope.clone());
        }
        all.extend(self.bindings.clone());
        all
    }
}

/// Function signature for type stubs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSig {
    pub params: Vec<(String, Type)>,
    pub ret: Type,
    pub is_method: bool,
}

/// Standard library type stubs
pub struct TypeStubs {
    /// Module -> (function_name -> signature)
    modules: HashMap<String, HashMap<String, FunctionSig>>,
    /// Builtin functions
    builtins: HashMap<String, FunctionSig>,
    /// Class definitions
    classes: HashMap<String, ClassDef>,
}

/// Class definition for type checking
#[derive(Debug, Clone)]
pub struct ClassDef {
    pub name: String,
    pub methods: HashMap<String, FunctionSig>,
    pub attributes: HashMap<String, Type>,
    pub bases: Vec<String>,
}

impl TypeStubs {
    /// Create Python standard library stubs
    pub fn python_stdlib() -> Self {
        let mut stubs = Self {
            modules: HashMap::new(),
            builtins: HashMap::new(),
            classes: HashMap::new(),
        };

        // Builtins
        stubs.builtins.insert(
            "len".to_string(),
            FunctionSig {
                params: vec![("obj".to_string(), Type::Unknown)],
                ret: Type::Int,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "str".to_string(),
            FunctionSig {
                params: vec![("obj".to_string(), Type::Unknown)],
                ret: Type::String,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "int".to_string(),
            FunctionSig {
                params: vec![("obj".to_string(), Type::Unknown)],
                ret: Type::Int,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "float".to_string(),
            FunctionSig {
                params: vec![("obj".to_string(), Type::Unknown)],
                ret: Type::Float,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "bool".to_string(),
            FunctionSig {
                params: vec![("obj".to_string(), Type::Unknown)],
                ret: Type::Bool,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "list".to_string(),
            FunctionSig {
                params: vec![("iterable".to_string(), Type::Unknown)],
                ret: Type::List(Box::new(Type::Unknown)),
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "dict".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Dict(Box::new(Type::Unknown), Box::new(Type::Unknown)),
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "set".to_string(),
            FunctionSig {
                params: vec![("iterable".to_string(), Type::Unknown)],
                ret: Type::Set(Box::new(Type::Unknown)),
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "print".to_string(),
            FunctionSig {
                params: vec![("args".to_string(), Type::Unknown)],
                ret: Type::None,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "open".to_string(),
            FunctionSig {
                params: vec![
                    ("file".to_string(), Type::String),
                    ("mode".to_string(), Type::String),
                ],
                ret: Type::Instance {
                    class_name: "TextIO".to_string(),
                    type_args: vec![],
                },
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "range".to_string(),
            FunctionSig {
                params: vec![
                    ("start".to_string(), Type::Int),
                    ("stop".to_string(), Type::Int),
                ],
                ret: Type::Instance {
                    class_name: "range".to_string(),
                    type_args: vec![],
                },
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "isinstance".to_string(),
            FunctionSig {
                params: vec![
                    ("obj".to_string(), Type::Unknown),
                    ("classinfo".to_string(), Type::Unknown),
                ],
                ret: Type::Bool,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "hasattr".to_string(),
            FunctionSig {
                params: vec![
                    ("obj".to_string(), Type::Unknown),
                    ("name".to_string(), Type::String),
                ],
                ret: Type::Bool,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "getattr".to_string(),
            FunctionSig {
                params: vec![
                    ("obj".to_string(), Type::Unknown),
                    ("name".to_string(), Type::String),
                ],
                ret: Type::Unknown,
                is_method: false,
            },
        );

        // os module
        let mut os_module = HashMap::new();
        os_module.insert(
            "getenv".to_string(),
            FunctionSig {
                params: vec![("key".to_string(), Type::String)],
                ret: Type::Optional(Box::new(Type::String)),
                is_method: false,
            },
        );
        os_module.insert(
            "getcwd".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::String,
                is_method: false,
            },
        );
        os_module.insert(
            "listdir".to_string(),
            FunctionSig {
                params: vec![("path".to_string(), Type::String)],
                ret: Type::List(Box::new(Type::String)),
                is_method: false,
            },
        );
        os_module.insert(
            "path.join".to_string(),
            FunctionSig {
                params: vec![("paths".to_string(), Type::String)],
                ret: Type::String,
                is_method: false,
            },
        );
        os_module.insert(
            "path.exists".to_string(),
            FunctionSig {
                params: vec![("path".to_string(), Type::String)],
                ret: Type::Bool,
                is_method: false,
            },
        );
        stubs.modules.insert("os".to_string(), os_module);

        // json module
        let mut json_module = HashMap::new();
        json_module.insert(
            "loads".to_string(),
            FunctionSig {
                params: vec![("s".to_string(), Type::String)],
                ret: Type::Unknown,
                is_method: false,
            },
        );
        json_module.insert(
            "dumps".to_string(),
            FunctionSig {
                params: vec![("obj".to_string(), Type::Unknown)],
                ret: Type::String,
                is_method: false,
            },
        );
        json_module.insert(
            "load".to_string(),
            FunctionSig {
                params: vec![("fp".to_string(), Type::Unknown)],
                ret: Type::Unknown,
                is_method: false,
            },
        );
        json_module.insert(
            "dump".to_string(),
            FunctionSig {
                params: vec![
                    ("obj".to_string(), Type::Unknown),
                    ("fp".to_string(), Type::Unknown),
                ],
                ret: Type::None,
                is_method: false,
            },
        );
        stubs.modules.insert("json".to_string(), json_module);

        // re module
        let mut re_module = HashMap::new();
        re_module.insert(
            "match".to_string(),
            FunctionSig {
                params: vec![
                    ("pattern".to_string(), Type::String),
                    ("string".to_string(), Type::String),
                ],
                ret: Type::Optional(Box::new(Type::Instance {
                    class_name: "Match".to_string(),
                    type_args: vec![],
                })),
                is_method: false,
            },
        );
        re_module.insert(
            "search".to_string(),
            FunctionSig {
                params: vec![
                    ("pattern".to_string(), Type::String),
                    ("string".to_string(), Type::String),
                ],
                ret: Type::Optional(Box::new(Type::Instance {
                    class_name: "Match".to_string(),
                    type_args: vec![],
                })),
                is_method: false,
            },
        );
        re_module.insert(
            "findall".to_string(),
            FunctionSig {
                params: vec![
                    ("pattern".to_string(), Type::String),
                    ("string".to_string(), Type::String),
                ],
                ret: Type::List(Box::new(Type::String)),
                is_method: false,
            },
        );
        stubs.modules.insert("re".to_string(), re_module);

        // str class methods
        let mut str_class = ClassDef {
            name: "str".to_string(),
            methods: HashMap::new(),
            attributes: HashMap::new(),
            bases: vec![],
        };
        str_class.methods.insert(
            "split".to_string(),
            FunctionSig {
                params: vec![("sep".to_string(), Type::Optional(Box::new(Type::String)))],
                ret: Type::List(Box::new(Type::String)),
                is_method: true,
            },
        );
        str_class.methods.insert(
            "join".to_string(),
            FunctionSig {
                params: vec![("iterable".to_string(), Type::List(Box::new(Type::String)))],
                ret: Type::String,
                is_method: true,
            },
        );
        str_class.methods.insert(
            "strip".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::String,
                is_method: true,
            },
        );
        str_class.methods.insert(
            "lower".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::String,
                is_method: true,
            },
        );
        str_class.methods.insert(
            "upper".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::String,
                is_method: true,
            },
        );
        str_class.methods.insert(
            "replace".to_string(),
            FunctionSig {
                params: vec![
                    ("old".to_string(), Type::String),
                    ("new".to_string(), Type::String),
                ],
                ret: Type::String,
                is_method: true,
            },
        );
        str_class.methods.insert(
            "startswith".to_string(),
            FunctionSig {
                params: vec![("prefix".to_string(), Type::String)],
                ret: Type::Bool,
                is_method: true,
            },
        );
        str_class.methods.insert(
            "endswith".to_string(),
            FunctionSig {
                params: vec![("suffix".to_string(), Type::String)],
                ret: Type::Bool,
                is_method: true,
            },
        );
        stubs.classes.insert("str".to_string(), str_class);

        // list class methods
        let mut list_class = ClassDef {
            name: "list".to_string(),
            methods: HashMap::new(),
            attributes: HashMap::new(),
            bases: vec![],
        };
        list_class.methods.insert(
            "append".to_string(),
            FunctionSig {
                params: vec![("item".to_string(), Type::Unknown)],
                ret: Type::None,
                is_method: true,
            },
        );
        list_class.methods.insert(
            "extend".to_string(),
            FunctionSig {
                params: vec![("iterable".to_string(), Type::Unknown)],
                ret: Type::None,
                is_method: true,
            },
        );
        list_class.methods.insert(
            "pop".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Unknown,
                is_method: true,
            },
        );
        list_class.methods.insert(
            "sort".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::None,
                is_method: true,
            },
        );
        list_class.methods.insert(
            "reverse".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::None,
                is_method: true,
            },
        );
        stubs.classes.insert("list".to_string(), list_class);

        // dict class methods
        let mut dict_class = ClassDef {
            name: "dict".to_string(),
            methods: HashMap::new(),
            attributes: HashMap::new(),
            bases: vec![],
        };
        dict_class.methods.insert(
            "get".to_string(),
            FunctionSig {
                params: vec![
                    ("key".to_string(), Type::Unknown),
                    (
                        "default".to_string(),
                        Type::Optional(Box::new(Type::Unknown)),
                    ),
                ],
                ret: Type::Unknown,
                is_method: true,
            },
        );
        dict_class.methods.insert(
            "keys".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Instance {
                    class_name: "dict_keys".to_string(),
                    type_args: vec![],
                },
                is_method: true,
            },
        );
        dict_class.methods.insert(
            "values".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Instance {
                    class_name: "dict_values".to_string(),
                    type_args: vec![],
                },
                is_method: true,
            },
        );
        dict_class.methods.insert(
            "items".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Instance {
                    class_name: "dict_items".to_string(),
                    type_args: vec![],
                },
                is_method: true,
            },
        );
        dict_class.methods.insert(
            "update".to_string(),
            FunctionSig {
                params: vec![("other".to_string(), Type::Unknown)],
                ret: Type::None,
                is_method: true,
            },
        );
        stubs.classes.insert("dict".to_string(), dict_class);

        stubs
    }

    /// Create JavaScript/TypeScript standard library stubs
    pub fn javascript_stdlib() -> Self {
        let mut stubs = Self {
            modules: HashMap::new(),
            builtins: HashMap::new(),
            classes: HashMap::new(),
        };

        // Global functions
        stubs.builtins.insert(
            "parseInt".to_string(),
            FunctionSig {
                params: vec![("string".to_string(), Type::String)],
                ret: Type::Int,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "parseFloat".to_string(),
            FunctionSig {
                params: vec![("string".to_string(), Type::String)],
                ret: Type::Float,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "String".to_string(),
            FunctionSig {
                params: vec![("value".to_string(), Type::Unknown)],
                ret: Type::String,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "Number".to_string(),
            FunctionSig {
                params: vec![("value".to_string(), Type::Unknown)],
                ret: Type::Float,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "Boolean".to_string(),
            FunctionSig {
                params: vec![("value".to_string(), Type::Unknown)],
                ret: Type::Bool,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "Array".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::List(Box::new(Type::Unknown)),
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "Object".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Dict(Box::new(Type::String), Box::new(Type::Unknown)),
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "console.log".to_string(),
            FunctionSig {
                params: vec![("args".to_string(), Type::Unknown)],
                ret: Type::None,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "JSON.parse".to_string(),
            FunctionSig {
                params: vec![("text".to_string(), Type::String)],
                ret: Type::Unknown,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "JSON.stringify".to_string(),
            FunctionSig {
                params: vec![("value".to_string(), Type::Unknown)],
                ret: Type::String,
                is_method: false,
            },
        );

        // Array methods
        let mut array_class = ClassDef {
            name: "Array".to_string(),
            methods: HashMap::new(),
            attributes: HashMap::new(),
            bases: vec![],
        };
        array_class.methods.insert(
            "push".to_string(),
            FunctionSig {
                params: vec![("item".to_string(), Type::Unknown)],
                ret: Type::Int,
                is_method: true,
            },
        );
        array_class.methods.insert(
            "pop".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Unknown,
                is_method: true,
            },
        );
        array_class.methods.insert(
            "map".to_string(),
            FunctionSig {
                params: vec![(
                    "callback".to_string(),
                    Type::Function {
                        params: vec![Type::Unknown],
                        ret: Box::new(Type::Unknown),
                    },
                )],
                ret: Type::List(Box::new(Type::Unknown)),
                is_method: true,
            },
        );
        array_class.methods.insert(
            "filter".to_string(),
            FunctionSig {
                params: vec![(
                    "callback".to_string(),
                    Type::Function {
                        params: vec![Type::Unknown],
                        ret: Box::new(Type::Bool),
                    },
                )],
                ret: Type::List(Box::new(Type::Unknown)),
                is_method: true,
            },
        );
        array_class.methods.insert(
            "reduce".to_string(),
            FunctionSig {
                params: vec![
                    (
                        "callback".to_string(),
                        Type::Function {
                            params: vec![Type::Unknown, Type::Unknown],
                            ret: Box::new(Type::Unknown),
                        },
                    ),
                    ("initial".to_string(), Type::Unknown),
                ],
                ret: Type::Unknown,
                is_method: true,
            },
        );
        array_class.methods.insert(
            "find".to_string(),
            FunctionSig {
                params: vec![(
                    "callback".to_string(),
                    Type::Function {
                        params: vec![Type::Unknown],
                        ret: Box::new(Type::Bool),
                    },
                )],
                ret: Type::Optional(Box::new(Type::Unknown)),
                is_method: true,
            },
        );
        array_class.methods.insert(
            "join".to_string(),
            FunctionSig {
                params: vec![("separator".to_string(), Type::String)],
                ret: Type::String,
                is_method: true,
            },
        );
        array_class
            .attributes
            .insert("length".to_string(), Type::Int);
        stubs.classes.insert("Array".to_string(), array_class);

        // String methods
        let mut string_class = ClassDef {
            name: "String".to_string(),
            methods: HashMap::new(),
            attributes: HashMap::new(),
            bases: vec![],
        };
        string_class.methods.insert(
            "split".to_string(),
            FunctionSig {
                params: vec![("separator".to_string(), Type::String)],
                ret: Type::List(Box::new(Type::String)),
                is_method: true,
            },
        );
        string_class.methods.insert(
            "toLowerCase".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::String,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "toUpperCase".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::String,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "trim".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::String,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "substring".to_string(),
            FunctionSig {
                params: vec![
                    ("start".to_string(), Type::Int),
                    ("end".to_string(), Type::Int),
                ],
                ret: Type::String,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "includes".to_string(),
            FunctionSig {
                params: vec![("searchString".to_string(), Type::String)],
                ret: Type::Bool,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "startsWith".to_string(),
            FunctionSig {
                params: vec![("searchString".to_string(), Type::String)],
                ret: Type::Bool,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "endsWith".to_string(),
            FunctionSig {
                params: vec![("searchString".to_string(), Type::String)],
                ret: Type::Bool,
                is_method: true,
            },
        );
        string_class
            .attributes
            .insert("length".to_string(), Type::Int);
        stubs.classes.insert("String".to_string(), string_class);

        stubs
    }

    /// Create Go standard library stubs
    pub fn go_stdlib() -> Self {
        let mut stubs = Self {
            modules: HashMap::new(),
            builtins: HashMap::new(),
            classes: HashMap::new(),
        };

        // Go builtin functions
        stubs.builtins.insert(
            "len".to_string(),
            FunctionSig {
                params: vec![("v".to_string(), Type::Unknown)],
                ret: Type::Int,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "cap".to_string(),
            FunctionSig {
                params: vec![("v".to_string(), Type::Unknown)],
                ret: Type::Int,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "make".to_string(),
            FunctionSig {
                params: vec![("t".to_string(), Type::Unknown)],
                ret: Type::Unknown,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "new".to_string(),
            FunctionSig {
                params: vec![("t".to_string(), Type::Unknown)],
                ret: Type::Unknown,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "append".to_string(),
            FunctionSig {
                params: vec![
                    ("slice".to_string(), Type::List(Box::new(Type::Unknown))),
                    ("elems".to_string(), Type::Unknown),
                ],
                ret: Type::List(Box::new(Type::Unknown)),
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "copy".to_string(),
            FunctionSig {
                params: vec![
                    ("dst".to_string(), Type::List(Box::new(Type::Unknown))),
                    ("src".to_string(), Type::List(Box::new(Type::Unknown))),
                ],
                ret: Type::Int,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "delete".to_string(),
            FunctionSig {
                params: vec![
                    (
                        "m".to_string(),
                        Type::Dict(Box::new(Type::Unknown), Box::new(Type::Unknown)),
                    ),
                    ("key".to_string(), Type::Unknown),
                ],
                ret: Type::None,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "panic".to_string(),
            FunctionSig {
                params: vec![("v".to_string(), Type::Unknown)],
                ret: Type::Never,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "recover".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Unknown,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "print".to_string(),
            FunctionSig {
                params: vec![("args".to_string(), Type::Unknown)],
                ret: Type::None,
                is_method: false,
            },
        );
        stubs.builtins.insert(
            "println".to_string(),
            FunctionSig {
                params: vec![("args".to_string(), Type::Unknown)],
                ret: Type::None,
                is_method: false,
            },
        );

        // fmt package
        let mut fmt_module = HashMap::new();
        fmt_module.insert(
            "Println".to_string(),
            FunctionSig {
                params: vec![("a".to_string(), Type::Unknown)],
                ret: Type::None,
                is_method: false,
            },
        );
        fmt_module.insert(
            "Printf".to_string(),
            FunctionSig {
                params: vec![
                    ("format".to_string(), Type::String),
                    ("a".to_string(), Type::Unknown),
                ],
                ret: Type::None,
                is_method: false,
            },
        );
        fmt_module.insert(
            "Sprintf".to_string(),
            FunctionSig {
                params: vec![
                    ("format".to_string(), Type::String),
                    ("a".to_string(), Type::Unknown),
                ],
                ret: Type::String,
                is_method: false,
            },
        );
        fmt_module.insert(
            "Errorf".to_string(),
            FunctionSig {
                params: vec![
                    ("format".to_string(), Type::String),
                    ("a".to_string(), Type::Unknown),
                ],
                ret: Type::Instance {
                    class_name: "error".to_string(),
                    type_args: vec![],
                },
                is_method: false,
            },
        );
        stubs.modules.insert("fmt".to_string(), fmt_module);

        // strings package
        let mut strings_module = HashMap::new();
        strings_module.insert(
            "Split".to_string(),
            FunctionSig {
                params: vec![
                    ("s".to_string(), Type::String),
                    ("sep".to_string(), Type::String),
                ],
                ret: Type::List(Box::new(Type::String)),
                is_method: false,
            },
        );
        strings_module.insert(
            "Join".to_string(),
            FunctionSig {
                params: vec![
                    ("elems".to_string(), Type::List(Box::new(Type::String))),
                    ("sep".to_string(), Type::String),
                ],
                ret: Type::String,
                is_method: false,
            },
        );
        strings_module.insert(
            "Contains".to_string(),
            FunctionSig {
                params: vec![
                    ("s".to_string(), Type::String),
                    ("substr".to_string(), Type::String),
                ],
                ret: Type::Bool,
                is_method: false,
            },
        );
        strings_module.insert(
            "HasPrefix".to_string(),
            FunctionSig {
                params: vec![
                    ("s".to_string(), Type::String),
                    ("prefix".to_string(), Type::String),
                ],
                ret: Type::Bool,
                is_method: false,
            },
        );
        strings_module.insert(
            "HasSuffix".to_string(),
            FunctionSig {
                params: vec![
                    ("s".to_string(), Type::String),
                    ("suffix".to_string(), Type::String),
                ],
                ret: Type::Bool,
                is_method: false,
            },
        );
        strings_module.insert(
            "TrimSpace".to_string(),
            FunctionSig {
                params: vec![("s".to_string(), Type::String)],
                ret: Type::String,
                is_method: false,
            },
        );
        strings_module.insert(
            "ToLower".to_string(),
            FunctionSig {
                params: vec![("s".to_string(), Type::String)],
                ret: Type::String,
                is_method: false,
            },
        );
        strings_module.insert(
            "ToUpper".to_string(),
            FunctionSig {
                params: vec![("s".to_string(), Type::String)],
                ret: Type::String,
                is_method: false,
            },
        );
        strings_module.insert(
            "Replace".to_string(),
            FunctionSig {
                params: vec![
                    ("s".to_string(), Type::String),
                    ("old".to_string(), Type::String),
                    ("new".to_string(), Type::String),
                    ("n".to_string(), Type::Int),
                ],
                ret: Type::String,
                is_method: false,
            },
        );
        stubs.modules.insert("strings".to_string(), strings_module);

        // os package
        let mut os_module = HashMap::new();
        os_module.insert(
            "Getenv".to_string(),
            FunctionSig {
                params: vec![("key".to_string(), Type::String)],
                ret: Type::String,
                is_method: false,
            },
        );
        os_module.insert(
            "Setenv".to_string(),
            FunctionSig {
                params: vec![
                    ("key".to_string(), Type::String),
                    ("value".to_string(), Type::String),
                ],
                ret: Type::Instance {
                    class_name: "error".to_string(),
                    type_args: vec![],
                },
                is_method: false,
            },
        );
        os_module.insert(
            "Exit".to_string(),
            FunctionSig {
                params: vec![("code".to_string(), Type::Int)],
                ret: Type::Never,
                is_method: false,
            },
        );
        os_module.insert(
            "Getwd".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Tuple(vec![
                    Type::String,
                    Type::Instance {
                        class_name: "error".to_string(),
                        type_args: vec![],
                    },
                ]),
                is_method: false,
            },
        );
        stubs.modules.insert("os".to_string(), os_module);

        // strconv package
        let mut strconv_module = HashMap::new();
        strconv_module.insert(
            "Atoi".to_string(),
            FunctionSig {
                params: vec![("s".to_string(), Type::String)],
                ret: Type::Tuple(vec![
                    Type::Int,
                    Type::Instance {
                        class_name: "error".to_string(),
                        type_args: vec![],
                    },
                ]),
                is_method: false,
            },
        );
        strconv_module.insert(
            "Itoa".to_string(),
            FunctionSig {
                params: vec![("i".to_string(), Type::Int)],
                ret: Type::String,
                is_method: false,
            },
        );
        stubs.modules.insert("strconv".to_string(), strconv_module);

        stubs
    }

    /// Create Java standard library stubs
    pub fn java_stdlib() -> Self {
        let mut stubs = Self {
            modules: HashMap::new(),
            builtins: HashMap::new(),
            classes: HashMap::new(),
        };

        // String class
        let mut string_class = ClassDef {
            name: "String".to_string(),
            methods: HashMap::new(),
            attributes: HashMap::new(),
            bases: vec![],
        };
        string_class.methods.insert(
            "length".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Int,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "charAt".to_string(),
            FunctionSig {
                params: vec![("index".to_string(), Type::Int)],
                ret: Type::Instance {
                    class_name: "char".to_string(),
                    type_args: vec![],
                },
                is_method: true,
            },
        );
        string_class.methods.insert(
            "substring".to_string(),
            FunctionSig {
                params: vec![
                    ("beginIndex".to_string(), Type::Int),
                    ("endIndex".to_string(), Type::Int),
                ],
                ret: Type::String,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "split".to_string(),
            FunctionSig {
                params: vec![("regex".to_string(), Type::String)],
                ret: Type::List(Box::new(Type::String)),
                is_method: true,
            },
        );
        string_class.methods.insert(
            "toLowerCase".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::String,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "toUpperCase".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::String,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "trim".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::String,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "contains".to_string(),
            FunctionSig {
                params: vec![("s".to_string(), Type::String)],
                ret: Type::Bool,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "startsWith".to_string(),
            FunctionSig {
                params: vec![("prefix".to_string(), Type::String)],
                ret: Type::Bool,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "endsWith".to_string(),
            FunctionSig {
                params: vec![("suffix".to_string(), Type::String)],
                ret: Type::Bool,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "equals".to_string(),
            FunctionSig {
                params: vec![("obj".to_string(), Type::Unknown)],
                ret: Type::Bool,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "isEmpty".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Bool,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "replace".to_string(),
            FunctionSig {
                params: vec![
                    ("oldChar".to_string(), Type::String),
                    ("newChar".to_string(), Type::String),
                ],
                ret: Type::String,
                is_method: true,
            },
        );
        stubs.classes.insert("String".to_string(), string_class);

        // List interface
        let mut list_class = ClassDef {
            name: "List".to_string(),
            methods: HashMap::new(),
            attributes: HashMap::new(),
            bases: vec!["Collection".to_string()],
        };
        list_class.methods.insert(
            "add".to_string(),
            FunctionSig {
                params: vec![("e".to_string(), Type::Unknown)],
                ret: Type::Bool,
                is_method: true,
            },
        );
        list_class.methods.insert(
            "get".to_string(),
            FunctionSig {
                params: vec![("index".to_string(), Type::Int)],
                ret: Type::Unknown,
                is_method: true,
            },
        );
        list_class.methods.insert(
            "set".to_string(),
            FunctionSig {
                params: vec![
                    ("index".to_string(), Type::Int),
                    ("element".to_string(), Type::Unknown),
                ],
                ret: Type::Unknown,
                is_method: true,
            },
        );
        list_class.methods.insert(
            "remove".to_string(),
            FunctionSig {
                params: vec![("index".to_string(), Type::Int)],
                ret: Type::Unknown,
                is_method: true,
            },
        );
        list_class.methods.insert(
            "size".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Int,
                is_method: true,
            },
        );
        list_class.methods.insert(
            "isEmpty".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Bool,
                is_method: true,
            },
        );
        list_class.methods.insert(
            "contains".to_string(),
            FunctionSig {
                params: vec![("o".to_string(), Type::Unknown)],
                ret: Type::Bool,
                is_method: true,
            },
        );
        list_class.methods.insert(
            "clear".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::None,
                is_method: true,
            },
        );
        stubs.classes.insert("List".to_string(), list_class);

        // Map interface
        let mut map_class = ClassDef {
            name: "Map".to_string(),
            methods: HashMap::new(),
            attributes: HashMap::new(),
            bases: vec![],
        };
        map_class.methods.insert(
            "put".to_string(),
            FunctionSig {
                params: vec![
                    ("key".to_string(), Type::Unknown),
                    ("value".to_string(), Type::Unknown),
                ],
                ret: Type::Unknown,
                is_method: true,
            },
        );
        map_class.methods.insert(
            "get".to_string(),
            FunctionSig {
                params: vec![("key".to_string(), Type::Unknown)],
                ret: Type::Unknown,
                is_method: true,
            },
        );
        map_class.methods.insert(
            "containsKey".to_string(),
            FunctionSig {
                params: vec![("key".to_string(), Type::Unknown)],
                ret: Type::Bool,
                is_method: true,
            },
        );
        map_class.methods.insert(
            "size".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Int,
                is_method: true,
            },
        );
        map_class.methods.insert(
            "isEmpty".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Bool,
                is_method: true,
            },
        );
        stubs.classes.insert("Map".to_string(), map_class);

        // System.out
        let mut system_out = HashMap::new();
        system_out.insert(
            "println".to_string(),
            FunctionSig {
                params: vec![("x".to_string(), Type::Unknown)],
                ret: Type::None,
                is_method: false,
            },
        );
        system_out.insert(
            "print".to_string(),
            FunctionSig {
                params: vec![("x".to_string(), Type::Unknown)],
                ret: Type::None,
                is_method: false,
            },
        );
        stubs.modules.insert("System.out".to_string(), system_out);

        // Integer class
        let mut integer_class = ClassDef {
            name: "Integer".to_string(),
            methods: HashMap::new(),
            attributes: HashMap::new(),
            bases: vec!["Number".to_string()],
        };
        integer_class.methods.insert(
            "parseInt".to_string(),
            FunctionSig {
                params: vec![("s".to_string(), Type::String)],
                ret: Type::Int,
                is_method: false, // static method
            },
        );
        integer_class.methods.insert(
            "toString".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::String,
                is_method: true,
            },
        );
        stubs.classes.insert("Integer".to_string(), integer_class);

        stubs
    }

    /// Create Rust standard library stubs
    pub fn rust_stdlib() -> Self {
        let mut stubs = Self {
            modules: HashMap::new(),
            builtins: HashMap::new(),
            classes: HashMap::new(),
        };

        // String class
        let mut string_class = ClassDef {
            name: "String".to_string(),
            methods: HashMap::new(),
            attributes: HashMap::new(),
            bases: vec![],
        };
        string_class.methods.insert(
            "len".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Int,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "is_empty".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Bool,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "push_str".to_string(),
            FunctionSig {
                params: vec![("s".to_string(), Type::String)],
                ret: Type::None,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "push".to_string(),
            FunctionSig {
                params: vec![(
                    "ch".to_string(),
                    Type::Instance {
                        class_name: "char".to_string(),
                        type_args: vec![],
                    },
                )],
                ret: Type::None,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "as_str".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::String,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "trim".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::String,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "to_lowercase".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::String,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "to_uppercase".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::String,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "contains".to_string(),
            FunctionSig {
                params: vec![("pat".to_string(), Type::String)],
                ret: Type::Bool,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "starts_with".to_string(),
            FunctionSig {
                params: vec![("pat".to_string(), Type::String)],
                ret: Type::Bool,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "ends_with".to_string(),
            FunctionSig {
                params: vec![("pat".to_string(), Type::String)],
                ret: Type::Bool,
                is_method: true,
            },
        );
        string_class.methods.insert(
            "split".to_string(),
            FunctionSig {
                params: vec![("pat".to_string(), Type::String)],
                ret: Type::Instance {
                    class_name: "Split".to_string(),
                    type_args: vec![],
                },
                is_method: true,
            },
        );
        string_class.methods.insert(
            "replace".to_string(),
            FunctionSig {
                params: vec![
                    ("from".to_string(), Type::String),
                    ("to".to_string(), Type::String),
                ],
                ret: Type::String,
                is_method: true,
            },
        );
        stubs.classes.insert("String".to_string(), string_class);

        // Vec class
        let mut vec_class = ClassDef {
            name: "Vec".to_string(),
            methods: HashMap::new(),
            attributes: HashMap::new(),
            bases: vec![],
        };
        vec_class.methods.insert(
            "push".to_string(),
            FunctionSig {
                params: vec![("value".to_string(), Type::Unknown)],
                ret: Type::None,
                is_method: true,
            },
        );
        vec_class.methods.insert(
            "pop".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Optional(Box::new(Type::Unknown)),
                is_method: true,
            },
        );
        vec_class.methods.insert(
            "len".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Int,
                is_method: true,
            },
        );
        vec_class.methods.insert(
            "is_empty".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Bool,
                is_method: true,
            },
        );
        vec_class.methods.insert(
            "clear".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::None,
                is_method: true,
            },
        );
        vec_class.methods.insert(
            "get".to_string(),
            FunctionSig {
                params: vec![("index".to_string(), Type::Int)],
                ret: Type::Optional(Box::new(Type::Unknown)),
                is_method: true,
            },
        );
        vec_class.methods.insert(
            "first".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Optional(Box::new(Type::Unknown)),
                is_method: true,
            },
        );
        vec_class.methods.insert(
            "last".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Optional(Box::new(Type::Unknown)),
                is_method: true,
            },
        );
        vec_class.methods.insert(
            "iter".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Instance {
                    class_name: "Iter".to_string(),
                    type_args: vec![],
                },
                is_method: true,
            },
        );
        stubs.classes.insert("Vec".to_string(), vec_class);

        // Option class
        let mut option_class = ClassDef {
            name: "Option".to_string(),
            methods: HashMap::new(),
            attributes: HashMap::new(),
            bases: vec![],
        };
        option_class.methods.insert(
            "unwrap".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Unknown,
                is_method: true,
            },
        );
        option_class.methods.insert(
            "unwrap_or".to_string(),
            FunctionSig {
                params: vec![("default".to_string(), Type::Unknown)],
                ret: Type::Unknown,
                is_method: true,
            },
        );
        option_class.methods.insert(
            "is_some".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Bool,
                is_method: true,
            },
        );
        option_class.methods.insert(
            "is_none".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Bool,
                is_method: true,
            },
        );
        option_class.methods.insert(
            "map".to_string(),
            FunctionSig {
                params: vec![(
                    "f".to_string(),
                    Type::Function {
                        params: vec![Type::Unknown],
                        ret: Box::new(Type::Unknown),
                    },
                )],
                ret: Type::Optional(Box::new(Type::Unknown)),
                is_method: true,
            },
        );
        option_class.methods.insert(
            "and_then".to_string(),
            FunctionSig {
                params: vec![(
                    "f".to_string(),
                    Type::Function {
                        params: vec![Type::Unknown],
                        ret: Box::new(Type::Optional(Box::new(Type::Unknown))),
                    },
                )],
                ret: Type::Optional(Box::new(Type::Unknown)),
                is_method: true,
            },
        );
        stubs.classes.insert("Option".to_string(), option_class);

        // Result class
        let mut result_class = ClassDef {
            name: "Result".to_string(),
            methods: HashMap::new(),
            attributes: HashMap::new(),
            bases: vec![],
        };
        result_class.methods.insert(
            "unwrap".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Unknown,
                is_method: true,
            },
        );
        result_class.methods.insert(
            "expect".to_string(),
            FunctionSig {
                params: vec![("msg".to_string(), Type::String)],
                ret: Type::Unknown,
                is_method: true,
            },
        );
        result_class.methods.insert(
            "is_ok".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Bool,
                is_method: true,
            },
        );
        result_class.methods.insert(
            "is_err".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Bool,
                is_method: true,
            },
        );
        result_class.methods.insert(
            "ok".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Optional(Box::new(Type::Unknown)),
                is_method: true,
            },
        );
        result_class.methods.insert(
            "err".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Optional(Box::new(Type::Unknown)),
                is_method: true,
            },
        );
        stubs.classes.insert("Result".to_string(), result_class);

        // HashMap class
        let mut hashmap_class = ClassDef {
            name: "HashMap".to_string(),
            methods: HashMap::new(),
            attributes: HashMap::new(),
            bases: vec![],
        };
        hashmap_class.methods.insert(
            "insert".to_string(),
            FunctionSig {
                params: vec![
                    ("key".to_string(), Type::Unknown),
                    ("value".to_string(), Type::Unknown),
                ],
                ret: Type::Optional(Box::new(Type::Unknown)),
                is_method: true,
            },
        );
        hashmap_class.methods.insert(
            "get".to_string(),
            FunctionSig {
                params: vec![("key".to_string(), Type::Unknown)],
                ret: Type::Optional(Box::new(Type::Unknown)),
                is_method: true,
            },
        );
        hashmap_class.methods.insert(
            "contains_key".to_string(),
            FunctionSig {
                params: vec![("key".to_string(), Type::Unknown)],
                ret: Type::Bool,
                is_method: true,
            },
        );
        hashmap_class.methods.insert(
            "len".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Int,
                is_method: true,
            },
        );
        hashmap_class.methods.insert(
            "is_empty".to_string(),
            FunctionSig {
                params: vec![],
                ret: Type::Bool,
                is_method: true,
            },
        );
        hashmap_class.methods.insert(
            "remove".to_string(),
            FunctionSig {
                params: vec![("key".to_string(), Type::Unknown)],
                ret: Type::Optional(Box::new(Type::Unknown)),
                is_method: true,
            },
        );
        stubs.classes.insert("HashMap".to_string(), hashmap_class);

        stubs
    }

    /// Look up a builtin function
    pub fn lookup_builtin(&self, name: &str) -> Option<&FunctionSig> {
        self.builtins.get(name)
    }

    /// Look up a module function
    pub fn lookup_module_func(&self, module: &str, func: &str) -> Option<&FunctionSig> {
        self.modules.get(module).and_then(|m| m.get(func))
    }

    /// Look up a class method
    pub fn lookup_method(&self, class_name: &str, method: &str) -> Option<&FunctionSig> {
        self.classes
            .get(class_name)
            .and_then(|c| c.methods.get(method))
    }

    /// Look up a class attribute
    pub fn lookup_attribute(&self, class_name: &str, attr: &str) -> Option<&Type> {
        self.classes
            .get(class_name)
            .and_then(|c| c.attributes.get(attr))
    }
}

/// Type error during inference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeError {
    /// Error message
    pub message: String,
    /// Line number
    pub line: usize,
    /// Column number
    pub column: usize,
    /// Error kind
    pub kind: TypeErrorKind,
}

/// Kinds of type errors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeErrorKind {
    /// Variable used before definition
    UndefinedVariable,
    /// Type mismatch in assignment or call
    TypeMismatch,
    /// Attribute not found on type
    AttributeNotFound,
    /// Method not found on type
    MethodNotFound,
    /// Wrong number of arguments
    ArgumentCount,
    /// Unification failed
    UnificationFailed,
    /// Other error
    Other,
}

/// Binary operator for type inference
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    FloorDiv,
    Mod,
    Pow,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
    LShift,
    RShift,
}

/// Unary operator
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnaryOp {
    Neg,
    Not,
    BitNot,
}

/// Result of type inference for a function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferredTypes {
    /// Function name
    pub function_name: String,
    /// File path
    pub file_path: String,
    /// Inferred parameter types
    pub parameters: Vec<(String, Type)>,
    /// Inferred return type
    pub return_type: Type,
    /// Variable types at each line
    pub variable_types: HashMap<usize, HashMap<String, Type>>,
    /// Type errors found
    pub errors: Vec<TypeError>,
}

impl InferredTypes {
    pub fn new(function_name: &str, file_path: &str) -> Self {
        Self {
            function_name: function_name.to_string(),
            file_path: file_path.to_string(),
            parameters: Vec::new(),
            return_type: Type::Unknown,
            variable_types: HashMap::new(),
            errors: Vec::new(),
        }
    }

    /// Format as markdown
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str(&format!("# Type Inference: `{}`\n\n", self.function_name));
        md.push_str(&format!("**File**: `{}`\n\n", self.file_path));

        // Parameters
        md.push_str("## Parameters\n\n");
        if self.parameters.is_empty() {
            md.push_str("*No parameters*\n\n");
        } else {
            for (name, ty) in &self.parameters {
                md.push_str(&format!("- `{}`: `{}`\n", name, ty.display_name()));
            }
            md.push('\n');
        }

        // Return type
        md.push_str(&format!(
            "## Return Type\n\n`{}`\n\n",
            self.return_type.display_name()
        ));

        // Variable types
        if !self.variable_types.is_empty() {
            md.push_str("## Variable Types by Line\n\n");
            let mut lines: Vec<_> = self.variable_types.keys().collect();
            lines.sort();
            for line in lines {
                if let Some(vars) = self.variable_types.get(line) {
                    md.push_str(&format!("**Line {}**:\n", line));
                    for (name, ty) in vars {
                        md.push_str(&format!("  - `{}`: `{}`\n", name, ty.display_name()));
                    }
                }
            }
            md.push('\n');
        }

        // Errors
        if !self.errors.is_empty() {
            md.push_str("## ⚠️ Type Errors\n\n");
            for error in &self.errors {
                md.push_str(&format!(
                    "- **Line {}:{}** ({:?}): {}\n",
                    error.line, error.column, error.kind, error.message
                ));
            }
        }

        md
    }
}

/// Main type inferencer
pub struct TypeInferencer<'a> {
    /// Source code (stored for potential future AST parsing)
    _source: &'a str,
    /// Control flow graph (optional)
    cfg: Option<&'a ControlFlowGraph>,
    /// Type stubs for stdlib
    stubs: TypeStubs,
    /// Accumulated constraints
    constraints: Vec<Constraint>,
    /// Type environment
    env: TypeEnv,
    /// Language being inferred (stored for language-specific handling)
    _language: String,
}

impl<'a> TypeInferencer<'a> {
    /// Create a new type inferencer
    pub fn new(source: &'a str, cfg: Option<&'a ControlFlowGraph>, language: &str) -> Self {
        let stubs = match language {
            "python" | "py" => TypeStubs::python_stdlib(),
            "javascript" | "js" | "typescript" | "ts" => TypeStubs::javascript_stdlib(),
            "go" => TypeStubs::go_stdlib(),
            "java" => TypeStubs::java_stdlib(),
            "rust" | "rs" => TypeStubs::rust_stdlib(),
            _ => TypeStubs::python_stdlib(),
        };

        Self {
            _source: source,
            cfg,
            stubs,
            constraints: Vec::new(),
            env: TypeEnv::new(),
            _language: language.to_string(),
        }
    }

    /// Infer types for a function from its CFG
    pub fn infer_from_cfg(&mut self, params: &[(String, Option<Type>)]) -> InferredTypes {
        let mut result = InferredTypes::new(
            self.cfg
                .map(|c| c.function_name.as_str())
                .unwrap_or("unknown"),
            self.cfg.map(|c| c.file_path.as_str()).unwrap_or("unknown"),
        );

        // Initialize parameters
        for (name, annotation) in params {
            let ty = annotation.clone().unwrap_or_else(|| self.env.fresh_var());
            self.env.bind(name.clone(), ty.clone());
            result.parameters.push((name.clone(), ty));
        }

        // Process CFG blocks if available
        if let Some(cfg) = self.cfg {
            for block_id in cfg.blocks.keys() {
                if let Err(e) = self.infer_block(*block_id, &mut result) {
                    result.errors.push(TypeError {
                        message: e.to_string(),
                        line: 0,
                        column: 0,
                        kind: TypeErrorKind::Other,
                    });
                }
            }
        }

        // Solve constraints
        if let Err(e) = self.solve_constraints() {
            result.errors.push(TypeError {
                message: e.to_string(),
                line: 0,
                column: 0,
                kind: TypeErrorKind::UnificationFailed,
            });
        }

        // Apply substitutions to get final types
        result.return_type = self.env.substitute(&result.return_type);
        result.parameters = result
            .parameters
            .into_iter()
            .map(|(n, t)| (n, self.env.substitute(&t)))
            .collect();

        result
    }

    fn infer_block(&mut self, block_id: BlockId, result: &mut InferredTypes) -> Result<()> {
        let cfg = self.cfg.ok_or_else(|| anyhow!("No CFG available"))?;
        let block = cfg
            .blocks
            .get(&block_id)
            .ok_or_else(|| anyhow!("Invalid block"))?;

        for stmt in &block.statements {
            match &stmt.kind {
                StatementKind::Assignment { variable } => {
                    let rhs_type = self.infer_expr_from_text(&stmt.text)?;
                    self.env.bind(variable.clone(), rhs_type.clone());

                    // Record variable type at this line
                    result
                        .variable_types
                        .entry(stmt.line)
                        .or_default()
                        .insert(variable.clone(), rhs_type);
                }
                StatementKind::Return => {
                    let ret_type = self.infer_expr_from_text(&stmt.text)?;
                    self.constraints
                        .push(Constraint::Equal(result.return_type.clone(), ret_type));
                }
                StatementKind::Call { function } => {
                    // Look up function return type
                    if let Some(sig) = self.stubs.lookup_builtin(function) {
                        // Record the call's result type if assigned
                        let _ = sig.ret.clone();
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Infer type from expression text (simplified)
    fn infer_expr_from_text(&mut self, text: &str) -> Result<Type> {
        let text = text.trim();

        // Check for literals
        if let Some(ty) = self.infer_literal(text) {
            return Ok(ty);
        }

        // Check for variable reference
        if is_identifier(text) {
            if let Some(ty) = self.env.lookup(text) {
                return Ok(ty.clone());
            } else if let Some(sig) = self.stubs.lookup_builtin(text) {
                return Ok(Type::Function {
                    params: sig.params.iter().map(|(_, t)| t.clone()).collect(),
                    ret: Box::new(sig.ret.clone()),
                });
            }
            return Ok(self.env.fresh_var());
        }

        // Check for list literal
        if text.starts_with('[') && text.ends_with(']') {
            let inner = &text[1..text.len() - 1];
            if inner.is_empty() {
                return Ok(Type::List(Box::new(self.env.fresh_var())));
            }
            // Try to infer element type from first element
            let first = inner.split(',').next().unwrap_or("").trim();
            let elem_type = self.infer_expr_from_text(first)?;
            return Ok(Type::List(Box::new(elem_type)));
        }

        // Check for dict literal
        if text.starts_with('{') && text.ends_with('}') {
            return Ok(Type::Dict(
                Box::new(self.env.fresh_var()),
                Box::new(self.env.fresh_var()),
            ));
        }

        // Check for function call
        if let Some(paren_idx) = text.find('(') {
            let func_name = text[..paren_idx].trim();
            if let Some(sig) = self.stubs.lookup_builtin(func_name) {
                return Ok(sig.ret.clone());
            }
            // Check for method call
            if let Some(dot_idx) = func_name.rfind('.') {
                let obj_name = &func_name[..dot_idx];
                let method_name = &func_name[dot_idx + 1..];

                if let Some(obj_type) = self.env.lookup(obj_name) {
                    let class_name = match obj_type {
                        Type::String => "str",
                        Type::List(_) => "list",
                        Type::Dict(_, _) => "dict",
                        Type::Instance { class_name, .. } => class_name.as_str(),
                        _ => return Ok(Type::Unknown),
                    };
                    if let Some(sig) = self.stubs.lookup_method(class_name, method_name) {
                        return Ok(sig.ret.clone());
                    }
                }
            }
            return Ok(Type::Unknown);
        }

        // Check for binary operations
        for (op_str, _op) in [
            (" + ", BinOp::Add),
            (" - ", BinOp::Sub),
            (" * ", BinOp::Mul),
            (" / ", BinOp::Div),
            (" // ", BinOp::FloorDiv),
            (" % ", BinOp::Mod),
            (" ** ", BinOp::Pow),
        ] {
            if let Some(idx) = text.find(op_str) {
                let left = &text[..idx];
                let right = &text[idx + op_str.len()..];
                let left_ty = self.infer_expr_from_text(left)?;
                let right_ty = self.infer_expr_from_text(right)?;
                return Ok(self.binary_op_result(&left_ty, &right_ty));
            }
        }

        // Check for comparison operations (return bool)
        for op_str in [" == ", " != ", " < ", " <= ", " > ", " >= ", " is ", " in "] {
            if text.contains(op_str) {
                return Ok(Type::Bool);
            }
        }

        // Check for logical operations
        if text.contains(" and ") || text.contains(" or ") || text.contains(" not ") {
            return Ok(Type::Bool);
        }

        Ok(Type::Unknown)
    }

    /// Infer literal type
    fn infer_literal(&self, text: &str) -> Option<Type> {
        let text = text.trim();

        // None/null/undefined/nil
        if text == "None" || text == "null" || text == "undefined" || text == "nil" {
            return Some(Type::None);
        }

        // Boolean
        if text == "True" || text == "False" || text == "true" || text == "false" {
            return Some(Type::Bool);
        }

        // String literals
        if (text.starts_with('"') && text.ends_with('"'))
            || (text.starts_with('\'') && text.ends_with('\''))
            || (text.starts_with("\"\"\"") && text.ends_with("\"\"\""))
            || (text.starts_with("'''") && text.ends_with("'''"))
            || (text.starts_with('`') && text.ends_with('`'))
        {
            return Some(Type::String);
        }

        // f-string
        if text.starts_with("f\"") || text.starts_with("f'") {
            return Some(Type::String);
        }

        // Integer
        if text.parse::<i64>().is_ok() {
            return Some(Type::Int);
        }

        // Hex/octal/binary
        if text.starts_with("0x") || text.starts_with("0o") || text.starts_with("0b") {
            return Some(Type::Int);
        }

        // Float
        if text.parse::<f64>().is_ok() {
            return Some(Type::Float);
        }

        None
    }

    /// Get result type of binary operation
    fn binary_op_result(&self, left: &Type, right: &Type) -> Type {
        match (left, right) {
            (Type::Int, Type::Int) => Type::Int,
            (Type::Float, Type::Float) => Type::Float,
            (Type::Int, Type::Float) | (Type::Float, Type::Int) => Type::Float,
            (Type::String, Type::String) => Type::String,
            (Type::String, Type::Int) | (Type::Int, Type::String) => Type::String, // string repetition
            (Type::List(a), Type::List(b)) if a == b => Type::List(a.clone()),
            _ => Type::Unknown,
        }
    }

    /// Solve accumulated constraints
    fn solve_constraints(&mut self) -> Result<()> {
        // Clone constraints to avoid borrow conflicts
        let constraints = self.constraints.clone();
        for constraint in constraints {
            match constraint {
                Constraint::Equal(t1, t2) => {
                    self.unify(&t1, &t2)?;
                }
                Constraint::Subtype(sub, sup) => {
                    if !sub.is_subtype_of(&sup) {
                        // Add substitution for type variables
                        if let Type::Var(id) = sub {
                            self.env.add_substitution(id, sup.clone());
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Unify two types
    fn unify(&mut self, t1: &Type, t2: &Type) -> Result<()> {
        match (t1, t2) {
            (Type::Var(id), t) | (t, Type::Var(id)) => {
                if let Type::Var(id2) = t {
                    if id == id2 {
                        return Ok(());
                    }
                }
                self.env.add_substitution(*id, t.clone());
                Ok(())
            }
            (Type::List(a), Type::List(b)) => self.unify(a, b),
            (Type::Dict(k1, v1), Type::Dict(k2, v2)) => {
                self.unify(k1, k2)?;
                self.unify(v1, v2)
            }
            (Type::Optional(a), Type::Optional(b)) => self.unify(a, b),
            (
                Type::Function {
                    params: p1,
                    ret: r1,
                },
                Type::Function {
                    params: p2,
                    ret: r2,
                },
            ) => {
                if p1.len() != p2.len() {
                    return Err(anyhow!("Function parameter count mismatch"));
                }
                for (a, b) in p1.iter().zip(p2.iter()) {
                    self.unify(a, b)?;
                }
                self.unify(r1, r2)
            }
            (a, b) if a == b => Ok(()),
            (Type::Unknown, _) | (_, Type::Unknown) => Ok(()),
            _ => Err(anyhow!(
                "Cannot unify {} with {}",
                t1.display_name(),
                t2.display_name()
            )),
        }
    }

    /// Infer types from a tree-sitter node
    pub fn infer_from_node(&mut self, node: Node, source: &[u8]) -> Result<InferredTypes> {
        let function_name =
            extract_function_name(node, source).unwrap_or_else(|| "anonymous".to_string());
        let file_path = "";

        let mut result = InferredTypes::new(&function_name, file_path);

        // Extract parameters
        if let Some(params_node) = find_child_by_kind(node, "parameters")
            .or_else(|| find_child_by_kind(node, "formal_parameters"))
        {
            self.extract_parameters(params_node, source, &mut result)?;
        }

        // Process function body
        if let Some(body) = find_child_by_kind(node, "block")
            .or_else(|| find_child_by_kind(node, "statement_block"))
        {
            self.process_node(body, source, &mut result)?;
        }

        // Solve constraints
        if let Err(e) = self.solve_constraints() {
            result.errors.push(TypeError {
                message: e.to_string(),
                line: 0,
                column: 0,
                kind: TypeErrorKind::UnificationFailed,
            });
        }

        // Apply substitutions
        result.return_type = self.env.substitute(&result.return_type);
        result.parameters = result
            .parameters
            .into_iter()
            .map(|(n, t)| (n, self.env.substitute(&t)))
            .collect();

        Ok(result)
    }

    fn extract_parameters(
        &mut self,
        node: Node,
        source: &[u8],
        result: &mut InferredTypes,
    ) -> Result<()> {
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                let kind = child.kind();

                if kind == "identifier" || kind == "typed_parameter" || kind == "required_parameter"
                {
                    if let Ok(text) = child.utf8_text(source) {
                        let name = text.split(':').next().unwrap_or(text).trim().to_string();
                        if !name.is_empty() && name != "self" && name != "this" {
                            let ty = self.env.fresh_var();
                            self.env.bind(name.clone(), ty.clone());
                            result.parameters.push((name, ty));
                        }
                    }
                }

                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        Ok(())
    }

    fn process_node(
        &mut self,
        node: Node,
        source: &[u8],
        result: &mut InferredTypes,
    ) -> Result<()> {
        let kind = node.kind();
        let line = node.start_position().row + 1;

        match kind {
            "assignment" | "expression_statement" => {
                if let Ok(text) = node.utf8_text(source) {
                    if let Some(eq_idx) = text.find('=') {
                        let var = text[..eq_idx].trim();
                        let expr = text[eq_idx + 1..].trim();

                        if is_identifier(var) {
                            let ty = self.infer_expr_from_text(expr)?;
                            self.env.bind(var.to_string(), ty.clone());
                            result
                                .variable_types
                                .entry(line)
                                .or_default()
                                .insert(var.to_string(), ty);
                        }
                    }
                }
            }
            "return_statement" => {
                if let Ok(text) = node.utf8_text(source) {
                    let expr = text.strip_prefix("return").unwrap_or(text).trim();
                    if !expr.is_empty() {
                        let ty = self.infer_expr_from_text(expr)?;
                        result.return_type = ty;
                    }
                }
            }
            _ => {}
        }

        // Recurse into children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.process_node(cursor.node(), source, result)?;
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Check for type errors in code
    pub fn check_type_errors(&mut self) -> Vec<TypeError> {
        let mut errors = Vec::new();

        // Check for uses of undefined variables
        if let Some(cfg) = self.cfg {
            for block in cfg.blocks.values() {
                for stmt in &block.statements {
                    let text = &stmt.text;
                    let vars = extract_identifiers(text);

                    for var in vars {
                        if self.env.lookup(&var).is_none()
                            && self.stubs.lookup_builtin(&var).is_none()
                        {
                            // Check if it's a keyword or literal
                            if !is_keyword(&var) && self.infer_literal(&var).is_none() {
                                errors.push(TypeError {
                                    message: format!("Undefined variable: {}", var),
                                    line: stmt.line,
                                    column: 0,
                                    kind: TypeErrorKind::UndefinedVariable,
                                });
                            }
                        }
                    }
                }
            }
        }

        errors
    }
}

// Helper functions

fn is_identifier(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return false;
    }
    let first = s.chars().next().unwrap();
    if !first.is_alphabetic() && first != '_' {
        return false;
    }
    s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

fn is_keyword(s: &str) -> bool {
    matches!(
        s,
        // Python keywords
        "and" | "as" | "assert" | "async" | "await" | "break" | "class" | "continue"
            | "def" | "del" | "elif" | "else" | "except" | "finally" | "for" | "from"
            | "global" | "if" | "import" | "in" | "is" | "lambda" | "nonlocal" | "not"
            | "or" | "pass" | "raise" | "return" | "try" | "while" | "with" | "yield"
            // JavaScript keywords
            | "const" | "let" | "var" | "function" | "new" | "typeof" | "instanceof"
            | "switch" | "case" | "default" | "throw" | "catch"
            // Common literals
            | "None" | "True" | "False" | "null" | "undefined" | "true" | "false"
            | "self" | "this"
    )
}

fn extract_identifiers(text: &str) -> Vec<String> {
    let mut identifiers = Vec::new();
    let mut current = String::new();

    for c in text.chars() {
        if c.is_alphanumeric() || c == '_' {
            current.push(c);
        } else {
            if !current.is_empty() && is_identifier(&current) && !is_keyword(&current) {
                identifiers.push(current.clone());
            }
            current.clear();
        }
    }

    if !current.is_empty() && is_identifier(&current) && !is_keyword(&current) {
        identifiers.push(current);
    }

    identifiers
}

fn find_child_by_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            if cursor.node().kind() == kind {
                return Some(cursor.node());
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    None
}

fn extract_function_name(node: Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "identifier" || child.kind() == "name" {
                return child.utf8_text(source).ok().map(|s| s.to_string());
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    None
}

// ============================================================================
// Static Type Parsing Functions for Go, Java, and Rust
// ============================================================================

/// Parse a Rust type string into a Type.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(parse_rust_type("i32"), Some(Type::Int));
/// assert_eq!(parse_rust_type("Vec<String>"), Some(Type::List(Box::new(Type::String))));
/// ```
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn parse_rust_type(type_str: &str) -> Option<Type> {
    let s = type_str.trim();

    // Handle references (strip &, &mut, &'lifetime)
    let s = if s.starts_with('&') {
        let s = s.trim_start_matches('&');
        // Strip mut
        let s = s.strip_prefix("mut ").unwrap_or(s);
        // Strip lifetime like 'a or 'static
        let s = if s.starts_with('\'') {
            if let Some(space_pos) = s.find(' ') {
                &s[space_pos + 1..]
            } else {
                s
            }
        } else {
            s
        };
        s.trim()
    } else {
        s
    };

    // Primitive types
    match s {
        "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64" | "u128"
        | "usize" => return Some(Type::Int),
        "f32" | "f64" => return Some(Type::Float),
        "bool" => return Some(Type::Bool),
        "str" | "String" => return Some(Type::String),
        "()" => return Some(Type::None),
        "!" => return Some(Type::Never),
        _ => {}
    }

    // Generic types: Vec<T>, Option<T>, Result<T, E>, HashMap<K, V>, etc.
    if let Some(open) = s.find('<') {
        let name = &s[..open];
        let close = s.rfind('>')?;
        let inner = &s[open + 1..close];

        // Parse type arguments
        let type_args = parse_rust_type_args(inner);

        match name {
            "Vec" | "VecDeque" | "LinkedList" | "HashSet" | "BTreeSet" => {
                let inner_type = type_args.first().cloned().unwrap_or(Type::Unknown);
                return Some(Type::List(Box::new(inner_type)));
            }
            "Option" => {
                let inner_type = type_args.first().cloned().unwrap_or(Type::Unknown);
                return Some(Type::Optional(Box::new(inner_type)));
            }
            "HashMap" | "BTreeMap" => {
                if type_args.len() >= 2 {
                    return Some(Type::Dict(
                        Box::new(type_args[0].clone()),
                        Box::new(type_args[1].clone()),
                    ));
                }
            }
            _ => {
                return Some(Type::Instance {
                    class_name: name.to_string(),
                    type_args,
                });
            }
        }
    }

    // Unknown/custom type
    Some(Type::Instance {
        class_name: s.to_string(),
        type_args: vec![],
    })
}

/// Parse comma-separated Rust type arguments (handling nested generics).
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn parse_rust_type_args(args_str: &str) -> Vec<Type> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut depth = 0;

    for ch in args_str.chars() {
        match ch {
            '<' => {
                depth += 1;
                current.push(ch);
            }
            '>' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                if let Some(ty) = parse_rust_type(current.trim()) {
                    result.push(ty);
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    if !current.trim().is_empty() {
        if let Some(ty) = parse_rust_type(current.trim()) {
            result.push(ty);
        }
    }

    result
}

/// Extract trait bounds from a Rust type constraint string.
///
/// # Examples
///
/// ```ignore
/// let bounds = extract_rust_trait_bounds("T: Clone + Debug");
/// assert!(bounds.contains(&"Clone".to_string()));
/// ```
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn extract_rust_trait_bounds(bounds_str: &str) -> Vec<String> {
    let mut result = Vec::new();
    let s = bounds_str.trim();

    // Handle "where T: Clone" format
    let s = s.strip_prefix("where").map(|rest| rest.trim()).unwrap_or(s);

    // Find the part after the colon
    if let Some(colon_pos) = s.find(':') {
        let bounds_part = &s[colon_pos + 1..];
        // Split by '+' for multiple bounds
        for bound in bounds_part.split('+') {
            let bound = bound.trim();
            if !bound.is_empty() {
                // Extract just the trait name (without generics)
                let trait_name = if let Some(lt_pos) = bound.find('<') {
                    &bound[..lt_pos]
                } else {
                    bound
                };
                result.push(trait_name.trim().to_string());
            }
        }
    }

    result
}

/// Represents a Rust type parameter with its bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustTypeParam {
    /// The type parameter name (e.g., "T")
    pub name: String,
    /// Trait bounds on the type parameter (e.g., ["Clone", "Debug"])
    pub bounds: Vec<String>,
}

/// Extract type parameters and their bounds from a Rust generic declaration.
///
/// # Examples
///
/// ```ignore
/// let params = extract_rust_type_params("<T: Clone, U: Debug>");
/// assert_eq!(params[0].name, "T");
/// assert!(params[0].bounds.contains(&"Clone".to_string()));
/// ```
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn extract_rust_type_params(generic_str: &str) -> Vec<RustTypeParam> {
    let mut result = Vec::new();
    let s = generic_str.trim();

    // Strip < and > if present
    let s = s.strip_prefix('<').unwrap_or(s);
    let s = s.strip_suffix('>').unwrap_or(s);

    // Split by comma, but respect nested angle brackets
    let mut depth = 0;
    let mut current = String::new();

    for ch in s.chars() {
        match ch {
            '<' => {
                depth += 1;
                current.push(ch);
            }
            '>' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                if !current.trim().is_empty() {
                    if let Some(param) = parse_single_rust_type_param(current.trim()) {
                        result.push(param);
                    }
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    if !current.trim().is_empty() {
        if let Some(param) = parse_single_rust_type_param(current.trim()) {
            result.push(param);
        }
    }

    result
}

fn parse_single_rust_type_param(param_str: &str) -> Option<RustTypeParam> {
    let s = param_str.trim();
    if s.is_empty() {
        return None;
    }

    // Check for "T: Bound1 + Bound2" format
    if let Some(colon_pos) = s.find(':') {
        let name = s[..colon_pos].trim().to_string();
        let bounds = extract_rust_trait_bounds(s);
        Some(RustTypeParam { name, bounds })
    } else {
        // No bounds, just a type parameter name
        Some(RustTypeParam {
            name: s.to_string(),
            bounds: vec![],
        })
    }
}

/// Parse a Go type string into a Type.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(parse_go_type("int"), Some(Type::Int));
/// assert_eq!(parse_go_type("[]string"), Some(Type::List(Box::new(Type::String))));
/// ```
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn parse_go_type(type_str: &str) -> Option<Type> {
    let s = type_str.trim();

    // Primitive types
    match s {
        "int" | "int8" | "int16" | "int32" | "int64" | "uint" | "uint8" | "uint16" | "uint32"
        | "uint64" | "uintptr" | "byte" | "rune" => return Some(Type::Int),
        "float32" | "float64" => return Some(Type::Float),
        "bool" => return Some(Type::Bool),
        "string" => return Some(Type::String),
        "error" => {
            return Some(Type::Instance {
                class_name: "error".to_string(),
                type_args: vec![],
            })
        }
        _ => {}
    }

    // Slice: []T
    if let Some(inner) = s.strip_prefix("[]") {
        let inner_type = parse_go_type(inner).unwrap_or(Type::Unknown);
        return Some(Type::List(Box::new(inner_type)));
    }

    // Array: [N]T (treat as list)
    if s.starts_with('[') {
        if let Some(close_bracket) = s.find(']') {
            let inner = &s[close_bracket + 1..];
            let inner_type = parse_go_type(inner).unwrap_or(Type::Unknown);
            return Some(Type::List(Box::new(inner_type)));
        }
    }

    // Map: map[K]V
    if let Some(rest) = s.strip_prefix("map[") {
        if let Some(bracket_close) = rest.find(']') {
            let key_type = parse_go_type(&rest[..bracket_close]).unwrap_or(Type::Unknown);
            let value_type = parse_go_type(&rest[bracket_close + 1..]).unwrap_or(Type::Unknown);
            return Some(Type::Dict(Box::new(key_type), Box::new(value_type)));
        }
    }

    // Channel: chan T, <-chan T, chan<- T
    if s.starts_with("chan ") || s.starts_with("<-chan ") || s.starts_with("chan<-") {
        return Some(Type::Instance {
            class_name: "chan".to_string(),
            type_args: vec![Type::Unknown],
        });
    }

    // Pointer: *T (represent as Optional)
    if let Some(inner) = s.strip_prefix('*') {
        let inner_type = parse_go_type(inner).unwrap_or(Type::Unknown);
        return Some(Type::Optional(Box::new(inner_type)));
    }

    // Function type: func(params) returns
    if s.starts_with("func") {
        return Some(Type::Function {
            params: vec![Type::Unknown],
            ret: Box::new(Type::Unknown),
        });
    }

    // Interface or struct type
    Some(Type::Instance {
        class_name: s.to_string(),
        type_args: vec![],
    })
}

/// Parse a Go type assertion expression like "x.(Type)".
///
/// # Examples
///
/// ```ignore
/// assert_eq!(parse_go_type_assertion("x.(string)"), Some(Type::String));
/// ```
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn parse_go_type_assertion(expr: &str) -> Option<Type> {
    let s = expr.trim();
    // Find ".(" and extract the type inside
    if let Some(dot_paren) = s.find(".(") {
        if s.ends_with(')') {
            let type_str = &s[dot_paren + 2..s.len() - 1];
            return parse_go_type(type_str);
        }
    }
    None
}

/// Represents a Go interface method signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoInterfaceMethod {
    /// Method name
    pub name: String,
    /// Parameter types
    pub params: Vec<Type>,
    /// Return types (Go supports multiple returns)
    pub returns: Vec<Type>,
}

/// Represents a Go interface definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoInterface {
    /// Interface name
    pub name: String,
    /// Methods in the interface
    pub methods: Vec<GoInterfaceMethod>,
    /// Embedded interfaces
    pub embedded: Vec<String>,
}

/// Check if a type satisfies a Go interface (structural typing).
///
/// # Arguments
///
/// * `type_methods` - Methods available on the type
/// * `interface_def` - The interface definition to check against
///
/// # Returns
///
/// `true` if the type has all methods required by the interface.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn check_go_interface_satisfaction(
    type_methods: &[GoInterfaceMethod],
    interface_def: &GoInterface,
) -> bool {
    for interface_method in &interface_def.methods {
        let has_method = type_methods.iter().any(|m| {
            m.name == interface_method.name
                && m.params.len() == interface_method.params.len()
                && m.returns.len() == interface_method.returns.len()
        });
        if !has_method {
            return false;
        }
    }
    true
}

/// Parse a Java type string into a Type.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(parse_java_type("int"), Some(Type::Int));
/// assert_eq!(parse_java_type("List<String>"), Some(Type::Instance { ... }));
/// ```
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn parse_java_type(type_str: &str) -> Option<Type> {
    let s = type_str.trim();

    // Primitive types
    match s {
        "int" | "long" | "short" | "byte" | "Integer" | "Long" | "Short" | "Byte" => {
            return Some(Type::Int)
        }
        "float" | "double" | "Float" | "Double" => return Some(Type::Float),
        "boolean" | "Boolean" => return Some(Type::Bool),
        "String" | "CharSequence" => return Some(Type::String),
        "void" | "Void" => return Some(Type::None),
        "char" | "Character" => {
            return Some(Type::Instance {
                class_name: "char".to_string(),
                type_args: vec![],
            })
        }
        _ => {}
    }

    // Generic types
    if let Some(open) = s.find('<') {
        let name = &s[..open];
        let close = s.rfind('>')?;
        let inner = &s[open + 1..close];

        // Parse type arguments
        let type_args = parse_java_type_args(inner);

        match name {
            "Optional" => {
                let inner_type = type_args.first().cloned().unwrap_or(Type::Unknown);
                return Some(Type::Optional(Box::new(inner_type)));
            }
            "List" | "ArrayList" | "LinkedList" | "Set" | "HashSet" | "TreeSet" => {
                return Some(Type::Instance {
                    class_name: name.to_string(),
                    type_args,
                });
            }
            "Map" | "HashMap" | "TreeMap" | "LinkedHashMap" => {
                return Some(Type::Instance {
                    class_name: name.to_string(),
                    type_args,
                });
            }
            _ => {
                return Some(Type::Instance {
                    class_name: name.to_string(),
                    type_args,
                });
            }
        }
    }

    // Array types
    if let Some(inner) = s.strip_suffix("[]") {
        let inner_type = parse_java_type(inner).unwrap_or(Type::Unknown);
        return Some(Type::List(Box::new(inner_type)));
    }

    // Wildcard types
    if s == "?" {
        return Some(Type::Unknown);
    }

    // Bounded wildcards: ? extends T, ? super T
    if let Some(bound) = s.strip_prefix("? extends ") {
        return parse_java_type(bound);
    }
    if let Some(bound) = s.strip_prefix("? super ") {
        return parse_java_type(bound);
    }

    // Regular class type
    Some(Type::Instance {
        class_name: s.to_string(),
        type_args: vec![],
    })
}

/// Parse comma-separated Java type arguments.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn parse_java_type_args(args_str: &str) -> Vec<Type> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut depth = 0;

    for ch in args_str.chars() {
        match ch {
            '<' => {
                depth += 1;
                current.push(ch);
            }
            '>' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                if let Some(ty) = parse_java_type(current.trim()) {
                    result.push(ty);
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    if !current.trim().is_empty() {
        if let Some(ty) = parse_java_type(current.trim()) {
            result.push(ty);
        }
    }

    result
}

/// Java annotation type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JavaAnnotation {
    /// Annotation name (e.g., "Nullable", "NonNull", "Override")
    pub name: String,
    /// Annotation parameters (key-value pairs)
    pub params: HashMap<String, String>,
}

/// Parse a Java type with annotations like @Nullable.
///
/// Returns a tuple of (parsed_type, annotations).
///
/// # Examples
///
/// ```ignore
/// let (ty, annots) = parse_java_annotated_type("@Nullable String");
/// assert_eq!(ty, Some(Type::Optional(Box::new(Type::String))));
/// assert_eq!(annots.len(), 1);
/// ```
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn parse_java_annotated_type(type_str: &str) -> (Option<Type>, Vec<JavaAnnotation>) {
    let s = type_str.trim();
    let mut annotations = Vec::new();
    let mut remaining = s;

    // Extract annotations
    while remaining.starts_with('@') {
        if let Some(space_pos) = remaining.find(|c: char| c.is_whitespace()) {
            let annotation_str = &remaining[1..space_pos];
            let annotation = JavaAnnotation {
                name: annotation_str.to_string(),
                params: HashMap::new(),
            };
            annotations.push(annotation);
            remaining = remaining[space_pos..].trim();
        } else {
            break;
        }
    }

    // Check for @Nullable annotation to convert to Optional
    let is_nullable = annotations.iter().any(|a| a.name == "Nullable");

    let base_type = parse_java_type(remaining);

    if is_nullable {
        if let Some(ty) = base_type {
            return (Some(Type::Optional(Box::new(ty))), annotations);
        }
    }

    (base_type, annotations)
}

/// Represents a Java generic type parameter with bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaTypeParam {
    /// The type parameter name (e.g., "T")
    pub name: String,
    /// Upper bounds (e.g., "extends Comparable<T>")
    pub upper_bounds: Vec<String>,
}

/// Extract type parameters from a Java generic declaration.
///
/// # Examples
///
/// ```ignore
/// let params = extract_java_type_params("<T extends Comparable<T>, U>");
/// assert_eq!(params[0].name, "T");
/// assert!(params[0].upper_bounds.contains(&"Comparable<T>".to_string()));
/// ```
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn extract_java_type_params(generic_str: &str) -> Vec<JavaTypeParam> {
    let mut result = Vec::new();
    let s = generic_str.trim();

    // Strip < and > if present
    let s = s.strip_prefix('<').unwrap_or(s);
    let s = s.strip_suffix('>').unwrap_or(s);

    // Split by comma, but respect nested angle brackets
    let mut depth = 0;
    let mut current = String::new();

    for ch in s.chars() {
        match ch {
            '<' => {
                depth += 1;
                current.push(ch);
            }
            '>' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                if !current.trim().is_empty() {
                    if let Some(param) = parse_single_java_type_param(current.trim()) {
                        result.push(param);
                    }
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    if !current.trim().is_empty() {
        if let Some(param) = parse_single_java_type_param(current.trim()) {
            result.push(param);
        }
    }

    result
}

fn parse_single_java_type_param(param_str: &str) -> Option<JavaTypeParam> {
    let s = param_str.trim();
    if s.is_empty() {
        return None;
    }

    // Check for "T extends Bound1 & Bound2" format
    if let Some(extends_pos) = s.find(" extends ") {
        let name = s[..extends_pos].trim().to_string();
        let bounds_str = &s[extends_pos + 9..];
        let upper_bounds: Vec<String> = bounds_str
            .split('&')
            .map(|b| b.trim().to_string())
            .collect();
        Some(JavaTypeParam { name, upper_bounds })
    } else {
        // No bounds, just a type parameter name
        Some(JavaTypeParam {
            name: s.to_string(),
            upper_bounds: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Type parsing functions are now public in the main module and available via super::*
    // - parse_rust_type, parse_rust_type_args, extract_rust_trait_bounds
    // - parse_go_type, parse_go_type_assertion
    // - parse_java_type, parse_java_type_args, parse_java_annotated_type

    // ==================== Existing Tests ====================

    #[test]
    fn test_type_display_name() {
        assert_eq!(Type::Int.display_name(), "int");
        assert_eq!(Type::String.display_name(), "str");
        assert_eq!(Type::Bool.display_name(), "bool");
        assert_eq!(Type::None.display_name(), "None");
        assert_eq!(Type::Unknown.display_name(), "Any");

        let list = Type::List(Box::new(Type::Int));
        assert_eq!(list.display_name(), "list[int]");

        let dict = Type::Dict(Box::new(Type::String), Box::new(Type::Int));
        assert_eq!(dict.display_name(), "dict[str, int]");

        let func = Type::Function {
            params: vec![Type::Int, Type::String],
            ret: Box::new(Type::Bool),
        };
        assert_eq!(func.display_name(), "(int, str) -> bool");
    }

    #[test]
    fn test_type_subtyping() {
        assert!(Type::Int.is_subtype_of(&Type::Int));
        assert!(Type::Int.is_subtype_of(&Type::Float));
        assert!(Type::Int.is_subtype_of(&Type::Unknown));
        assert!(Type::Never.is_subtype_of(&Type::Int));
        assert!(Type::None.is_subtype_of(&Type::Optional(Box::new(Type::Int))));
        assert!(Type::Int.is_subtype_of(&Type::Optional(Box::new(Type::Int))));
    }

    #[test]
    fn test_type_env() {
        let mut env = TypeEnv::new();

        env.bind("x".to_string(), Type::Int);
        assert_eq!(env.lookup("x"), Some(&Type::Int));
        assert_eq!(env.lookup("y"), None);

        let var = env.fresh_var();
        assert!(matches!(var, Type::Var(0)));

        let var2 = env.fresh_var();
        assert!(matches!(var2, Type::Var(1)));
    }

    #[test]
    fn test_type_env_scopes() {
        let mut env = TypeEnv::new();

        env.bind("x".to_string(), Type::Int);
        env.push_scope();
        env.bind("y".to_string(), Type::String);

        assert!(env.lookup("x").is_some());
        assert!(env.lookup("y").is_some());

        env.pop_scope();
        assert!(env.lookup("x").is_some());
        assert!(env.lookup("y").is_none());
    }

    #[test]
    fn test_type_stubs_python() {
        let stubs = TypeStubs::python_stdlib();

        let len_sig = stubs.lookup_builtin("len").unwrap();
        assert_eq!(len_sig.ret, Type::Int);

        let str_sig = stubs.lookup_builtin("str").unwrap();
        assert_eq!(str_sig.ret, Type::String);

        let getenv = stubs.lookup_module_func("os", "getenv").unwrap();
        assert!(matches!(getenv.ret, Type::Optional(_)));

        let split = stubs.lookup_method("str", "split").unwrap();
        assert!(matches!(split.ret, Type::List(_)));
    }

    #[test]
    fn test_type_stubs_javascript() {
        let stubs = TypeStubs::javascript_stdlib();

        let parse_int = stubs.lookup_builtin("parseInt").unwrap();
        assert_eq!(parse_int.ret, Type::Int);

        let push = stubs.lookup_method("Array", "push").unwrap();
        assert_eq!(push.ret, Type::Int);

        let length = stubs.lookup_attribute("Array", "length").unwrap();
        assert_eq!(*length, Type::Int);
    }

    #[test]
    fn test_infer_literals() {
        let inferencer = TypeInferencer::new("", None, "python");

        assert_eq!(inferencer.infer_literal("42"), Some(Type::Int));
        assert_eq!(inferencer.infer_literal("3.14"), Some(Type::Float));
        assert_eq!(inferencer.infer_literal("\"hello\""), Some(Type::String));
        assert_eq!(inferencer.infer_literal("True"), Some(Type::Bool));
        assert_eq!(inferencer.infer_literal("None"), Some(Type::None));
        assert_eq!(inferencer.infer_literal("foo"), None);
    }

    #[test]
    fn test_infer_expr() {
        let mut inferencer = TypeInferencer::new("", None, "python");
        inferencer.env.bind("x".to_string(), Type::Int);

        assert_eq!(inferencer.infer_expr_from_text("42").unwrap(), Type::Int);
        assert_eq!(
            inferencer.infer_expr_from_text("\"hello\"").unwrap(),
            Type::String
        );
        assert_eq!(inferencer.infer_expr_from_text("x").unwrap(), Type::Int);
        assert!(matches!(
            inferencer.infer_expr_from_text("[]").unwrap(),
            Type::List(_)
        ));
        assert!(matches!(
            inferencer.infer_expr_from_text("{}").unwrap(),
            Type::Dict(_, _)
        ));
    }

    #[test]
    fn test_infer_binary_ops() {
        let mut inferencer = TypeInferencer::new("", None, "python");
        inferencer.env.bind("x".to_string(), Type::Int);
        inferencer.env.bind("y".to_string(), Type::Int);

        assert_eq!(inferencer.infer_expr_from_text("x + y").unwrap(), Type::Int);
        assert_eq!(
            inferencer.infer_expr_from_text("x == y").unwrap(),
            Type::Bool
        );
        assert_eq!(
            inferencer.infer_expr_from_text("x > y").unwrap(),
            Type::Bool
        );
    }

    #[test]
    fn test_infer_function_call() {
        let mut inferencer = TypeInferencer::new("", None, "python");

        assert_eq!(
            inferencer.infer_expr_from_text("len([])").unwrap(),
            Type::Int
        );
        assert_eq!(
            inferencer.infer_expr_from_text("str(42)").unwrap(),
            Type::String
        );
    }

    #[test]
    fn test_type_simplify() {
        let union = Type::Union(vec![Type::Int, Type::Int]);
        let simplified = union.simplify();
        assert_eq!(simplified, Type::Int);

        let nested = Type::Union(vec![Type::Union(vec![Type::Int, Type::String]), Type::Bool]);
        let simplified = nested.simplify();
        assert!(matches!(simplified, Type::Union(v) if v.len() == 3));
    }

    #[test]
    fn test_is_identifier() {
        assert!(is_identifier("foo"));
        assert!(is_identifier("_bar"));
        assert!(is_identifier("baz123"));
        assert!(!is_identifier("123"));
        assert!(!is_identifier("foo-bar"));
        assert!(!is_identifier(""));
    }

    #[test]
    fn test_is_keyword() {
        assert!(is_keyword("if"));
        assert!(is_keyword("return"));
        assert!(is_keyword("def"));
        assert!(is_keyword("const"));
        assert!(is_keyword("None"));
        assert!(!is_keyword("foo"));
    }

    #[test]
    fn test_extract_identifiers() {
        let ids = extract_identifiers("x + y * z");
        assert!(ids.contains(&"x".to_string()));
        assert!(ids.contains(&"y".to_string()));
        assert!(ids.contains(&"z".to_string()));

        let ids2 = extract_identifiers("if x and y:");
        // 'if' and 'and' are keywords, should be filtered
        assert!(!ids2.contains(&"if".to_string()));
        assert!(!ids2.contains(&"and".to_string()));
        assert!(ids2.contains(&"x".to_string()));
        assert!(ids2.contains(&"y".to_string()));
    }

    #[test]
    fn test_inferred_types_markdown() {
        let mut result = InferredTypes::new("test_func", "test.py");
        result.parameters = vec![
            ("x".to_string(), Type::Int),
            ("y".to_string(), Type::String),
        ];
        result.return_type = Type::Bool;

        let md = result.to_markdown();
        assert!(md.contains("test_func"));
        assert!(md.contains("int"));
        assert!(md.contains("str"));
        assert!(md.contains("bool"));
    }

    #[test]
    fn test_unification() {
        let mut inferencer = TypeInferencer::new("", None, "python");

        // Var with concrete
        let var = inferencer.env.fresh_var();
        assert!(inferencer.unify(&var, &Type::Int).is_ok());

        // List unification
        let list1 = Type::List(Box::new(inferencer.env.fresh_var()));
        let list2 = Type::List(Box::new(Type::String));
        assert!(inferencer.unify(&list1, &list2).is_ok());

        // Mismatched types
        assert!(inferencer.unify(&Type::Int, &Type::String).is_err());
    }

    #[test]
    fn test_type_error_kinds() {
        let error = TypeError {
            message: "test error".to_string(),
            line: 1,
            column: 5,
            kind: TypeErrorKind::UndefinedVariable,
        };

        assert_eq!(error.kind, TypeErrorKind::UndefinedVariable);
        assert_eq!(error.line, 1);
    }

    // ==================== Go Type Inference Tests ====================

    #[test]
    fn test_type_stubs_go() {
        let stubs = TypeStubs::go_stdlib();

        // fmt package
        let println = stubs.lookup_module_func("fmt", "Println").unwrap();
        assert_eq!(println.ret, Type::None);

        let sprintf = stubs.lookup_module_func("fmt", "Sprintf").unwrap();
        assert_eq!(sprintf.ret, Type::String);

        // strings package
        let split = stubs.lookup_module_func("strings", "Split").unwrap();
        assert!(matches!(split.ret, Type::List(_)));

        let contains = stubs.lookup_module_func("strings", "Contains").unwrap();
        assert_eq!(contains.ret, Type::Bool);

        // os package
        let getenv = stubs.lookup_module_func("os", "Getenv").unwrap();
        assert_eq!(getenv.ret, Type::String);

        // builtin functions
        let len_sig = stubs.lookup_builtin("len").unwrap();
        assert_eq!(len_sig.ret, Type::Int);

        let make_sig = stubs.lookup_builtin("make").unwrap();
        assert_eq!(make_sig.ret, Type::Unknown);

        let append_sig = stubs.lookup_builtin("append").unwrap();
        assert!(matches!(append_sig.ret, Type::List(_)));
    }

    #[test]
    fn test_go_type_inference_short_declaration() {
        let mut inferencer = TypeInferencer::new("", None, "go");

        // x := 42 should infer x as int
        assert_eq!(inferencer.infer_expr_from_text("42").unwrap(), Type::Int);

        // s := "hello" should infer s as string
        assert_eq!(
            inferencer.infer_expr_from_text("\"hello\"").unwrap(),
            Type::String
        );

        // Go nil
        assert_eq!(inferencer.infer_literal("nil"), Some(Type::None));
    }

    #[test]
    fn test_go_type_assertion_extraction() {
        // Type assertions like v.(Type) should extract Type
        let ty = parse_go_type_assertion("x.(string)");
        assert_eq!(ty, Some(Type::String));

        let ty = parse_go_type_assertion("v.(int)");
        assert_eq!(ty, Some(Type::Int));

        let ty = parse_go_type_assertion("r.(io.Reader)");
        assert!(matches!(ty, Some(Type::Instance { class_name, .. }) if class_name == "io.Reader"));
    }

    #[test]
    fn test_go_slice_and_map_types() {
        // []string -> List<String>
        let ty = parse_go_type("[]string");
        assert!(matches!(ty, Some(Type::List(inner)) if *inner == Type::String));

        // map[string]int -> Dict<String, Int>
        let ty = parse_go_type("map[string]int");
        assert!(matches!(ty, Some(Type::Dict(k, v)) if *k == Type::String && *v == Type::Int));

        // *int -> pointer to int (represented as Optional)
        let ty = parse_go_type("*int");
        assert!(matches!(ty, Some(Type::Optional(inner)) if *inner == Type::Int));
    }

    // ==================== Java Type Inference Tests ====================

    #[test]
    fn test_type_stubs_java() {
        let stubs = TypeStubs::java_stdlib();

        // String methods
        let length = stubs.lookup_method("String", "length").unwrap();
        assert_eq!(length.ret, Type::Int);

        let substring = stubs.lookup_method("String", "substring").unwrap();
        assert_eq!(substring.ret, Type::String);

        let split = stubs.lookup_method("String", "split").unwrap();
        assert!(matches!(split.ret, Type::List(_)));

        // List methods
        let add = stubs.lookup_method("List", "add").unwrap();
        assert_eq!(add.ret, Type::Bool);

        let size = stubs.lookup_method("List", "size").unwrap();
        assert_eq!(size.ret, Type::Int);

        let get = stubs.lookup_method("List", "get").unwrap();
        assert_eq!(get.ret, Type::Unknown); // generic type

        // System class
        let println = stubs.lookup_module_func("System.out", "println").unwrap();
        assert_eq!(println.ret, Type::None);
    }

    #[test]
    fn test_java_generics_parsing() {
        // List<String> -> Instance with type args
        let ty = parse_java_type("List<String>");
        assert!(matches!(
            ty,
            Some(Type::Instance { class_name, type_args })
            if class_name == "List" && type_args.len() == 1 && type_args[0] == Type::String
        ));

        // Map<String, Integer>
        let ty = parse_java_type("Map<String, Integer>");
        assert!(matches!(
            ty,
            Some(Type::Instance { class_name, type_args })
            if class_name == "Map" && type_args.len() == 2
        ));

        // Optional<String>
        let ty = parse_java_type("Optional<String>");
        assert!(matches!(
            ty,
            Some(Type::Optional(inner)) if *inner == Type::String
        ));
    }

    #[test]
    fn test_java_annotation_detection() {
        // @Nullable String -> Optional<String>
        let (ty, annots) = parse_java_annotated_type("@Nullable String");
        assert!(matches!(ty, Some(Type::Optional(inner)) if *inner == Type::String));
        assert_eq!(annots.len(), 1);
        assert_eq!(annots[0].name, "Nullable");

        // @NonNull List<String> -> List<String> (not optional)
        let (ty, annots) = parse_java_annotated_type("@NonNull List<String>");
        assert!(matches!(ty, Some(Type::Instance { class_name, .. }) if class_name == "List"));
        assert_eq!(annots.len(), 1);
        assert_eq!(annots[0].name, "NonNull");

        // Multiple annotations
        let (ty, annots) = parse_java_annotated_type("@Override @Nullable String");
        assert!(matches!(ty, Some(Type::Optional(inner)) if *inner == Type::String));
        assert_eq!(annots.len(), 2);
    }

    #[test]
    fn test_java_primitive_types() {
        assert_eq!(parse_java_type("int"), Some(Type::Int));
        assert_eq!(parse_java_type("long"), Some(Type::Int));
        assert_eq!(parse_java_type("double"), Some(Type::Float));
        assert_eq!(parse_java_type("float"), Some(Type::Float));
        assert_eq!(parse_java_type("boolean"), Some(Type::Bool));
        assert_eq!(parse_java_type("String"), Some(Type::String));
        assert_eq!(parse_java_type("void"), Some(Type::None));
    }

    // ==================== Rust Type Inference Tests ====================

    #[test]
    fn test_type_stubs_rust() {
        let stubs = TypeStubs::rust_stdlib();

        // String methods
        let len = stubs.lookup_method("String", "len").unwrap();
        assert_eq!(len.ret, Type::Int);

        let is_empty = stubs.lookup_method("String", "is_empty").unwrap();
        assert_eq!(is_empty.ret, Type::Bool);

        let push_str = stubs.lookup_method("String", "push_str").unwrap();
        assert_eq!(push_str.ret, Type::None);

        // Vec methods
        let push = stubs.lookup_method("Vec", "push").unwrap();
        assert_eq!(push.ret, Type::None);

        let pop = stubs.lookup_method("Vec", "pop").unwrap();
        assert!(matches!(pop.ret, Type::Optional(_)));

        // Option methods
        let unwrap = stubs.lookup_method("Option", "unwrap").unwrap();
        assert_eq!(unwrap.ret, Type::Unknown);

        let is_some = stubs.lookup_method("Option", "is_some").unwrap();
        assert_eq!(is_some.ret, Type::Bool);
    }

    #[test]
    fn test_rust_type_parsing() {
        // Primitive types
        assert_eq!(parse_rust_type("i32"), Some(Type::Int));
        assert_eq!(parse_rust_type("i64"), Some(Type::Int));
        assert_eq!(parse_rust_type("u32"), Some(Type::Int));
        assert_eq!(parse_rust_type("f64"), Some(Type::Float));
        assert_eq!(parse_rust_type("bool"), Some(Type::Bool));
        assert_eq!(parse_rust_type("String"), Some(Type::String));
        assert_eq!(parse_rust_type("&str"), Some(Type::String));
    }

    #[test]
    fn test_rust_generic_types() {
        // Vec<i32>
        let ty = parse_rust_type("Vec<i32>");
        assert!(matches!(ty, Some(Type::List(inner)) if *inner == Type::Int));

        // Option<String>
        let ty = parse_rust_type("Option<String>");
        assert!(matches!(ty, Some(Type::Optional(inner)) if *inner == Type::String));

        // Result<T, E>
        let ty = parse_rust_type("Result<i32, String>");
        assert!(matches!(
            ty,
            Some(Type::Instance { class_name, type_args })
            if class_name == "Result" && type_args.len() == 2
        ));

        // HashMap<String, i32>
        let ty = parse_rust_type("HashMap<String, i32>");
        assert!(matches!(
            ty,
            Some(Type::Dict(k, v))
            if *k == Type::String && *v == Type::Int
        ));
    }

    #[test]
    fn test_rust_trait_bounds_extraction() {
        // fn foo<T: Clone>(x: T) -> extract Clone bound
        let bounds = extract_rust_trait_bounds("T: Clone");
        assert!(bounds.contains(&"Clone".to_string()));

        // T: Clone + Debug
        let bounds = extract_rust_trait_bounds("T: Clone + Debug");
        assert!(bounds.contains(&"Clone".to_string()));
        assert!(bounds.contains(&"Debug".to_string()));

        // where T: Clone
        let bounds = extract_rust_trait_bounds("where T: Clone");
        assert!(bounds.contains(&"Clone".to_string()));
    }

    #[test]
    fn test_rust_lifetime_parsing() {
        // &'a str -> string with lifetime
        let ty = parse_rust_type("&'a str");
        assert_eq!(ty, Some(Type::String));

        // &'static str
        let ty = parse_rust_type("&'static str");
        assert_eq!(ty, Some(Type::String));

        // References are stripped to their underlying type
        let ty = parse_rust_type("&i32");
        assert_eq!(ty, Some(Type::Int));

        let ty = parse_rust_type("&mut String");
        assert_eq!(ty, Some(Type::String));
    }

    #[test]
    fn test_rust_inferencer_creation() {
        let inferencer = TypeInferencer::new("", None, "rust");
        // Verify inferencer is configured for Rust
        assert!(inferencer.stubs.lookup_method("String", "len").is_some());
    }

    #[test]
    fn test_go_inferencer_creation() {
        let inferencer = TypeInferencer::new("", None, "go");
        // Verify inferencer is configured for Go
        assert!(inferencer.stubs.lookup_builtin("len").is_some());
        assert!(inferencer
            .stubs
            .lookup_module_func("fmt", "Println")
            .is_some());
    }

    #[test]
    fn test_java_inferencer_creation() {
        let inferencer = TypeInferencer::new("", None, "java");
        // Verify inferencer is configured for Java
        assert!(inferencer.stubs.lookup_method("String", "length").is_some());
    }

    // ==================== New Static Type Extraction Tests ====================

    #[test]
    fn test_rust_type_params_extraction() {
        // Simple type parameter
        let params = extract_rust_type_params("<T>");
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "T");
        assert!(params[0].bounds.is_empty());

        // Type parameter with single bound
        let params = extract_rust_type_params("<T: Clone>");
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "T");
        assert!(params[0].bounds.contains(&"Clone".to_string()));

        // Type parameter with multiple bounds
        let params = extract_rust_type_params("<T: Clone + Debug>");
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "T");
        assert!(params[0].bounds.contains(&"Clone".to_string()));
        assert!(params[0].bounds.contains(&"Debug".to_string()));

        // Multiple type parameters
        let params = extract_rust_type_params("<T: Clone, U: Debug>");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].name, "T");
        assert!(params[0].bounds.contains(&"Clone".to_string()));
        assert_eq!(params[1].name, "U");
        assert!(params[1].bounds.contains(&"Debug".to_string()));

        // Type parameter with no angle brackets
        let params = extract_rust_type_params("T: Clone");
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "T");

        // Empty string
        let params = extract_rust_type_params("");
        assert!(params.is_empty());
    }

    #[test]
    fn test_rust_type_params_with_generics_in_bounds() {
        // Bound with generics: T: Iterator<Item = u32>
        let params = extract_rust_type_params("<T: Iterator<Item = u32>>");
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "T");
        assert!(params[0].bounds.contains(&"Iterator".to_string()));

        // Multiple params with generic bounds
        let params = extract_rust_type_params("<T: From<String>, U: Into<i32>>");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].name, "T");
        assert_eq!(params[1].name, "U");
    }

    #[test]
    fn test_java_type_params_extraction() {
        // Simple type parameter
        let params = extract_java_type_params("<T>");
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "T");
        assert!(params[0].upper_bounds.is_empty());

        // Type parameter with extends bound
        let params = extract_java_type_params("<T extends Comparable<T>>");
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "T");
        assert_eq!(params[0].upper_bounds.len(), 1);
        assert!(params[0].upper_bounds[0].contains("Comparable"));

        // Type parameter with multiple bounds
        let params = extract_java_type_params("<T extends Serializable & Comparable<T>>");
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "T");
        assert_eq!(params[0].upper_bounds.len(), 2);
        assert!(params[0].upper_bounds.contains(&"Serializable".to_string()));

        // Multiple type parameters
        let params = extract_java_type_params("<K, V>");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].name, "K");
        assert_eq!(params[1].name, "V");

        // Multiple type parameters with bounds
        let params = extract_java_type_params("<K extends Comparable<K>, V extends Serializable>");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].name, "K");
        assert!(!params[0].upper_bounds.is_empty());
        assert_eq!(params[1].name, "V");
        assert!(!params[1].upper_bounds.is_empty());
    }

    #[test]
    fn test_java_wildcard_types() {
        // Unbounded wildcard
        let ty = parse_java_type("?");
        assert_eq!(ty, Some(Type::Unknown));

        // Upper bounded wildcard
        let ty = parse_java_type("? extends Number");
        assert!(matches!(ty, Some(Type::Instance { class_name, .. }) if class_name == "Number"));

        // Lower bounded wildcard - Integer maps to Type::Int in Java primitives
        let ty = parse_java_type("? super Integer");
        assert_eq!(ty, Some(Type::Int));

        // Lower bounded wildcard with non-primitive class
        let ty = parse_java_type("? super MyClass");
        assert!(matches!(ty, Some(Type::Instance { class_name, .. }) if class_name == "MyClass"));
    }

    #[test]
    fn test_go_interface_satisfaction_basic() {
        // Define a simple interface with one method
        let reader_interface = GoInterface {
            name: "Reader".to_string(),
            methods: vec![GoInterfaceMethod {
                name: "Read".to_string(),
                params: vec![Type::List(Box::new(Type::Int))],
                returns: vec![
                    Type::Int,
                    Type::Instance {
                        class_name: "error".to_string(),
                        type_args: vec![],
                    },
                ],
            }],
            embedded: vec![],
        };

        // Type with matching method should satisfy
        let type_methods = vec![GoInterfaceMethod {
            name: "Read".to_string(),
            params: vec![Type::List(Box::new(Type::Int))],
            returns: vec![
                Type::Int,
                Type::Instance {
                    class_name: "error".to_string(),
                    type_args: vec![],
                },
            ],
        }];
        assert!(check_go_interface_satisfaction(
            &type_methods,
            &reader_interface
        ));

        // Type missing the method should not satisfy
        let empty_methods: Vec<GoInterfaceMethod> = vec![];
        assert!(!check_go_interface_satisfaction(
            &empty_methods,
            &reader_interface
        ));

        // Type with wrong method signature should not satisfy (different param count)
        let wrong_methods = vec![GoInterfaceMethod {
            name: "Read".to_string(),
            params: vec![], // Wrong param count
            returns: vec![Type::Int],
        }];
        assert!(!check_go_interface_satisfaction(
            &wrong_methods,
            &reader_interface
        ));
    }

    #[test]
    fn test_go_interface_satisfaction_multiple_methods() {
        // Interface with multiple methods
        let read_writer_interface = GoInterface {
            name: "ReadWriter".to_string(),
            methods: vec![
                GoInterfaceMethod {
                    name: "Read".to_string(),
                    params: vec![Type::List(Box::new(Type::Int))],
                    returns: vec![Type::Int],
                },
                GoInterfaceMethod {
                    name: "Write".to_string(),
                    params: vec![Type::List(Box::new(Type::Int))],
                    returns: vec![Type::Int],
                },
            ],
            embedded: vec![],
        };

        // Type with both methods should satisfy
        let full_methods = vec![
            GoInterfaceMethod {
                name: "Read".to_string(),
                params: vec![Type::List(Box::new(Type::Int))],
                returns: vec![Type::Int],
            },
            GoInterfaceMethod {
                name: "Write".to_string(),
                params: vec![Type::List(Box::new(Type::Int))],
                returns: vec![Type::Int],
            },
        ];
        assert!(check_go_interface_satisfaction(
            &full_methods,
            &read_writer_interface
        ));

        // Type with only one method should not satisfy
        let partial_methods = vec![GoInterfaceMethod {
            name: "Read".to_string(),
            params: vec![Type::List(Box::new(Type::Int))],
            returns: vec![Type::Int],
        }];
        assert!(!check_go_interface_satisfaction(
            &partial_methods,
            &read_writer_interface
        ));
    }

    #[test]
    fn test_go_empty_interface_satisfaction() {
        // Empty interface (any type satisfies it)
        let empty_interface = GoInterface {
            name: "any".to_string(),
            methods: vec![],
            embedded: vec![],
        };

        // Any type should satisfy empty interface
        let any_methods: Vec<GoInterfaceMethod> = vec![];
        assert!(check_go_interface_satisfaction(
            &any_methods,
            &empty_interface
        ));

        let some_methods = vec![GoInterfaceMethod {
            name: "Foo".to_string(),
            params: vec![],
            returns: vec![],
        }];
        assert!(check_go_interface_satisfaction(
            &some_methods,
            &empty_interface
        ));
    }

    #[test]
    fn test_go_channel_type_parsing() {
        // Basic channel
        let ty = parse_go_type("chan int");
        assert!(matches!(ty, Some(Type::Instance { class_name, .. }) if class_name == "chan"));

        // Receive-only channel
        let ty = parse_go_type("<-chan string");
        assert!(matches!(ty, Some(Type::Instance { class_name, .. }) if class_name == "chan"));

        // Send-only channel
        let ty = parse_go_type("chan<- int");
        assert!(matches!(ty, Some(Type::Instance { class_name, .. }) if class_name == "chan"));
    }

    #[test]
    fn test_go_function_type_parsing() {
        let ty = parse_go_type("func(int) string");
        assert!(matches!(ty, Some(Type::Function { .. })));

        let ty = parse_go_type("func()");
        assert!(matches!(ty, Some(Type::Function { .. })));
    }

    #[test]
    fn test_go_array_type_parsing() {
        // Fixed-size array [5]int
        let ty = parse_go_type("[5]int");
        assert!(matches!(ty, Some(Type::List(inner)) if *inner == Type::Int));

        // Nested array
        let ty = parse_go_type("[3][]string");
        assert!(matches!(ty, Some(Type::List(_))));
    }

    #[test]
    fn test_rust_never_type() {
        let ty = parse_rust_type("!");
        assert_eq!(ty, Some(Type::Never));
    }

    #[test]
    fn test_rust_unit_type() {
        let ty = parse_rust_type("()");
        assert_eq!(ty, Some(Type::None));
    }

    #[test]
    fn test_rust_result_type() {
        let ty = parse_rust_type("Result<String, Error>");
        assert!(matches!(
            ty,
            Some(Type::Instance { class_name, type_args })
            if class_name == "Result" && type_args.len() == 2
        ));
    }

    #[test]
    fn test_java_char_type() {
        let ty = parse_java_type("char");
        assert!(matches!(ty, Some(Type::Instance { class_name, .. }) if class_name == "char"));

        let ty = parse_java_type("Character");
        assert!(matches!(ty, Some(Type::Instance { class_name, .. }) if class_name == "char"));
    }

    #[test]
    fn test_java_nested_generics() {
        // Map<String, List<Integer>>
        let ty = parse_java_type("Map<String, List<Integer>>");
        assert!(matches!(
            ty,
            Some(Type::Instance { class_name, type_args })
            if class_name == "Map" && type_args.len() == 2
        ));
    }
}
