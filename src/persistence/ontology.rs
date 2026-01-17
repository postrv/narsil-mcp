//! Narsil RDF ontology definitions.
//!
//! Defines the vocabulary for code intelligence entities including:
//! - Symbols (functions, classes, methods, etc.)
//! - Relationships (calls, imports, defines)
//! - Security findings (vulnerabilities, taint flows)
//! - Metrics (complexity, lines of code)

/// The narsil ontology in Turtle format.
///
/// This defines the core vocabulary for representing code intelligence
/// data as RDF triples. The ontology includes:
///
/// ## Classes
///
/// - `narsil:Repository` - A code repository
/// - `narsil:File` - A source file
/// - `narsil:Symbol` - Base class for all code symbols
/// - `narsil:Function` - A function definition
/// - `narsil:Method` - A method (function bound to class)
/// - `narsil:Class` - A class definition
/// - `narsil:Struct` - A struct definition
/// - `narsil:Trait` - A trait/interface definition
/// - `narsil:Module` - A module/package
/// - `narsil:SecurityFinding` - A security vulnerability
/// - `narsil:TaintSource` - A source of tainted data
/// - `narsil:TaintSink` - A sink for tainted data
///
/// ## Object Properties
///
/// - `narsil:containsFile` - Repository contains file
/// - `narsil:definesSymbol` - File defines symbol
/// - `narsil:calls` - Function calls function
/// - `narsil:imports` - Module imports module
/// - `narsil:hasVulnerability` - Symbol has vulnerability
/// - `narsil:taintFlowsTo` - Taint source flows to sink
/// - `narsil:hasParent` - Symbol has parent (class, module)
///
/// ## Data Properties
///
/// - `narsil:filePath` - Path to file
/// - `narsil:startLine` - Starting line number
/// - `narsil:endLine` - Ending line number
/// - `narsil:signature` - Function signature
/// - `narsil:docComment` - Documentation comment
/// - `narsil:complexity` - Cyclomatic complexity
/// - `narsil:severity` - Vulnerability severity
/// - `narsil:cweId` - CWE identifier
/// - `narsil:owaspCategory` - OWASP category
pub const NARSIL_ONTOLOGY: &str = r#"@prefix narsil: <https://narsilmcp.com/ontology/v1#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .

# Ontology metadata
<https://narsilmcp.com/ontology/v1> a owl:Ontology ;
    rdfs:label "Narsil Code Intelligence Ontology" ;
    rdfs:comment "Vocabulary for representing code intelligence data as RDF" ;
    owl:versionInfo "1.0" .

# ===== Core Classes =====

narsil:Repository a owl:Class ;
    rdfs:label "Repository" ;
    rdfs:comment "A code repository" .

narsil:File a owl:Class ;
    rdfs:label "File" ;
    rdfs:comment "A source code file" .

narsil:Symbol a owl:Class ;
    rdfs:label "Symbol" ;
    rdfs:comment "Base class for all code symbols" .

narsil:Function a owl:Class ;
    rdfs:subClassOf narsil:Symbol ;
    rdfs:label "Function" ;
    rdfs:comment "A function definition" .

narsil:Method a owl:Class ;
    rdfs:subClassOf narsil:Function ;
    rdfs:label "Method" ;
    rdfs:comment "A method (function bound to a class)" .

narsil:Class a owl:Class ;
    rdfs:subClassOf narsil:Symbol ;
    rdfs:label "Class" ;
    rdfs:comment "A class definition" .

narsil:Struct a owl:Class ;
    rdfs:subClassOf narsil:Symbol ;
    rdfs:label "Struct" ;
    rdfs:comment "A struct definition" .

narsil:Trait a owl:Class ;
    rdfs:subClassOf narsil:Symbol ;
    rdfs:label "Trait" ;
    rdfs:comment "A trait or interface definition" .

narsil:Module a owl:Class ;
    rdfs:subClassOf narsil:Symbol ;
    rdfs:label "Module" ;
    rdfs:comment "A module or package" .

narsil:Enum a owl:Class ;
    rdfs:subClassOf narsil:Symbol ;
    rdfs:label "Enum" ;
    rdfs:comment "An enumeration type" .

narsil:Constant a owl:Class ;
    rdfs:subClassOf narsil:Symbol ;
    rdfs:label "Constant" ;
    rdfs:comment "A constant or static value" .

narsil:Variable a owl:Class ;
    rdfs:subClassOf narsil:Symbol ;
    rdfs:label "Variable" ;
    rdfs:comment "A variable declaration" .

# ===== Security Classes =====

narsil:SecurityFinding a owl:Class ;
    rdfs:label "Security Finding" ;
    rdfs:comment "A security issue or vulnerability" .

narsil:Vulnerability a owl:Class ;
    rdfs:subClassOf narsil:SecurityFinding ;
    rdfs:label "Vulnerability" ;
    rdfs:comment "A security vulnerability" .

narsil:TaintSource a owl:Class ;
    rdfs:label "Taint Source" ;
    rdfs:comment "A source of potentially tainted data" .

narsil:TaintSink a owl:Class ;
    rdfs:label "Taint Sink" ;
    rdfs:comment "A sink where tainted data can cause harm" .

narsil:TaintFlow a owl:Class ;
    rdfs:label "Taint Flow" ;
    rdfs:comment "A flow of tainted data from source to sink" .

# ===== Quality Metric Classes =====

narsil:Metric a owl:Class ;
    rdfs:label "Metric" ;
    rdfs:comment "A code quality metric" .

narsil:CyclomaticComplexity a owl:Class ;
    rdfs:subClassOf narsil:Metric ;
    rdfs:label "Cyclomatic Complexity" ;
    rdfs:comment "Cyclomatic complexity measurement" .

narsil:CognitiveComplexity a owl:Class ;
    rdfs:subClassOf narsil:Metric ;
    rdfs:label "Cognitive Complexity" ;
    rdfs:comment "Cognitive complexity measurement" .

# ===== Object Properties =====

narsil:containsFile a owl:ObjectProperty ;
    rdfs:domain narsil:Repository ;
    rdfs:range narsil:File ;
    rdfs:label "contains file" ;
    rdfs:comment "Repository contains a file" .

narsil:definesSymbol a owl:ObjectProperty ;
    rdfs:domain narsil:File ;
    rdfs:range narsil:Symbol ;
    rdfs:label "defines symbol" ;
    rdfs:comment "File defines a symbol" .

narsil:calls a owl:ObjectProperty ;
    rdfs:domain narsil:Function ;
    rdfs:range narsil:Function ;
    rdfs:label "calls" ;
    rdfs:comment "Function calls another function" .

narsil:imports a owl:ObjectProperty ;
    rdfs:domain narsil:Module ;
    rdfs:range narsil:Module ;
    rdfs:label "imports" ;
    rdfs:comment "Module imports another module" .

narsil:hasParent a owl:ObjectProperty ;
    rdfs:domain narsil:Symbol ;
    rdfs:range narsil:Symbol ;
    rdfs:label "has parent" ;
    rdfs:comment "Symbol has a parent (class, module, etc.)" .

narsil:hasVulnerability a owl:ObjectProperty ;
    rdfs:domain narsil:Symbol ;
    rdfs:range narsil:Vulnerability ;
    rdfs:label "has vulnerability" ;
    rdfs:comment "Symbol has an associated vulnerability" .

narsil:taintFlowsTo a owl:ObjectProperty, owl:TransitiveProperty ;
    rdfs:domain narsil:TaintSource ;
    rdfs:range narsil:TaintSink ;
    rdfs:label "taint flows to" ;
    rdfs:comment "Tainted data flows from source to sink (transitive)" .

narsil:hasFinding a owl:ObjectProperty ;
    rdfs:domain narsil:Symbol ;
    rdfs:range narsil:SecurityFinding ;
    rdfs:label "has finding" ;
    rdfs:comment "Symbol has a security finding" .

narsil:referencesSymbol a owl:ObjectProperty ;
    rdfs:domain narsil:Symbol ;
    rdfs:range narsil:Symbol ;
    rdfs:label "references symbol" ;
    rdfs:comment "Symbol references another symbol" .

# ===== Data Properties =====

narsil:filePath a owl:DatatypeProperty ;
    rdfs:domain narsil:File ;
    rdfs:range xsd:string ;
    rdfs:label "file path" ;
    rdfs:comment "Path to the file relative to repository root" .

narsil:name a owl:DatatypeProperty ;
    rdfs:domain narsil:Symbol ;
    rdfs:range xsd:string ;
    rdfs:label "name" ;
    rdfs:comment "Name of the symbol" .

narsil:startLine a owl:DatatypeProperty ;
    rdfs:domain narsil:Symbol ;
    rdfs:range xsd:integer ;
    rdfs:label "start line" ;
    rdfs:comment "Starting line number (1-indexed)" .

narsil:endLine a owl:DatatypeProperty ;
    rdfs:domain narsil:Symbol ;
    rdfs:range xsd:integer ;
    rdfs:label "end line" ;
    rdfs:comment "Ending line number (1-indexed)" .

narsil:signature a owl:DatatypeProperty ;
    rdfs:domain narsil:Function ;
    rdfs:range xsd:string ;
    rdfs:label "signature" ;
    rdfs:comment "Function signature" .

narsil:docComment a owl:DatatypeProperty ;
    rdfs:domain narsil:Symbol ;
    rdfs:range xsd:string ;
    rdfs:label "documentation comment" ;
    rdfs:comment "Documentation comment for the symbol" .

narsil:language a owl:DatatypeProperty ;
    rdfs:domain narsil:File ;
    rdfs:range xsd:string ;
    rdfs:label "language" ;
    rdfs:comment "Programming language of the file" .

narsil:complexity a owl:DatatypeProperty ;
    rdfs:domain narsil:Function ;
    rdfs:range xsd:integer ;
    rdfs:label "complexity" ;
    rdfs:comment "Cyclomatic complexity value" .

narsil:cognitiveComplexity a owl:DatatypeProperty ;
    rdfs:domain narsil:Function ;
    rdfs:range xsd:integer ;
    rdfs:label "cognitive complexity" ;
    rdfs:comment "Cognitive complexity value" .

narsil:severity a owl:DatatypeProperty ;
    rdfs:domain narsil:SecurityFinding ;
    rdfs:range xsd:string ;
    rdfs:label "severity" ;
    rdfs:comment "Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)" .

narsil:cweId a owl:DatatypeProperty ;
    rdfs:domain narsil:SecurityFinding ;
    rdfs:range xsd:string ;
    rdfs:label "CWE ID" ;
    rdfs:comment "Common Weakness Enumeration identifier" .

narsil:owaspCategory a owl:DatatypeProperty ;
    rdfs:domain narsil:SecurityFinding ;
    rdfs:range xsd:string ;
    rdfs:label "OWASP category" ;
    rdfs:comment "OWASP Top 10 category" .

narsil:message a owl:DatatypeProperty ;
    rdfs:domain narsil:SecurityFinding ;
    rdfs:range xsd:string ;
    rdfs:label "message" ;
    rdfs:comment "Description of the security finding" .

narsil:ruleId a owl:DatatypeProperty ;
    rdfs:domain narsil:SecurityFinding ;
    rdfs:range xsd:string ;
    rdfs:label "rule ID" ;
    rdfs:comment "Identifier of the rule that triggered this finding" .

narsil:symbolKind a owl:DatatypeProperty ;
    rdfs:domain narsil:Symbol ;
    rdfs:range xsd:string ;
    rdfs:label "symbol kind" ;
    rdfs:comment "Kind of symbol (function, class, method, etc.)" .

narsil:isPublic a owl:DatatypeProperty ;
    rdfs:domain narsil:Symbol ;
    rdfs:range xsd:boolean ;
    rdfs:label "is public" ;
    rdfs:comment "Whether the symbol is publicly visible" .

narsil:isAsync a owl:DatatypeProperty ;
    rdfs:domain narsil:Function ;
    rdfs:range xsd:boolean ;
    rdfs:label "is async" ;
    rdfs:comment "Whether the function is asynchronous" .
"#;

/// Prefixes commonly used in SPARQL queries against the narsil graph.
pub const NARSIL_SPARQL_PREFIXES: &str = r#"
PREFIX narsil: <https://narsilmcp.com/ontology/v1#>
PREFIX code: <https://narsilmcp.com/code/>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ontology_is_valid_turtle() {
        // The ontology should be parseable as Turtle
        // This is a basic syntax check
        assert!(NARSIL_ONTOLOGY.contains("@prefix narsil:"));
        assert!(NARSIL_ONTOLOGY.contains("narsil:Function a owl:Class"));
        assert!(NARSIL_ONTOLOGY.contains("narsil:calls a owl:ObjectProperty"));
    }

    #[test]
    fn test_ontology_defines_core_classes() {
        assert!(NARSIL_ONTOLOGY.contains("narsil:Repository a owl:Class"));
        assert!(NARSIL_ONTOLOGY.contains("narsil:File a owl:Class"));
        assert!(NARSIL_ONTOLOGY.contains("narsil:Symbol a owl:Class"));
        assert!(NARSIL_ONTOLOGY.contains("narsil:Function a owl:Class"));
        assert!(NARSIL_ONTOLOGY.contains("narsil:Class a owl:Class"));
    }

    #[test]
    fn test_ontology_defines_security_classes() {
        assert!(NARSIL_ONTOLOGY.contains("narsil:SecurityFinding a owl:Class"));
        assert!(NARSIL_ONTOLOGY.contains("narsil:Vulnerability a owl:Class"));
        assert!(NARSIL_ONTOLOGY.contains("narsil:TaintSource a owl:Class"));
        assert!(NARSIL_ONTOLOGY.contains("narsil:TaintSink a owl:Class"));
    }

    #[test]
    fn test_ontology_defines_properties() {
        assert!(NARSIL_ONTOLOGY.contains("narsil:calls a owl:ObjectProperty"));
        assert!(NARSIL_ONTOLOGY.contains("narsil:imports a owl:ObjectProperty"));
        assert!(NARSIL_ONTOLOGY.contains("narsil:complexity a owl:DatatypeProperty"));
        assert!(NARSIL_ONTOLOGY.contains("narsil:severity a owl:DatatypeProperty"));
    }

    #[test]
    fn test_sparql_prefixes_contains_narsil() {
        assert!(NARSIL_SPARQL_PREFIXES.contains("PREFIX narsil:"));
        assert!(NARSIL_SPARQL_PREFIXES.contains("PREFIX code:"));
    }
}
