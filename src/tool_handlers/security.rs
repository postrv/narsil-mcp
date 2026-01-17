//! Security scanning tool handlers

use anyhow::Result;
use serde_json::Value;

use super::{ArgExtractor, ToolHandler};
use crate::index::{CodeIntelEngine, SecurityScanOptions};

/// Handler for scan_security tool
///
/// Phase C2: Added max_findings and offset parameters for pagination
pub struct ScanSecurityHandler;

#[async_trait::async_trait]
impl ToolHandler for ScanSecurityHandler {
    fn name(&self) -> &'static str {
        "scan_security"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let opts = SecurityScanOptions {
            path: args.get_str("path"),
            severity_threshold: args.get_str("severity_threshold"),
            ruleset: args.get_str("ruleset"),
            exclude_tests: args.get_bool("exclude_tests"),
            max_findings: args.get_u64("max_findings").map(|v| v as usize),
            offset: args.get_u64("offset").map(|v| v as usize),
        };
        engine.scan_security(repo, opts).await
    }
}

/// Handler for check_owasp_top10 tool
pub struct CheckOwaspTop10Handler;

#[async_trait::async_trait]
impl ToolHandler for CheckOwaspTop10Handler {
    fn name(&self) -> &'static str {
        "check_owasp_top10"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path");
        let exclude_tests = args.get_bool("exclude_tests");
        engine.check_owasp_top10(repo, path, exclude_tests).await
    }
}

/// Handler for check_cwe_top25 tool
pub struct CheckCweTop25Handler;

#[async_trait::async_trait]
impl ToolHandler for CheckCweTop25Handler {
    fn name(&self) -> &'static str {
        "check_cwe_top25"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path");
        let exclude_tests = args.get_bool("exclude_tests");
        engine.check_cwe_top25(repo, path, exclude_tests).await
    }
}

/// Handler for find_injection_vulnerabilities tool
pub struct FindInjectionVulnerabilitiesHandler;

#[async_trait::async_trait]
impl ToolHandler for FindInjectionVulnerabilitiesHandler {
    fn name(&self) -> &'static str {
        "find_injection_vulnerabilities"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path");
        let exclude_tests = args.get_bool("exclude_tests");
        let vulnerability_types: Vec<String> = args
            .get_array("vulnerability_types")
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_else(|| vec!["all".to_string()]);
        engine
            .find_injection_vulnerabilities(repo, path, exclude_tests, &vulnerability_types)
            .await
    }
}

/// Handler for trace_taint tool
pub struct TraceTaintHandler;

#[async_trait::async_trait]
impl ToolHandler for TraceTaintHandler {
    fn name(&self) -> &'static str {
        "trace_taint"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path").unwrap_or("");
        let line = args.get_u64_or("line", 1) as usize;
        engine.trace_taint(repo, path, line).await
    }
}

/// Handler for get_taint_sources tool
pub struct GetTaintSourcesHandler;

#[async_trait::async_trait]
impl ToolHandler for GetTaintSourcesHandler {
    fn name(&self) -> &'static str {
        "get_taint_sources"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path");
        let exclude_tests = args.get_bool("exclude_tests");
        let source_types: Vec<String> = args
            .get_array("source_types")
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_else(|| vec!["all".to_string()]);
        engine
            .get_taint_sources(repo, path, exclude_tests, &source_types)
            .await
    }
}

/// Handler for get_security_summary tool
pub struct GetSecuritySummaryHandler;

#[async_trait::async_trait]
impl ToolHandler for GetSecuritySummaryHandler {
    fn name(&self) -> &'static str {
        "get_security_summary"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let exclude_tests = args.get_bool("exclude_tests");
        engine.get_security_summary(repo, exclude_tests).await
    }
}

/// Handler for explain_vulnerability tool
pub struct ExplainVulnerabilityHandler;

#[async_trait::async_trait]
impl ToolHandler for ExplainVulnerabilityHandler {
    fn name(&self) -> &'static str {
        "explain_vulnerability"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let rule_id = args.get_str("rule_id");
        let cwe = args.get_str("cwe");
        engine.explain_vulnerability(rule_id, cwe).await
    }
}

/// Handler for suggest_fix tool
pub struct SuggestFixHandler;

#[async_trait::async_trait]
impl ToolHandler for SuggestFixHandler {
    fn name(&self) -> &'static str {
        "suggest_fix"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path").unwrap_or("");
        let line = args.get_u64_or("line", 1) as usize;
        let rule_id = args.get_str("rule_id");
        engine.suggest_fix(repo, path, line, rule_id).await
    }
}
