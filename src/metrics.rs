//! Performance metrics tracking for tool operations
//!
//! Phase 2 feature - tracks timing for all operations.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Statistics for a single metric
#[derive(Debug, Clone)]
pub struct MetricStats {
    pub count: u64,
    pub total_ms: u64,
    pub min_ms: u64,
    pub max_ms: u64,
    samples: Vec<u64>, // Store all samples for percentile calculation
}

impl Default for MetricStats {
    fn default() -> Self {
        Self {
            count: 0,
            total_ms: 0,
            min_ms: u64::MAX,
            max_ms: 0,
            samples: Vec::new(),
        }
    }
}

impl MetricStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, duration_ms: u64) {
        self.count += 1;
        self.total_ms += duration_ms;
        self.min_ms = self.min_ms.min(duration_ms);
        self.max_ms = self.max_ms.max(duration_ms);
        self.samples.push(duration_ms);
    }

    pub fn avg_ms(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.total_ms as f64 / self.count as f64
        }
    }

    pub fn percentile(&self, p: f64) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }

        let mut sorted = self.samples.clone();
        sorted.sort_unstable();

        let index = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
        let index = index.saturating_sub(1).min(sorted.len() - 1);
        sorted[index]
    }

    pub fn p50(&self) -> u64 {
        self.percentile(50.0)
    }

    pub fn p95(&self) -> u64 {
        self.percentile(95.0)
    }

    pub fn p99(&self) -> u64 {
        self.percentile(99.0)
    }
}

/// Repository indexing metrics
#[derive(Debug, Clone)]
pub struct RepoIndexMetrics {
    pub repo_name: String,
    pub index_time_ms: u64,
    pub file_count: usize,
    pub symbol_count: usize,
    pub indexed_at: Instant,
}

/// Global metrics collection
pub struct Metrics {
    start_time: Instant,
    tool_metrics: Arc<RwLock<HashMap<String, MetricStats>>>,
    repo_index_metrics: Arc<RwLock<Vec<RepoIndexMetrics>>>,
    file_parse_metrics: Arc<RwLock<MetricStats>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            tool_metrics: Arc::new(RwLock::new(HashMap::new())),
            repo_index_metrics: Arc::new(RwLock::new(Vec::new())),
            file_parse_metrics: Arc::new(RwLock::new(MetricStats::new())),
        }
    }

    /// Record a tool execution time
    pub fn record_tool(&self, tool_name: &str, duration: Duration) {
        let duration_ms = duration.as_millis() as u64;
        let mut metrics = self.tool_metrics.write();
        let stats = metrics.entry(tool_name.to_string()).or_default();
        stats.record(duration_ms);
    }

    /// Record repository indexing time
    pub fn record_repo_index(
        &self,
        repo_name: String,
        duration: Duration,
        file_count: usize,
        symbol_count: usize,
    ) {
        let metric = RepoIndexMetrics {
            repo_name,
            index_time_ms: duration.as_millis() as u64,
            file_count,
            symbol_count,
            indexed_at: Instant::now(),
        };
        self.repo_index_metrics.write().push(metric);
    }

    /// Record a single file parsing time
    pub fn record_file_parse(&self, duration: Duration) {
        let duration_ms = duration.as_micros() as u64; // Use microseconds for file parsing
        self.file_parse_metrics.write().record(duration_ms);
    }

    /// Get statistics for a specific tool
    pub fn get_tool_stats(&self, tool_name: &str) -> Option<MetricStats> {
        self.tool_metrics.read().get(tool_name).cloned()
    }

    /// Get all tool statistics
    pub fn get_all_tool_stats(&self) -> HashMap<String, MetricStats> {
        self.tool_metrics.read().clone()
    }

    /// Get repository index metrics
    pub fn get_repo_index_metrics(&self) -> Vec<RepoIndexMetrics> {
        self.repo_index_metrics.read().clone()
    }

    /// Get file parsing statistics
    pub fn get_file_parse_stats(&self) -> MetricStats {
        self.file_parse_metrics.read().clone()
    }

    /// Get total requests served across all tools
    pub fn total_requests(&self) -> u64 {
        self.tool_metrics.read().values().map(|s| s.count).sum()
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Format uptime as human-readable string
    pub fn uptime_string(&self) -> String {
        let seconds = self.uptime_seconds();
        let days = seconds / 86400;
        let hours = (seconds % 86400) / 3600;
        let minutes = (seconds % 3600) / 60;
        let secs = seconds % 60;

        if days > 0 {
            format!("{}d {}h {}m {}s", days, hours, minutes, secs)
        } else if hours > 0 {
            format!("{}h {}m {}s", hours, minutes, secs)
        } else if minutes > 0 {
            format!("{}m {}s", minutes, secs)
        } else {
            format!("{}s", secs)
        }
    }

    /// Generate a formatted metrics report
    pub fn report(&self) -> String {
        let mut output = String::new();

        output.push_str("# Performance Metrics\n\n");
        output.push_str(&format!("**Uptime**: {}\n", self.uptime_string()));
        output.push_str(&format!(
            "**Total Requests**: {}\n\n",
            self.total_requests()
        ));

        // Repository indexing metrics
        output.push_str("## Repository Indexing\n\n");
        let repo_metrics = self.get_repo_index_metrics();
        if !repo_metrics.is_empty() {
            output.push_str("| Repository | Index Time | Files | Symbols | Files/sec |\n");
            output.push_str("|------------|------------|-------|---------|----------|\n");

            for metric in &repo_metrics {
                let files_per_sec = if metric.index_time_ms > 0 {
                    (metric.file_count as f64 / (metric.index_time_ms as f64 / 1000.0)).round()
                        as u64
                } else {
                    0
                };
                output.push_str(&format!(
                    "| {} | {}ms | {} | {} | {} |\n",
                    metric.repo_name,
                    metric.index_time_ms,
                    metric.file_count,
                    metric.symbol_count,
                    files_per_sec
                ));
            }
            output.push('\n');
        } else {
            output.push_str("*No repositories indexed yet.*\n\n");
        }

        // File parsing metrics
        let parse_stats = self.get_file_parse_stats();
        if parse_stats.count > 0 {
            output.push_str("## File Parsing\n\n");
            output.push_str("| Metric | Value |\n");
            output.push_str("|--------|-------|\n");
            output.push_str(&format!("| Files Parsed | {} |\n", parse_stats.count));
            output.push_str(&format!(
                "| Avg Parse Time | {:.2}Âµs |\n",
                parse_stats.avg_ms()
            ));
            output.push_str(&format!("| Min Parse Time | {}Âµs |\n", parse_stats.min_ms));
            output.push_str(&format!("| Max Parse Time | {}Âµs |\n", parse_stats.max_ms));
            output.push_str(&format!("| P50 Parse Time | {}Âµs |\n", parse_stats.p50()));
            output.push_str(&format!("| P95 Parse Time | {}Âµs |\n", parse_stats.p95()));
            output.push_str(&format!("| P99 Parse Time | {}Âµs |\n", parse_stats.p99()));
            output.push('\n');
        }

        // Tool execution metrics
        output.push_str("## Tool Execution Times\n\n");
        let tool_stats = self.get_all_tool_stats();

        if !tool_stats.is_empty() {
            output.push_str("| Tool | Calls | Avg (ms) | P50 (ms) | P95 (ms) | P99 (ms) | Min (ms) | Max (ms) |\n");
            output.push_str("|------|-------|----------|----------|----------|----------|----------|----------|\n");

            let mut tools: Vec<_> = tool_stats.iter().collect();
            tools.sort_by_key(|(name, _)| *name);

            for (tool_name, stats) in tools {
                output.push_str(&format!(
                    "| {} | {} | {:.2} | {} | {} | {} | {} | {} |\n",
                    tool_name,
                    stats.count,
                    stats.avg_ms(),
                    stats.p50(),
                    stats.p95(),
                    stats.p99(),
                    stats.min_ms,
                    stats.max_ms
                ));
            }
        } else {
            output.push_str("*No tool calls recorded yet.*\n");
        }

        output
    }

    /// Generate a JSON report of all metrics
    pub fn report_json(&self) -> serde_json::Value {
        use serde_json::json;

        let tool_stats = self.get_all_tool_stats();
        let tool_metrics: serde_json::Value = tool_stats
            .iter()
            .map(|(name, stats)| {
                (
                    name.clone(),
                    json!({
                        "count": stats.count,
                        "avg_ms": stats.avg_ms(),
                        "p50_ms": stats.p50(),
                        "p95_ms": stats.p95(),
                        "p99_ms": stats.p99(),
                        "min_ms": stats.min_ms,
                        "max_ms": stats.max_ms,
                        "total_ms": stats.total_ms
                    }),
                )
            })
            .collect();

        let repo_metrics = self.get_repo_index_metrics();
        let repo_json: Vec<serde_json::Value> = repo_metrics
            .iter()
            .map(|metric| {
                json!({
                    "repo_name": metric.repo_name,
                    "index_time_ms": metric.index_time_ms,
                    "file_count": metric.file_count,
                    "symbol_count": metric.symbol_count
                })
            })
            .collect();

        let parse_stats = self.get_file_parse_stats();

        json!({
            "uptime_seconds": self.uptime_seconds(),
            "uptime_string": self.uptime_string(),
            "total_requests": self.total_requests(),
            "repository_indexing": repo_json,
            "file_parsing": {
                "count": parse_stats.count,
                "avg_us": parse_stats.avg_ms(),
                "p50_us": parse_stats.p50(),
                "p95_us": parse_stats.p95(),
                "p99_us": parse_stats.p99(),
                "min_us": parse_stats.min_ms,
                "max_us": parse_stats.max_ms,
            },
            "tools": tool_metrics
        })
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_metric_stats_basic() {
        let mut stats = MetricStats::new();
        assert_eq!(stats.count, 0);
        assert_eq!(stats.avg_ms(), 0.0);

        stats.record(100);
        assert_eq!(stats.count, 1);
        assert_eq!(stats.avg_ms(), 100.0);
        assert_eq!(stats.min_ms, 100);
        assert_eq!(stats.max_ms, 100);
    }

    #[test]
    fn test_metric_stats_percentiles() {
        let mut stats = MetricStats::new();
        // Add values 1-100
        for i in 1..=100 {
            stats.record(i);
        }

        assert_eq!(stats.count, 100);
        assert_eq!(stats.avg_ms(), 50.5);
        assert_eq!(stats.p50(), 50);
        assert_eq!(stats.p95(), 95);
        assert_eq!(stats.p99(), 99);
    }

    #[test]
    fn test_metrics_tool_recording() {
        let metrics = Metrics::new();

        metrics.record_tool("list_repos", Duration::from_millis(50));
        metrics.record_tool("list_repos", Duration::from_millis(100));
        metrics.record_tool("find_symbols", Duration::from_millis(200));

        let stats = metrics.get_tool_stats("list_repos").unwrap();
        assert_eq!(stats.count, 2);
        assert_eq!(stats.avg_ms(), 75.0);
        assert_eq!(stats.min_ms, 50);
        assert_eq!(stats.max_ms, 100);

        let stats = metrics.get_tool_stats("find_symbols").unwrap();
        assert_eq!(stats.count, 1);
        assert_eq!(stats.avg_ms(), 200.0);

        assert_eq!(metrics.total_requests(), 3);
    }

    #[test]
    fn test_metrics_repo_indexing() {
        let metrics = Metrics::new();

        metrics.record_repo_index(
            "test-repo".to_string(),
            Duration::from_millis(5000),
            100,
            500,
        );

        let repo_metrics = metrics.get_repo_index_metrics();
        assert_eq!(repo_metrics.len(), 1);
        assert_eq!(repo_metrics[0].repo_name, "test-repo");
        assert_eq!(repo_metrics[0].index_time_ms, 5000);
        assert_eq!(repo_metrics[0].file_count, 100);
        assert_eq!(repo_metrics[0].symbol_count, 500);
    }

    #[test]
    fn test_metrics_file_parsing() {
        let metrics = Metrics::new();

        metrics.record_file_parse(Duration::from_micros(100));
        metrics.record_file_parse(Duration::from_micros(200));
        metrics.record_file_parse(Duration::from_micros(150));

        let parse_stats = metrics.get_file_parse_stats();
        assert_eq!(parse_stats.count, 3);
        assert_eq!(parse_stats.avg_ms(), 150.0);
        assert_eq!(parse_stats.min_ms, 100);
        assert_eq!(parse_stats.max_ms, 200);
    }

    #[test]
    fn test_uptime() {
        let metrics = Metrics::new();
        thread::sleep(Duration::from_millis(100));
        // Uptime should be at least 0 (it's u64 so always >= 0)
        let uptime = metrics.uptime_seconds();
        assert!(uptime < 10, "Uptime should be reasonable for a test");
        let uptime_str = metrics.uptime_string();
        assert!(uptime_str.contains('s'));
    }

    #[test]
    fn test_metrics_report() {
        let metrics = Metrics::new();

        metrics.record_tool("test_tool", Duration::from_millis(100));
        metrics.record_repo_index("test-repo".to_string(), Duration::from_secs(1), 50, 250);

        let report = metrics.report();
        assert!(report.contains("Performance Metrics"));
        assert!(report.contains("test_tool"));
        assert!(report.contains("test-repo"));
    }

    #[test]
    fn test_metrics_json_report() {
        let metrics = Metrics::new();

        metrics.record_tool("test_tool", Duration::from_millis(100));
        metrics.record_file_parse(Duration::from_micros(500));

        let json = metrics.report_json();
        assert!(json["total_requests"].as_u64().unwrap() > 0);
        assert!(json["tools"]["test_tool"]["count"].as_u64().unwrap() > 0);
        assert!(json["file_parsing"]["count"].as_u64().unwrap() > 0);
    }

    #[test]
    fn test_empty_percentiles() {
        let stats = MetricStats::new();
        assert_eq!(stats.p50(), 0);
        assert_eq!(stats.p95(), 0);
        assert_eq!(stats.p99(), 0);
    }

    #[test]
    fn test_single_value_percentiles() {
        let mut stats = MetricStats::new();
        stats.record(42);
        assert_eq!(stats.p50(), 42);
        assert_eq!(stats.p95(), 42);
        assert_eq!(stats.p99(), 42);
    }

    #[test]
    fn test_uptime_formatting() {
        let metrics = Metrics::new();
        // Simulate different uptimes by directly checking the format logic
        let uptime = metrics.uptime_string();
        // Should be in format like "0s" or similar for a new instance
        assert!(!uptime.is_empty());
    }
}
