/// Configuration schema structures
///
/// These structures define the YAML configuration format for narsil-xref.
/// They are designed to be serialized/deserialized with serde.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Default version for configuration
fn default_version() -> String {
    "1.0".to_string()
}

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConfig {
    /// Configuration version (currently "1.0")
    #[serde(default = "default_version")]
    pub version: String,

    /// Tool groups to expose, e.g. `[code, git]`. The machine-wide default,
    /// applied to any invocation that does not pass `--expose` (or set
    /// `NARSIL_EXPOSE`, or select a profile that lists its own groups) —
    /// useful when the command line comes from an editor plugin you would
    /// rather not edit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expose: Vec<String>,

    /// Days an adopted repository may go unqueried before the idle sweep drops
    /// it. A repository is adopted when a stdio process asks a running server
    /// to index a project that server was not started with; the ones it *was*
    /// started with are never swept. The machine-wide default, overridden by a
    /// profile's own value and by `--adopted-repo-ttl-days`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adopted_repo_ttl_days: Option<u64>,

    /// SSE server memory limits: `off`, `<N>x` (times the RSS after the last
    /// full index pass), `<N>M` or `<N>G`. Overridden by `--memory-soft-limit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_soft_limit: Option<String>,

    /// As `memory_soft_limit`; above it the server exits. Overridden by `--memory-hard-limit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_hard_limit: Option<String>,

    /// Seconds between memory summaries while RSS stays above the soft limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_soft_limit_interval_secs: Option<u64>,

    /// Base URL of an SSE server, e.g. `http://127.0.0.1:7557`, that a stdio
    /// process pings when servers.json lists no server; a socket-activated
    /// server has no entry before its first start. Overridden by `--sse-url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sse_url: Option<String>,

    /// Named repository profiles for reusable workspace path sets.
    #[serde(default)]
    pub profiles: HashMap<String, RepoProfile>,

    /// Per-tool overrides
    #[serde(default)]
    pub tools: ToolsConfig,
}

impl Default for ToolConfig {
    fn default() -> Self {
        Self {
            version: default_version(),
            expose: Vec::new(),
            adopted_repo_ttl_days: None,
            memory_soft_limit: None,
            memory_hard_limit: None,
            memory_soft_limit_interval_secs: None,
            sse_url: None,
            profiles: HashMap::new(),
            tools: ToolsConfig::default(),
        }
    }
}

/// One repository in a profile: either a bare path (all defaults) or a path
/// with per-repo overrides. The untagged enum lets a YAML list mix both forms.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RepoEntry {
    /// `- ~/src/foo` — index the whole repo with the global defaults.
    Path(PathBuf),
    /// `- { path: ..., index_filter: [...], clangd: { jobs: 2 } }`.
    Detailed(RepoEntrySettings),
}

/// clangd tuning for a repo or profile group. Every field None = inherit the
/// group default, then the global/compiled default. The dials bound clangd's
/// parallelism, not its absolute RSS — clangd has no hard memory-cap flag.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClangdSettings {
    /// Run clangd for this repo. None/true = run; false = skip clangd.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// clangd `-j N`: async worker count, which also bounds background-index
    /// parallelism — the biggest RSS/CPU lever. None = clangd default (= ncpu).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jobs: Option<usize>,

    /// `--background-index`. None/true = on; false adds `--background-index=false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_index: Option<bool>,
}

/// ccls tuning for a repo or profile group. None on a field = inherit.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CclsSettings {
    /// Run ccls for this repo. None/true = run; false = skip ccls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// ccls `index.threads`: indexer thread count (the ccls analog of clangd -j).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threads: Option<usize>,

    /// ccls `cache.retainInMemory`: file caches kept resident. 0 = none (reload
    /// from disk, lowest memory, higher per-query latency). None = ccls default (2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_in_memory: Option<usize>,

    /// Background indexing. None/true = on; false sets index.initialBlacklist [".*"].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_index: Option<bool>,
}

/// gtags tuning for a repo or profile group. global(1)/gtags(1) are short-lived
/// subprocesses — no steady-state memory dial, only on/off and DB generation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GtagsSettings {
    /// Run gtags ref/def augmentation here. None = inherit --gtags/--no-gtags intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Auto-build GTAGS when absent (writes into the tree). None = inherit --gtags-generate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generate: Option<bool>,
}

/// Per-repo overrides for a profile entry. `index_filter`/`lsp_scope` accept
/// paths relative to the repo root (no need to repeat the absolute prefix);
/// absolute entries are also matched against the absolute path. The clangd/ccls/
/// gtags blocks tune each backend independently; an unset field inherits the
/// profile-group default (see `with_group_defaults`) then the global default.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoEntrySettings {
    /// Repository path.
    pub path: PathBuf,

    /// Restrict the base (tree-sitter) index to these paths for this repo.
    /// Overrides the global --index-filter when non-empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub index_filter: Vec<String>,

    /// Restrict the clangd/ccls augment pass to these paths for this repo.
    /// Overrides the global --lsp-scope when non-empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lsp_scope: Vec<String>,

    /// Minimum percent of this repo's C sources that compile_commands.json must
    /// cover to be trusted as the index filter. Below this the manifest is
    /// treated as stale/partial and ignored (all sources indexed), so a one-off
    /// `bear` capture of a single TU cannot silently gut the index. 0 disables
    /// the check (always honour the manifest). Unset = global default (25).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compile_commands_min_coverage_pct: Option<usize>,

    /// Per-repo clangd tuning. None = inherit the group/global default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clangd: Option<ClangdSettings>,

    /// Per-repo ccls tuning. None = inherit the group/global default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ccls: Option<CclsSettings>,

    /// Per-repo gtags tuning. None = inherit the group/global default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gtags: Option<GtagsSettings>,
}

/// A per-backend block whose unset (None) fields can inherit from a group
/// default. Implemented by the three backend settings structs so
/// `RepoEntrySettings::with_group_defaults` can fold them uniformly.
trait InheritFrom {
    /// Return a copy of `self` with each unset field filled from `group`;
    /// fields `self` already set win.
    fn inherit_from(&self, group: &Self) -> Self;
}

impl InheritFrom for ClangdSettings {
    fn inherit_from(&self, group: &ClangdSettings) -> ClangdSettings {
        ClangdSettings {
            enabled: self.enabled.or(group.enabled),
            jobs: self.jobs.or(group.jobs),
            background_index: self.background_index.or(group.background_index),
        }
    }
}

impl InheritFrom for CclsSettings {
    fn inherit_from(&self, group: &CclsSettings) -> CclsSettings {
        CclsSettings {
            enabled: self.enabled.or(group.enabled),
            threads: self.threads.or(group.threads),
            retain_in_memory: self.retain_in_memory.or(group.retain_in_memory),
            background_index: self.background_index.or(group.background_index),
        }
    }
}

impl InheritFrom for GtagsSettings {
    fn inherit_from(&self, group: &GtagsSettings) -> GtagsSettings {
        GtagsSettings {
            enabled: self.enabled.or(group.enabled),
            generate: self.generate.or(group.generate),
        }
    }
}

/// Combine a repo-entry block with a group default: a present entry block
/// inherits the group's unset fields; an absent entry block takes the group
/// block whole; absent on both stays None.
fn merge_block<T: InheritFrom + Clone>(repo: Option<T>, group: Option<&T>) -> Option<T> {
    match (repo, group) {
        (Some(repo), Some(group)) => Some(repo.inherit_from(group)),
        (Some(repo), None) => Some(repo),
        (None, Some(group)) => Some(group.clone()),
        (None, None) => None,
    }
}

impl RepoEntrySettings {
    /// Fold profile-group backend defaults into this entry's unset per-backend
    /// fields. The entry's own values win field by field; group values fill the
    /// gaps. `path`/`index_filter`/`lsp_scope` are per-repo only and untouched.
    pub fn with_group_defaults(
        mut self,
        clangd: Option<&ClangdSettings>,
        ccls: Option<&CclsSettings>,
        gtags: Option<&GtagsSettings>,
    ) -> RepoEntrySettings {
        self.clangd = merge_block(self.clangd, clangd);
        self.ccls = merge_block(self.ccls, ccls);
        self.gtags = merge_block(self.gtags, gtags);
        self
    }
}

impl RepoEntry {
    /// The repository path, regardless of entry form.
    pub fn path(&self) -> &Path {
        match self {
            RepoEntry::Path(path) => path,
            RepoEntry::Detailed(settings) => &settings.path,
        }
    }

    /// The per-repo overrides; a bare path yields all-default settings.
    pub fn settings(&self) -> RepoEntrySettings {
        match self {
            RepoEntry::Path(path) => RepoEntrySettings {
                path: path.clone(),
                ..Default::default()
            },
            RepoEntry::Detailed(settings) => settings.clone(),
        }
    }
}

/// Named workspace profile selected with `--profile NAME`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoProfile {
    /// Repository entries to index when this profile is selected. Each entry is
    /// a bare path or a path with per-repo overrides.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<RepoEntry>,

    /// Optional directory to auto-discover repositories from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discover: Option<PathBuf>,

    /// Tool groups to expose with this profile, e.g. `[code, git]`.
    /// Same values as `--expose`, which takes precedence when both are set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expose: Vec<String>,

    /// Days an adopted repository may go unqueried before the idle sweep drops
    /// it, for a server running this profile. Takes precedence over the
    /// machine-wide value; `--adopted-repo-ttl-days` takes precedence over both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adopted_repo_ttl_days: Option<u64>,

    /// Enable git integration for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<bool>,

    /// Enable call graph analysis for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_graph: Option<bool>,

    /// Enable persistent index storage for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persist: Option<bool>,

    /// Enable watch mode for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watch: Option<bool>,

    /// Enable LSP integration for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lsp: Option<bool>,

    /// Group-default clangd tuning. Each repo entry inherits the unset fields
    /// (see `RepoEntrySettings::with_group_defaults`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clangd: Option<ClangdSettings>,

    /// Group-default ccls tuning. Inherited by each repo entry's unset fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ccls: Option<CclsSettings>,

    /// Group-default gtags tuning. Inherited by each repo entry's unset fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gtags: Option<GtagsSettings>,

    /// TF-IDF embedding dimension (default: 512). Lower values reduce memory;
    /// higher values improve find_similar_code accuracy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_dim: Option<usize>,

    /// When true, use compile_commands.json to restrict which C/C++ source files
    /// are indexed. Headers are always indexed regardless.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_compile_commands: Option<bool>,

    /// Path to compile_commands.json, relative to the repo root.
    /// Defaults to "compile_commands.json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compile_commands_path: Option<PathBuf>,

    /// Glob patterns (relative to repo root) for files to always index,
    /// regardless of compile_commands filtering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
}

/// Tools configuration (per-tool overrides)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolsConfig {
    /// Individual tool overrides
    #[serde(default)]
    pub overrides: HashMap<String, ToolOverride>,
}

/// Individual tool override configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOverride {
    /// Whether this tool is enabled
    pub enabled: bool,

    /// Optional reason for the override
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Required feature flags for this tool
    #[serde(default)]
    pub required_flags: Vec<String>,

    /// Tool-specific configuration
    #[serde(default)]
    pub config: HashMap<String, serde_json::Value>,

    /// Performance impact indicator (low, medium, high)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub performance_impact: Option<String>,

    /// Whether this tool requires an API key
    #[serde(default)]
    pub requires_api_key: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_tool_config() {
        let config = ToolConfig::default();
        assert_eq!(config.version, "1.0");
        assert!(config.profiles.is_empty());
        assert!(config.tools.overrides.is_empty());
    }

    #[test]
    fn test_version_only_config() {
        // Issue #5: a config without a tools field must still parse
        let yaml = r#"
version: "1.0"
"#;
        let config: ToolConfig = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(config.version, "1.0");
        assert!(config.tools.overrides.is_empty());
    }

    #[test]
    fn test_repo_profile_config() {
        let yaml = r#"
version: "1.0"
profiles:
  work:
    repos:
      - ~/src/api
      - ~/src/web
    git: true
    call_graph: true
    expose: [code, git]
"#;
        let config: ToolConfig = serde_saphyr::from_str(yaml).unwrap();
        let profile = config.profiles.get("work").unwrap();
        assert_eq!(profile.repos.len(), 2);
        assert!(matches!(profile.repos[0], RepoEntry::Path(_)));
        assert_eq!(profile.git, Some(true));
        assert_eq!(profile.call_graph, Some(true));
        assert_eq!(profile.expose, vec!["code".to_string(), "git".to_string()]);
    }

    #[test]
    fn test_repo_entry_mixed_bare_and_detailed() {
        let yaml = r#"
profiles:
  work:
    repos:
      - ~/src/liburing
      - path: ~/src/linux
        clangd: { enabled: false, background_index: false }
        ccls: { enabled: false }
        index_filter: [fs, mm, io_uring]
        lsp_scope: [fs/fuse]
"#;
        let config: ToolConfig = serde_saphyr::from_str(yaml).unwrap();
        let profile = config.profiles.get("work").unwrap();
        assert_eq!(profile.repos.len(), 2);

        // Bare path -> all defaults.
        let bare = profile.repos[0].settings();
        assert!(bare.clangd.is_none());
        assert!(bare.ccls.is_none());
        assert!(bare.index_filter.is_empty());

        // Detailed entry -> overrides carried through.
        let detailed = profile.repos[1].settings();
        assert_eq!(detailed.path, PathBuf::from("~/src/linux"));
        let clangd = detailed.clangd.unwrap();
        assert_eq!(clangd.enabled, Some(false));
        assert_eq!(clangd.background_index, Some(false));
        assert_eq!(detailed.ccls.unwrap().enabled, Some(false));
        assert_eq!(detailed.index_filter, vec!["fs", "mm", "io_uring"]);
        assert_eq!(detailed.lsp_scope, vec!["fs/fuse"]);
    }

    #[test]
    fn test_with_group_defaults_merge() {
        let yaml = r#"
profiles:
  work:
    clangd: { jobs: 4, background_index: true }
    ccls: { enabled: false }
    repos:
      - ~/src/libA
      - path: ~/src/linux
        clangd: { jobs: 2, background_index: false }
        gtags: { enabled: true }
"#;
        let config: ToolConfig = serde_saphyr::from_str(yaml).unwrap();
        let profile = config.profiles.get("work").unwrap();

        // Bare entry inherits the whole group block.
        let bare = profile.repos[0].settings().with_group_defaults(
            profile.clangd.as_ref(),
            profile.ccls.as_ref(),
            profile.gtags.as_ref(),
        );
        let clangd = bare.clangd.unwrap();
        assert_eq!(clangd.jobs, Some(4));
        assert_eq!(clangd.background_index, Some(true));
        assert_eq!(bare.ccls.unwrap().enabled, Some(false));
        assert!(bare.gtags.is_none());

        // Detailed entry wins field by field; group fills the gaps.
        let linux = profile.repos[1].settings().with_group_defaults(
            profile.clangd.as_ref(),
            profile.ccls.as_ref(),
            profile.gtags.as_ref(),
        );
        let clangd = linux.clangd.unwrap();
        assert_eq!(clangd.jobs, Some(2)); // repo overrides group's 4
        assert_eq!(clangd.background_index, Some(false)); // repo overrides group's true
        assert_eq!(linux.ccls.unwrap().enabled, Some(false)); // inherited from group
        assert_eq!(linux.gtags.unwrap().enabled, Some(true)); // repo-only block kept
    }

    #[test]
    fn test_stale_keys_rejected() {
        // The pre-split lsp:/background_index: keys no longer exist on a repo
        // entry; deny_unknown_fields turns them into a hard parse error instead
        // of a silent no-op, prompting migration to the new clangd/ccls blocks.
        let yaml = r#"
profiles:
  work:
    repos:
      - path: ~/src/linux
        background_index: false
"#;
        let parsed: Result<ToolConfig, _> = serde_saphyr::from_str(yaml);
        assert!(
            parsed.is_err(),
            "stale background_index: key must be rejected"
        );
    }

    #[test]
    fn test_expose_only_config() {
        let yaml = r#"expose: [code]"#;
        let config: ToolConfig = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(config.expose, vec!["code".to_string()]);
        assert_eq!(config.version, "1.0"); // Should use default
    }
}
