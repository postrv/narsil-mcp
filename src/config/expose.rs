/// Tool groups selected with `--expose` / `expose:` in config.yaml.
use std::collections::HashSet;

/// One switchable band of tools. Several groups may be active at once — so
/// the union a caller picked never needs a name of its own.
///
/// A group earns a name when it answers a *different question*, not when it
/// answers the same question at a different scale: repo-wide call graphs sit in
/// [`ExposeGroup::Code`] beside the per-symbol lookups, while complexity and
/// hotspots are [`ExposeGroup::Analysis`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExposeGroup {
    /// Addressing a repo and recovering from a stale index. Always folded into
    /// the union: without these a client cannot name a repository or repair an
    /// empty answer, whatever else it selected.
    Base,
    /// What the code is, at every scale: symbols, references, search, file
    /// text, LSP lookups; call and import edges both per-symbol and as whole
    /// graphs; complexity, hotspots, cycles; per-function CFG and def-use.
    Code,
    /// Why the code is the way it is: blame, history, commit diffs, branch
    /// state, contributors.
    Git,
    /// Derived analysis of code the caller is already reading: complexity
    /// metrics, hotspots, import graphs, cycles, per-function control and data
    /// flow. Off by default — a model holding the source can work these out,
    /// so the schemas cost context to restate what is already in front of it.
    Analysis,
}

impl ExposeGroup {
    /// Every group, in the order they are printed in `--help` and the docs.
    pub const ALL: [ExposeGroup; 4] = [
        ExposeGroup::Base,
        ExposeGroup::Code,
        ExposeGroup::Git,
        ExposeGroup::Analysis,
    ];

    /// The CLI spelling of this group.
    pub fn name(&self) -> &'static str {
        match self {
            ExposeGroup::Base => "base",
            ExposeGroup::Code => "code",
            ExposeGroup::Git => "git",
            ExposeGroup::Analysis => "analysis",
        }
    }

    /// Parse a group from a string; hyphen and underscore both work.
    pub fn parse(s: &str) -> Option<Self> {
        let normalized = s.to_lowercase().replace('_', "-");
        ExposeGroup::ALL
            .iter()
            .copied()
            .find(|g| g.name() == normalized)
    }

    /// Tool names belonging to this group.
    pub fn tools(&self) -> HashSet<&'static str> {
        match self {
            ExposeGroup::Base => Self::base_tools(),
            ExposeGroup::Code => Self::code_tools(),
            ExposeGroup::Git => Self::git_tools(),
            ExposeGroup::Analysis => Self::analysis_tools(),
        }
    }

    /// Which group owns a tool.
    /// Not a hot path — the renderer walks groups, not tools.
    pub fn of(tool: &str) -> Option<Self> {
        ExposeGroup::ALL
            .iter()
            .copied()
            .find(|g| g.tools().contains(tool))
    }

    /// Union of the selected groups, with `Base` always folded in. An empty
    /// selection yields an empty set, which the filter reads as "no group
    /// filter — every registered tool".
    pub fn union(groups: &[ExposeGroup]) -> HashSet<&'static str> {
        if groups.is_empty() {
            return HashSet::new();
        }

        let mut tools = Self::base_tools();
        for group in groups {
            tools.extend(group.tools());
        }
        tools
    }

    fn base_tools() -> HashSet<&'static str> {
        [
            "list_repos",
            "get_index_status",
            // The documented recovery when a query comes back empty.
            "reindex",
            "forget_repo",
            "discover_repos",
            "validate_repo",
            "get_metrics",
            "get_incremental_status",
        ]
        .iter()
        .copied()
        .collect()
    }

    fn code_tools() -> HashSet<&'static str> {
        [
            "get_project_structure",
            "get_file",
            "get_excerpt",
            "find_symbols",
            "get_symbol_definition",
            "find_symbol_usages",
            "find_references",
            "get_dependencies",
            "get_export_map",
            "search_code",
            "semantic_search",
            "hybrid_search",
            "get_callers",
            "get_callees",
            "find_call_path",
            // Gated behind FeatureFlag::Lsp already, so these disappear on
            // their own when no language server is configured.
            "go_to_definition",
            "get_hover_info",
            "get_type_info",
            // Callers, callees and metrics in one round trip rather than two.
            "get_call_graph",
            // "where did this value come from" across a function too long to
            // hold in view — retrieval, not restatement.
            "get_reaching_definitions",
        ]
        .iter()
        .copied()
        .collect()
    }

    /// Derived analysis, as opposed to retrieval. The distinction that puts a
    /// tool here: its answer is something a caller holding the source can work
    /// out unaided, so paying schema bytes on every request to offer it is a
    /// bad trade. Useful to a human reading `narsil-mcp tools list` or driving
    /// the HTTP frontend, which is why these stay registered.
    fn analysis_tools() -> HashSet<&'static str> {
        [
            "get_complexity",
            "get_function_hotspots",
            "get_control_flow",
            "get_data_flow",
            "get_code_graph",
        ]
        .iter()
        .copied()
        .collect()
    }

    fn git_tools() -> HashSet<&'static str> {
        [
            "get_blame",
            "get_file_history",
            "get_symbol_history",
            "get_recent_changes",
            "get_commit_range",
            "get_commit_diff",
            "get_branch_info",
            "get_modified_files",
            "get_contributors",
            "get_hotspots",
        ]
        .iter()
        .copied()
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tool added to the registry must be assigned a group; otherwise it is
    /// unreachable under any `--expose` and nothing says so.
    #[test]
    fn test_expose_groups_partition_registry() {
        use crate::tool_metadata::TOOL_METADATA;

        for tool_name in TOOL_METADATA.keys() {
            let owners: Vec<&'static str> = ExposeGroup::ALL
                .iter()
                .filter(|g| g.tools().contains(tool_name))
                .map(|g| g.name())
                .collect();

            assert_eq!(
                owners.len(),
                1,
                "{}: must belong to exactly one ExposeGroup, has {:?}",
                tool_name,
                owners
            );
        }
    }

    #[test]
    fn test_expose_parse() {
        assert_eq!(ExposeGroup::parse("code"), Some(ExposeGroup::Code));
        assert_eq!(ExposeGroup::parse("CODE"), Some(ExposeGroup::Code));
        assert_eq!(ExposeGroup::parse("analysis"), Some(ExposeGroup::Analysis));
        assert_eq!(ExposeGroup::parse("structure"), None);
    }

    #[test]
    fn test_expose_union_always_folds_in_base() {
        let tools = ExposeGroup::union(&[ExposeGroup::Git]);
        assert!(tools.contains("get_blame"));
        assert!(tools.contains("list_repos"), "base must always be present");
        assert!(!tools.contains("find_symbols"));
    }

    /// Empty means "no group filter", not "expose nothing" — the filter falls
    /// back to the preset.
    #[test]
    fn test_expose_union_empty_is_empty() {
        assert!(ExposeGroup::union(&[]).is_empty());
    }

    #[test]
    fn test_expose_of_names_the_owning_group() {
        assert_eq!(ExposeGroup::of("get_callers"), Some(ExposeGroup::Code));
        assert_eq!(ExposeGroup::of("get_blame"), Some(ExposeGroup::Git));
        assert_eq!(
            ExposeGroup::of("get_complexity"),
            Some(ExposeGroup::Analysis)
        );
    }

    /// The two kept in `code` earn it by answering something the caller cannot
    /// derive from source it is already holding; the rest moved to `analysis`.
    #[test]
    fn test_code_keeps_the_retrieval_shaped_graph_tools() {
        let code = ExposeGroup::Code.tools();
        assert!(code.contains("get_call_graph"), "saves a round trip");
        assert!(code.contains("get_reaching_definitions"), "retrieval");

        let analysis = ExposeGroup::Analysis.tools();
        for restated in [
            "get_complexity",
            "get_control_flow",
            "get_data_flow",
            "get_function_hotspots",
        ] {
            assert!(
                analysis.contains(restated),
                "{restated} belongs to analysis"
            );
            assert!(!code.contains(restated), "{restated} must leave code");
        }
    }
}
