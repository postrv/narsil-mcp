//! CCG Access Tiers (Triple-Heart Model) implementation.
//!
//! This module implements WebACL-based access control for Code Context Graphs,
//! enabling tiered access based on the Triple-Heart Model:
//!
//! - **Public Tier (🔴 Red Heart):** Access by anyone (`foaf:Agent`)
//! - **Authenticated Tier (🟡 Yellow Heart):** Access by authenticated agents (`acl:AuthenticatedAgent`)
//! - **Private Tier (🔵 Blue Heart):** Access by specific agents via WebACL
//!
//! # Example
//!
//! ```ignore
//! use narsil_mcp::ccg::access::{AccessTier, AccessControl, AgentId};
//!
//! // Create public access control
//! let public_acl = AccessControl::new(AccessTier::Public);
//! let ttl = public_acl.to_turtle();
//!
//! // Create private access with specific agents
//! let private_acl = AccessControl::new(AccessTier::Private)
//!     .with_agent(AgentId::new("https://security-scanner.ai/#agent"));
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// WebACL namespace URI.
pub const ACL_NS: &str = "http://www.w3.org/ns/auth/acl#";

/// FOAF namespace URI.
pub const FOAF_NS: &str = "http://xmlns.com/foaf/0.1/";

/// CCG ACL namespace URI.
pub const CCG_ACL_NS: &str = "https://codecontextgraph.com/acl/v1#";

/// Access tier for CCG resources (Triple-Heart Model).
///
/// Each tier represents a different level of access control:
/// - `Public`: Anyone can access (🔴 Red Heart)
/// - `Authenticated`: Any authenticated agent with WebID (🟡 Yellow Heart)
/// - `Private`: Only specific agents (🔵 Blue Heart)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessTier {
    /// Public tier: accessible by any agent (foaf:Agent)
    ///
    /// Use case: Discovery, basic structure, language info
    #[default]
    Public,

    /// Authenticated tier: accessible by any authenticated agent (acl:AuthenticatedAgent)
    ///
    /// Use case: Capability indexes, symbol counts, metrics
    Authenticated,

    /// Private tier: accessible by specific agents only
    ///
    /// Use case: Security findings, full analysis data
    Private,
}

impl AccessTier {
    /// Returns the emoji representation of this tier (for display).
    #[must_use]
    pub const fn emoji(&self) -> &'static str {
        match self {
            Self::Public => "🔴",
            Self::Authenticated => "🟡",
            Self::Private => "🔵",
        }
    }

    /// Returns the tier name (for display).
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Public => "Public",
            Self::Authenticated => "Authenticated",
            Self::Private => "Private",
        }
    }

    /// Returns the heart color name for this tier.
    #[must_use]
    pub const fn heart_color(&self) -> &'static str {
        match self {
            Self::Public => "Red",
            Self::Authenticated => "Yellow",
            Self::Private => "Blue",
        }
    }

    /// Returns the WebACL agent class for this tier.
    ///
    /// - Public: `foaf:Agent`
    /// - Authenticated: `acl:AuthenticatedAgent`
    /// - Private: Returns None (requires specific agents)
    #[must_use]
    pub fn agent_class(&self) -> Option<&'static str> {
        match self {
            Self::Public => Some("http://xmlns.com/foaf/0.1/Agent"),
            Self::Authenticated => Some("http://www.w3.org/ns/auth/acl#AuthenticatedAgent"),
            Self::Private => None,
        }
    }

    /// Returns the default CCG layers accessible at this tier.
    ///
    /// - Public: L0 (Manifest) only
    /// - Authenticated: L0, L1 (Architecture)
    /// - Private: All layers (L0-L3)
    #[must_use]
    pub fn accessible_layers(&self) -> &'static [super::Layer] {
        use super::Layer;
        match self {
            Self::Public => &[Layer::Manifest],
            Self::Authenticated => &[Layer::Manifest, Layer::Architecture],
            Self::Private => &[
                Layer::Manifest,
                Layer::Architecture,
                Layer::SymbolIndex,
                Layer::FullDetail,
            ],
        }
    }
}

impl std::fmt::Display for AccessTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.emoji(), self.name())
    }
}

/// An agent identifier (WebID URI).
///
/// Agents are identified by a dereferenceable URI that resolves to
/// information about the agent (following the WebID specification).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(String);

impl AgentId {
    /// Creates a new agent ID from a URI string.
    ///
    /// # Arguments
    ///
    /// * `uri` - The WebID URI of the agent
    ///
    /// # Example
    ///
    /// ```ignore
    /// let agent = AgentId::new("https://security-scanner.ai/#agent");
    /// ```
    #[must_use]
    pub fn new(uri: impl Into<String>) -> Self {
        Self(uri.into())
    }

    /// Returns the URI of this agent.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for AgentId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for AgentId {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

/// WebACL access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessMode {
    /// Read access
    Read,
    /// Write access
    Write,
    /// Append access
    Append,
    /// Control access (modify ACL)
    Control,
}

impl AccessMode {
    /// Returns the WebACL URI for this access mode.
    #[must_use]
    pub const fn uri(&self) -> &'static str {
        match self {
            Self::Read => "http://www.w3.org/ns/auth/acl#Read",
            Self::Write => "http://www.w3.org/ns/auth/acl#Write",
            Self::Append => "http://www.w3.org/ns/auth/acl#Append",
            Self::Control => "http://www.w3.org/ns/auth/acl#Control",
        }
    }

    /// Returns the short name for this access mode.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Read => "Read",
            Self::Write => "Write",
            Self::Append => "Append",
            Self::Control => "Control",
        }
    }
}

/// An authorization rule in WebACL format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    /// Unique identifier for this authorization (used in Turtle output)
    pub id: String,
    /// The resource this authorization applies to
    pub resource: String,
    /// Access tier (determines agent class)
    pub tier: AccessTier,
    /// Specific agents (for Private tier)
    pub agents: HashSet<AgentId>,
    /// Access modes granted
    pub modes: HashSet<AccessMode>,
}

impl Authorization {
    /// Creates a new authorization for the given resource.
    #[must_use]
    pub fn new(id: impl Into<String>, resource: impl Into<String>, tier: AccessTier) -> Self {
        let mut modes = HashSet::new();
        modes.insert(AccessMode::Read);

        Self {
            id: id.into(),
            resource: resource.into(),
            tier,
            agents: HashSet::new(),
            modes,
        }
    }

    /// Adds a specific agent to this authorization (for Private tier).
    #[must_use]
    pub fn with_agent(mut self, agent: impl Into<AgentId>) -> Self {
        self.agents.insert(agent.into());
        self
    }

    /// Adds an access mode to this authorization.
    #[must_use]
    pub fn with_mode(mut self, mode: AccessMode) -> Self {
        self.modes.insert(mode);
        self
    }

    /// Converts this authorization to Turtle format.
    #[must_use]
    pub fn to_turtle(&self) -> String {
        let mut lines = Vec::new();

        lines.push(format!("<#{}> a acl:Authorization ;", self.id));
        lines.push(format!("    acl:accessTo <{}> ;", self.resource));

        // Add agent class or specific agents
        if let Some(agent_class) = self.tier.agent_class() {
            lines.push(format!("    acl:agentClass <{}> ;", agent_class));
        } else {
            // Private tier: list specific agents
            for agent in &self.agents {
                lines.push(format!("    acl:agent <{}> ;", agent.uri()));
            }
        }

        // Add access modes
        let modes: Vec<_> = self
            .modes
            .iter()
            .map(|m| format!("acl:{}", m.name()))
            .collect();
        lines.push(format!("    acl:mode {} .", modes.join(", ")));

        lines.join("\n")
    }
}

/// Access control configuration for a CCG resource.
///
/// This struct generates WebACL-compliant access control lists for CCG layers,
/// supporting the Triple-Heart Model for tiered access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControl {
    /// Base URI for the CCG resource
    pub base_uri: Option<String>,
    /// Repository name
    pub repo: String,
    /// Authorizations for different resources
    pub authorizations: Vec<Authorization>,
}

impl AccessControl {
    /// Creates a new access control configuration for a repository.
    #[must_use]
    pub fn new(repo: impl Into<String>) -> Self {
        Self {
            base_uri: None,
            repo: repo.into(),
            authorizations: Vec::new(),
        }
    }

    /// Sets the base URI for CCG resources.
    #[must_use]
    pub fn with_base_uri(mut self, uri: impl Into<String>) -> Self {
        self.base_uri = Some(uri.into());
        self
    }

    /// Adds a default authorization for a layer at the specified tier.
    #[must_use]
    pub fn with_layer_access(mut self, layer: super::Layer, tier: AccessTier) -> Self {
        let base = self
            .base_uri
            .clone()
            .unwrap_or_else(|| "https://codecontextgraph.com/ccg".to_string());

        let layer_name = match layer {
            super::Layer::Manifest => "manifest",
            super::Layer::Architecture => "architecture",
            super::Layer::SymbolIndex => "symbol-index",
            super::Layer::FullDetail => "full-detail",
        };

        let resource = format!("{}/{}/{}", base, self.repo, layer_name);
        let auth = Authorization::new(format!("{}-access", layer_name), resource, tier);
        self.authorizations.push(auth);
        self
    }

    /// Adds a private authorization for a layer with specific agents.
    #[must_use]
    pub fn with_private_layer_access(
        mut self,
        layer: super::Layer,
        agents: impl IntoIterator<Item = AgentId>,
    ) -> Self {
        let base = self
            .base_uri
            .clone()
            .unwrap_or_else(|| "https://codecontextgraph.com/ccg".to_string());

        let layer_name = match layer {
            super::Layer::Manifest => "manifest",
            super::Layer::Architecture => "architecture",
            super::Layer::SymbolIndex => "symbol-index",
            super::Layer::FullDetail => "full-detail",
        };

        let resource = format!("{}/{}/{}", base, self.repo, layer_name);
        let mut auth = Authorization::new(
            format!("{}-access", layer_name),
            resource,
            AccessTier::Private,
        );
        for agent in agents {
            auth.agents.insert(agent);
        }
        self.authorizations.push(auth);
        self
    }

    /// Generates the default Triple-Heart access control for a CCG.
    ///
    /// This creates the standard access pattern:
    /// - L0 (Manifest): Public access
    /// - L1 (Architecture): Authenticated access
    /// - L2 (Symbol Index): Private access
    /// - L3 (Full Detail): Private access
    #[must_use]
    pub fn default_triple_heart(repo: impl Into<String>) -> Self {
        Self::new(repo)
            .with_layer_access(super::Layer::Manifest, AccessTier::Public)
            .with_layer_access(super::Layer::Architecture, AccessTier::Authenticated)
            .with_layer_access(super::Layer::SymbolIndex, AccessTier::Private)
            .with_layer_access(super::Layer::FullDetail, AccessTier::Private)
    }

    /// Generates the public access control (all layers public).
    #[must_use]
    pub fn all_public(repo: impl Into<String>) -> Self {
        let repo = repo.into();
        Self::new(repo)
            .with_layer_access(super::Layer::Manifest, AccessTier::Public)
            .with_layer_access(super::Layer::Architecture, AccessTier::Public)
            .with_layer_access(super::Layer::SymbolIndex, AccessTier::Public)
            .with_layer_access(super::Layer::FullDetail, AccessTier::Public)
    }

    /// Converts this access control to Turtle format (RDF).
    #[must_use]
    pub fn to_turtle(&self) -> String {
        let mut lines = Vec::new();

        // Prefixes
        lines.push("@prefix acl: <http://www.w3.org/ns/auth/acl#> .".to_string());
        lines.push("@prefix foaf: <http://xmlns.com/foaf/0.1/> .".to_string());
        lines.push(String::new());

        // Comment header
        lines.push(format!("# WebACL for CCG: {}", self.repo));
        lines.push("# Triple-Heart Access Model".to_string());
        lines.push(String::new());

        // Authorizations
        for auth in &self.authorizations {
            lines.push(auth.to_turtle());
            lines.push(String::new());
        }

        lines.join("\n")
    }

    /// Checks if an agent has access to a specific layer.
    ///
    /// # Arguments
    ///
    /// * `layer` - The layer to check access for
    /// * `agent` - The agent requesting access (None for anonymous)
    /// * `is_authenticated` - Whether the agent is authenticated
    ///
    /// # Returns
    ///
    /// `true` if the agent has read access to the layer.
    pub fn has_access(
        &self,
        layer: super::Layer,
        agent: Option<&AgentId>,
        is_authenticated: bool,
    ) -> bool {
        let layer_name = match layer {
            super::Layer::Manifest => "manifest",
            super::Layer::Architecture => "architecture",
            super::Layer::SymbolIndex => "symbol-index",
            super::Layer::FullDetail => "full-detail",
        };

        for auth in &self.authorizations {
            // Check if this authorization is for the requested layer
            if !auth.resource.ends_with(layer_name) {
                continue;
            }

            // Check if read access is granted
            if !auth.modes.contains(&AccessMode::Read) {
                continue;
            }

            match auth.tier {
                AccessTier::Public => return true,
                AccessTier::Authenticated if is_authenticated => return true,
                AccessTier::Private => {
                    if let Some(agent_id) = agent {
                        if auth.agents.contains(agent_id) {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }

        false
    }
}

impl Default for AccessControl {
    fn default() -> Self {
        Self::new("unknown")
    }
}

/// Access control metadata to include in CCG output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessMetadata {
    /// The access tier for this layer
    pub tier: AccessTier,
    /// URI to the ACL resource (if published)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acl_uri: Option<String>,
    /// Agents with access (for Private tier only, truncated for privacy)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authorized_agents: Vec<String>,
}

impl AccessMetadata {
    /// Creates new access metadata for the given tier.
    #[must_use]
    pub fn new(tier: AccessTier) -> Self {
        Self {
            tier,
            acl_uri: None,
            authorized_agents: Vec::new(),
        }
    }

    /// Sets the ACL URI.
    #[must_use]
    pub fn with_acl_uri(mut self, uri: impl Into<String>) -> Self {
        self.acl_uri = Some(uri.into());
        self
    }

    /// Adds an authorized agent (for Private tier).
    #[must_use]
    pub fn with_agent(mut self, agent: impl Into<String>) -> Self {
        self.authorized_agents.push(agent.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccg::Layer;

    // ===== AccessTier Tests =====

    #[test]
    fn test_access_tier_emoji() {
        assert_eq!(AccessTier::Public.emoji(), "🔴");
        assert_eq!(AccessTier::Authenticated.emoji(), "🟡");
        assert_eq!(AccessTier::Private.emoji(), "🔵");
    }

    #[test]
    fn test_access_tier_name() {
        assert_eq!(AccessTier::Public.name(), "Public");
        assert_eq!(AccessTier::Authenticated.name(), "Authenticated");
        assert_eq!(AccessTier::Private.name(), "Private");
    }

    #[test]
    fn test_access_tier_heart_color() {
        assert_eq!(AccessTier::Public.heart_color(), "Red");
        assert_eq!(AccessTier::Authenticated.heart_color(), "Yellow");
        assert_eq!(AccessTier::Private.heart_color(), "Blue");
    }

    #[test]
    fn test_access_tier_agent_class() {
        assert_eq!(
            AccessTier::Public.agent_class(),
            Some("http://xmlns.com/foaf/0.1/Agent")
        );
        assert_eq!(
            AccessTier::Authenticated.agent_class(),
            Some("http://www.w3.org/ns/auth/acl#AuthenticatedAgent")
        );
        assert_eq!(AccessTier::Private.agent_class(), None);
    }

    #[test]
    fn test_access_tier_accessible_layers() {
        assert_eq!(AccessTier::Public.accessible_layers(), &[Layer::Manifest]);
        assert_eq!(
            AccessTier::Authenticated.accessible_layers(),
            &[Layer::Manifest, Layer::Architecture]
        );
        assert_eq!(
            AccessTier::Private.accessible_layers(),
            &[
                Layer::Manifest,
                Layer::Architecture,
                Layer::SymbolIndex,
                Layer::FullDetail
            ]
        );
    }

    #[test]
    fn test_access_tier_default() {
        assert_eq!(AccessTier::default(), AccessTier::Public);
    }

    #[test]
    fn test_access_tier_display() {
        assert_eq!(format!("{}", AccessTier::Public), "🔴 Public");
        assert_eq!(format!("{}", AccessTier::Authenticated), "🟡 Authenticated");
        assert_eq!(format!("{}", AccessTier::Private), "🔵 Private");
    }

    #[test]
    fn test_access_tier_serialization() {
        let tier = AccessTier::Public;
        let json = serde_json::to_string(&tier).unwrap();
        assert_eq!(json, "\"public\"");

        let tier: AccessTier = serde_json::from_str("\"authenticated\"").unwrap();
        assert_eq!(tier, AccessTier::Authenticated);
    }

    // ===== AgentId Tests =====

    #[test]
    fn test_agent_id_new() {
        let agent = AgentId::new("https://example.com/#agent");
        assert_eq!(agent.uri(), "https://example.com/#agent");
    }

    #[test]
    fn test_agent_id_display() {
        let agent = AgentId::new("https://scanner.ai/#bot");
        assert_eq!(format!("{agent}"), "https://scanner.ai/#bot");
    }

    #[test]
    fn test_agent_id_from_str() {
        let agent: AgentId = "https://example.com/#agent".into();
        assert_eq!(agent.uri(), "https://example.com/#agent");
    }

    #[test]
    fn test_agent_id_equality() {
        let a1 = AgentId::new("https://example.com/#agent");
        let a2 = AgentId::new("https://example.com/#agent");
        let a3 = AgentId::new("https://other.com/#agent");

        assert_eq!(a1, a2);
        assert_ne!(a1, a3);
    }

    // ===== AccessMode Tests =====

    #[test]
    fn test_access_mode_uri() {
        assert_eq!(AccessMode::Read.uri(), "http://www.w3.org/ns/auth/acl#Read");
        assert_eq!(
            AccessMode::Write.uri(),
            "http://www.w3.org/ns/auth/acl#Write"
        );
        assert_eq!(
            AccessMode::Append.uri(),
            "http://www.w3.org/ns/auth/acl#Append"
        );
        assert_eq!(
            AccessMode::Control.uri(),
            "http://www.w3.org/ns/auth/acl#Control"
        );
    }

    #[test]
    fn test_access_mode_name() {
        assert_eq!(AccessMode::Read.name(), "Read");
        assert_eq!(AccessMode::Write.name(), "Write");
        assert_eq!(AccessMode::Append.name(), "Append");
        assert_eq!(AccessMode::Control.name(), "Control");
    }

    // ===== Authorization Tests =====

    #[test]
    fn test_authorization_new() {
        let auth = Authorization::new("test", "https://example.com/resource", AccessTier::Public);
        assert_eq!(auth.id, "test");
        assert_eq!(auth.resource, "https://example.com/resource");
        assert_eq!(auth.tier, AccessTier::Public);
        assert!(auth.modes.contains(&AccessMode::Read));
    }

    #[test]
    fn test_authorization_with_agent() {
        let auth = Authorization::new("test", "https://example.com/resource", AccessTier::Private)
            .with_agent(AgentId::new("https://agent.ai/#bot"));

        assert_eq!(auth.agents.len(), 1);
        assert!(auth.agents.contains(&AgentId::new("https://agent.ai/#bot")));
    }

    #[test]
    fn test_authorization_with_mode() {
        let auth = Authorization::new("test", "https://example.com/resource", AccessTier::Private)
            .with_mode(AccessMode::Write);

        assert!(auth.modes.contains(&AccessMode::Read));
        assert!(auth.modes.contains(&AccessMode::Write));
    }

    #[test]
    fn test_authorization_to_turtle_public() {
        let auth = Authorization::new(
            "public-access",
            "https://example.com/ccg/repo/manifest",
            AccessTier::Public,
        );
        let turtle = auth.to_turtle();

        assert!(turtle.contains("<#public-access> a acl:Authorization"));
        assert!(turtle.contains("acl:accessTo <https://example.com/ccg/repo/manifest>"));
        assert!(turtle.contains("acl:agentClass <http://xmlns.com/foaf/0.1/Agent>"));
        assert!(turtle.contains("acl:mode acl:Read"));
    }

    #[test]
    fn test_authorization_to_turtle_authenticated() {
        let auth = Authorization::new(
            "auth-access",
            "https://example.com/ccg/repo/architecture",
            AccessTier::Authenticated,
        );
        let turtle = auth.to_turtle();

        assert!(
            turtle.contains("acl:agentClass <http://www.w3.org/ns/auth/acl#AuthenticatedAgent>")
        );
    }

    #[test]
    fn test_authorization_to_turtle_private() {
        let auth = Authorization::new(
            "private-access",
            "https://example.com/ccg/repo/security",
            AccessTier::Private,
        )
        .with_agent(AgentId::new("https://security-scanner.ai/#agent"));

        let turtle = auth.to_turtle();

        assert!(turtle.contains("acl:agent <https://security-scanner.ai/#agent>"));
        assert!(!turtle.contains("acl:agentClass"));
    }

    // ===== AccessControl Tests =====

    #[test]
    fn test_access_control_new() {
        let acl = AccessControl::new("test-repo");
        assert_eq!(acl.repo, "test-repo");
        assert!(acl.authorizations.is_empty());
    }

    #[test]
    fn test_access_control_with_base_uri() {
        let acl = AccessControl::new("test-repo").with_base_uri("https://codecontextgraph.com/ccg");
        assert_eq!(
            acl.base_uri,
            Some("https://codecontextgraph.com/ccg".to_string())
        );
    }

    #[test]
    fn test_access_control_with_layer_access() {
        let acl = AccessControl::new("test-repo")
            .with_base_uri("https://example.com/ccg")
            .with_layer_access(Layer::Manifest, AccessTier::Public);

        assert_eq!(acl.authorizations.len(), 1);
        assert!(acl.authorizations[0].resource.contains("manifest"));
        assert_eq!(acl.authorizations[0].tier, AccessTier::Public);
    }

    #[test]
    fn test_access_control_default_triple_heart() {
        let acl = AccessControl::default_triple_heart("test-repo");

        assert_eq!(acl.authorizations.len(), 4);

        // Find each authorization by layer
        let manifest = acl
            .authorizations
            .iter()
            .find(|a| a.resource.contains("manifest"))
            .unwrap();
        let arch = acl
            .authorizations
            .iter()
            .find(|a| a.resource.contains("architecture"))
            .unwrap();
        let index = acl
            .authorizations
            .iter()
            .find(|a| a.resource.contains("symbol-index"))
            .unwrap();
        let detail = acl
            .authorizations
            .iter()
            .find(|a| a.resource.contains("full-detail"))
            .unwrap();

        assert_eq!(manifest.tier, AccessTier::Public);
        assert_eq!(arch.tier, AccessTier::Authenticated);
        assert_eq!(index.tier, AccessTier::Private);
        assert_eq!(detail.tier, AccessTier::Private);
    }

    #[test]
    fn test_access_control_all_public() {
        let acl = AccessControl::all_public("test-repo");

        assert_eq!(acl.authorizations.len(), 4);
        for auth in &acl.authorizations {
            assert_eq!(auth.tier, AccessTier::Public);
        }
    }

    #[test]
    fn test_access_control_to_turtle() {
        let acl = AccessControl::new("test-repo")
            .with_base_uri("https://example.com/ccg")
            .with_layer_access(Layer::Manifest, AccessTier::Public);

        let turtle = acl.to_turtle();

        assert!(turtle.contains("@prefix acl: <http://www.w3.org/ns/auth/acl#>"));
        assert!(turtle.contains("@prefix foaf: <http://xmlns.com/foaf/0.1/>"));
        assert!(turtle.contains("# WebACL for CCG: test-repo"));
        assert!(turtle.contains("a acl:Authorization"));
    }

    #[test]
    fn test_access_control_has_access_public() {
        let acl = AccessControl::new("test-repo")
            .with_base_uri("https://example.com/ccg")
            .with_layer_access(Layer::Manifest, AccessTier::Public);

        // Anyone can access public layers
        assert!(acl.has_access(Layer::Manifest, None, false));
        assert!(acl.has_access(Layer::Manifest, None, true));

        // Other layers have no authorization
        assert!(!acl.has_access(Layer::Architecture, None, false));
    }

    #[test]
    fn test_access_control_has_access_authenticated() {
        let acl = AccessControl::new("test-repo")
            .with_base_uri("https://example.com/ccg")
            .with_layer_access(Layer::Architecture, AccessTier::Authenticated);

        // Unauthenticated cannot access
        assert!(!acl.has_access(Layer::Architecture, None, false));

        // Authenticated can access
        assert!(acl.has_access(Layer::Architecture, None, true));

        let agent = AgentId::new("https://agent.ai/#bot");
        assert!(acl.has_access(Layer::Architecture, Some(&agent), true));
    }

    #[test]
    fn test_access_control_has_access_private() {
        let trusted_agent = AgentId::new("https://trusted.ai/#agent");
        let untrusted_agent = AgentId::new("https://untrusted.ai/#agent");

        let acl = AccessControl::new("test-repo")
            .with_base_uri("https://example.com/ccg")
            .with_private_layer_access(Layer::SymbolIndex, vec![trusted_agent.clone()]);

        // No agent cannot access
        assert!(!acl.has_access(Layer::SymbolIndex, None, true));

        // Untrusted agent cannot access
        assert!(!acl.has_access(Layer::SymbolIndex, Some(&untrusted_agent), true));

        // Trusted agent can access
        assert!(acl.has_access(Layer::SymbolIndex, Some(&trusted_agent), true));
    }

    #[test]
    fn test_access_control_triple_heart_access() {
        let acl = AccessControl::default_triple_heart("test-repo");

        // Public layers - anyone
        assert!(acl.has_access(Layer::Manifest, None, false));

        // Authenticated layers - only authenticated
        assert!(!acl.has_access(Layer::Architecture, None, false));
        assert!(acl.has_access(Layer::Architecture, None, true));

        // Private layers - no one without explicit agent
        assert!(!acl.has_access(Layer::SymbolIndex, None, true));
        assert!(!acl.has_access(Layer::FullDetail, None, true));
    }

    // ===== AccessMetadata Tests =====

    #[test]
    fn test_access_metadata_new() {
        let meta = AccessMetadata::new(AccessTier::Public);
        assert_eq!(meta.tier, AccessTier::Public);
        assert!(meta.acl_uri.is_none());
        assert!(meta.authorized_agents.is_empty());
    }

    #[test]
    fn test_access_metadata_with_acl_uri() {
        let meta = AccessMetadata::new(AccessTier::Public).with_acl_uri("https://example.com/.acl");
        assert_eq!(meta.acl_uri, Some("https://example.com/.acl".to_string()));
    }

    #[test]
    fn test_access_metadata_with_agent() {
        let meta = AccessMetadata::new(AccessTier::Private).with_agent("https://agent.ai/#bot");
        assert_eq!(meta.authorized_agents.len(), 1);
        assert_eq!(meta.authorized_agents[0], "https://agent.ai/#bot");
    }

    #[test]
    fn test_access_metadata_serialization() {
        let meta = AccessMetadata::new(AccessTier::Public);
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("\"tier\":\"public\""));
    }

    #[test]
    fn test_access_metadata_serialization_skips_empty() {
        let meta = AccessMetadata::new(AccessTier::Public);
        let json = serde_json::to_string(&meta).unwrap();
        // Empty fields should be skipped
        assert!(!json.contains("acl_uri"));
        assert!(!json.contains("authorized_agents"));
    }
}
