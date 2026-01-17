//! Supply Chain Security Analysis
//!
//! This module provides:
//! - SBOM (Software Bill of Materials) generation in CycloneDX and SPDX formats
//! - Dependency vulnerability scanning via OSV (Open Source Vulnerabilities) API
//! - License compliance checking and compatibility analysis
//! - Package manager support for Cargo.toml, package.json, requirements.txt, go.mod

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Unique identifier for a dependency
pub type DependencyId = String;

/// Supported SBOM output formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum SbomFormat {
    #[default]
    CycloneDX,
    Spdx,
    Json,
}

/// Supported package manager ecosystems
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Cargo, // Rust - Cargo.toml
    Npm,   // JavaScript/Node - package.json
    PyPI,  // Python - requirements.txt, pyproject.toml
    Go,    // Go - go.mod
    Maven, // Java - pom.xml
    NuGet, // .NET - *.csproj
    Unknown,
}

impl Ecosystem {
    pub fn from_file(filename: &str) -> Self {
        match filename {
            "Cargo.toml" | "Cargo.lock" => Ecosystem::Cargo,
            "package.json" | "package-lock.json" | "yarn.lock" => Ecosystem::Npm,
            "requirements.txt" | "pyproject.toml" | "Pipfile" | "setup.py" => Ecosystem::PyPI,
            "go.mod" | "go.sum" => Ecosystem::Go,
            "pom.xml" => Ecosystem::Maven,
            f if f.ends_with(".csproj") || f == "packages.config" => Ecosystem::NuGet,
            _ => Ecosystem::Unknown,
        }
    }

    pub fn manifest_files(&self) -> &[&str] {
        match self {
            Ecosystem::Cargo => &["Cargo.toml", "Cargo.lock"],
            Ecosystem::Npm => &["package.json", "package-lock.json", "yarn.lock"],
            Ecosystem::PyPI => &["requirements.txt", "pyproject.toml", "Pipfile", "setup.py"],
            Ecosystem::Go => &["go.mod", "go.sum"],
            Ecosystem::Maven => &["pom.xml"],
            Ecosystem::NuGet => &["*.csproj", "packages.config"],
            Ecosystem::Unknown => &[],
        }
    }
}

/// Dependency information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub source: Option<String>,          // Registry URL or git repo
    pub checksum: Option<String>,        // SHA256 hash
    pub license: Option<String>,         // SPDX license identifier
    pub dependencies: Vec<DependencyId>, // Transitive dependencies
    pub dev_dependency: bool,
    pub optional: bool,
}

impl Dependency {
    pub fn new(name: &str, version: &str, ecosystem: Ecosystem) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem,
            source: None,
            checksum: None,
            license: None,
            dependencies: Vec::new(),
            dev_dependency: false,
            optional: false,
        }
    }

    pub fn purl(&self) -> String {
        // Package URL format: pkg:type/namespace/name@version
        let pkg_type = match self.ecosystem {
            Ecosystem::Cargo => "cargo",
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "pypi",
            Ecosystem::Go => "golang",
            Ecosystem::Maven => "maven",
            Ecosystem::NuGet => "nuget",
            Ecosystem::Unknown => "generic",
        };
        format!("pkg:{}/{}@{}", pkg_type, self.name, self.version)
    }
}

/// Vulnerability severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VulnSeverity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl VulnSeverity {
    pub fn from_cvss(score: f64) -> Self {
        match score {
            s if s >= 9.0 => VulnSeverity::Critical,
            s if s >= 7.0 => VulnSeverity::High,
            s if s >= 4.0 => VulnSeverity::Medium,
            s if s > 0.0 => VulnSeverity::Low,
            _ => VulnSeverity::Unknown,
        }
    }
}

/// Vulnerability information from OSV
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,           // OSV/CVE/GHSA ID
    pub aliases: Vec<String>, // Other IDs (CVE, GHSA, etc.)
    pub summary: String,
    pub details: Option<String>,
    pub severity: VulnSeverity,
    pub cvss_score: Option<f64>,
    pub affected_versions: Vec<String>,
    pub fixed_versions: Vec<String>, // Versions that fix this vuln
    pub references: Vec<String>,     // URLs for more info
    pub published: Option<String>,   // ISO date
    pub modified: Option<String>,    // ISO date
}

/// Result of vulnerability scan for a dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyVuln {
    pub dependency: Dependency,
    pub vulnerabilities: Vec<Vulnerability>,
    pub risk_level: VulnSeverity,   // Highest severity found
    pub upgrade_to: Option<String>, // Safe version to upgrade to
}

/// SPDX License identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct License {
    pub id: String, // SPDX identifier (e.g., "MIT", "Apache-2.0")
    pub name: String,
    pub is_osi_approved: bool,
    pub is_copyleft: bool,
    pub is_permissive: bool,
}

impl License {
    pub fn from_spdx(id: &str) -> Self {
        let id_lower = id.to_lowercase();
        let (is_copyleft, is_permissive, is_osi_approved) = match id_lower.as_str() {
            "mit" => (false, true, true),
            "apache-2.0" => (false, true, true),
            "bsd-2-clause" | "bsd-3-clause" => (false, true, true),
            "isc" => (false, true, true),
            "unlicense" | "cc0-1.0" => (false, true, false),
            "gpl-2.0" | "gpl-2.0-only" => (true, false, true),
            "gpl-3.0" | "gpl-3.0-only" => (true, false, true),
            "lgpl-2.1" | "lgpl-3.0" => (true, false, true),
            "agpl-3.0" => (true, false, true),
            "mpl-2.0" => (true, false, true),
            "eupl-1.2" => (true, false, true),
            "bsl-1.0" => (false, true, true),
            _ => (false, false, false),
        };

        Self {
            id: id.to_string(),
            name: Self::license_name(id),
            is_osi_approved,
            is_copyleft,
            is_permissive,
        }
    }

    fn license_name(id: &str) -> String {
        match id.to_uppercase().as_str() {
            "MIT" => "MIT License".to_string(),
            "APACHE-2.0" => "Apache License 2.0".to_string(),
            "GPL-2.0" | "GPL-2.0-ONLY" => "GNU General Public License v2.0".to_string(),
            "GPL-3.0" | "GPL-3.0-ONLY" => "GNU General Public License v3.0".to_string(),
            "LGPL-2.1" => "GNU Lesser General Public License v2.1".to_string(),
            "LGPL-3.0" => "GNU Lesser General Public License v3.0".to_string(),
            "BSD-2-CLAUSE" => "BSD 2-Clause License".to_string(),
            "BSD-3-CLAUSE" => "BSD 3-Clause License".to_string(),
            "ISC" => "ISC License".to_string(),
            "MPL-2.0" => "Mozilla Public License 2.0".to_string(),
            "AGPL-3.0" => "GNU Affero General Public License v3.0".to_string(),
            "UNLICENSE" => "The Unlicense".to_string(),
            "CC0-1.0" => "Creative Commons Zero v1.0 Universal".to_string(),
            "BSL-1.0" => "Boost Software License 1.0".to_string(),
            _ => id.to_string(),
        }
    }
}

/// License compatibility issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseIssue {
    pub dependency: String,
    pub license: String,
    pub issue_type: LicenseIssueType,
    pub message: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseIssueType {
    Unknown,      // License not recognized
    Copyleft,     // May require source disclosure
    Incompatible, // Conflicts with project license
    Commercial,   // Commercial/proprietary restrictions
    NoLicense,    // No license specified
}

/// License compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseReport {
    pub project_license: Option<String>,
    pub dependencies_by_license: HashMap<String, Vec<String>>, // license -> deps
    pub issues: Vec<LicenseIssue>,
    pub copyleft_deps: Vec<String>,
    pub permissive_deps: Vec<String>,
    pub unknown_license_deps: Vec<String>,
    pub summary: String,
}

/// Software Bill of Materials (SBOM)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    pub format: SbomFormat,
    pub spec_version: String,
    pub serial_number: String,
    pub version: u32,
    pub metadata: SbomMetadata,
    pub components: Vec<SbomComponent>,
    pub dependencies: Vec<SbomDependency>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomMetadata {
    pub timestamp: String,
    pub tools: Vec<String>,
    pub component: Option<SbomComponent>, // The root project
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomComponent {
    pub bom_ref: String,
    pub component_type: String, // "library", "application", "framework"
    pub name: String,
    pub version: String,
    pub purl: Option<String>,
    pub licenses: Vec<String>,
    pub hashes: Vec<SbomHash>,
    pub external_references: Vec<SbomExternalRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomHash {
    pub alg: String, // "SHA-256", "SHA-512", etc.
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomExternalRef {
    pub ref_type: String, // "vcs", "website", "issue-tracker"
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDependency {
    pub ref_id: String,
    pub depends_on: Vec<String>,
}

/// Upgrade recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeRecommendation {
    pub dependency: String,
    pub current_version: String,
    pub recommended_version: String,
    pub reason: UpgradeReason,
    pub breaking_changes: bool,
    pub vulnerabilities_fixed: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeReason {
    Security,      // Fixes vulnerabilities
    Deprecation,   // Current version deprecated
    EndOfLife,     // No longer supported
    Compatibility, // Better compatibility
    Performance,   // Performance improvements
}

/// Supply chain analyzer
pub struct SupplyChainAnalyzer {
    known_licenses: HashMap<String, License>,
    license_compatibility: HashMap<String, HashSet<String>>,
}

impl Default for SupplyChainAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl SupplyChainAnalyzer {
    pub fn new() -> Self {
        let mut analyzer = Self {
            known_licenses: HashMap::new(),
            license_compatibility: HashMap::new(),
        };
        analyzer.init_licenses();
        analyzer
    }

    /// Phase D1: Extract project license from Cargo.toml content
    ///
    /// Parses the `[package].license` field from Cargo.toml content.
    /// Returns `Some(license)` if found, `None` otherwise.
    pub fn extract_cargo_project_license(content: &str) -> Option<String> {
        let parsed: toml::Value = toml::from_str(content).ok()?;
        parsed
            .get("package")
            .and_then(|pkg| pkg.get("license"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Phase D2: Extract project license from package.json content
    ///
    /// Supports multiple formats:
    /// - String: `"license": "MIT"`
    /// - Object (deprecated): `"license": {"type": "MIT"}`
    /// - Array (deprecated): `"licenses": [{"type": "MIT"}, {"type": "Apache-2.0"}]`
    pub fn extract_npm_project_license(content: &str) -> Option<String> {
        let parsed: serde_json::Value = serde_json::from_str(content).ok()?;

        // Try "license" field first (most common)
        if let Some(license) = parsed.get("license") {
            // String format: "license": "MIT"
            if let Some(s) = license.as_str() {
                return Some(s.to_string());
            }
            // Object format (deprecated): "license": {"type": "MIT"}
            if let Some(obj) = license.as_object() {
                if let Some(license_type) = obj.get("type").and_then(|v| v.as_str()) {
                    return Some(license_type.to_string());
                }
            }
        }

        // Try deprecated "licenses" array: [{"type": "MIT"}, {"type": "Apache-2.0"}]
        if let Some(licenses) = parsed.get("licenses").and_then(|v| v.as_array()) {
            let license_types: Vec<String> = licenses
                .iter()
                .filter_map(|l| l.get("type").and_then(|v| v.as_str()).map(String::from))
                .collect();

            if !license_types.is_empty() {
                return Some(license_types.join(" OR "));
            }
        }

        None
    }

    /// Phase D3: Parse package-lock.json content for dependencies with licenses
    ///
    /// Supports lockfileVersion 2 and 3 formats which include license information
    /// in the "packages" object. Each package entry can have a "license" field.
    pub fn parse_package_lock_content(&self, content: &str) -> Result<Vec<Dependency>, String> {
        let parsed: serde_json::Value = serde_json::from_str(content)
            .map_err(|e| format!("Failed to parse package-lock.json: {}", e))?;

        let mut deps = Vec::new();

        // Parse "packages" object (lockfileVersion 2 and 3)
        if let Some(packages) = parsed.get("packages").and_then(|v| v.as_object()) {
            for (key, value) in packages {
                // Skip the root project entry (empty key or just "")
                if key.is_empty() {
                    continue;
                }

                // Extract package name from the key (e.g., "node_modules/lodash" -> "lodash")
                let name = key.strip_prefix("node_modules/").unwrap_or(key).to_string();

                // Skip nested node_modules (scoped packages are ok)
                if name.contains("node_modules/") {
                    continue;
                }

                let version = value
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*")
                    .to_string();

                let license = value
                    .get("license")
                    .and_then(|v| v.as_str())
                    .map(String::from);

                let dev = value.get("dev").and_then(|v| v.as_bool()).unwrap_or(false);

                let optional = value
                    .get("optional")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                let mut dep = Dependency::new(&name, &version, Ecosystem::Npm);
                dep.license = license;
                dep.dev_dependency = dev;
                dep.optional = optional;
                dep.source = Some("https://registry.npmjs.org".to_string());
                deps.push(dep);
            }
        }

        Ok(deps)
    }

    fn init_licenses(&mut self) {
        // Initialize common licenses
        let common_licenses = [
            "MIT",
            "Apache-2.0",
            "GPL-2.0",
            "GPL-3.0",
            "LGPL-2.1",
            "LGPL-3.0",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "ISC",
            "MPL-2.0",
            "AGPL-3.0",
            "Unlicense",
            "CC0-1.0",
            "BSL-1.0",
        ];

        for id in common_licenses {
            self.known_licenses
                .insert(id.to_lowercase(), License::from_spdx(id));
        }

        // License compatibility matrix (simplified)
        // MIT can be combined with most licenses
        self.license_compatibility.insert(
            "mit".to_string(),
            [
                "apache-2.0",
                "bsd-2-clause",
                "bsd-3-clause",
                "isc",
                "unlicense",
                "cc0-1.0",
                "bsl-1.0",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        );

        // Apache-2.0 has some restrictions with GPL-2.0
        self.license_compatibility.insert(
            "apache-2.0".to_string(),
            [
                "mit",
                "bsd-2-clause",
                "bsd-3-clause",
                "isc",
                "gpl-3.0",
                "lgpl-3.0",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        );
    }

    /// Phase D4: Enrich npm dependencies with known license information
    /// This provides license info for common npm packages without needing external API calls
    pub fn enrich_npm_licenses(&self, deps: &mut [Dependency]) {
        // License database for top 100+ most commonly used npm packages
        // Format: package_name -> SPDX license expression
        const KNOWN_NPM_LICENSES: &[(&str, &str)] = &[
            // Core/popular packages
            ("lodash", "MIT"),
            ("underscore", "MIT"),
            ("ramda", "MIT"),
            ("moment", "MIT"),
            ("dayjs", "MIT"),
            ("date-fns", "MIT"),
            ("luxon", "MIT"),
            // React ecosystem
            ("react", "MIT"),
            ("react-dom", "MIT"),
            ("react-router", "MIT"),
            ("react-router-dom", "MIT"),
            ("redux", "MIT"),
            ("react-redux", "MIT"),
            ("@reduxjs/toolkit", "MIT"),
            ("next", "MIT"),
            ("gatsby", "MIT"),
            ("styled-components", "MIT"),
            ("emotion", "MIT"),
            ("@emotion/react", "MIT"),
            ("@emotion/styled", "MIT"),
            // Vue ecosystem
            ("vue", "MIT"),
            ("vuex", "MIT"),
            ("vue-router", "MIT"),
            ("nuxt", "MIT"),
            ("pinia", "MIT"),
            // Angular
            ("@angular/core", "MIT"),
            ("@angular/common", "MIT"),
            ("@angular/router", "MIT"),
            ("rxjs", "Apache-2.0"),
            // Build tools
            ("webpack", "MIT"),
            ("rollup", "MIT"),
            ("parcel", "MIT"),
            ("esbuild", "MIT"),
            ("vite", "MIT"),
            ("babel-core", "MIT"),
            ("@babel/core", "MIT"),
            ("@babel/preset-env", "MIT"),
            ("typescript", "Apache-2.0"),
            // HTTP/Networking
            ("axios", "MIT"),
            ("node-fetch", "MIT"),
            ("got", "MIT"),
            ("superagent", "MIT"),
            ("request", "Apache-2.0"),
            ("isomorphic-fetch", "MIT"),
            ("cross-fetch", "MIT"),
            // Express and middleware
            ("express", "MIT"),
            ("koa", "MIT"),
            ("fastify", "MIT"),
            ("hapi", "BSD-3-Clause"),
            ("body-parser", "MIT"),
            ("cors", "MIT"),
            ("helmet", "MIT"),
            ("morgan", "MIT"),
            ("cookie-parser", "MIT"),
            ("compression", "MIT"),
            // Database/ORM
            ("mongoose", "MIT"),
            ("sequelize", "MIT"),
            ("typeorm", "MIT"),
            ("prisma", "Apache-2.0"),
            ("@prisma/client", "Apache-2.0"),
            ("knex", "MIT"),
            ("pg", "MIT"),
            ("mysql2", "MIT"),
            ("mongodb", "Apache-2.0"),
            ("redis", "MIT"),
            ("ioredis", "MIT"),
            // Testing
            ("jest", "MIT"),
            ("mocha", "MIT"),
            ("chai", "MIT"),
            ("jasmine", "MIT"),
            ("vitest", "MIT"),
            ("cypress", "MIT"),
            ("playwright", "Apache-2.0"),
            ("puppeteer", "Apache-2.0"),
            ("sinon", "BSD-3-Clause"),
            ("nyc", "ISC"),
            ("istanbul", "BSD-3-Clause"),
            // Linting/Formatting
            ("eslint", "MIT"),
            ("prettier", "MIT"),
            ("stylelint", "MIT"),
            ("tslint", "Apache-2.0"),
            // CLI/Utils
            ("commander", "MIT"),
            ("yargs", "MIT"),
            ("inquirer", "MIT"),
            ("chalk", "MIT"),
            ("ora", "MIT"),
            ("debug", "MIT"),
            ("dotenv", "BSD-2-Clause"),
            ("cross-env", "MIT"),
            ("rimraf", "ISC"),
            ("mkdirp", "MIT"),
            ("glob", "ISC"),
            ("minimatch", "ISC"),
            ("minimist", "MIT"),
            // Utilities
            ("uuid", "MIT"),
            ("nanoid", "MIT"),
            ("crypto-js", "MIT"),
            ("bcrypt", "MIT"),
            ("bcryptjs", "MIT"),
            ("jsonwebtoken", "MIT"),
            ("validator", "MIT"),
            ("joi", "BSD-3-Clause"),
            ("yup", "MIT"),
            ("zod", "MIT"),
            ("ajv", "MIT"),
            // Async/Promises
            ("async", "MIT"),
            ("bluebird", "MIT"),
            ("p-limit", "MIT"),
            ("p-queue", "MIT"),
            // File handling
            ("fs-extra", "MIT"),
            ("graceful-fs", "ISC"),
            ("chokidar", "MIT"),
            ("formidable", "MIT"),
            ("multer", "MIT"),
            // Streams
            ("through2", "MIT"),
            ("concat-stream", "MIT"),
            ("readable-stream", "MIT"),
            // Logging
            ("winston", "MIT"),
            ("pino", "MIT"),
            ("bunyan", "MIT"),
            ("log4js", "Apache-2.0"),
            // Websockets
            ("socket.io", "MIT"),
            ("ws", "MIT"),
            // GraphQL
            ("graphql", "MIT"),
            ("apollo-server", "MIT"),
            ("@apollo/client", "MIT"),
            // Markdown/Parsing
            ("marked", "MIT"),
            ("markdown-it", "MIT"),
            ("remark", "MIT"),
            ("cheerio", "MIT"),
            ("jsdom", "MIT"),
            ("htmlparser2", "MIT"),
            // Image processing
            ("sharp", "Apache-2.0"),
            ("jimp", "MIT"),
            // Other popular packages
            ("classnames", "MIT"),
            ("clsx", "MIT"),
            ("prop-types", "MIT"),
            ("immer", "MIT"),
            ("zustand", "MIT"),
            ("mobx", "MIT"),
            ("recoil", "MIT"),
            ("swr", "MIT"),
            ("react-query", "MIT"),
            ("@tanstack/react-query", "MIT"),
            ("axios-retry", "Apache-2.0"),
            ("retry", "MIT"),
            ("semver", "ISC"),
            ("lru-cache", "ISC"),
            ("node-cache", "MIT"),
        ];

        let license_map: HashMap<&str, &str> = KNOWN_NPM_LICENSES.iter().cloned().collect();

        for dep in deps.iter_mut() {
            if dep.ecosystem == Ecosystem::Npm && dep.license.is_none() {
                if let Some(&license) = license_map.get(dep.name.as_str()) {
                    dep.license = Some(license.to_string());
                }
            }
        }
    }

    /// Enrich Cargo dependencies with known license information
    /// This provides license info for common crates without needing external API calls
    pub fn enrich_crate_licenses(&self, deps: &mut [Dependency]) {
        // License database for top 100+ most commonly used Rust crates
        // Format: crate_name -> SPDX license expression
        const KNOWN_CRATE_LICENSES: &[(&str, &str)] = &[
            // Core utilities
            ("serde", "MIT OR Apache-2.0"),
            ("serde_json", "MIT OR Apache-2.0"),
            ("serde_derive", "MIT OR Apache-2.0"),
            ("tokio", "MIT"),
            ("tokio-util", "MIT"),
            ("async-trait", "MIT OR Apache-2.0"),
            ("futures", "MIT OR Apache-2.0"),
            ("futures-core", "MIT OR Apache-2.0"),
            ("futures-util", "MIT OR Apache-2.0"),
            // Async runtime
            ("async-std", "MIT OR Apache-2.0"),
            ("smol", "MIT OR Apache-2.0"),
            // Web frameworks
            ("actix-web", "MIT OR Apache-2.0"),
            ("actix-rt", "MIT OR Apache-2.0"),
            ("axum", "MIT"),
            ("hyper", "MIT"),
            ("reqwest", "MIT OR Apache-2.0"),
            ("rocket", "MIT OR Apache-2.0"),
            ("warp", "MIT"),
            ("tower", "MIT"),
            ("tower-http", "MIT"),
            // Database
            ("sqlx", "MIT OR Apache-2.0"),
            ("diesel", "MIT OR Apache-2.0"),
            ("rusqlite", "MIT"),
            ("sea-orm", "MIT OR Apache-2.0"),
            ("mongodb", "Apache-2.0"),
            ("redis", "BSD-3-Clause"),
            // Serialization
            ("toml", "MIT OR Apache-2.0"),
            ("yaml-rust", "MIT OR Apache-2.0"),
            ("ron", "MIT OR Apache-2.0"),
            ("bincode", "MIT"),
            ("postcard", "MIT OR Apache-2.0"),
            // Crypto
            ("ring", "ISC AND MIT AND OpenSSL"),
            ("rustls", "MIT OR Apache-2.0"),
            ("sha2", "MIT OR Apache-2.0"),
            ("md5", "MIT OR Apache-2.0"),
            ("hmac", "MIT OR Apache-2.0"),
            ("bcrypt", "MIT"),
            ("argon2", "MIT OR Apache-2.0"),
            ("aes", "MIT OR Apache-2.0"),
            ("rsa", "MIT OR Apache-2.0"),
            // Error handling
            ("anyhow", "MIT OR Apache-2.0"),
            ("thiserror", "MIT OR Apache-2.0"),
            ("eyre", "MIT OR Apache-2.0"),
            ("miette", "Apache-2.0"),
            // CLI
            ("clap", "MIT OR Apache-2.0"),
            ("structopt", "MIT OR Apache-2.0"),
            ("argh", "BSD-3-Clause"),
            ("indicatif", "MIT"),
            ("console", "MIT"),
            ("dialoguer", "MIT"),
            // Logging
            ("log", "MIT OR Apache-2.0"),
            ("env_logger", "MIT OR Apache-2.0"),
            ("tracing", "MIT"),
            ("tracing-subscriber", "MIT"),
            ("pretty_env_logger", "MIT OR Apache-2.0"),
            ("fern", "MIT"),
            // Utilities
            ("regex", "MIT OR Apache-2.0"),
            ("lazy_static", "MIT OR Apache-2.0"),
            ("once_cell", "MIT OR Apache-2.0"),
            ("itertools", "MIT OR Apache-2.0"),
            ("chrono", "MIT OR Apache-2.0"),
            ("time", "MIT OR Apache-2.0"),
            ("uuid", "MIT OR Apache-2.0"),
            ("url", "MIT OR Apache-2.0"),
            ("base64", "MIT OR Apache-2.0"),
            ("hex", "MIT OR Apache-2.0"),
            ("bytes", "MIT"),
            ("memchr", "MIT OR Unlicense"),
            ("rayon", "MIT OR Apache-2.0"),
            ("crossbeam", "MIT OR Apache-2.0"),
            ("parking_lot", "MIT OR Apache-2.0"),
            ("dashmap", "MIT"),
            ("num-traits", "MIT OR Apache-2.0"),
            ("num-derive", "MIT OR Apache-2.0"),
            ("rand", "MIT OR Apache-2.0"),
            ("rand_core", "MIT OR Apache-2.0"),
            ("getrandom", "MIT OR Apache-2.0"),
            // Parsing/Text
            ("nom", "MIT"),
            ("pest", "MIT OR Apache-2.0"),
            ("tree-sitter", "MIT"),
            ("pulldown-cmark", "MIT"),
            ("syntect", "MIT"),
            // Testing
            ("criterion", "MIT OR Apache-2.0"),
            ("proptest", "MIT OR Apache-2.0"),
            ("quickcheck", "MIT OR Unlicense"),
            ("mockall", "MIT OR Apache-2.0"),
            ("tempfile", "MIT OR Apache-2.0"),
            ("assert_cmd", "MIT OR Apache-2.0"),
            // Build/FFI
            ("cc", "MIT OR Apache-2.0"),
            ("bindgen", "BSD-3-Clause"),
            ("libc", "MIT OR Apache-2.0"),
            ("winapi", "MIT OR Apache-2.0"),
            ("nix", "MIT"),
            // File/IO
            ("walkdir", "MIT OR Unlicense"),
            ("ignore", "MIT OR Unlicense"),
            ("globset", "MIT OR Unlicense"),
            ("memmap2", "MIT OR Apache-2.0"),
            ("notify", "MIT OR Apache-2.0"),
            ("flate2", "MIT OR Apache-2.0"),
            ("zip", "MIT"),
            ("tar", "MIT OR Apache-2.0"),
            // Network
            ("tonic", "MIT"),
            ("prost", "Apache-2.0"),
            ("http", "MIT OR Apache-2.0"),
            ("native-tls", "MIT OR Apache-2.0"),
            ("rustls-pemfile", "MIT OR Apache-2.0"),
            ("webpki", "ISC"),
            // Derive/Proc macros
            ("derive_more", "MIT"),
            ("strum", "MIT"),
            ("strum_macros", "MIT"),
            ("quote", "MIT OR Apache-2.0"),
            ("syn", "MIT OR Apache-2.0"),
            ("proc-macro2", "MIT OR Apache-2.0"),
            // Git
            ("git2", "MIT OR Apache-2.0"),
            ("gix", "MIT OR Apache-2.0"),
            // Tantivy
            ("tantivy", "MIT"),
            // Other common
            ("cfg-if", "MIT OR Apache-2.0"),
            ("either", "MIT OR Apache-2.0"),
            ("smallvec", "MIT OR Apache-2.0"),
            ("tinyvec", "MIT OR Zlib OR Apache-2.0"),
            ("arrayvec", "MIT OR Apache-2.0"),
            ("indexmap", "MIT OR Apache-2.0"),
            ("hashbrown", "MIT OR Apache-2.0"),
            ("ahash", "MIT OR Apache-2.0"),
            ("phf", "MIT"),
            ("bitflags", "MIT OR Apache-2.0"),
            ("semver", "MIT OR Apache-2.0"),
            ("version_check", "MIT OR Apache-2.0"),
            ("autocfg", "MIT OR Apache-2.0"),
        ];

        let license_map: HashMap<&str, &str> = KNOWN_CRATE_LICENSES.iter().cloned().collect();

        for dep in deps.iter_mut() {
            if dep.ecosystem == Ecosystem::Cargo && dep.license.is_none() {
                if let Some(&license) = license_map.get(dep.name.as_str()) {
                    dep.license = Some(license.to_string());
                }
            }
        }
    }

    /// Parse dependencies from a project directory
    ///
    /// Phase D5: Integrates all license sources:
    /// 1. Prefers lock files (Cargo.lock, package-lock.json) which have license info
    /// 2. Falls back to manifest files (Cargo.toml, package.json)
    /// 3. Applies license enrichment databases for Cargo and npm
    pub fn parse_dependencies(&self, project_path: &Path) -> Result<Vec<Dependency>, String> {
        let mut all_deps = Vec::new();

        // Prefer Cargo.lock for Rust projects (has all transitive dependencies)
        let cargo_lock = project_path.join("Cargo.lock");
        let cargo_toml = project_path.join("Cargo.toml");
        if cargo_lock.exists() {
            let deps = self.parse_cargo_lock(&cargo_lock)?;
            all_deps.extend(deps);
        } else if cargo_toml.exists() {
            // Fallback to Cargo.toml if no lock file
            let deps = self.parse_cargo_toml(&cargo_toml)?;
            all_deps.extend(deps);
        }

        // Phase D5: Prefer package-lock.json for npm (has license info per package)
        let package_lock = project_path.join("package-lock.json");
        let package_json = project_path.join("package.json");
        if package_lock.exists() {
            // Parse package-lock.json for licenses
            let lock_content = std::fs::read_to_string(&package_lock)
                .map_err(|e| format!("Failed to read package-lock.json: {}", e))?;
            let mut deps = self.parse_package_lock_content(&lock_content)?;
            // Apply npm license enrichment for any packages without license
            self.enrich_npm_licenses(&mut deps);
            all_deps.extend(deps);
        } else if package_json.exists() {
            // Fall back to package.json
            let mut deps = self.parse_package_json(&package_json)?;
            // Apply npm license enrichment
            self.enrich_npm_licenses(&mut deps);
            all_deps.extend(deps);
        }

        // Look for requirements.txt
        let requirements_txt = project_path.join("requirements.txt");
        if requirements_txt.exists() {
            let deps = self.parse_requirements_txt(&requirements_txt)?;
            all_deps.extend(deps);
        }

        // Look for go.mod
        let go_mod = project_path.join("go.mod");
        if go_mod.exists() {
            let deps = self.parse_go_mod(&go_mod)?;
            all_deps.extend(deps);
        }

        Ok(all_deps)
    }

    /// Parse Cargo.toml for Rust dependencies
    pub fn parse_cargo_toml(&self, path: &Path) -> Result<Vec<Dependency>, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read Cargo.toml: {}", e))?;

        let parsed: toml::Value =
            toml::from_str(&content).map_err(|e| format!("Failed to parse Cargo.toml: {}", e))?;

        let mut deps = Vec::new();

        // Parse [dependencies]
        if let Some(dependencies) = parsed.get("dependencies").and_then(|v| v.as_table()) {
            for (name, value) in dependencies {
                let dep = self.parse_cargo_dependency(name, value, false)?;
                deps.push(dep);
            }
        }

        // Parse [dev-dependencies]
        if let Some(dev_deps) = parsed.get("dev-dependencies").and_then(|v| v.as_table()) {
            for (name, value) in dev_deps {
                let mut dep = self.parse_cargo_dependency(name, value, true)?;
                dep.dev_dependency = true;
                deps.push(dep);
            }
        }

        // Parse [build-dependencies]
        if let Some(build_deps) = parsed.get("build-dependencies").and_then(|v| v.as_table()) {
            for (name, value) in build_deps {
                let dep = self.parse_cargo_dependency(name, value, true)?;
                deps.push(dep);
            }
        }

        // Enrich with known license information
        self.enrich_crate_licenses(&mut deps);

        Ok(deps)
    }

    fn parse_cargo_dependency(
        &self,
        name: &str,
        value: &toml::Value,
        is_dev: bool,
    ) -> Result<Dependency, String> {
        let version = match value {
            toml::Value::String(v) => v.clone(),
            toml::Value::Table(t) => t
                .get("version")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| {
                    t.get("git")
                        .and_then(|v| v.as_str())
                        .map(|s| format!("git:{}", s))
                })
                .or_else(|| {
                    t.get("path")
                        .and_then(|v| v.as_str())
                        .map(|s| format!("path:{}", s))
                })
                .unwrap_or_else(|| "*".to_string()),
            _ => "*".to_string(),
        };

        let optional = value
            .as_table()
            .and_then(|t| t.get("optional"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let mut dep = Dependency::new(name, &version, Ecosystem::Cargo);
        dep.dev_dependency = is_dev;
        dep.optional = optional;
        dep.source = Some("https://crates.io".to_string());

        Ok(dep)
    }

    /// Parse Cargo.lock for all transitive Rust dependencies
    /// This provides a more complete picture than Cargo.toml alone
    pub fn parse_cargo_lock(&self, path: &Path) -> Result<Vec<Dependency>, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read Cargo.lock: {}", e))?;

        let parsed: toml::Value =
            toml::from_str(&content).map_err(|e| format!("Failed to parse Cargo.lock: {}", e))?;

        let mut deps = Vec::new();

        if let Some(packages) = parsed.get("package").and_then(|v| v.as_array()) {
            for pkg in packages {
                let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("");
                let source = pkg.get("source").and_then(|v| v.as_str()).map(String::from);
                let checksum = pkg
                    .get("checksum")
                    .and_then(|v| v.as_str())
                    .map(String::from);

                if !name.is_empty() {
                    let mut dep = Dependency::new(name, version, Ecosystem::Cargo);
                    dep.source = source;
                    dep.checksum = checksum;
                    deps.push(dep);
                }
            }
        }

        // Enrich with known license information
        self.enrich_crate_licenses(&mut deps);

        Ok(deps)
    }

    /// Parse package.json for Node.js dependencies
    pub fn parse_package_json(&self, path: &Path) -> Result<Vec<Dependency>, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read package.json: {}", e))?;

        let parsed: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse package.json: {}", e))?;

        let mut deps = Vec::new();

        // Parse dependencies
        if let Some(dependencies) = parsed.get("dependencies").and_then(|v| v.as_object()) {
            for (name, value) in dependencies {
                let version = value.as_str().unwrap_or("*");
                let mut dep = Dependency::new(name, version, Ecosystem::Npm);
                dep.source = Some("https://registry.npmjs.org".to_string());
                deps.push(dep);
            }
        }

        // Parse devDependencies
        if let Some(dev_deps) = parsed.get("devDependencies").and_then(|v| v.as_object()) {
            for (name, value) in dev_deps {
                let version = value.as_str().unwrap_or("*");
                let mut dep = Dependency::new(name, version, Ecosystem::Npm);
                dep.dev_dependency = true;
                dep.source = Some("https://registry.npmjs.org".to_string());
                deps.push(dep);
            }
        }

        // Parse peerDependencies
        if let Some(peer_deps) = parsed.get("peerDependencies").and_then(|v| v.as_object()) {
            for (name, value) in peer_deps {
                let version = value.as_str().unwrap_or("*");
                let mut dep = Dependency::new(name, version, Ecosystem::Npm);
                dep.optional = true;
                dep.source = Some("https://registry.npmjs.org".to_string());
                deps.push(dep);
            }
        }

        // Parse optionalDependencies
        if let Some(opt_deps) = parsed
            .get("optionalDependencies")
            .and_then(|v| v.as_object())
        {
            for (name, value) in opt_deps {
                let version = value.as_str().unwrap_or("*");
                let mut dep = Dependency::new(name, version, Ecosystem::Npm);
                dep.optional = true;
                dep.source = Some("https://registry.npmjs.org".to_string());
                deps.push(dep);
            }
        }

        Ok(deps)
    }

    /// Parse requirements.txt for Python dependencies
    pub fn parse_requirements_txt(&self, path: &Path) -> Result<Vec<Dependency>, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read requirements.txt: {}", e))?;

        let mut deps = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Skip -r, -e, -c options
            if line.starts_with('-') {
                continue;
            }

            // Parse requirement specifier
            // Formats: package==1.0, package>=1.0, package~=1.0, package[extras]==1.0
            let (name, version) = self.parse_python_requirement(line)?;

            let mut dep = Dependency::new(&name, &version, Ecosystem::PyPI);
            dep.source = Some("https://pypi.org".to_string());
            deps.push(dep);
        }

        Ok(deps)
    }

    fn parse_python_requirement(&self, spec: &str) -> Result<(String, String), String> {
        // Remove comments
        let spec = spec.split('#').next().unwrap_or(spec).trim();

        // Remove extras like [dev,test]
        let spec = if let Some(bracket_pos) = spec.find('[') {
            if let Some(close_pos) = spec.find(']') {
                format!("{}{}", &spec[..bracket_pos], &spec[close_pos + 1..])
            } else {
                spec.to_string()
            }
        } else {
            spec.to_string()
        };

        // Find version specifier
        let version_ops = ["===", "==", "!=", "~=", ">=", "<=", ">", "<"];

        for op in version_ops {
            if let Some(pos) = spec.find(op) {
                let name = spec[..pos].trim().to_string();
                let version = spec[pos..].trim().to_string();
                return Ok((name, version));
            }
        }

        // No version specified
        Ok((spec.trim().to_string(), "*".to_string()))
    }

    /// Parse go.mod for Go dependencies
    pub fn parse_go_mod(&self, path: &Path) -> Result<Vec<Dependency>, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("Failed to read go.mod: {}", e))?;

        let mut deps = Vec::new();
        let mut in_require = false;

        for line in content.lines() {
            let line = line.trim();

            // Skip comments
            if line.starts_with("//") {
                continue;
            }

            // Check for require block start
            if line.starts_with("require (") || line == "require (" {
                in_require = true;
                continue;
            }

            // Check for block end
            if line == ")" {
                in_require = false;
                continue;
            }

            // Single-line require
            if line.starts_with("require ") && !line.contains('(') {
                let parts: Vec<&str> = line
                    .strip_prefix("require ")
                    .unwrap()
                    .split_whitespace()
                    .collect();
                if parts.len() >= 2 {
                    let name = parts[0];
                    let version = parts[1];
                    let mut dep = Dependency::new(name, version, Ecosystem::Go);
                    dep.source = Some("https://proxy.golang.org".to_string());
                    deps.push(dep);
                }
                continue;
            }

            // Inside require block
            if in_require && !line.is_empty() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let name = parts[0];
                    let version = parts[1];
                    let is_indirect = line.contains("// indirect");

                    let mut dep = Dependency::new(name, version, Ecosystem::Go);
                    dep.source = Some("https://proxy.golang.org".to_string());
                    dep.optional = is_indirect;
                    deps.push(dep);
                }
            }
        }

        Ok(deps)
    }

    /// Generate SBOM in specified format
    ///
    /// Phase C1: Added `compact` parameter to control JSON formatting.
    /// When `compact` is true, outputs minified JSON without whitespace (~25% smaller).
    pub fn generate_sbom(
        &self,
        project_path: &Path,
        project_name: &str,
        project_version: &str,
        format: SbomFormat,
        compact: bool,
    ) -> Result<String, String> {
        let deps = self.parse_dependencies(project_path)?;

        let sbom = self.create_sbom(project_name, project_version, deps, format);

        match format {
            SbomFormat::CycloneDX => self.render_cyclonedx(&sbom, compact),
            SbomFormat::Spdx => self.render_spdx(&sbom, compact),
            SbomFormat::Json => {
                if compact {
                    serde_json::to_string(&sbom)
                        .map_err(|e| format!("Failed to serialize SBOM: {}", e))
                } else {
                    serde_json::to_string_pretty(&sbom)
                        .map_err(|e| format!("Failed to serialize SBOM: {}", e))
                }
            }
        }
    }

    fn create_sbom(
        &self,
        project_name: &str,
        project_version: &str,
        deps: Vec<Dependency>,
        format: SbomFormat,
    ) -> Sbom {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let serial = format!("urn:uuid:{}", uuid::Uuid::new_v4());

        let root_component = SbomComponent {
            bom_ref: format!("{}@{}", project_name, project_version),
            component_type: "application".to_string(),
            name: project_name.to_string(),
            version: project_version.to_string(),
            purl: None,
            licenses: Vec::new(),
            hashes: Vec::new(),
            external_references: Vec::new(),
        };

        let components: Vec<SbomComponent> = deps
            .iter()
            .map(|dep| SbomComponent {
                bom_ref: format!("{}@{}", dep.name, dep.version),
                component_type: "library".to_string(),
                name: dep.name.clone(),
                version: dep.version.clone(),
                purl: Some(dep.purl()),
                licenses: dep.license.iter().cloned().collect(),
                hashes: dep
                    .checksum
                    .iter()
                    .map(|h| SbomHash {
                        alg: "SHA-256".to_string(),
                        content: h.clone(),
                    })
                    .collect(),
                external_references: dep
                    .source
                    .iter()
                    .map(|s| SbomExternalRef {
                        ref_type: "vcs".to_string(),
                        url: s.clone(),
                    })
                    .collect(),
            })
            .collect();

        let dependencies: Vec<SbomDependency> = deps
            .iter()
            .map(|dep| SbomDependency {
                ref_id: format!("{}@{}", dep.name, dep.version),
                depends_on: dep.dependencies.clone(),
            })
            .collect();

        Sbom {
            format,
            spec_version: match format {
                SbomFormat::CycloneDX => "1.5".to_string(),
                SbomFormat::Spdx => "2.3".to_string(),
                SbomFormat::Json => "1.0".to_string(),
            },
            serial_number: serial,
            version: 1,
            metadata: SbomMetadata {
                timestamp,
                tools: vec!["narsil-mcp".to_string()],
                component: Some(root_component),
            },
            components,
            dependencies,
        }
    }

    fn render_cyclonedx(&self, sbom: &Sbom, compact: bool) -> Result<String, String> {
        let mut output = serde_json::json!({
            "$schema": "https://cyclonedx.org/schema/bom-1.5.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": sbom.spec_version,
            "serialNumber": sbom.serial_number,
            "version": sbom.version,
            "metadata": {
                "timestamp": sbom.metadata.timestamp,
                "tools": sbom.metadata.tools.iter().map(|t| {
                    serde_json::json!({ "name": t })
                }).collect::<Vec<_>>()
            },
            "components": sbom.components.iter().map(|c| {
                let mut comp = serde_json::json!({
                    "bom-ref": c.bom_ref,
                    "type": c.component_type,
                    "name": c.name,
                    "version": c.version
                });
                if let Some(purl) = &c.purl {
                    comp["purl"] = serde_json::Value::String(purl.clone());
                }
                if !c.licenses.is_empty() {
                    comp["licenses"] = serde_json::json!(
                        c.licenses.iter().map(|l| {
                            serde_json::json!({ "license": { "id": l } })
                        }).collect::<Vec<_>>()
                    );
                }
                comp
            }).collect::<Vec<_>>(),
            "dependencies": sbom.dependencies.iter().map(|d| {
                serde_json::json!({
                    "ref": d.ref_id,
                    "dependsOn": d.depends_on
                })
            }).collect::<Vec<_>>()
        });

        // Add root component to metadata if present
        if let Some(root) = &sbom.metadata.component {
            output["metadata"]["component"] = serde_json::json!({
                "bom-ref": root.bom_ref,
                "type": root.component_type,
                "name": root.name,
                "version": root.version
            });
        }

        // Phase C1: Use compact or pretty JSON based on parameter
        if compact {
            serde_json::to_string(&output).map_err(|e| format!("Failed to render CycloneDX: {}", e))
        } else {
            serde_json::to_string_pretty(&output)
                .map_err(|e| format!("Failed to render CycloneDX: {}", e))
        }
    }

    fn render_spdx(&self, sbom: &Sbom, compact: bool) -> Result<String, String> {
        let doc_namespace = format!(
            "https://spdx.org/spdxdocs/{}-{}",
            sbom.metadata
                .component
                .as_ref()
                .map(|c| c.name.as_str())
                .unwrap_or("project"),
            sbom.serial_number
        );

        let output = serde_json::json!({
            "spdxVersion": format!("SPDX-{}", sbom.spec_version),
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": sbom.metadata.component.as_ref().map(|c| c.name.as_str()).unwrap_or("Unknown"),
            "documentNamespace": doc_namespace,
            "creationInfo": {
                "created": sbom.metadata.timestamp,
                "creators": sbom.metadata.tools.iter().map(|t| format!("Tool: {}", t)).collect::<Vec<_>>()
            },
            "packages": sbom.components.iter().enumerate().map(|(i, c)| {
                serde_json::json!({
                    "SPDXID": format!("SPDXRef-Package-{}", i),
                    "name": c.name,
                    "versionInfo": c.version,
                    "downloadLocation": c.external_references.first().map(|r| r.url.as_str()).unwrap_or("NOASSERTION"),
                    "filesAnalyzed": false,
                    "licenseConcluded": c.licenses.first().cloned().unwrap_or_else(|| "NOASSERTION".to_string()),
                    "licenseDeclared": c.licenses.first().cloned().unwrap_or_else(|| "NOASSERTION".to_string()),
                    "copyrightText": "NOASSERTION",
                    "externalRefs": c.purl.as_ref().map(|p| vec![serde_json::json!({
                        "referenceCategory": "PACKAGE_MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": p
                    })]).unwrap_or_default()
                })
            }).collect::<Vec<_>>(),
            "relationships": sbom.dependencies.iter().flat_map(|d| {
                d.depends_on.iter().map(|dep| {
                    serde_json::json!({
                        "spdxElementId": format!("SPDXRef-Package-{}", d.ref_id),
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": format!("SPDXRef-Package-{}", dep)
                    })
                }).collect::<Vec<_>>()
            }).collect::<Vec<_>>()
        });

        // Phase C1: Use compact or pretty JSON based on parameter
        if compact {
            serde_json::to_string(&output).map_err(|e| format!("Failed to render SPDX: {}", e))
        } else {
            serde_json::to_string_pretty(&output)
                .map_err(|e| format!("Failed to render SPDX: {}", e))
        }
    }

    /// Check dependencies for vulnerabilities using OSV API
    pub fn check_vulnerabilities(&self, deps: &[Dependency]) -> Vec<DependencyVuln> {
        deps.iter()
            .filter_map(|dep| {
                let vulns = self.query_osv(dep);
                if vulns.is_empty() {
                    None
                } else {
                    let risk_level = vulns
                        .iter()
                        .map(|v| v.severity)
                        .max()
                        .unwrap_or(VulnSeverity::Unknown);

                    let upgrade_to = vulns
                        .iter()
                        .filter_map(|v| v.fixed_versions.first())
                        .next()
                        .cloned();

                    Some(DependencyVuln {
                        dependency: dep.clone(),
                        vulnerabilities: vulns,
                        risk_level,
                        upgrade_to,
                    })
                }
            })
            .collect()
    }

    /// Query OSV API for vulnerabilities
    fn query_osv(&self, dep: &Dependency) -> Vec<Vulnerability> {
        // In a real implementation, this would make HTTP requests to:
        // https://api.osv.dev/v1/query
        // POST { "package": { "name": "...", "ecosystem": "..." }, "version": "..." }

        // For now, return built-in known vulnerabilities for demonstration
        self.get_known_vulnerabilities(dep)
    }

    /// Get known vulnerabilities from built-in database
    fn get_known_vulnerabilities(&self, dep: &Dependency) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Example known vulnerabilities (in production, this would query OSV)
        match dep.ecosystem {
            Ecosystem::Npm => {
                // lodash < 4.17.21 has prototype pollution
                if dep.name == "lodash" && self.version_lt(&dep.version, "4.17.21") {
                    vulns.push(Vulnerability {
                        id: "GHSA-jf85-cpcp-j695".to_string(),
                        aliases: vec!["CVE-2021-23337".to_string()],
                        summary: "Prototype Pollution in lodash".to_string(),
                        details: Some("Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.".to_string()),
                        severity: VulnSeverity::High,
                        cvss_score: Some(7.2),
                        affected_versions: vec!["< 4.17.21".to_string()],
                        fixed_versions: vec!["4.17.21".to_string()],
                        references: vec!["https://github.com/lodash/lodash/blob/master/CHANGELOG.md".to_string()],
                        published: Some("2021-02-15".to_string()),
                        modified: Some("2021-05-18".to_string()),
                    });
                }

                // axios < 1.6.0 has SSRF vulnerability
                if dep.name == "axios" && self.version_lt(&dep.version, "1.6.0") {
                    vulns.push(Vulnerability {
                        id: "GHSA-wf5p-g6vw-rhxx".to_string(),
                        aliases: vec!["CVE-2023-45857".to_string()],
                        summary: "Axios Cross-Site Request Forgery Vulnerability".to_string(),
                        details: Some("An issue was discovered in Axios before 1.6.0 that could lead to inadvertent credential exposure.".to_string()),
                        severity: VulnSeverity::Medium,
                        cvss_score: Some(6.5),
                        affected_versions: vec!["< 1.6.0".to_string()],
                        fixed_versions: vec!["1.6.0".to_string()],
                        references: vec!["https://github.com/axios/axios/releases/tag/v1.6.0".to_string()],
                        published: Some("2023-11-08".to_string()),
                        modified: Some("2023-11-10".to_string()),
                    });
                }
            }
            Ecosystem::PyPI => {
                // requests < 2.31.0 has vulnerability
                if dep.name == "requests" && self.version_lt(&dep.version, "2.31.0") {
                    vulns.push(Vulnerability {
                        id: "GHSA-j8r2-6x86-q33q".to_string(),
                        aliases: vec!["CVE-2023-32681".to_string()],
                        summary: "Unintended leak of Proxy-Authorization header in requests".to_string(),
                        details: Some("Since Requests 2.3.0, Requests has been leaking Proxy-Authorization headers to destination servers when redirected to an HTTPS endpoint.".to_string()),
                        severity: VulnSeverity::Medium,
                        cvss_score: Some(6.1),
                        affected_versions: vec![">=2.3.0,<2.31.0".to_string()],
                        fixed_versions: vec!["2.31.0".to_string()],
                        references: vec!["https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q".to_string()],
                        published: Some("2023-05-22".to_string()),
                        modified: Some("2023-05-26".to_string()),
                    });
                }
            }
            Ecosystem::Cargo => {
                // regex < 1.5.5 has ReDoS
                if dep.name == "regex" && self.version_lt(&dep.version, "1.5.5") {
                    vulns.push(Vulnerability {
                        id: "RUSTSEC-2022-0013".to_string(),
                        aliases: vec!["CVE-2022-24713".to_string()],
                        summary: "Regex denial of service".to_string(),
                        details: Some("The regex crate features built-in mitigations to prevent untrusted regexes from consuming arbitrary CPU time and memory during parsing and compilation. However, the mitigations could be bypassed.".to_string()),
                        severity: VulnSeverity::High,
                        cvss_score: Some(7.5),
                        affected_versions: vec!["< 1.5.5".to_string()],
                        fixed_versions: vec!["1.5.5".to_string()],
                        references: vec!["https://rustsec.org/advisories/RUSTSEC-2022-0013.html".to_string()],
                        published: Some("2022-03-08".to_string()),
                        modified: Some("2022-03-08".to_string()),
                    });
                }
            }
            Ecosystem::Go => {
                // net/http in Go has various vulnerabilities based on version
                if dep.name.contains("golang.org/x/net") && self.version_lt(&dep.version, "0.17.0")
                {
                    vulns.push(Vulnerability {
                        id: "GO-2023-2102".to_string(),
                        aliases: vec!["CVE-2023-44487".to_string()],
                        summary: "HTTP/2 rapid reset attack".to_string(),
                        details: Some("A malicious HTTP/2 client can rapidly reset streams and cause extreme resource consumption.".to_string()),
                        severity: VulnSeverity::High,
                        cvss_score: Some(7.5),
                        affected_versions: vec!["< 0.17.0".to_string()],
                        fixed_versions: vec!["0.17.0".to_string()],
                        references: vec!["https://pkg.go.dev/vuln/GO-2023-2102".to_string()],
                        published: Some("2023-10-10".to_string()),
                        modified: Some("2023-10-12".to_string()),
                    });
                }
            }
            _ => {}
        }

        vulns
    }

    /// Simple version comparison (for demonstration)
    fn version_lt(&self, version: &str, than: &str) -> bool {
        // Handle version ranges and prefixes
        let version = version.trim_start_matches(['=', '>', '<', '~', '^', 'v']);
        let than = than.trim_start_matches(['=', '>', '<', '~', '^', 'v']);

        // Split into parts
        let v_parts: Vec<u32> = version
            .split(['.', '-'])
            .filter_map(|p| p.parse().ok())
            .collect();
        let t_parts: Vec<u32> = than
            .split(['.', '-'])
            .filter_map(|p| p.parse().ok())
            .collect();

        // Compare
        for (v, t) in v_parts.iter().zip(t_parts.iter()) {
            if v < t {
                return true;
            }
            if v > t {
                return false;
            }
        }

        v_parts.len() < t_parts.len()
    }

    /// Check license compliance
    pub fn check_licenses(
        &self,
        deps: &[Dependency],
        project_license: Option<&str>,
    ) -> LicenseReport {
        let mut by_license: HashMap<String, Vec<String>> = HashMap::new();
        let mut issues = Vec::new();
        let mut copyleft = Vec::new();
        let mut permissive = Vec::new();
        let mut unknown = Vec::new();

        for dep in deps {
            let license_id = dep.license.clone().unwrap_or_else(|| "UNKNOWN".to_string());

            by_license
                .entry(license_id.clone())
                .or_default()
                .push(dep.name.clone());

            if let Some(license) = self.known_licenses.get(&license_id.to_lowercase()) {
                if license.is_copyleft {
                    copyleft.push(dep.name.clone());

                    // Check if copyleft is compatible with project license
                    if let Some(proj_lic) = project_license {
                        if !self.is_license_compatible(proj_lic, &license_id) {
                            issues.push(LicenseIssue {
                                dependency: dep.name.clone(),
                                license: license_id.clone(),
                                issue_type: LicenseIssueType::Copyleft,
                                message: format!(
                                    "Copyleft license '{}' may require source disclosure",
                                    license_id
                                ),
                                recommendation:
                                    "Review copyleft obligations or find alternative dependency"
                                        .to_string(),
                            });
                        }
                    }
                } else if license.is_permissive {
                    permissive.push(dep.name.clone());
                }
            } else if license_id == "UNKNOWN" {
                unknown.push(dep.name.clone());
                issues.push(LicenseIssue {
                    dependency: dep.name.clone(),
                    license: license_id.clone(),
                    issue_type: LicenseIssueType::NoLicense,
                    message: "No license information available".to_string(),
                    recommendation: "Verify the license manually before using in production"
                        .to_string(),
                });
            } else {
                unknown.push(dep.name.clone());
                issues.push(LicenseIssue {
                    dependency: dep.name.clone(),
                    license: license_id.clone(),
                    issue_type: LicenseIssueType::Unknown,
                    message: format!("Unknown license identifier: {}", license_id),
                    recommendation: "Review license terms manually".to_string(),
                });
            }
        }

        let summary = format!(
            "{} dependencies: {} permissive, {} copyleft, {} unknown, {} issues",
            deps.len(),
            permissive.len(),
            copyleft.len(),
            unknown.len(),
            issues.len()
        );

        LicenseReport {
            project_license: project_license.map(|s| s.to_string()),
            dependencies_by_license: by_license,
            issues,
            copyleft_deps: copyleft,
            permissive_deps: permissive,
            unknown_license_deps: unknown,
            summary,
        }
    }

    fn is_license_compatible(&self, project: &str, dep_license: &str) -> bool {
        let proj_lower = project.to_lowercase();
        let dep_lower = dep_license.to_lowercase();

        // Same license is always compatible
        if proj_lower == dep_lower {
            return true;
        }

        // Check compatibility matrix
        if let Some(compatible) = self.license_compatibility.get(&proj_lower) {
            return compatible.contains(&dep_lower);
        }

        // Permissive licenses are generally compatible with everything
        if let Some(license) = self.known_licenses.get(&dep_lower) {
            return license.is_permissive;
        }

        false
    }

    /// Find upgrade path for vulnerable dependencies
    pub fn find_upgrade_path(&self, vulns: &[DependencyVuln]) -> Vec<UpgradeRecommendation> {
        vulns
            .iter()
            .filter_map(|v| {
                let recommended = v.upgrade_to.clone().or_else(|| {
                    v.vulnerabilities
                        .iter()
                        .filter_map(|vuln| vuln.fixed_versions.first())
                        .next()
                        .cloned()
                })?;

                Some(UpgradeRecommendation {
                    dependency: v.dependency.name.clone(),
                    current_version: v.dependency.version.clone(),
                    recommended_version: recommended,
                    reason: UpgradeReason::Security,
                    breaking_changes: self.has_major_version_change(
                        &v.dependency.version,
                        v.upgrade_to.as_deref().unwrap_or("0.0.0"),
                    ),
                    vulnerabilities_fixed: v
                        .vulnerabilities
                        .iter()
                        .map(|vuln| vuln.id.clone())
                        .collect(),
                })
            })
            .collect()
    }

    fn has_major_version_change(&self, from: &str, to: &str) -> bool {
        let from_major: Option<u32> = from
            .trim_start_matches(['v', '^', '~', '=', '>', '<'])
            .split('.')
            .next()
            .and_then(|s| s.parse().ok());
        let to_major: Option<u32> = to
            .trim_start_matches(['v', '^', '~', '=', '>', '<'])
            .split('.')
            .next()
            .and_then(|s| s.parse().ok());

        match (from_major, to_major) {
            (Some(f), Some(t)) => f != t,
            _ => false,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn create_temp_file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        path
    }

    // ========================================================================
    // Ecosystem Tests
    // ========================================================================

    #[test]
    fn test_ecosystem_from_file() {
        assert_eq!(Ecosystem::from_file("Cargo.toml"), Ecosystem::Cargo);
        assert_eq!(Ecosystem::from_file("Cargo.lock"), Ecosystem::Cargo);
        assert_eq!(Ecosystem::from_file("package.json"), Ecosystem::Npm);
        assert_eq!(Ecosystem::from_file("requirements.txt"), Ecosystem::PyPI);
        assert_eq!(Ecosystem::from_file("go.mod"), Ecosystem::Go);
        assert_eq!(Ecosystem::from_file("pom.xml"), Ecosystem::Maven);
        assert_eq!(Ecosystem::from_file("MyProject.csproj"), Ecosystem::NuGet);
        assert_eq!(Ecosystem::from_file("unknown.txt"), Ecosystem::Unknown);
    }

    #[test]
    fn test_ecosystem_manifest_files() {
        assert!(Ecosystem::Cargo.manifest_files().contains(&"Cargo.toml"));
        assert!(Ecosystem::Npm.manifest_files().contains(&"package.json"));
        assert!(Ecosystem::PyPI
            .manifest_files()
            .contains(&"requirements.txt"));
        assert!(Ecosystem::Go.manifest_files().contains(&"go.mod"));
    }

    // ========================================================================
    // Dependency Tests
    // ========================================================================

    #[test]
    fn test_dependency_purl() {
        let dep = Dependency::new("serde", "1.0.0", Ecosystem::Cargo);
        assert_eq!(dep.purl(), "pkg:cargo/serde@1.0.0");

        let npm_dep = Dependency::new("lodash", "4.17.21", Ecosystem::Npm);
        assert_eq!(npm_dep.purl(), "pkg:npm/lodash@4.17.21");

        let py_dep = Dependency::new("requests", "2.28.0", Ecosystem::PyPI);
        assert_eq!(py_dep.purl(), "pkg:pypi/requests@2.28.0");
    }

    // ========================================================================
    // Cargo.toml Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_cargo_toml() {
        let dir = TempDir::new().unwrap();
        let content = r#"
[package]
name = "test-project"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"

[dev-dependencies]
criterion = "0.5"

[build-dependencies]
cc = "1.0"
"#;
        create_temp_file(&dir, "Cargo.toml", content);

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer
            .parse_cargo_toml(&dir.path().join("Cargo.toml"))
            .unwrap();

        assert!(deps.len() >= 4);
        assert!(deps.iter().any(|d| d.name == "serde" && d.version == "1.0"));
        assert!(deps.iter().any(|d| d.name == "tokio" && d.version == "1.0"));
        assert!(deps
            .iter()
            .any(|d| d.name == "criterion" && d.dev_dependency));
    }

    #[test]
    fn test_parse_cargo_with_git_dependency() {
        let dir = TempDir::new().unwrap();
        let content = r#"
[dependencies]
my-crate = { git = "https://github.com/example/my-crate" }
"#;
        create_temp_file(&dir, "Cargo.toml", content);

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer
            .parse_cargo_toml(&dir.path().join("Cargo.toml"))
            .unwrap();

        assert_eq!(deps.len(), 1);
        assert!(deps[0].version.starts_with("git:"));
    }

    #[test]
    fn test_parse_cargo_optional_dependency() {
        let dir = TempDir::new().unwrap();
        let content = r#"
[dependencies]
serde_json = { version = "1.0", optional = true }
"#;
        create_temp_file(&dir, "Cargo.toml", content);

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer
            .parse_cargo_toml(&dir.path().join("Cargo.toml"))
            .unwrap();

        assert_eq!(deps.len(), 1);
        assert!(deps[0].optional);
    }

    // ========================================================================
    // package.json Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_package_json() {
        let dir = TempDir::new().unwrap();
        let content = r#"
{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.21",
    "axios": "^1.0.0"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}
"#;
        create_temp_file(&dir, "package.json", content);

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer
            .parse_package_json(&dir.path().join("package.json"))
            .unwrap();

        assert_eq!(deps.len(), 3);
        assert!(deps.iter().any(|d| d.name == "lodash" && !d.dev_dependency));
        assert!(deps.iter().any(|d| d.name == "jest" && d.dev_dependency));
    }

    #[test]
    fn test_parse_package_json_peer_deps() {
        let dir = TempDir::new().unwrap();
        let content = r#"
{
  "name": "test",
  "peerDependencies": {
    "react": "^18.0.0"
  },
  "optionalDependencies": {
    "fsevents": "^2.0.0"
  }
}
"#;
        create_temp_file(&dir, "package.json", content);

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer
            .parse_package_json(&dir.path().join("package.json"))
            .unwrap();

        assert_eq!(deps.len(), 2);
        assert!(deps.iter().all(|d| d.optional));
    }

    // ========================================================================
    // requirements.txt Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_requirements_txt() {
        let dir = TempDir::new().unwrap();
        let content = r#"
# Production dependencies
requests==2.28.0
flask>=2.0.0
django~=4.0

# With extras
celery[redis]>=5.0.0
"#;
        create_temp_file(&dir, "requirements.txt", content);

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer
            .parse_requirements_txt(&dir.path().join("requirements.txt"))
            .unwrap();

        assert_eq!(deps.len(), 4);
        assert!(deps
            .iter()
            .any(|d| d.name == "requests" && d.version == "==2.28.0"));
        assert!(deps
            .iter()
            .any(|d| d.name == "flask" && d.version == ">=2.0.0"));
        assert!(deps
            .iter()
            .any(|d| d.name == "celery" && d.version == ">=5.0.0"));
    }

    #[test]
    fn test_parse_requirements_with_comments() {
        let dir = TempDir::new().unwrap();
        let content = r#"
# This is a comment
requests  # inline comment
numpy>=1.0  # another comment
"#;
        create_temp_file(&dir, "requirements.txt", content);

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer
            .parse_requirements_txt(&dir.path().join("requirements.txt"))
            .unwrap();

        assert_eq!(deps.len(), 2);
        assert!(deps
            .iter()
            .any(|d| d.name == "requests" && d.version == "*"));
        assert!(deps
            .iter()
            .any(|d| d.name == "numpy" && d.version == ">=1.0"));
    }

    // ========================================================================
    // go.mod Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_go_mod() {
        let dir = TempDir::new().unwrap();
        let content = r#"
module github.com/example/project

go 1.21

require (
    github.com/gin-gonic/gin v1.9.0
    golang.org/x/net v0.17.0
    github.com/stretchr/testify v1.8.0 // indirect
)

require github.com/single/dep v1.0.0
"#;
        create_temp_file(&dir, "go.mod", content);

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer.parse_go_mod(&dir.path().join("go.mod")).unwrap();

        assert_eq!(deps.len(), 4);
        assert!(deps
            .iter()
            .any(|d| d.name == "github.com/gin-gonic/gin" && d.version == "v1.9.0"));
        assert!(deps
            .iter()
            .any(|d| d.name == "github.com/stretchr/testify" && d.optional));
        assert!(deps.iter().any(|d| d.name == "github.com/single/dep"));
    }

    // ========================================================================
    // SBOM Generation Tests
    // ========================================================================

    #[test]
    fn test_generate_sbom_cyclonedx() {
        let dir = TempDir::new().unwrap();
        let content = r#"
[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#;
        create_temp_file(&dir, "Cargo.toml", content);

        let analyzer = SupplyChainAnalyzer::new();
        let sbom = analyzer
            .generate_sbom(dir.path(), "test", "0.1.0", SbomFormat::CycloneDX, false)
            .unwrap();

        assert!(sbom.contains("CycloneDX"));
        assert!(sbom.contains("\"specVersion\": \"1.5\""));
        assert!(sbom.contains("serde"));
        assert!(sbom.contains("pkg:cargo/serde@1.0"));
    }

    #[test]
    fn test_generate_sbom_spdx() {
        let dir = TempDir::new().unwrap();
        let content = r#"
[package]
name = "test"

[dependencies]
tokio = "1.0"
"#;
        create_temp_file(&dir, "Cargo.toml", content);

        let analyzer = SupplyChainAnalyzer::new();
        let sbom = analyzer
            .generate_sbom(dir.path(), "test", "1.0.0", SbomFormat::Spdx, false)
            .unwrap();

        assert!(sbom.contains("SPDX-2.3"));
        assert!(sbom.contains("tokio"));
        assert!(sbom.contains("packages"));
    }

    #[test]
    fn test_generate_sbom_json() {
        let dir = TempDir::new().unwrap();
        let content = r#"{ "name": "test", "dependencies": { "lodash": "^4.0.0" } }"#;
        create_temp_file(&dir, "package.json", content);

        let analyzer = SupplyChainAnalyzer::new();
        let sbom = analyzer
            .generate_sbom(dir.path(), "test", "1.0.0", SbomFormat::Json, false)
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&sbom).unwrap();
        assert!(parsed.get("components").is_some());
        assert!(parsed.get("metadata").is_some());
    }

    // ========================================================================
    // Vulnerability Scanning Tests
    // ========================================================================

    #[test]
    fn test_check_vulnerabilities_lodash() {
        let analyzer = SupplyChainAnalyzer::new();
        let deps = vec![Dependency::new("lodash", "4.17.0", Ecosystem::Npm)];

        let vulns = analyzer.check_vulnerabilities(&deps);

        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].dependency.name, "lodash");
        assert!(!vulns[0].vulnerabilities.is_empty());
        assert!(vulns[0]
            .vulnerabilities
            .iter()
            .any(|v| v.id.contains("GHSA")));
    }

    #[test]
    fn test_check_vulnerabilities_safe_version() {
        let analyzer = SupplyChainAnalyzer::new();
        let deps = vec![Dependency::new("lodash", "4.17.21", Ecosystem::Npm)];

        let vulns = analyzer.check_vulnerabilities(&deps);
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_vulnerability_severity_from_cvss() {
        assert_eq!(VulnSeverity::from_cvss(9.5), VulnSeverity::Critical);
        assert_eq!(VulnSeverity::from_cvss(8.0), VulnSeverity::High);
        assert_eq!(VulnSeverity::from_cvss(5.0), VulnSeverity::Medium);
        assert_eq!(VulnSeverity::from_cvss(2.0), VulnSeverity::Low);
        assert_eq!(VulnSeverity::from_cvss(0.0), VulnSeverity::Unknown);
    }

    #[test]
    fn test_check_vulnerabilities_requests() {
        let analyzer = SupplyChainAnalyzer::new();
        let deps = vec![Dependency::new("requests", "2.28.0", Ecosystem::PyPI)];

        let vulns = analyzer.check_vulnerabilities(&deps);
        assert_eq!(vulns.len(), 1);
        assert!(vulns[0]
            .vulnerabilities
            .iter()
            .any(|v| v.aliases.contains(&"CVE-2023-32681".to_string())));
    }

    #[test]
    fn test_check_vulnerabilities_regex_crate() {
        let analyzer = SupplyChainAnalyzer::new();
        let deps = vec![Dependency::new("regex", "1.5.0", Ecosystem::Cargo)];

        let vulns = analyzer.check_vulnerabilities(&deps);
        assert_eq!(vulns.len(), 1);
        assert!(vulns[0]
            .vulnerabilities
            .iter()
            .any(|v| v.id.contains("RUSTSEC")));
    }

    // ========================================================================
    // License Compliance Tests
    // ========================================================================

    #[test]
    fn test_license_from_spdx() {
        let mit = License::from_spdx("MIT");
        assert!(mit.is_permissive);
        assert!(!mit.is_copyleft);
        assert!(mit.is_osi_approved);

        let gpl = License::from_spdx("GPL-3.0");
        assert!(gpl.is_copyleft);
        assert!(!gpl.is_permissive);
        assert!(gpl.is_osi_approved);
    }

    #[test]
    fn test_check_licenses_permissive() {
        let analyzer = SupplyChainAnalyzer::new();
        let mut dep = Dependency::new("serde", "1.0.0", Ecosystem::Cargo);
        dep.license = Some("MIT".to_string());

        let report = analyzer.check_licenses(&[dep], Some("MIT"));

        assert!(report.permissive_deps.contains(&"serde".to_string()));
        assert!(report.copyleft_deps.is_empty());
        assert!(report.issues.is_empty());
    }

    #[test]
    fn test_check_licenses_copyleft_warning() {
        let analyzer = SupplyChainAnalyzer::new();
        let mut dep = Dependency::new("some-lib", "1.0.0", Ecosystem::Cargo);
        dep.license = Some("GPL-3.0".to_string());

        let report = analyzer.check_licenses(&[dep], Some("MIT"));

        assert!(report.copyleft_deps.contains(&"some-lib".to_string()));
        assert!(!report.issues.is_empty());
        assert!(report
            .issues
            .iter()
            .any(|i| i.issue_type == LicenseIssueType::Copyleft));
    }

    #[test]
    fn test_check_licenses_unknown() {
        let analyzer = SupplyChainAnalyzer::new();
        let dep = Dependency::new("mystery-lib", "1.0.0", Ecosystem::Npm);

        let report = analyzer.check_licenses(&[dep], None);

        assert!(report
            .unknown_license_deps
            .contains(&"mystery-lib".to_string()));
        assert!(report
            .issues
            .iter()
            .any(|i| i.issue_type == LicenseIssueType::NoLicense));
    }

    #[test]
    fn test_license_compatibility_mit_apache() {
        let analyzer = SupplyChainAnalyzer::new();
        let mut deps = vec![
            Dependency::new("dep1", "1.0", Ecosystem::Cargo),
            Dependency::new("dep2", "1.0", Ecosystem::Cargo),
        ];
        deps[0].license = Some("MIT".to_string());
        deps[1].license = Some("Apache-2.0".to_string());

        let report = analyzer.check_licenses(&deps, Some("MIT"));

        // Both MIT and Apache-2.0 are permissive and compatible
        assert_eq!(report.permissive_deps.len(), 2);
    }

    // ========================================================================
    // Upgrade Path Tests
    // ========================================================================

    #[test]
    fn test_find_upgrade_path() {
        let analyzer = SupplyChainAnalyzer::new();
        let deps = vec![Dependency::new("lodash", "4.17.0", Ecosystem::Npm)];

        let vulns = analyzer.check_vulnerabilities(&deps);
        let upgrades = analyzer.find_upgrade_path(&vulns);

        assert_eq!(upgrades.len(), 1);
        assert_eq!(upgrades[0].dependency, "lodash");
        assert_eq!(upgrades[0].recommended_version, "4.17.21");
        assert_eq!(upgrades[0].reason, UpgradeReason::Security);
        assert!(!upgrades[0].breaking_changes);
    }

    #[test]
    fn test_breaking_change_detection() {
        let analyzer = SupplyChainAnalyzer::new();
        assert!(analyzer.has_major_version_change("1.0.0", "2.0.0"));
        assert!(!analyzer.has_major_version_change("1.0.0", "1.1.0"));
        assert!(!analyzer.has_major_version_change("1.0.0", "1.0.1"));
        assert!(analyzer.has_major_version_change("^1.0.0", "^2.0.0"));
    }

    // ========================================================================
    // Version Comparison Tests
    // ========================================================================

    #[test]
    fn test_version_comparison() {
        let analyzer = SupplyChainAnalyzer::new();
        assert!(analyzer.version_lt("1.0.0", "2.0.0"));
        assert!(analyzer.version_lt("1.0.0", "1.1.0"));
        assert!(analyzer.version_lt("1.0.0", "1.0.1"));
        assert!(!analyzer.version_lt("2.0.0", "1.0.0"));
        assert!(!analyzer.version_lt("1.0.0", "1.0.0"));
    }

    #[test]
    fn test_version_comparison_with_prefix() {
        let analyzer = SupplyChainAnalyzer::new();
        assert!(analyzer.version_lt("^1.0.0", "2.0.0"));
        assert!(analyzer.version_lt("~1.0.0", "1.1.0"));
        assert!(analyzer.version_lt("v1.0.0", "v2.0.0"));
        assert!(analyzer.version_lt(">=1.0.0", "2.0.0"));
    }

    // ========================================================================
    // Multi-ecosystem Tests
    // ========================================================================

    #[test]
    fn test_parse_multiple_ecosystems() {
        let dir = TempDir::new().unwrap();

        // Create Cargo.toml
        create_temp_file(
            &dir,
            "Cargo.toml",
            r#"
[dependencies]
serde = "1.0"
"#,
        );

        // Create package.json
        create_temp_file(
            &dir,
            "package.json",
            r#"
{ "dependencies": { "lodash": "^4.17.21" } }
"#,
        );

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer.parse_dependencies(dir.path()).unwrap();

        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.ecosystem == Ecosystem::Cargo));
        assert!(deps.iter().any(|d| d.ecosystem == Ecosystem::Npm));
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_empty_manifest() {
        let dir = TempDir::new().unwrap();
        create_temp_file(&dir, "Cargo.toml", "[package]\nname = \"empty\"");

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer
            .parse_cargo_toml(&dir.path().join("Cargo.toml"))
            .unwrap();

        assert!(deps.is_empty());
    }

    #[test]
    fn test_no_manifest_files() {
        let dir = TempDir::new().unwrap();

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer.parse_dependencies(dir.path()).unwrap();

        assert!(deps.is_empty());
    }

    // ========================================================================
    // Phase C1: Compact SBOM Tests
    // ========================================================================

    #[test]
    fn test_sbom_compact_json_smaller() {
        let dir = TempDir::new().unwrap();
        let content = r#"
[package]
name = "test-project"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"
thiserror = "1.0"
"#;
        create_temp_file(&dir, "Cargo.toml", content);

        let analyzer = SupplyChainAnalyzer::new();

        // Generate compact SBOM
        let compact = analyzer
            .generate_sbom(
                dir.path(),
                "test-project",
                "0.1.0",
                SbomFormat::CycloneDX,
                true, // compact
            )
            .unwrap();

        // Generate pretty SBOM
        let pretty = analyzer
            .generate_sbom(
                dir.path(),
                "test-project",
                "0.1.0",
                SbomFormat::CycloneDX,
                false, // not compact
            )
            .unwrap();

        // Compact should be smaller (at least 20% smaller due to removed whitespace)
        assert!(
            compact.len() < pretty.len(),
            "Compact ({} bytes) should be smaller than pretty ({} bytes)",
            compact.len(),
            pretty.len()
        );

        // Verify both are valid JSON
        let _: serde_json::Value =
            serde_json::from_str(&compact).expect("Compact should be valid JSON");
        let _: serde_json::Value =
            serde_json::from_str(&pretty).expect("Pretty should be valid JSON");
    }

    // ========================================================================
    // Phase D1: Parse License from Cargo.toml Tests
    // ========================================================================

    #[test]
    fn test_parse_cargo_toml_package_license() {
        let content = "[package]\nlicense = \"MIT\"";
        assert_eq!(
            SupplyChainAnalyzer::extract_cargo_project_license(content),
            Some("MIT".to_string())
        );
    }

    #[test]
    fn test_parse_cargo_toml_package_license_expression() {
        let content = "[package]\nlicense = \"MIT OR Apache-2.0\"";
        assert_eq!(
            SupplyChainAnalyzer::extract_cargo_project_license(content),
            Some("MIT OR Apache-2.0".to_string())
        );
    }

    #[test]
    fn test_parse_cargo_toml_no_license() {
        let content = "[package]\nname = \"test\"";
        assert_eq!(
            SupplyChainAnalyzer::extract_cargo_project_license(content),
            None
        );
    }

    // ========================================================================
    // Phase D2: Parse License from package.json Tests
    // ========================================================================

    #[test]
    fn test_parse_package_json_license_string() {
        let content = r#"{"license": "MIT"}"#;
        assert_eq!(
            SupplyChainAnalyzer::extract_npm_project_license(content),
            Some("MIT".to_string())
        );
    }

    #[test]
    fn test_parse_package_json_license_object() {
        // Deprecated format but still used
        let content =
            r#"{"license": {"type": "MIT", "url": "https://opensource.org/licenses/MIT"}}"#;
        assert_eq!(
            SupplyChainAnalyzer::extract_npm_project_license(content),
            Some("MIT".to_string())
        );
    }

    #[test]
    fn test_parse_package_json_licenses_array() {
        // Deprecated format but still used for dual licensing
        let content = r#"{"licenses": [{"type": "MIT"}, {"type": "Apache-2.0"}]}"#;
        assert_eq!(
            SupplyChainAnalyzer::extract_npm_project_license(content),
            Some("MIT OR Apache-2.0".to_string())
        );
    }

    #[test]
    fn test_parse_package_json_no_license() {
        let content = r#"{"name": "test"}"#;
        assert_eq!(
            SupplyChainAnalyzer::extract_npm_project_license(content),
            None
        );
    }

    // ========================================================================
    // Phase D3: Parse package-lock.json Tests
    // ========================================================================

    #[test]
    fn test_parse_package_lock_licenses() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "license": "MIT"
                },
                "node_modules/axios": {
                    "version": "1.6.0",
                    "license": "MIT"
                }
            }
        }"#;

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer.parse_package_lock_content(content).unwrap();

        assert_eq!(deps.len(), 2);
        assert!(deps
            .iter()
            .any(|d| d.name == "lodash" && d.license == Some("MIT".to_string())));
        assert!(deps
            .iter()
            .any(|d| d.name == "axios" && d.license == Some("MIT".to_string())));
    }

    #[test]
    fn test_parse_package_lock_v2_format() {
        // lockfileVersion 2 has both "packages" and "dependencies"
        let content = r#"{
            "lockfileVersion": 2,
            "packages": {
                "": {
                    "name": "my-project",
                    "version": "1.0.0"
                },
                "node_modules/express": {
                    "version": "4.18.2",
                    "license": "MIT"
                }
            }
        }"#;

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer.parse_package_lock_content(content).unwrap();

        assert!(deps
            .iter()
            .any(|d| d.name == "express" && d.license == Some("MIT".to_string())));
    }

    #[test]
    fn test_parse_package_lock_no_license_field() {
        let content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/some-pkg": {
                    "version": "1.0.0"
                }
            }
        }"#;

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer.parse_package_lock_content(content).unwrap();

        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "some-pkg");
        assert_eq!(deps[0].license, None);
    }

    // ========================================================================
    // Phase D4: npm License Enrichment Database Tests
    // ========================================================================

    #[test]
    fn test_npm_common_licenses_database() {
        let analyzer = SupplyChainAnalyzer::new();
        let mut deps = vec![
            Dependency::new("lodash", "4.17.21", Ecosystem::Npm),
            Dependency::new("express", "4.18.2", Ecosystem::Npm),
            Dependency::new("react", "18.2.0", Ecosystem::Npm),
        ];

        analyzer.enrich_npm_licenses(&mut deps);

        assert_eq!(
            deps[0].license,
            Some("MIT".to_string()),
            "lodash should be MIT"
        );
        assert_eq!(
            deps[1].license,
            Some("MIT".to_string()),
            "express should be MIT"
        );
        assert_eq!(
            deps[2].license,
            Some("MIT".to_string()),
            "react should be MIT"
        );
    }

    #[test]
    fn test_npm_enrichment_does_not_overwrite_existing() {
        let analyzer = SupplyChainAnalyzer::new();
        let mut deps = vec![Dependency::new("lodash", "4.17.21", Ecosystem::Npm)];
        deps[0].license = Some("Apache-2.0".to_string()); // Set a different license

        analyzer.enrich_npm_licenses(&mut deps);

        // Should NOT overwrite existing license
        assert_eq!(deps[0].license, Some("Apache-2.0".to_string()));
    }

    #[test]
    fn test_npm_enrichment_only_npm_ecosystem() {
        let analyzer = SupplyChainAnalyzer::new();
        let mut deps = vec![
            Dependency::new("lodash", "4.17.21", Ecosystem::Cargo), // Wrong ecosystem
        ];

        analyzer.enrich_npm_licenses(&mut deps);

        // Should NOT enrich Cargo deps
        assert_eq!(deps[0].license, None);
    }

    // ========================================================================
    // Phase D5: Integration Tests for License Sources
    // ========================================================================

    #[test]
    fn test_parse_dependencies_prefers_package_lock_for_licenses() {
        let dir = TempDir::new().unwrap();

        // Create package-lock.json with license info
        let lock_content = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "license": "MIT"
                }
            }
        }"#;
        create_temp_file(&dir, "package-lock.json", lock_content);

        // Create package.json (no license info per-dep)
        let pkg_content = r#"{ "dependencies": { "lodash": "^4.17.21" } }"#;
        create_temp_file(&dir, "package.json", pkg_content);

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer.parse_dependencies(dir.path()).unwrap();

        // Should have license from package-lock.json
        assert!(deps
            .iter()
            .any(|d| d.name == "lodash" && d.license == Some("MIT".to_string())));
    }

    #[test]
    fn test_parse_dependencies_applies_npm_enrichment() {
        let dir = TempDir::new().unwrap();

        // Create package.json with deps but no license in lock
        let pkg_content =
            r#"{ "dependencies": { "express": "^4.18.2", "unknown-pkg": "^1.0.0" } }"#;
        create_temp_file(&dir, "package.json", pkg_content);

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer.parse_dependencies(dir.path()).unwrap();

        // express should be enriched from database
        assert!(
            deps.iter()
                .any(|d| d.name == "express" && d.license == Some("MIT".to_string())),
            "express should have MIT license from enrichment database"
        );
        // unknown-pkg should remain without license
        assert!(
            deps.iter()
                .any(|d| d.name == "unknown-pkg" && d.license.is_none()),
            "unknown-pkg should have no license"
        );
    }

    #[test]
    fn test_license_detection_comprehensive() {
        let dir = TempDir::new().unwrap();

        // Create Cargo.toml with known packages
        let cargo_content = r#"
[package]
name = "test"
license = "MIT"

[dependencies]
serde = "1.0"
tokio = "1.0"
"#;
        create_temp_file(&dir, "Cargo.toml", cargo_content);

        // Create package.json with known packages
        let pkg_content = r#"{ "dependencies": { "lodash": "^4.17.21", "express": "^4.18.2" } }"#;
        create_temp_file(&dir, "package.json", pkg_content);

        let analyzer = SupplyChainAnalyzer::new();
        let deps = analyzer.parse_dependencies(dir.path()).unwrap();

        // Count how many have licenses
        let with_license = deps.iter().filter(|d| d.license.is_some()).count();
        let total = deps.len();

        // All 4 packages should have licenses (serde, tokio from Cargo db; lodash, express from npm db)
        assert_eq!(total, 4, "Should have 4 dependencies total");
        assert_eq!(
            with_license, 4,
            "All 4 packages should have licenses from enrichment"
        );
    }

    #[test]
    fn test_sbom_compact_all_formats() {
        let dir = TempDir::new().unwrap();
        let content = r#"
[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#;
        create_temp_file(&dir, "Cargo.toml", content);

        let analyzer = SupplyChainAnalyzer::new();

        // Test compact for all formats
        for format in [SbomFormat::CycloneDX, SbomFormat::Spdx, SbomFormat::Json] {
            let compact = analyzer
                .generate_sbom(dir.path(), "test", "0.1.0", format, true)
                .unwrap();
            let pretty = analyzer
                .generate_sbom(dir.path(), "test", "0.1.0", format, false)
                .unwrap();

            assert!(
                compact.len() <= pretty.len(),
                "Format {:?}: Compact ({} bytes) should be <= pretty ({} bytes)",
                format,
                compact.len(),
                pretty.len()
            );
        }
    }
}
