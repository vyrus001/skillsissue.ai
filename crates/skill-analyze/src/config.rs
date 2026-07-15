use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;

#[derive(Clone, Debug)]
pub struct Policy {
    pub version: String,
    sensitive_globs: GlobSet,
    pub marker_prefix: String,
    pub allowed_write_roots: Vec<String>,
    pub trusted_egress_domains: Vec<String>,
    pub require_source_to_sink: bool,
    pub flag_untrusted_download_exec: bool,
    pub flag_persistence_writes: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawPolicy {
    schema_version: Option<u32>,
    version: String,
    policy_version: String,
    sensitive_path_globs: Vec<String>,
    allowed_write_roots: Vec<String>,
    trusted_egress_domains: Vec<String>,
    marker_prefix: String,
    require_source_to_sink: Option<bool>,
    flag_untrusted_download_exec: Option<bool>,
    flag_persistence_writes: Option<bool>,
    policy: Option<Box<RawPolicy>>,
}

impl Policy {
    pub fn load_or_default(path: &Path) -> Result<Self> {
        let raw = if path.exists() {
            let source = fs::read_to_string(path)
                .with_context(|| format!("reading policy config {}", path.display()))?;
            let mut decoded: RawPolicy = toml::from_str(&source)
                .with_context(|| format!("parsing policy config {}", path.display()))?;
            if let Some(nested) = decoded.policy.take() {
                *nested
            } else {
                decoded
            }
        } else {
            RawPolicy::default()
        };

        let sensitive = if raw.sensitive_path_globs.is_empty() {
            vec![
                "**/.ssh/**".to_string(),
                "**/.aws/**".to_string(),
                "**/.env".to_string(),
                "**/.env.*".to_string(),
                "**/*credential*".to_string(),
                "**/*secret*".to_string(),
            ]
        } else {
            raw.sensitive_path_globs
        };
        let mut builder = GlobSetBuilder::new();
        for pattern in sensitive {
            builder.add(
                Glob::new(&pattern)
                    .with_context(|| format!("invalid sensitive path glob {pattern:?}"))?,
            );
        }

        let schema_version = raw.schema_version.unwrap_or(1);
        if schema_version != 1 {
            anyhow::bail!("unsupported policy schema_version {schema_version}");
        }
        Ok(Self {
            version: if !raw.policy_version.is_empty() {
                raw.policy_version
            } else if raw.version.is_empty() {
                "default-v1".to_string()
            } else {
                raw.version
            },
            sensitive_globs: builder.build()?,
            marker_prefix: if raw.marker_prefix.is_empty() {
                "#data".to_string()
            } else {
                raw.marker_prefix
            },
            allowed_write_roots: if raw.allowed_write_roots.is_empty() {
                vec![
                    "/skill".to_string(),
                    "/skills".to_string(),
                    "/workspace/skill".to_string(),
                    "/opt/skill".to_string(),
                    "/tmp/skill-detonator".to_string(),
                ]
            } else {
                raw.allowed_write_roots
            },
            trusted_egress_domains: raw
                .trusted_egress_domains
                .into_iter()
                .map(|domain| normalize_domain(&domain))
                .filter(|domain| !domain.is_empty())
                .collect(),
            require_source_to_sink: raw.require_source_to_sink.unwrap_or(true),
            flag_untrusted_download_exec: raw.flag_untrusted_download_exec.unwrap_or(true),
            flag_persistence_writes: raw.flag_persistence_writes.unwrap_or(true),
        })
    }

    pub fn is_sensitive_path(&self, path: &str) -> bool {
        // Files shipped inside the skill closure are untrusted inputs, not host
        // secrets. Only synthetic/out-of-closure sensitive paths receive marks.
        if ["/work/skill", "/skill", "/skills", "/opt/skill"]
            .iter()
            .any(|root| path_is_within(path, root))
        {
            return false;
        }
        self.sensitive_globs.is_match(normalize_path(path))
    }

    pub fn is_allowed_write(&self, path: &str) -> bool {
        self.allowed_write_roots
            .iter()
            .any(|root| path_is_within(path, root))
    }

    pub fn is_trusted_domain(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        self.trusted_egress_domains
            .iter()
            .any(|trusted| domain == *trusted || domain.ends_with(&format!(".{trusted}")))
    }
}

#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    pub version: String,
    pub threshold: f64,
    pub domain_indicators: Vec<String>,
    pub path_indicators: Vec<String>,
    pub command_indicators: Vec<String>,
    pub ignored_domains: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawDiscoveryConfig {
    schema_version: Option<u32>,
    analyzer_version: String,
    auto_enable_candidates: Option<bool>,
    threshold: Option<f64>,
    confidence_threshold: Option<f64>,
    candidate_confidence_threshold: Option<f64>,
    domain_indicators: Vec<String>,
    path_indicators: Vec<String>,
    skill_path_indicators: Vec<String>,
    command_indicators: Vec<String>,
    download_indicators: Vec<String>,
    execution_indicators: Vec<String>,
    ignored_domains: Vec<String>,
    discovery: Option<Box<RawDiscoveryConfig>>,
}

impl DiscoveryConfig {
    pub fn load_or_default(path: &Path) -> Result<Self> {
        let raw = if path.exists() {
            let source = fs::read_to_string(path)
                .with_context(|| format!("reading discovery config {}", path.display()))?;
            let mut decoded: RawDiscoveryConfig = toml::from_str(&source)
                .with_context(|| format!("parsing discovery config {}", path.display()))?;
            if let Some(nested) = decoded.discovery.take() {
                *nested
            } else {
                decoded
            }
        } else {
            RawDiscoveryConfig::default()
        };

        let schema_version = raw.schema_version.unwrap_or(1);
        if schema_version != 1 {
            anyhow::bail!("unsupported discovery schema_version {schema_version}");
        }
        if raw.auto_enable_candidates.unwrap_or(false) {
            anyhow::bail!("auto_enable_candidates is forbidden; candidates require human review");
        }
        Ok(Self {
            version: if raw.analyzer_version.is_empty() {
                "platform-discovery-v1".into()
            } else {
                raw.analyzer_version
            },
            threshold: raw
                .threshold
                .or(raw.confidence_threshold)
                .or(raw.candidate_confidence_threshold)
                .unwrap_or(0.70)
                .clamp(0.0, 1.0),
            domain_indicators: defaults_if_empty(
                raw.domain_indicators,
                &[
                    "skill",
                    "skills",
                    "skillhub",
                    "marketplace",
                    "plugin",
                    "clawhub",
                ],
            ),
            path_indicators: defaults_if_empty(
                if raw.path_indicators.is_empty() {
                    raw.skill_path_indicators
                } else {
                    raw.path_indicators
                },
                &[
                    "/skill/",
                    "/skills/",
                    "/plugins/",
                    "/marketplace/",
                    "/install-skill",
                    "/api/skills",
                    "skill.json",
                    "skill.md",
                ],
            ),
            command_indicators: defaults_if_empty(
                if raw.command_indicators.is_empty() {
                    raw.download_indicators
                        .iter()
                        .flat_map(|download| {
                            raw.execution_indicators
                                .iter()
                                .map(move |execute| format!("{download} {execute}"))
                        })
                        .collect()
                } else {
                    raw.command_indicators
                },
                &[
                    "install skill",
                    "add skill",
                    "skill install",
                    "plugin install",
                ],
            ),
            ignored_domains: raw
                .ignored_domains
                .into_iter()
                .map(|domain| normalize_domain(&domain))
                .collect(),
        })
    }
}

fn defaults_if_empty(values: Vec<String>, defaults: &[&str]) -> Vec<String> {
    if values.is_empty() {
        defaults.iter().map(|value| (*value).to_string()).collect()
    } else {
        values
    }
}

pub fn normalize_domain(value: &str) -> String {
    value
        .trim()
        .trim_end_matches('.')
        .trim_start_matches("www.")
        .to_ascii_lowercase()
}

fn path_is_within(path: &str, root: &str) -> bool {
    if !path.starts_with('/') || !root.starts_with('/') {
        return false;
    }
    let path = path_components(path);
    let root = path_components(root);
    path.starts_with(&root)
}

fn normalize_path(path: &str) -> String {
    format!("/{}", path_components(path).join("/"))
}

fn path_components(path: &str) -> Vec<&str> {
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            component => components.push(component),
        }
    }
    components
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn path_roots_respect_component_boundaries() {
        assert!(path_is_within("/skill/output.txt", "/skill"));
        assert!(!path_is_within("/skill-escape/output.txt", "/skill"));
        assert!(!path_is_within("/skill/../../etc/profile", "/skill"));
    }

    #[test]
    fn repository_configs_use_supported_aliases() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let policy = Policy::load_or_default(&root.join("config/policy.toml")).unwrap();
        assert_eq!(policy.version, "skilldetonate-v2");
        assert_eq!(policy.marker_prefix, "#data_");
        assert!(policy.is_sensitive_path("/home/detonator/.ssh/id_ed25519"));
        assert!(policy.is_allowed_write("/tmp/download"));
        assert!(policy.is_allowed_write("/dev/null"));
        assert!(policy.is_allowed_write("/dev/tty"));
        assert!(policy.is_allowed_write("/sys/kernel/debug/tracing/trace_marker"));
        assert!(!policy.is_allowed_write("/dev/mem"));
        assert!(!policy.is_allowed_write("/dev/tty0"));
        assert!(!policy.is_allowed_write("/sys/kernel/debug/tracing/trace_marker_extra"));

        let discovery =
            DiscoveryConfig::load_or_default(&root.join("config/discovery.toml")).unwrap();
        assert_eq!(discovery.version, "platform-discovery-v2");
        assert_eq!(discovery.threshold, 0.75);
        assert!(discovery
            .path_indicators
            .iter()
            .any(|value| value == "/registry/"));
        assert!(discovery
            .ignored_domains
            .iter()
            .any(|value| value == "github.com"));
        assert!(discovery
            .ignored_domains
            .iter()
            .any(|value| value == "skillsissue-relay"));
    }
}
