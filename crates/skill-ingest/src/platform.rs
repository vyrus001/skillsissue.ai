use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use skills_core::csv_store::read_csv_records;
use skills_core::records::{PlatformRecord, SCHEMA_VERSION};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterKind {
    LocalDirectory,
    GitRepository,
    ClawhubApi,
    SitemapCatalog,
}

impl AdapterKind {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "local" | "directory" | "local-directory" => Ok(Self::LocalDirectory),
            "git" | "git-repository" | "repository" | "github" | "github-archive"
            | "git-archive" => Ok(Self::GitRepository),
            "clawhub-api" => Ok(Self::ClawhubApi),
            "catalog" | "sitemap-catalog" | "web-catalog" => Ok(Self::SitemapCatalog),
            other => bail!("unsupported ingestion adapter {other:?}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformSource {
    pub platform_id: String,
    pub name: String,
    pub adapter: AdapterKind,
    pub locator: String,
    pub source_path: Option<PathBuf>,
    pub revision: Option<String>,
    pub rate_limit_per_minute: Option<u32>,
}

/// Strictly schema-check the platform registry, then load only rows explicitly
/// marked supported and enabled.
pub fn load_enabled_platforms(path: &Path) -> Result<Vec<PlatformSource>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect platform registry {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!(
            "platform registry must be a real regular file: {}",
            path.display()
        );
    }
    let rows: Vec<PlatformRecord> = read_csv_records(path)
        .with_context(|| format!("read platform registry {}", path.display()))?;
    let mut seen = BTreeSet::new();
    let mut platforms = Vec::new();
    for row in rows {
        let platform_id = row.platform_id.trim().to_owned();
        if platform_id.is_empty() {
            bail!("{} contains an empty platform_id", path.display());
        }
        if !is_safe_id(&platform_id) {
            bail!(
                "{} contains unsafe platform_id {platform_id:?}",
                path.display()
            );
        }
        if !seen.insert(platform_id.clone()) {
            bail!(
                "{} contains duplicate platform_id {platform_id:?}",
                path.display()
            );
        }
        if row.schema_version != SCHEMA_VERSION {
            bail!(
                "{} platform {platform_id:?} has unsupported schema version {}",
                path.display(),
                row.schema_version
            );
        }
        if row.rate_limit_per_minute == Some(0) {
            bail!(
                "{} platform {platform_id:?} has a zero request rate limit",
                path.display()
            );
        }
        if !row.enabled || !row.status.eq_ignore_ascii_case("supported") {
            continue;
        }
        let adapter = AdapterKind::parse(&row.adapter)
            .with_context(|| format!("{} platform {platform_id:?}", path.display()))?;
        let locator = row.ingest_uri.trim().to_owned();
        if locator.is_empty() {
            bail!(
                "{}: enabled platform {platform_id:?} has no ingest_uri",
                path.display()
            );
        }
        platforms.push(PlatformSource {
            platform_id,
            name: row.display_name,
            adapter,
            locator,
            source_path: None,
            revision: None,
            rate_limit_per_minute: row.rate_limit_per_minute,
        });
    }
    platforms.sort_by(|left, right| left.platform_id.cmp(&right.platform_id));
    Ok(platforms)
}

fn is_safe_id(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use skills_core::csv_store::write_csv_records_atomic;
    use std::fs;

    #[test]
    fn loads_only_supported_enabled_rows_in_stable_order() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("platforms.csv");
        let mut disabled = platform("disabled", "local-directory", "fixtures");
        disabled.enabled = false;
        let mut future = platform("future", "local-directory", "fixtures");
        future.status = "candidate".to_owned();
        write_csv_records_atomic(
            &path,
            [
                platform("zed", "git-repository", "https://example.test/z.git"),
                disabled,
                platform("alpha", "local-directory", "fixtures"),
                future,
            ],
        )
        .unwrap();

        let rows = load_enabled_platforms(&path).unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row.platform_id.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "zed"]
        );
        assert!(rows.iter().all(|row| row.rate_limit_per_minute.is_none()));
    }

    #[test]
    fn rejects_duplicate_ids_even_when_one_is_disabled() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("platforms.csv");
        write_csv_records_atomic(&path, [platform("local", "local", "fixtures")]).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        let row = content.lines().nth(1).unwrap();
        fs::write(&path, format!("{content}{row}\r\n")).unwrap();
        assert!(
            load_enabled_platforms(&path)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn missing_registry_is_a_configuration_error() {
        let temp = tempfile::tempdir().unwrap();
        assert!(load_enabled_platforms(&temp.path().join("missing.csv")).is_err());
    }

    fn platform(id: &str, adapter: &str, ingest_uri: &str) -> PlatformRecord {
        PlatformRecord {
            schema_version: SCHEMA_VERSION,
            platform_id: id.to_owned(),
            display_name: id.to_owned(),
            canonical_domain: "example.invalid".to_owned(),
            base_url: "https://example.invalid".to_owned(),
            ingest_uri: ingest_uri.to_owned(),
            adapter: adapter.to_owned(),
            status: "supported".to_owned(),
            enabled: true,
            discovery_method: "test".to_owned(),
            confidence: 1.0,
            first_seen_at: None,
            last_seen_at: None,
            rate_limit_per_minute: None,
            terms_url: None,
            evidence_url: None,
            notes: None,
        }
    }
}
