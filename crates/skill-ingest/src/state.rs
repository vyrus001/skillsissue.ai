use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use skills_core::canonical::{CanonicalSkill, archive_skill_tree};
use skills_core::csv_store::{initialize_csv, read_csv_records, write_csv_records_atomic};
use skills_core::lock::WorkspaceLock;
use skills_core::records::{DiscoveryRecord, IngestRejectionRecord, SCHEMA_VERSION, SkillRecord};
use skills_core::stable_id_v1;
use skills_core::time::utc_now_rfc3339;
use skills_core::{ArtifactValidationLimits, validate_skill_artifact};

use crate::prepare::PreparedSkill;

const ADAPTER_VERSION: &str = "skill-ingest/v1";

pub(crate) struct PendingIngest {
    pub prepared: PreparedSkill,
    pub canonical: CanonicalSkill,
    pub platform_id: String,
    pub source_url: String,
    pub source_revision: String,
    pub source_path: String,
    pub source_native_id: String,
}

pub(crate) struct PendingRejection {
    pub platform_id: String,
    pub source_url: String,
    pub source_revision: String,
    pub source_path: String,
    pub reason: String,
    pub adapter_version: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PersistSummary {
    pub new_skills: usize,
    pub new_discoveries: usize,
    pub duplicate_skills: usize,
    pub duplicate_discoveries: usize,
}

pub(crate) fn persist(repo_root: &Path, pending: Vec<PendingIngest>) -> Result<PersistSummary> {
    if pending.is_empty() {
        return Ok(PersistSummary::default());
    }
    let declared_metadata = pending
        .iter()
        .map(|item| {
            (
                item.canonical.skill_id.clone(),
                read_declared_metadata(item.prepared.root()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    // Compression and full archive validation are intentionally outside the
    // shared ledger lock so detonation/analysis readers are not blocked.
    let mut artifact_plans = plan_artifacts(repo_root, &pending)?;
    let observed_at = utc_now_rfc3339();
    let run_id = ingest_run_id(&observed_at, &pending);
    let _lock = WorkspaceLock::acquire(repo_root).context("acquire ingestion state lock")?;
    let data_dir = ensure_directory_beneath(repo_root, Path::new("data"))?;
    let skills_path = data_dir.join("skills.csv");
    let discoveries_path = data_dir.join("discoveries.csv");
    ensure_regular_file_or_absent(&skills_path)?;
    ensure_regular_file_or_absent(&discoveries_path)?;
    initialize_csv::<SkillRecord>(&skills_path)?;
    initialize_csv::<DiscoveryRecord>(&discoveries_path)?;

    let existing_skills: Vec<SkillRecord> = read_csv_records(&skills_path)?;
    let existing_discoveries: Vec<DiscoveryRecord> = read_csv_records(&discoveries_path)?;
    let mut skills = BTreeMap::new();
    for record in existing_skills {
        if record.schema_version != SCHEMA_VERSION {
            bail!(
                "skill {} has unsupported schema version {}",
                record.skill_id,
                record.schema_version
            );
        }
        let key = record.skill_id.clone();
        if skills.insert(key.clone(), record).is_some() {
            bail!("duplicate skill ID in existing state: {key}");
        }
    }
    let mut discoveries = BTreeMap::new();
    for record in existing_discoveries {
        if record.schema_version != SCHEMA_VERSION {
            bail!(
                "discovery {} has unsupported schema version {}",
                record.discovery_id,
                record.schema_version
            );
        }
        let key = record.discovery_id.clone();
        if discoveries.insert(key.clone(), record).is_some() {
            bail!("duplicate discovery ID in existing state: {key}");
        }
    }
    let mut archived = BTreeSet::new();
    let mut summary = PersistSummary::default();

    for item in pending {
        validate_canonical_identity(&item.canonical)?;
        let (bundle_relative, manifest_relative) = artifact_paths(&item.canonical.sha256)?;
        if archived.insert(item.canonical.skill_id.clone()) {
            artifact_plans
                .get_mut(&item.canonical.skill_id)
                .context("missing prepared artifact plan")?
                .install()?;
        }

        let metadata = declared_metadata
            .get(&item.canonical.skill_id)
            .cloned()
            .unwrap_or_default();
        let mut skill = SkillRecord::from_canonical(
            &item.canonical,
            bundle_relative,
            manifest_relative,
            observed_at.clone(),
        );
        skill.name = metadata.name;
        skill.publisher = metadata.publisher.clone();
        skill.declared_version = metadata.version;
        skill.entrypoint = Some("SKILL.md".to_owned());
        skill.license = metadata.license;
        match skills.get(&skill.skill_id) {
            Some(existing) => {
                summary.duplicate_skills += 1;
                ensure_same_skill(existing, &skill)?;
                skill.first_seen_at.clone_from(&existing.first_seen_at);
                if skill.name.is_none() {
                    skill.name.clone_from(&existing.name);
                }
                if skill.publisher.is_none() {
                    skill.publisher.clone_from(&existing.publisher);
                }
                if skill.declared_version.is_none() {
                    skill
                        .declared_version
                        .clone_from(&existing.declared_version);
                }
                if skill.license.is_none() {
                    skill.license.clone_from(&existing.license);
                }
            }
            None => summary.new_skills += 1,
        }
        skills.insert(skill.skill_id.clone(), skill);

        let discovery_id = discovery_id(
            &item.canonical.skill_id,
            &item.platform_id,
            &item.source_url,
            &item.source_revision,
            &item.source_path,
        );
        let mut discovery = DiscoveryRecord {
            schema_version: SCHEMA_VERSION,
            discovery_id: discovery_id.clone(),
            skill_id: item.canonical.skill_id,
            platform_id: item.platform_id,
            source_native_id: item.source_native_id,
            source_url: item.source_url,
            source_revision: Some(item.source_revision),
            source_path: Some(item.source_path),
            etag: None,
            publisher_display: metadata.publisher,
            published_at: None,
            first_seen_at: observed_at.clone(),
            last_seen_at: observed_at.clone(),
            ingest_run_id: run_id.clone(),
            adapter_version: ADAPTER_VERSION.to_owned(),
        };
        if let Some(existing) = discoveries.get(&discovery_id) {
            summary.duplicate_discoveries += 1;
            ensure_same_discovery(existing, &discovery)?;
            discovery.first_seen_at.clone_from(&existing.first_seen_at);
            if discovery.publisher_display.is_none() {
                discovery
                    .publisher_display
                    .clone_from(&existing.publisher_display);
            }
            if discovery.published_at.is_none() {
                discovery.published_at.clone_from(&existing.published_at);
            }
            if discovery.etag.is_none() {
                discovery.etag.clone_from(&existing.etag);
            }
        } else {
            summary.new_discoveries += 1;
        }
        discoveries.insert(discovery_id, discovery);
    }

    // Skills are committed before discoveries, so an interruption can at worst
    // leave an unreferenced content object, never a dangling discovery.
    write_csv_records_atomic(&skills_path, skills.into_values().collect::<Vec<_>>())?;
    write_csv_records_atomic(
        &discoveries_path,
        discoveries.into_values().collect::<Vec<_>>(),
    )?;
    Ok(summary)
}

pub(crate) fn persist_rejections(
    repo_root: &Path,
    pending: Vec<PendingRejection>,
) -> Result<usize> {
    if pending.is_empty() {
        return Ok(0);
    }
    let observed_at = utc_now_rfc3339();
    let _lock = WorkspaceLock::acquire(repo_root).context("acquire rejection ledger lock")?;
    let data_dir = ensure_directory_beneath(repo_root, Path::new("data"))?;
    let path = data_dir.join("ingest_rejections.csv");
    ensure_regular_file_or_absent(&path)?;
    initialize_csv::<IngestRejectionRecord>(&path)?;
    let existing: Vec<IngestRejectionRecord> = read_csv_records(&path)?;
    let mut records = BTreeMap::new();
    for record in existing {
        if record.schema_version != SCHEMA_VERSION {
            bail!(
                "rejection {} has unsupported schema version {}",
                record.rejection_id,
                record.schema_version
            );
        }
        let key = record.rejection_id.clone();
        if records.insert(key.clone(), record).is_some() {
            bail!("duplicate rejection ID in existing state: {key}");
        }
    }
    let mut inserted = 0;
    for rejection in pending {
        let rejection_id = rejection_id(
            &rejection.platform_id,
            &rejection.source_url,
            &rejection.source_revision,
            &rejection.source_path,
            &rejection.adapter_version,
        );
        let existing = records.get(&rejection_id);
        if existing.is_none() {
            inserted += 1;
        }
        let first_seen_at = existing
            .map(|record| record.first_seen_at.as_str().min(&observed_at).to_owned())
            .unwrap_or_else(|| observed_at.clone());
        let last_seen_at = existing
            .map(|record| record.last_seen_at.as_str().max(&observed_at).to_owned())
            .unwrap_or_else(|| observed_at.clone());
        let record = IngestRejectionRecord {
            schema_version: SCHEMA_VERSION,
            rejection_id: rejection_id.clone(),
            platform_id: rejection.platform_id,
            source_url: rejection.source_url,
            source_revision: rejection.source_revision,
            source_path: rejection.source_path,
            reason: existing
                .map(|record| record.reason.clone())
                .unwrap_or_else(|| sanitize_rejection_reason(&rejection.reason)),
            first_seen_at,
            last_seen_at,
            adapter_version: rejection.adapter_version,
        };
        records.insert(rejection_id, record);
    }
    write_csv_records_atomic(&path, records.into_values().collect::<Vec<_>>())?;
    Ok(inserted)
}

pub(crate) fn read_rejections(repo_root: &Path) -> Result<Vec<IngestRejectionRecord>> {
    let path = repo_root.join("data/ingest_rejections.csv");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            read_csv_records(path).map_err(Into::into)
        }
        Ok(_) => bail!(
            "rejection ledger must be a real regular file: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => {
            Err(error).with_context(|| format!("inspect rejection ledger {}", path.display()))
        }
    }
}

fn rejection_id(
    platform: &str,
    url: &str,
    revision: &str,
    path: &str,
    adapter_version: &str,
) -> String {
    stable_id_v1(
        "rejection",
        [
            platform.as_bytes(),
            url.as_bytes(),
            revision.as_bytes(),
            path.as_bytes(),
            adapter_version.as_bytes(),
        ],
    )
}

fn sanitize_rejection_reason(reason: &str) -> String {
    let mut sanitized = String::from("rejected: ");
    for character in reason.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if sanitized.len() + character.len_utf8() > 4_096 {
            break;
        }
        sanitized.push(character);
    }
    sanitized
}

fn artifact_paths(canonical_sha256: &str) -> Result<(String, String)> {
    if canonical_sha256.len() != 64
        || !canonical_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("canonical SHA-256 is not normalized lowercase hex");
    }
    let prefix = &canonical_sha256[..2];
    let base = format!("corpus/sha256/{prefix}/{canonical_sha256}");
    Ok((
        format!("{base}/bundle.tar.zst"),
        format!("{base}/manifest.json"),
    ))
}

fn plan_artifacts(
    repo_root: &Path,
    pending: &[PendingIngest],
) -> Result<BTreeMap<String, ArtifactPlan>> {
    let mut plans = BTreeMap::new();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for item in pending {
        if plans.contains_key(&item.canonical.skill_id) {
            continue;
        }
        validate_canonical_identity(&item.canonical)?;
        let (bundle_relative, manifest_relative) = artifact_paths(&item.canonical.sha256)?;
        let artifact_parent = Path::new(&bundle_relative)
            .parent()
            .context("bundle path has no parent")?;
        let parent = ensure_directory_beneath(repo_root, artifact_parent)?;
        let bundle = repo_root.join(&bundle_relative);
        let manifest = repo_root.join(&manifest_relative);
        ensure_regular_file_or_absent(&bundle)?;
        ensure_regular_file_or_absent(&manifest)?;

        let state = if validate_skill_artifact(
            &bundle,
            &manifest,
            &item.canonical,
            ArtifactValidationLimits::default(),
        )
        .is_ok()
        {
            ArtifactPlanState::Reuse {
                bundle: FileFingerprint::capture(&bundle)?,
                manifest: FileFingerprint::capture(&manifest)?,
            }
        } else {
            let suffix = format!(
                "{}-{nonce}-{}",
                std::process::id(),
                &item.canonical.sha256[..8]
            );
            let staged_bundle = parent.join(format!(".bundle-{suffix}.tmp"));
            let staged_manifest = parent.join(format!(".manifest-{suffix}.tmp"));
            ensure_regular_file_or_absent(&staged_bundle)?;
            ensure_regular_file_or_absent(&staged_manifest)?;
            let artifact =
                archive_skill_tree(item.prepared.root(), &staged_bundle, &staged_manifest)
                    .with_context(|| {
                        format!("stage canonical skill {}", item.canonical.skill_id)
                    })?;
            if artifact.canonical != item.canonical {
                bail!(
                    "staged skill changed during archival: {}",
                    item.canonical.skill_id
                );
            }
            validate_skill_artifact(
                &staged_bundle,
                &staged_manifest,
                &item.canonical,
                ArtifactValidationLimits::default(),
            )
            .with_context(|| format!("validate staged skill {}", item.canonical.skill_id))?;
            ArtifactPlanState::Staged {
                bundle: Some(staged_bundle),
                manifest: Some(staged_manifest),
            }
        };
        plans.insert(
            item.canonical.skill_id.clone(),
            ArtifactPlan {
                final_bundle: bundle,
                final_manifest: manifest,
                state,
            },
        );
    }
    Ok(plans)
}

struct ArtifactPlan {
    final_bundle: PathBuf,
    final_manifest: PathBuf,
    state: ArtifactPlanState,
}

enum ArtifactPlanState {
    Reuse {
        bundle: FileFingerprint,
        manifest: FileFingerprint,
    },
    Staged {
        bundle: Option<PathBuf>,
        manifest: Option<PathBuf>,
    },
}

impl ArtifactPlan {
    fn install(&mut self) -> Result<()> {
        ensure_regular_file_or_absent(&self.final_bundle)?;
        ensure_regular_file_or_absent(&self.final_manifest)?;
        match &mut self.state {
            ArtifactPlanState::Reuse { bundle, manifest } => {
                if FileFingerprint::capture(&self.final_bundle)? != *bundle
                    || FileFingerprint::capture(&self.final_manifest)? != *manifest
                {
                    bail!("validated artifact changed before ledger commit");
                }
            }
            ArtifactPlanState::Staged { bundle, manifest } => {
                let staged_bundle = bundle.as_ref().context("staged bundle already installed")?;
                let staged_manifest = manifest
                    .as_ref()
                    .context("staged manifest already installed")?;
                replace_file(staged_bundle, &self.final_bundle)?;
                *bundle = None;
                replace_file(staged_manifest, &self.final_manifest)?;
                *manifest = None;
                if let Some(parent) = self.final_bundle.parent() {
                    sync_directory(parent)?;
                }
            }
        }
        Ok(())
    }
}

impl Drop for ArtifactPlan {
    fn drop(&mut self) {
        if let ArtifactPlanState::Staged { bundle, manifest } = &self.state {
            if let Some(path) = bundle {
                let _ = fs::remove_file(path);
            }
            if let Some(path) = manifest {
                let _ = fs::remove_file(path);
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileFingerprint {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl FileFingerprint {
    fn capture(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("fingerprint artifact {}", path.display()))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!("artifact is not a real regular file: {}", path.display());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                len: metadata.len(),
                modified: metadata.modified().ok(),
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                len: metadata.len(),
                modified: metadata.modified().ok(),
            })
        }
    }
}

fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(windows)]
    if destination.exists() {
        fs::remove_file(destination)
            .with_context(|| format!("remove old artifact {}", destination.display()))?;
    }
    fs::rename(source, destination).with_context(|| {
        format!(
            "install staged artifact {} -> {}",
            source.display(),
            destination.display()
        )
    })
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    use std::fs::File;
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync artifact directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn ensure_directory_beneath(repo_root: &Path, relative: &Path) -> Result<PathBuf> {
    if relative.is_absolute() {
        bail!("repository storage path must be relative");
    }
    let canonical_root = fs::canonicalize(repo_root)
        .with_context(|| format!("canonicalize repository root {}", repo_root.display()))?;
    let mut current = canonical_root.clone();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            bail!("repository storage path is not normalized");
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => bail!(
                "repository storage component is not a real directory: {}",
                current.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).with_context(|| {
                    format!("create repository storage directory {}", current.display())
                })?;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect storage path {}", current.display()));
            }
        }
    }
    let resolved = fs::canonicalize(&current)
        .with_context(|| format!("canonicalize storage path {}", current.display()))?;
    if !resolved.starts_with(&canonical_root) {
        bail!("repository storage path escaped the repository root");
    }
    Ok(resolved)
}

fn ensure_regular_file_or_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => bail!(
            "repository state path is not a real regular file: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("inspect repository state path {}", path.display()))
        }
    }
}

fn validate_canonical_identity(canonical: &CanonicalSkill) -> Result<()> {
    let expected = format!("sha256:v1:{}", canonical.sha256);
    if canonical.skill_id != expected {
        bail!(
            "canonical skill ID/hash mismatch: expected {expected}, got {}",
            canonical.skill_id
        );
    }
    artifact_paths(&canonical.sha256)?;
    Ok(())
}

pub(crate) fn discovery_id(
    skill_id: &str,
    platform_id: &str,
    source_url: &str,
    revision: &str,
    source_path: &str,
) -> String {
    stable_id_v1(
        "discovery",
        [
            skill_id.as_bytes(),
            platform_id.as_bytes(),
            source_url.as_bytes(),
            revision.as_bytes(),
            source_path.as_bytes(),
        ],
    )
}

fn ingest_run_id(observed_at: &str, pending: &[PendingIngest]) -> String {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_be_bytes();
    let process_id = std::process::id().to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![observed_at.as_bytes(), &nonce, &process_id];
    for item in pending {
        parts.push(item.canonical.skill_id.as_bytes());
        parts.push(item.platform_id.as_bytes());
        parts.push(item.source_path.as_bytes());
    }
    stable_id_v1("ingest", parts)
}

fn ensure_same_skill(existing: &SkillRecord, incoming: &SkillRecord) -> Result<()> {
    if existing.sha256 != incoming.sha256
        || existing.blake3 != incoming.blake3
        || existing.canonicalization_version != incoming.canonicalization_version
        || existing.size_bytes != incoming.size_bytes
        || existing.file_count != incoming.file_count
    {
        bail!(
            "skill ID collision or corrupt existing record for {}",
            incoming.skill_id
        );
    }
    Ok(())
}

fn ensure_same_discovery(existing: &DiscoveryRecord, incoming: &DiscoveryRecord) -> Result<()> {
    if existing.skill_id != incoming.skill_id
        || existing.platform_id != incoming.platform_id
        || existing.source_native_id != incoming.source_native_id
        || existing.source_url != incoming.source_url
        || existing.source_revision != incoming.source_revision
        || existing.source_path != incoming.source_path
    {
        bail!(
            "discovery ID collision or corrupt existing record for {}",
            incoming.discovery_id
        );
    }
    Ok(())
}

#[derive(Clone, Default)]
struct DeclaredMetadata {
    name: Option<String>,
    publisher: Option<String>,
    version: Option<String>,
    license: Option<String>,
}

fn read_declared_metadata(skill_root: &Path) -> DeclaredMetadata {
    let Ok(bytes) = fs::read(skill_root.join("SKILL.md")) else {
        return DeclaredMetadata::default();
    };
    let text = String::from_utf8_lossy(&bytes);
    let mut lines = text.lines();
    if lines.next().map(str::trim) != Some("---") {
        return DeclaredMetadata::default();
    }
    let mut metadata = DeclaredMetadata::default();
    for line in lines.take(256) {
        let line = line.trim_end();
        if line.trim() == "---" {
            break;
        }
        // Only top-level scalar frontmatter is accepted. This intentionally
        // avoids executing parsers with YAML tags or resolving aliases.
        if line.starts_with(char::is_whitespace) || line.trim_start().starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = clean_scalar(value);
        match key.trim() {
            "name" => metadata.name = value,
            "publisher" | "author" => metadata.publisher = value,
            "version" => metadata.version = value,
            "license" => metadata.license = value,
            _ => {}
        }
    }
    metadata
}

fn clean_scalar(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || matches!(value, "null" | "Null" | "NULL" | "~")
        || value.len() > 1_024
        || value.chars().any(char::is_control)
    {
        return None;
    }
    let unquoted = if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    };
    if unquoted
        .bytes()
        .next()
        .is_some_and(|byte| matches!(byte, b'=' | b'+' | b'-' | b'@'))
    {
        return None;
    }
    Some(unquoted.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_layout_is_content_addressed() {
        let sha = "a".repeat(64);
        let (bundle, manifest) = artifact_paths(&sha).unwrap();
        assert_eq!(bundle, format!("corpus/sha256/aa/{sha}/bundle.tar.zst"));
        assert_eq!(manifest, format!("corpus/sha256/aa/{sha}/manifest.json"));
    }

    #[test]
    fn discovery_ids_are_domain_separated_and_unambiguous() {
        let first = discovery_id("ab", "c", "d", "e", "f");
        let second = discovery_id("a", "bc", "d", "e", "f");
        assert_ne!(first, second);
        assert_eq!(first, discovery_id("ab", "c", "d", "e", "f"));
    }

    #[test]
    fn extracts_safe_scalar_frontmatter_without_yaml_evaluation() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("SKILL.md"),
            "---\nname: \"fixture\"\nauthor: Example\nversion: 1.2.3\nlicense: Apache-2.0\nnested:\n  ignored: yes\n---\n# Body\n",
        )
        .unwrap();
        let metadata = read_declared_metadata(temp.path());
        assert_eq!(metadata.name.as_deref(), Some("fixture"));
        assert_eq!(metadata.publisher.as_deref(), Some("Example"));
        assert_eq!(metadata.version.as_deref(), Some("1.2.3"));
        assert_eq!(metadata.license.as_deref(), Some("Apache-2.0"));
    }

    #[test]
    fn rejects_spreadsheet_formula_metadata() {
        for value in ["=1+1", "+cmd", "-2+3", "@SUM(A1:A2)", "\"=quoted\""] {
            assert_eq!(clean_scalar(value), None);
        }
    }

    #[test]
    fn rejection_reasons_are_control_free_and_byte_bounded() {
        let reason = format!("bad\n{}", "💣".repeat(2_000));
        let sanitized = sanitize_rejection_reason(&reason);
        assert!(sanitized.starts_with("rejected: "));
        assert!(sanitized.len() <= 4_096);
        assert!(!sanitized.chars().any(char::is_control));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_repository_storage_paths() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), workspace.path().join("corpus")).unwrap();
        assert!(ensure_directory_beneath(workspace.path(), Path::new("corpus/sha256")).is_err());

        fs::create_dir(workspace.path().join("data")).unwrap();
        symlink(
            outside.path().join("skills.csv"),
            workspace.path().join("data/skills.csv"),
        )
        .unwrap();
        assert!(ensure_regular_file_or_absent(&workspace.path().join("data/skills.csv")).is_err());
    }
}
