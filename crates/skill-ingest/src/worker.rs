use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use skills_core::canonical::canonicalize_skill_tree;
use skills_core::csv_store::read_csv_records;
use skills_core::records::{DiscoveryRecord, SCHEMA_VERSION};

use crate::catalog::{CatalogCandidate, CatalogSource};
use crate::clawhub::{ClawhubCandidate, KnownDisposition};
use crate::git::{GitCheckout, clone_read_only};
use crate::platform::{AdapterKind, PlatformSource, load_enabled_platforms};
use crate::prepare::{
    SecurityLimits, discover_skill_directories, discover_skill_directories_filtered, prepare_skill,
};
use crate::state::{
    PendingIngest, PendingRejection, discovery_id, persist, persist_rejections, read_rejections,
};

const MAX_RETAINED_STAGE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_RETAINED_STAGE_ENTRIES: u64 = 32_768;
const MAX_TRANSIENT_PLATFORM_ERRORS: usize = 32;

#[derive(Clone, Debug)]
pub struct IngestRequest {
    pub path: PathBuf,
    pub platform_id: String,
    pub allow_unregistered_platform: bool,
    pub source_url: String,
    pub revision: String,
    pub limit: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct IngestSummary {
    pub platforms_checked: usize,
    pub discovered: usize,
    pub new_skills: usize,
    pub ingested: usize,
    pub duplicate_skills: usize,
    pub duplicate_discoveries: usize,
    pub rejected: usize,
    pub quarantined_skipped: usize,
    pub rejection_messages: Vec<String>,
    pub errors: Vec<String>,
}

impl IngestSummary {
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    fn absorb_persist(&mut self, persisted: crate::state::PersistSummary) {
        self.new_skills += persisted.new_skills;
        self.ingested += persisted.new_discoveries;
        self.duplicate_skills += persisted.duplicate_skills;
        self.duplicate_discoveries += persisted.duplicate_discoveries;
    }
}

#[derive(Clone, Debug)]
pub struct Worker {
    repo_root: PathBuf,
    limits: SecurityLimits,
    poll_sequence: Arc<AtomicU64>,
}

impl Worker {
    pub fn new(repo_root: impl AsRef<Path>, limits: SecurityLimits) -> Result<Self> {
        limits.validate()?;
        let repo_root = fs::canonicalize(repo_root.as_ref()).with_context(|| {
            format!(
                "canonicalize repository root {}",
                repo_root.as_ref().display()
            )
        })?;
        if !repo_root.is_dir() {
            bail!("repository root is not a directory");
        }
        Ok(Self {
            repo_root,
            limits,
            poll_sequence: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    pub fn run_once(&self, limit: usize) -> Result<IngestSummary> {
        if limit == 0 {
            bail!("ingestion limit must be greater than zero");
        }
        let mut platforms = load_enabled_platforms(&self.repo_root.join("data/platforms.csv"))?;
        let poll_sequence = self.next_poll_sequence();
        rotate_for_sequence(&mut platforms, poll_sequence);
        let known = KnownObservations::load(&self.repo_root, self.limits)?;
        let mut summary = IngestSummary::default();
        let platform_count = platforms.len();
        for (index, platform) in platforms.into_iter().enumerate() {
            let remaining = limit.saturating_sub(summary.discovered);
            if remaining == 0 {
                break;
            }
            summary.platforms_checked += 1;
            let quota = fair_platform_quota(remaining, platform_count - index);
            let result = match platform.adapter {
                AdapterKind::ClawhubApi => self.collect_clawhub(&platform, quota, &known),
                AdapterKind::SitemapCatalog => {
                    self.collect_catalog(&platform, quota, poll_sequence, &known)
                }
                AdapterKind::LocalDirectory | AdapterKind::GitRepository => {
                    self.acquire_platform(&platform).and_then(|source| {
                        self.collect_source(
                            source.scan_root(),
                            &platform.platform_id,
                            source.source_url(),
                            source.revision(),
                            source.path_prefix(),
                            quota,
                            &known,
                            source.can_skip_exact_observations(),
                        )
                    })
                }
            };
            match result {
                Ok(mut collected) => {
                    summary.discovered += collected.attempted;
                    summary.rejected += collected.rejected;
                    summary.duplicate_skills += collected.skipped_known;
                    summary.duplicate_discoveries += collected.skipped_known;
                    summary.quarantined_skipped += collected.skipped_rejections;
                    summary
                        .rejection_messages
                        .append(&mut collected.rejection_messages);
                    summary.errors.append(&mut collected.errors);
                    if !collected.pending.is_empty() {
                        summary.absorb_persist(persist(&self.repo_root, collected.pending)?);
                    }
                    persist_rejections(&self.repo_root, collected.rejections)?;
                }
                Err(error) => summary
                    .errors
                    .push(format!("platform {}: {error:#}", platform.platform_id)),
            }
        }
        Ok(summary)
    }

    pub fn ingest_path(&self, request: IngestRequest) -> Result<IngestSummary> {
        if request.limit == 0 {
            bail!("ingestion limit must be greater than zero");
        }
        validate_provenance_value("platform ID", &request.platform_id, 128)?;
        validate_source_url(&request.source_url)?;
        validate_provenance_value("revision", &request.revision, 512)?;
        let platforms = load_enabled_platforms(&self.repo_root.join("data/platforms.csv"))?;
        let registered = platforms
            .iter()
            .any(|platform| platform.platform_id == request.platform_id);
        if !(registered
            || request.allow_unregistered_platform && is_fixture_platform_id(&request.platform_id))
        {
            bail!(
                "platform {:?} is not supported and enabled in data/platforms.csv; test fixtures \
                 require --allow-unregistered-platform and a fixture: prefix",
                request.platform_id
            );
        }
        let source_root = non_symlink_directory(&request.path)?;
        let known = KnownObservations::load(&self.repo_root, self.limits)?;
        let mut collected = self.collect_source(
            &source_root,
            &request.platform_id,
            &request.source_url,
            &request.revision,
            "",
            request.limit,
            &known,
            false,
        )?;
        let mut summary = IngestSummary {
            platforms_checked: 1,
            discovered: collected.attempted,
            rejected: collected.rejected,
            duplicate_skills: collected.skipped_known,
            duplicate_discoveries: collected.skipped_known,
            quarantined_skipped: collected.skipped_rejections,
            rejection_messages: std::mem::take(&mut collected.rejection_messages),
            errors: std::mem::take(&mut collected.errors),
            ..IngestSummary::default()
        };
        if !collected.pending.is_empty() {
            summary.absorb_persist(persist(&self.repo_root, collected.pending)?);
        }
        persist_rejections(&self.repo_root, collected.rejections)?;
        Ok(summary)
    }

    fn next_poll_sequence(&self) -> u64 {
        let local = self.poll_sequence.fetch_add(1, Ordering::Relaxed);
        let external = ["SKILLS_INGEST_RUN_SEQUENCE", "GITHUB_RUN_NUMBER"]
            .into_iter()
            .find_map(|name| std::env::var(name).ok()?.parse::<u64>().ok())
            .unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    / (6 * 60 * 60)
            });
        external.wrapping_add(local)
    }

    fn acquire_platform(&self, platform: &PlatformSource) -> Result<AcquiredSource> {
        validate_provenance_value("platform ID", &platform.platform_id, 128)?;
        match platform.adapter {
            AdapterKind::LocalDirectory => {
                let base = if Path::new(&platform.locator).is_absolute() {
                    non_symlink_directory(Path::new(&platform.locator))?
                } else {
                    safe_subdirectory(&self.repo_root, Path::new(&platform.locator))?
                };
                let (scan_root, prefix) = match &platform.source_path {
                    Some(relative) => (
                        safe_subdirectory(&base, relative)?,
                        portable_relative(relative)?,
                    ),
                    None => (base, String::new()),
                };
                Ok(AcquiredSource::Local {
                    scan_root,
                    source_url: platform.locator.clone(),
                    revision: platform
                        .revision
                        .clone()
                        .unwrap_or_else(|| "working-tree".to_owned()),
                    path_prefix: prefix,
                })
            }
            AdapterKind::GitRepository => {
                let locator = repository_locator(&self.repo_root, &platform.locator);
                let checkout = clone_read_only(&locator, platform.revision.as_deref())?;
                let (scan_root, prefix) = match &platform.source_path {
                    Some(relative) => (
                        safe_subdirectory(&checkout.root, relative)?,
                        portable_relative(relative)?,
                    ),
                    None => (checkout.root.clone(), String::new()),
                };
                Ok(AcquiredSource::Git {
                    checkout,
                    scan_root,
                    path_prefix: prefix,
                })
            }
            AdapterKind::ClawhubApi | AdapterKind::SitemapCatalog => {
                bail!("catalog sources are acquired through their catalog adapters")
            }
        }
    }

    fn collect_catalog(
        &self,
        platform: &PlatformSource,
        limit: usize,
        poll_sequence: u64,
        known: &KnownObservations,
    ) -> Result<Collected> {
        validate_provenance_value("platform ID", &platform.platform_id, 128)?;
        let probe_limit = limit.saturating_mul(4).clamp(4, 64);
        let scan = crate::catalog::discover(
            &platform.locator,
            &platform.platform_id,
            poll_sequence,
            platform.rate_limit_per_minute,
            probe_limit,
        )?;
        let mut collected = Collected::default();
        collected.errors.extend(scan.errors);
        for candidate in scan.candidates {
            if collected.attempted >= limit
                || collected.errors.len() >= MAX_TRANSIENT_PLATFORM_ERRORS
            {
                break;
            }
            let remaining = limit.saturating_sub(collected.attempted);
            let result = match &candidate.source {
                CatalogSource::GitHub(source) => {
                    let checkout = clone_read_only(
                        &source.repository_url,
                        source.requested_revision.as_deref(),
                    )
                    .or_else(|error| {
                        if source.requested_revision.is_some() {
                            clone_read_only(&source.repository_url, None).with_context(|| {
                                format!("requested revision failed first: {error:#}")
                            })
                        } else {
                            Err(error)
                        }
                    });
                    checkout.and_then(|checkout| {
                        let (scan_root, provenance_prefix) = match &source.source_path {
                            Some(path) => match safe_subdirectory(&checkout.root, path) {
                                Ok(root) => (root, source.provenance_prefix.as_str()),
                                Err(_) => (
                                    checkout.root.clone(),
                                    source.repository_provenance_prefix.as_str(),
                                ),
                            },
                            None => (checkout.root.clone(), source.provenance_prefix.as_str()),
                        };
                        self.collect_source(
                            &scan_root,
                            &platform.platform_id,
                            &candidate.detail_url,
                            &checkout.revision,
                            provenance_prefix,
                            remaining,
                            known,
                            true,
                        )
                    })
                }
                CatalogSource::Markdown { markdown_url } => self.collect_catalog_markdown(
                    platform,
                    &candidate,
                    markdown_url,
                    remaining,
                    known,
                ),
            };
            match result {
                Ok(child) => collected.absorb(child),
                Err(error) => collected
                    .errors
                    .push(format!("catalog skill {}: {error:#}", candidate.detail_url)),
            }
        }
        Ok(collected)
    }

    fn collect_catalog_markdown(
        &self,
        platform: &PlatformSource,
        candidate: &CatalogCandidate,
        markdown_url: &str,
        limit: usize,
        known: &KnownObservations,
    ) -> Result<Collected> {
        let bytes = crate::catalog::fetch_markdown(
            markdown_url,
            &candidate.detail_url,
            platform.rate_limit_per_minute,
            self.limits.max_bytes_per_skill,
        )?;
        let revision = format!("blake3:{}", blake3::hash(&bytes).to_hex());
        let temp = tempfile::tempdir().context("stage catalog Markdown skill")?;
        let skill_root = temp.path().join("skill");
        fs::create_dir(&skill_root).context("create catalog skill directory")?;
        fs::write(skill_root.join("SKILL.md"), bytes).context("stage catalog SKILL.md")?;
        self.collect_source(
            &skill_root,
            &platform.platform_id,
            &candidate.detail_url,
            &revision,
            &candidate.provenance_path,
            limit,
            known,
            true,
        )
    }

    fn collect_clawhub(
        &self,
        platform: &PlatformSource,
        limit: usize,
        known: &KnownObservations,
    ) -> Result<Collected> {
        validate_provenance_value("platform ID", &platform.platform_id, 128)?;
        let mut collected = Collected::default();
        let rejection_limit = limit.saturating_mul(10).clamp(256, 10_000);
        let rejection_policy = rejection_policy(self.limits);
        let byte_cap = MAX_RETAINED_STAGE_BYTES.max(self.limits.max_bytes_per_skill);
        let entry_cap = MAX_RETAINED_STAGE_ENTRIES.max(self.limits.max_files_per_skill);
        let scan_stats = crate::clawhub::scan(
            &platform.locator,
            self.limits,
            platform.rate_limit_per_minute,
            |observation| match known.classify_exact(
                &platform.platform_id,
                &observation.source_url,
                &observation.source_revision,
                &observation.source_path,
            ) {
                Some(KnownKind::Discovery) => KnownDisposition::Discovery,
                Some(KnownKind::Rejection) => KnownDisposition::Rejection,
                None => KnownDisposition::New,
            },
            |candidate| {
                match candidate {
                    ClawhubCandidate::Downloaded(downloaded) => {
                        let observation = downloaded.observation.clone();
                        validate_source_url(&observation.source_url)?;
                        validate_provenance_value(
                            "source native ID",
                            &observation.source_native_id,
                            200,
                        )?;
                        validate_provenance_value("revision", &observation.source_revision, 512)?;
                        validate_provenance_value("source path", &observation.source_path, 1_024)?;
                        let prepared = prepare_skill(
                            downloaded.source_root(),
                            downloaded.skill_dir(),
                            self.limits,
                        )
                        .and_then(|prepared| {
                            let canonical = canonicalize_skill_tree(prepared.root())
                                .context("canonicalize validated ClawHub skill")?;
                            let id = discovery_id(
                                &canonical.skill_id,
                                &platform.platform_id,
                                &observation.source_url,
                                &observation.source_revision,
                                &observation.source_path,
                            );
                            if known.contains_id(&id) {
                                return Ok(None);
                            }
                            Ok(Some(PendingIngest {
                                prepared,
                                canonical,
                                platform_id: platform.platform_id.clone(),
                                source_url: observation.source_url.clone(),
                                source_revision: observation.source_revision.clone(),
                                source_path: observation.source_path.clone(),
                                source_native_id: observation.source_native_id.clone(),
                            }))
                        });
                        match prepared {
                            Ok(Some(value)) => {
                                collected.attempted += 1;
                                collected.staged_bytes = collected
                                    .staged_bytes
                                    .saturating_add(value.canonical.size_bytes);
                                collected.staged_entries = collected
                                    .staged_entries
                                    .saturating_add(value.canonical.entries.len() as u64);
                                collected.pending.push(value);
                            }
                            Ok(None) => collected.skipped_known += 1,
                            Err(error) => collected.reject(
                                &platform.platform_id,
                                &observation.source_url,
                                &observation.source_revision,
                                observation.source_path,
                                format!("ClawHub staged skill: {error:#}"),
                                &rejection_policy,
                            ),
                        }
                    }
                    ClawhubCandidate::Rejected {
                        observation,
                        reason,
                    } => collected.reject(
                        &platform.platform_id,
                        &observation.source_url,
                        &observation.source_revision,
                        observation.source_path,
                        reason,
                        &rejection_policy,
                    ),
                    ClawhubCandidate::Error {
                        observation,
                        message,
                    } => collected.errors.push(format!(
                        "ClawHub skill {} at {}: {message}",
                        observation.source_native_id, observation.source_revision
                    )),
                }
                let stage_has_room = collected.pending.is_empty()
                    || (collected.staged_bytes
                        <= byte_cap.saturating_sub(self.limits.max_bytes_per_skill)
                        && collected.staged_entries
                            <= entry_cap.saturating_sub(self.limits.max_files_per_skill));
                Ok(collected.attempted < limit
                    && collected.rejections.len() < rejection_limit
                    && collected.errors.len() < MAX_TRANSIENT_PLATFORM_ERRORS
                    && stage_has_room)
            },
        )?;
        collected.skipped_known = collected
            .skipped_known
            .saturating_add(scan_stats.skipped_discoveries);
        collected.skipped_rejections = collected
            .skipped_rejections
            .saturating_add(scan_stats.skipped_rejections);
        Ok(collected)
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_source(
        &self,
        source_root: &Path,
        platform_id: &str,
        source_url: &str,
        revision: &str,
        source_path_prefix: &str,
        limit: usize,
        known: &KnownObservations,
        can_skip_exact_observations: bool,
    ) -> Result<Collected> {
        validate_source_url(source_url)?;
        validate_provenance_value("revision", revision, 512)?;
        let source_root = non_symlink_directory(source_root)?;
        let mut collected = Collected::default();
        let rejection_limit = limit.saturating_mul(10).clamp(256, 10_000);
        let candidate_limit = limit.saturating_add(rejection_limit);
        let rejection_policy = rejection_policy(self.limits);
        let directories = if can_skip_exact_observations {
            discover_skill_directories_filtered(
                &source_root,
                candidate_limit,
                self.limits.max_depth,
                |directory| {
                    let source_path = source_path_for(&source_root, directory, source_path_prefix)
                        .unwrap_or_else(|_| {
                            encoded_source_path(&source_root, directory, source_path_prefix)
                        });
                    match known.classify_exact(platform_id, source_url, revision, &source_path) {
                        Some(KnownKind::Discovery) => {
                            collected.skipped_known += 1;
                            Ok(false)
                        }
                        Some(KnownKind::Rejection) => {
                            collected.skipped_rejections += 1;
                            Ok(false)
                        }
                        None => Ok(true),
                    }
                },
            )?
        } else {
            discover_skill_directories(&source_root, usize::MAX, self.limits.max_depth)?
        };
        let byte_cap = MAX_RETAINED_STAGE_BYTES.max(self.limits.max_bytes_per_skill);
        let entry_cap = MAX_RETAINED_STAGE_ENTRIES.max(self.limits.max_files_per_skill);
        for directory in directories {
            if collected.attempted >= limit || collected.rejections.len() >= rejection_limit {
                break;
            }
            let source_path = match source_path_for(&source_root, &directory, source_path_prefix) {
                Ok(path) => path,
                Err(error) => {
                    let encoded = encoded_source_path(&source_root, &directory, source_path_prefix);
                    if known.contains_rejection(platform_id, source_url, revision, &encoded) {
                        collected.skipped_rejections += 1;
                    } else {
                        collected.reject(
                            platform_id,
                            source_url,
                            revision,
                            encoded,
                            format!("unsafe provenance path: {error:#}"),
                            &rejection_policy,
                        );
                    }
                    continue;
                }
            };
            if known.contains_rejection(platform_id, source_url, revision, &source_path) {
                collected.skipped_rejections += 1;
                continue;
            }
            if !collected.pending.is_empty()
                && (collected.staged_bytes
                    > byte_cap.saturating_sub(self.limits.max_bytes_per_skill)
                    || collected.staged_entries
                        > entry_cap.saturating_sub(self.limits.max_files_per_skill))
            {
                break;
            }
            let result: Result<Option<PendingIngest>> =
                prepare_skill(&source_root, &directory, self.limits).and_then(|prepared| {
                    let canonical = canonicalize_skill_tree(prepared.root())
                        .context("canonicalize validated skill")?;
                    let id = discovery_id(
                        &canonical.skill_id,
                        platform_id,
                        source_url,
                        revision,
                        &source_path,
                    );
                    if known.contains_id(&id) {
                        return Ok(None);
                    }
                    Ok(Some(PendingIngest {
                        prepared,
                        canonical,
                        platform_id: platform_id.to_owned(),
                        source_url: source_url.to_owned(),
                        source_revision: revision.to_owned(),
                        source_path: source_path.clone(),
                        source_native_id: source_path.clone(),
                    }))
                });
            match result {
                Ok(Some(value)) => {
                    collected.attempted += 1;
                    collected.staged_bytes = collected
                        .staged_bytes
                        .saturating_add(value.canonical.size_bytes);
                    collected.staged_entries = collected
                        .staged_entries
                        .saturating_add(value.canonical.entries.len() as u64);
                    collected.pending.push(value);
                }
                Ok(None) => collected.skipped_known += 1,
                Err(error) => {
                    let display = directory
                        .strip_prefix(&source_root)
                        .unwrap_or(&directory)
                        .display();
                    collected.reject(
                        platform_id,
                        source_url,
                        revision,
                        source_path,
                        format!("{display}: {error:#}"),
                        &rejection_policy,
                    );
                }
            }
        }
        Ok(collected)
    }
}

#[derive(Default)]
struct Collected {
    attempted: usize,
    rejected: usize,
    skipped_known: usize,
    skipped_rejections: usize,
    staged_bytes: u64,
    staged_entries: u64,
    rejection_messages: Vec<String>,
    rejections: Vec<PendingRejection>,
    errors: Vec<String>,
    pending: Vec<PendingIngest>,
}

impl Collected {
    fn absorb(&mut self, mut other: Self) {
        self.attempted = self.attempted.saturating_add(other.attempted);
        self.rejected = self.rejected.saturating_add(other.rejected);
        self.skipped_known = self.skipped_known.saturating_add(other.skipped_known);
        self.skipped_rejections = self
            .skipped_rejections
            .saturating_add(other.skipped_rejections);
        self.staged_bytes = self.staged_bytes.saturating_add(other.staged_bytes);
        self.staged_entries = self.staged_entries.saturating_add(other.staged_entries);
        self.rejection_messages
            .append(&mut other.rejection_messages);
        self.rejections.append(&mut other.rejections);
        self.errors.append(&mut other.errors);
        self.pending.append(&mut other.pending);
    }
}

impl Collected {
    fn reject(
        &mut self,
        platform: &str,
        url: &str,
        revision: &str,
        path: String,
        reason: String,
        adapter_version: &str,
    ) {
        self.rejected += 1;
        self.rejection_messages
            .push(format!("rejected skill {path}: {reason}"));
        self.rejections.push(PendingRejection {
            platform_id: platform.to_owned(),
            source_url: url.to_owned(),
            source_revision: revision.to_owned(),
            source_path: path,
            reason,
            adapter_version: adapter_version.to_owned(),
        });
    }
}

#[derive(Clone, Copy)]
enum KnownKind {
    Discovery,
    Rejection,
}

#[derive(Default)]
struct KnownObservations {
    exact_discoveries: BTreeSet<(String, String, String, String)>,
    exact_rejections: BTreeSet<(String, String, String, String)>,
    discovery_ids: BTreeSet<String>,
}

impl KnownObservations {
    fn load(repo_root: &Path, limits: SecurityLimits) -> Result<Self> {
        let path = repo_root.join("data/discoveries.csv");
        let records: Vec<DiscoveryRecord> = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                read_csv_records(&path)?
            }
            Ok(_) => bail!(
                "discovery registry must be a real regular file: {}",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect discovery registry {}", path.display()));
            }
        };
        let mut exact_discoveries = BTreeSet::new();
        let mut discovery_ids = BTreeSet::new();
        for record in records {
            if record.schema_version != SCHEMA_VERSION {
                bail!(
                    "discovery {} has unsupported schema version {}",
                    record.discovery_id,
                    record.schema_version
                );
            }
            discovery_ids.insert(record.discovery_id.clone());
            let (Some(revision), Some(path)) = (
                record.source_revision.as_deref(),
                record.source_path.as_deref(),
            ) else {
                continue;
            };
            exact_discoveries.insert((
                record.platform_id,
                record.source_url,
                revision.to_owned(),
                path.to_owned(),
            ));
        }
        let mut exact_rejections = BTreeSet::new();
        let rejection_policy = rejection_policy(limits);
        for record in read_rejections(repo_root)? {
            if record.schema_version != SCHEMA_VERSION {
                bail!(
                    "rejection {} has unsupported schema version {}",
                    record.rejection_id,
                    record.schema_version
                );
            }
            if record.adapter_version != rejection_policy {
                continue;
            }
            exact_rejections.insert((
                record.platform_id,
                record.source_url,
                record.source_revision,
                record.source_path,
            ));
        }
        Ok(Self {
            exact_discoveries,
            exact_rejections,
            discovery_ids,
        })
    }

    fn classify_exact(
        &self,
        platform: &str,
        url: &str,
        revision: &str,
        path: &str,
    ) -> Option<KnownKind> {
        let key = (
            platform.to_owned(),
            url.to_owned(),
            revision.to_owned(),
            path.to_owned(),
        );
        if self.exact_discoveries.contains(&key) {
            Some(KnownKind::Discovery)
        } else if self.exact_rejections.contains(&key) {
            Some(KnownKind::Rejection)
        } else {
            None
        }
    }

    fn contains_rejection(&self, platform: &str, url: &str, revision: &str, path: &str) -> bool {
        self.exact_rejections.contains(&(
            platform.to_owned(),
            url.to_owned(),
            revision.to_owned(),
            path.to_owned(),
        ))
    }

    fn contains_id(&self, discovery_id: &str) -> bool {
        self.discovery_ids.contains(discovery_id)
    }
}

enum AcquiredSource {
    Local {
        scan_root: PathBuf,
        source_url: String,
        revision: String,
        path_prefix: String,
    },
    Git {
        checkout: GitCheckout,
        scan_root: PathBuf,
        path_prefix: String,
    },
}

impl AcquiredSource {
    fn scan_root(&self) -> &Path {
        match self {
            Self::Local { scan_root, .. } | Self::Git { scan_root, .. } => scan_root,
        }
    }

    fn source_url(&self) -> &str {
        match self {
            Self::Local { source_url, .. } => source_url,
            Self::Git { checkout, .. } => &checkout.source_url,
        }
    }

    fn revision(&self) -> &str {
        match self {
            Self::Local { revision, .. } => revision,
            Self::Git { checkout, .. } => &checkout.revision,
        }
    }

    fn path_prefix(&self) -> &str {
        match self {
            Self::Local { path_prefix, .. } | Self::Git { path_prefix, .. } => path_prefix,
        }
    }

    fn can_skip_exact_observations(&self) -> bool {
        matches!(self, Self::Git { .. })
    }
}

fn source_path_for(
    source_root: &Path,
    directory: &Path,
    source_path_prefix: &str,
) -> Result<String> {
    let relative = directory
        .strip_prefix(source_root)
        .context("discovered skill escaped source root")?;
    Ok(join_portable(
        source_path_prefix,
        portable_relative(relative)?.as_str(),
    ))
}

fn encoded_source_path(source_root: &Path, directory: &Path, prefix: &str) -> String {
    let relative = directory.strip_prefix(source_root).unwrap_or(directory);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut bytes = prefix.as_bytes().to_vec();
        if !bytes.is_empty() {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(relative.as_os_str().as_bytes());
        format!("raw-unix:{}", encode_hex(&bytes))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let mut units = prefix.encode_utf16().collect::<Vec<_>>();
        if !units.is_empty() {
            units.push(b'/' as u16);
        }
        units.extend(relative.as_os_str().encode_wide());
        let mut encoded = String::from("raw-windows:");
        for unit in units {
            use std::fmt::Write as _;
            let _ = write!(encoded, "{unit:04x}");
        }
        encoded
    }
}

#[cfg(unix)]
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn fair_platform_quota(remaining: usize, platforms_left: usize) -> usize {
    if platforms_left == 0 {
        return 0;
    }
    remaining.div_ceil(platforms_left)
}

fn rejection_policy(limits: SecurityLimits) -> String {
    format!(
        "skill-ingest/v1;files={};bytes={};file-bytes={};depth={}",
        limits.max_files_per_skill,
        limits.max_bytes_per_skill,
        limits.max_file_bytes,
        limits.max_depth
    )
}

fn rotate_for_sequence<T>(items: &mut [T], sequence: u64) {
    if !items.is_empty() {
        items.rotate_left((sequence % items.len() as u64) as usize);
    }
}

fn non_symlink_directory(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect source directory {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("source must be a non-symlink directory: {}", path.display());
    }
    fs::canonicalize(path)
        .with_context(|| format!("canonicalize source directory {}", path.display()))
}

fn safe_subdirectory(root: &Path, relative: &Path) -> Result<PathBuf> {
    if relative.as_os_str().is_empty() || relative == Path::new(".") {
        return non_symlink_directory(root);
    }
    let mut current = non_symlink_directory(root)?;
    for component in relative.components() {
        let Component::Normal(component) = component else {
            bail!("source_path must be a normalized relative path");
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("inspect source_path component {}", current.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "source_path component is not a real directory: {}",
                current.display()
            );
        }
    }
    let canonical = fs::canonicalize(&current)?;
    let root = fs::canonicalize(root)?;
    if !canonical.starts_with(&root) {
        bail!("source_path escaped the acquisition root");
    }
    Ok(canonical)
}

fn portable_relative(path: &Path) -> Result<String> {
    if path == Path::new(".") {
        return Ok(String::new());
    }
    let mut output = String::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            bail!("source_path must be a normalized relative path");
        };
        let value = component.to_str().context("source_path must be UTF-8")?;
        if value.contains('\\')
            || value.chars().any(char::is_control)
            || value
                .bytes()
                .next()
                .is_some_and(|byte| matches!(byte, b'=' | b'+' | b'-' | b'@'))
        {
            bail!("source_path contains a non-portable component");
        }
        if !output.is_empty() {
            output.push('/');
        }
        output.push_str(value);
    }
    Ok(output)
}

fn join_portable(prefix: &str, relative: &str) -> String {
    match (prefix.is_empty(), relative == "." || relative.is_empty()) {
        (true, true) => ".".to_owned(),
        (true, false) => relative.to_owned(),
        (false, true) => prefix.to_owned(),
        (false, false) => format!("{prefix}/{relative}"),
    }
}

fn repository_locator(repo_root: &Path, locator: &str) -> String {
    let candidate = Path::new(locator);
    if candidate.is_absolute() || url::Url::parse(locator).is_ok() {
        locator.to_owned()
    } else {
        repo_root.join(candidate).to_string_lossy().into_owned()
    }
}

fn validate_provenance_value(label: &str, value: &str, max_len: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max_len
        || value.chars().any(|character| character.is_control())
        || value
            .bytes()
            .next()
            .is_some_and(|byte| matches!(byte, b'=' | b'+' | b'-' | b'@'))
    {
        bail!("invalid {label}");
    }
    Ok(())
}

fn validate_source_url(value: &str) -> Result<()> {
    validate_provenance_value("source URL", value, 4_096)?;
    if let Ok(url) = url::Url::parse(value) {
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            bail!("source URL must not contain credentials, a query, or a fragment");
        }
    } else if value.contains(['?', '#']) {
        bail!("source locator must not contain a query or fragment");
    }
    Ok(())
}

fn is_fixture_platform_id(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("fixture:") else {
        return false;
    };
    !suffix.is_empty()
        && suffix.len() <= 120
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use skills_core::csv_store::{read_csv_records, write_csv_records_atomic};
    use skills_core::records::{DiscoveryRecord, PlatformRecord, SCHEMA_VERSION, SkillRecord};
    use std::process::Command;

    #[test]
    fn rejects_parent_components_in_subdirectory() {
        let temp = tempfile::tempdir().unwrap();
        assert!(safe_subdirectory(temp.path(), Path::new("../escape")).is_err());
    }

    #[test]
    fn joins_source_paths_portably() {
        assert_eq!(join_portable("", "."), ".");
        assert_eq!(join_portable("skills", "."), "skills");
        assert_eq!(join_portable("skills", "one"), "skills/one");
    }

    #[test]
    fn platform_quota_is_fair_and_bounded_when_possible() {
        assert_eq!(fair_platform_quota(10, 3), 4);
        assert_eq!(fair_platform_quota(6, 2), 3);
        assert_eq!(fair_platform_quota(3, 1), 3);
        assert_eq!(fair_platform_quota(2, 3), 1);
        let mut platforms = ["alpha", "beta", "gamma"];
        rotate_for_sequence(&mut platforms, 1);
        assert_eq!(platforms, ["beta", "gamma", "alpha"]);
        let mut changed = SecurityLimits::default();
        changed.max_file_bytes -= 1;
        assert_ne!(
            rejection_policy(SecurityLimits::default()),
            rejection_policy(changed)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_source_path_has_a_lossless_quarantine_identity() {
        use std::os::unix::ffi::OsStringExt;

        let root = tempfile::tempdir().unwrap();
        let directory = root
            .path()
            .join(std::ffi::OsString::from_vec(vec![b'a', 0x80]));
        fs::create_dir(&directory).unwrap();
        assert!(source_path_for(root.path(), &directory, "").is_err());
        let encoded = encoded_source_path(root.path(), &directory, "");
        assert_eq!(encoded, "raw-unix:6180");
    }

    #[test]
    fn ingest_path_archives_and_deduplicates_a_local_fixture() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join("data")).unwrap();
        fs::create_dir_all(workspace.path().join("fixtures/example")).unwrap();
        fs::write(
            workspace.path().join("fixtures/example/SKILL.md"),
            "---\nname: deterministic-fixture\nversion: 1.0.0\n---\n# Test\n",
        )
        .unwrap();
        write_platforms(
            workspace.path(),
            "local",
            "Local",
            "local-directory",
            "fixtures",
        );
        let worker = Worker::new(workspace.path(), SecurityLimits::default()).unwrap();
        let request = IngestRequest {
            path: workspace.path().join("fixtures"),
            platform_id: "local".to_owned(),
            allow_unregistered_platform: false,
            source_url: "local://fixture-corpus".to_owned(),
            revision: "fixture-v1".to_owned(),
            limit: 10,
        };

        let first = worker.ingest_path(request.clone()).unwrap();
        assert_eq!(first.new_skills, 1);
        assert_eq!(first.ingested, 1);
        assert!(!first.has_errors());
        let second = worker.ingest_path(request).unwrap();
        assert_eq!(second.new_skills, 0);
        assert_eq!(second.ingested, 0);
        assert_eq!(second.duplicate_skills, 1);
        assert_eq!(second.duplicate_discoveries, 1);

        let skills: Vec<SkillRecord> =
            read_csv_records(workspace.path().join("data/skills.csv")).unwrap();
        let discoveries: Vec<DiscoveryRecord> =
            read_csv_records(workspace.path().join("data/discoveries.csv")).unwrap();
        assert_eq!(skills.len(), 1);
        assert_eq!(discoveries.len(), 1);
        assert_eq!(skills[0].name.as_deref(), Some("deterministic-fixture"));
        assert_eq!(skills[0].declared_version.as_deref(), Some("1.0.0"));
        assert!(workspace.path().join(&skills[0].bundle_path).is_file());
        assert!(workspace.path().join(&skills[0].manifest_path).is_file());
        assert_eq!(discoveries[0].platform_id, "local");
        assert_eq!(discoveries[0].source_path.as_deref(), Some("example"));
    }

    #[cfg(unix)]
    #[test]
    fn duplicate_content_reuses_valid_bundle_and_repairs_corruption() {
        use std::os::unix::fs::MetadataExt;

        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join("data")).unwrap();
        fs::create_dir_all(workspace.path().join("fixtures/example")).unwrap();
        fs::write(
            workspace.path().join("fixtures/example/SKILL.md"),
            "# Stable fixture\n",
        )
        .unwrap();
        write_platforms(
            workspace.path(),
            "local",
            "Local",
            "local-directory",
            "fixtures",
        );
        let worker = Worker::new(workspace.path(), SecurityLimits::default()).unwrap();
        let mut request = IngestRequest {
            path: workspace.path().join("fixtures"),
            platform_id: "local".to_owned(),
            allow_unregistered_platform: false,
            source_url: "local://fixture-corpus".to_owned(),
            revision: "fixture-v1".to_owned(),
            limit: 1,
        };
        worker.ingest_path(request.clone()).unwrap();
        let skills: Vec<SkillRecord> =
            read_csv_records(workspace.path().join("data/skills.csv")).unwrap();
        let bundle = workspace.path().join(&skills[0].bundle_path);
        let original_inode = fs::metadata(&bundle).unwrap().ino();

        request.revision = "fixture-v2".to_owned();
        let duplicate = worker.ingest_path(request.clone()).unwrap();
        assert_eq!(duplicate.duplicate_skills, 1);
        assert_eq!(fs::metadata(&bundle).unwrap().ino(), original_inode);

        fs::write(&bundle, b"corrupt archive").unwrap();
        request.revision = "fixture-v3".to_owned();
        worker.ingest_path(request).unwrap();
        assert_ne!(fs::read(&bundle).unwrap(), b"corrupt archive");
        assert_ne!(fs::metadata(&bundle).unwrap().ino(), original_inode);
    }

    #[test]
    fn unregistered_platform_escape_hatch_is_fixture_namespaced() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join("data")).unwrap();
        fs::create_dir(workspace.path().join("fixture")).unwrap();
        fs::write(workspace.path().join("fixture/SKILL.md"), "# Fixture\n").unwrap();
        write_platforms(
            workspace.path(),
            "local",
            "Local",
            "local-directory",
            "fixture",
        );
        let worker = Worker::new(workspace.path(), SecurityLimits::default()).unwrap();
        let mut request = IngestRequest {
            path: workspace.path().join("fixture"),
            platform_id: "fixture:test".to_owned(),
            allow_unregistered_platform: false,
            source_url: "local://fixture".to_owned(),
            revision: "fixture-v1".to_owned(),
            limit: 1,
        };
        assert!(worker.ingest_path(request.clone()).is_err());
        request.allow_unregistered_platform = true;
        assert_eq!(worker.ingest_path(request.clone()).unwrap().ingested, 1);

        request.platform_id = "not-fixture".to_owned();
        assert!(worker.ingest_path(request).is_err());
    }

    #[test]
    fn bounded_polls_advance_past_exact_prior_observations() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join("data")).unwrap();
        for name in ["a", "b", "c"] {
            let skill = workspace.path().join("fixtures").join(name);
            fs::create_dir_all(&skill).unwrap();
            fs::write(skill.join("SKILL.md"), format!("# {name}\n")).unwrap();
        }
        write_platforms(
            workspace.path(),
            "local",
            "Local",
            "local-directory",
            "fixtures",
        );
        let worker = Worker::new(workspace.path(), SecurityLimits::default()).unwrap();
        let request = IngestRequest {
            path: workspace.path().join("fixtures"),
            platform_id: "local".to_owned(),
            allow_unregistered_platform: false,
            source_url: "local://fixture-corpus".to_owned(),
            revision: "immutable-fixture-v1".to_owned(),
            limit: 1,
        };

        for expected_total in 1..=3 {
            let summary = worker.ingest_path(request.clone()).unwrap();
            assert_eq!(summary.ingested, 1);
            let discoveries: Vec<DiscoveryRecord> =
                read_csv_records(workspace.path().join("data/discoveries.csv")).unwrap();
            assert_eq!(discoveries.len(), expected_total);
        }
        let complete = worker.ingest_path(request).unwrap();
        assert_eq!(complete.ingested, 0);
        assert_eq!(complete.duplicate_discoveries, 3);
    }

    #[cfg(unix)]
    #[test]
    fn rejected_paths_are_quarantined_without_starving_valid_skills() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join("data")).unwrap();
        let invalid = workspace.path().join("fixtures/=invalid");
        fs::create_dir_all(&invalid).unwrap();
        fs::write(invalid.join("SKILL.md"), "# Invalid path\n").unwrap();
        let valid = workspace.path().join("fixtures/b-valid");
        fs::create_dir_all(&valid).unwrap();
        fs::write(valid.join("SKILL.md"), "# Valid\n").unwrap();
        write_platforms(
            workspace.path(),
            "local",
            "Local",
            "local-directory",
            "fixtures",
        );
        let worker = Worker::new(workspace.path(), SecurityLimits::default()).unwrap();
        let request = IngestRequest {
            path: workspace.path().join("fixtures"),
            platform_id: "local".to_owned(),
            allow_unregistered_platform: false,
            source_url: "local://fixture-corpus".to_owned(),
            revision: "immutable-fixture-v1".to_owned(),
            limit: 1,
        };

        let first = worker.ingest_path(request.clone()).unwrap();
        assert_eq!(first.rejected, 1);
        assert_eq!(first.ingested, 1);
        assert!(!first.has_errors());
        let first_rejections = read_rejections(workspace.path()).unwrap();
        assert_eq!(first_rejections.len(), 1);
        assert_eq!(first_rejections[0].source_path, "raw-unix:3d696e76616c6964");
        assert!(
            !first_rejections[0]
                .source_path
                .starts_with(['=', '+', '-', '@'])
        );
        let rejection_id = first_rejections[0].rejection_id.clone();

        let second = worker.ingest_path(request).unwrap();
        assert_eq!(second.rejected, 0);
        assert_eq!(second.quarantined_skipped, 1);
        assert_eq!(second.ingested, 0);
        let second_rejections = read_rejections(workspace.path()).unwrap();
        assert_eq!(second_rejections[0].rejection_id, rejection_id);
    }

    #[test]
    fn once_ingests_a_local_git_repository_without_executing_it() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let workspace = tempfile::tempdir().unwrap();
        let repository = workspace.path().join("fixtures/git-source");
        fs::create_dir_all(repository.join("nested-skill")).unwrap();
        fs::write(
            repository.join("nested-skill/SKILL.md"),
            "---\nname: git-fixture\n---\n# Test\n",
        )
        .unwrap();
        run_git(&repository, &["init", "--quiet"]);
        run_git(&repository, &["config", "user.name", "ingest-test"]);
        run_git(
            &repository,
            &["config", "user.email", "ingest-test@example.invalid"],
        );
        run_git(&repository, &["add", "nested-skill/SKILL.md"]);
        run_git(&repository, &["commit", "--quiet", "-m", "fixture"]);
        let revision = git_output(&repository, &["rev-parse", "HEAD"]);

        fs::create_dir(workspace.path().join("data")).unwrap();
        write_platforms(
            workspace.path(),
            "git-fixture",
            "Git Fixture",
            "github_archive",
            "fixtures/git-source",
        );
        let worker = Worker::new(workspace.path(), SecurityLimits::default()).unwrap();
        let summary = worker.run_once(10).unwrap();
        assert!(!summary.has_errors(), "{:?}", summary.errors);
        assert_eq!(summary.new_skills, 1);
        assert_eq!(summary.ingested, 1);

        let discoveries: Vec<DiscoveryRecord> =
            read_csv_records(workspace.path().join("data/discoveries.csv")).unwrap();
        assert_eq!(discoveries.len(), 1);
        assert_eq!(
            discoveries[0].source_revision.as_deref(),
            Some(revision.as_str())
        );
        assert_eq!(discoveries[0].source_path.as_deref(), Some("nested-skill"));
    }

    fn write_platforms(
        workspace: &Path,
        platform_id: &str,
        display_name: &str,
        adapter: &str,
        ingest_uri: &str,
    ) {
        write_csv_records_atomic(
            workspace.join("data/platforms.csv"),
            [PlatformRecord {
                schema_version: SCHEMA_VERSION,
                platform_id: platform_id.to_owned(),
                display_name: display_name.to_owned(),
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
            }],
        )
        .unwrap();
    }

    fn run_git(repository: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn git_output(repository: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
}
