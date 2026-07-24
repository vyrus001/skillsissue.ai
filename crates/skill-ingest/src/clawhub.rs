use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE, LOCATION};
use reqwest::redirect::Policy;
use serde::Deserialize;
use tempfile::TempDir;
use url::Url;
use zip::ZipArchive;

use crate::prepare::{SecurityLimits, discover_skill_directories};

const CATALOG_PAGE_SIZE: usize = 200;
const MAX_CATALOG_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DOWNLOAD_BYTES: u64 = 128 * 1024 * 1024;
const MAX_HANDOFF_BYTES: usize = 64 * 1024;
const MAX_AMBIGUOUS_MATCHES: usize = 100;
const MAX_PAGES: usize = 10_000;
const MAX_CURSOR_BYTES: usize = 8 * 1024;
const MAX_ZIP_ENTRIES: usize = 100_000;
const MAX_ZIP_PATH_BYTES: usize = 4 * 1024;
const MAX_COMPRESSION_RATIO: u64 = 1_000;
const CLAWHUB_HOST: &str = "clawhub.ai";
const GITHUB_ARCHIVE_HOSTS: &[&str] = &[
    "api.github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClawhubObservation {
    pub source_native_id: String,
    pub source_url: String,
    pub source_revision: String,
    pub source_path: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KnownDisposition {
    New,
    Discovery,
    Rejection,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ScanStats {
    pub pages: usize,
    pub catalog_items: usize,
    pub skipped_discoveries: usize,
    pub skipped_rejections: usize,
}

pub(crate) enum ClawhubCandidate {
    Downloaded(DownloadedSkill),
    Error {
        observation: ClawhubObservation,
        message: String,
    },
    Rejected {
        observation: ClawhubObservation,
        reason: String,
    },
}

pub(crate) struct DownloadedSkill {
    _temp: TempDir,
    source_root: PathBuf,
    skill_dir: PathBuf,
    pub observation: ClawhubObservation,
}

impl DownloadedSkill {
    pub fn source_root(&self) -> &Path {
        &self.source_root
    }

    pub fn skill_dir(&self) -> &Path {
        &self.skill_dir
    }
}

/// Enumerate the official ClawHub catalog in update order. Known observations
/// are filtered before archive downloads whenever the catalog exposes a
/// version, and pagination continues until `visit` asks to stop or the catalog
/// is exhausted.
pub(crate) fn scan<F, K>(
    locator: &str,
    limits: SecurityLimits,
    rate_limit_per_minute: Option<u32>,
    classify: K,
    visit: F,
) -> Result<ScanStats>
where
    F: FnMut(ClawhubCandidate) -> Result<bool>,
    K: FnMut(&ClawhubObservation) -> KnownDisposition,
{
    let transport = ReqwestTransport::new(rate_limit_per_minute)?;
    scan_with_transport(&transport, locator, limits, classify, visit)
}

fn scan_with_transport<T, F, K>(
    transport: &T,
    locator: &str,
    limits: SecurityLimits,
    mut classify: K,
    mut visit: F,
) -> Result<ScanStats>
where
    T: HttpTransport,
    F: FnMut(ClawhubCandidate) -> Result<bool>,
    K: FnMut(&ClawhubObservation) -> KnownDisposition,
{
    limits.validate()?;
    let base = validate_clawhub_base(locator)?;
    let settings = ScanSettings {
        limits,
        clawhub_policy: FetchPolicy {
            hosts: &[CLAWHUB_HOST],
            max_redirects: 0,
        },
        github_policy: FetchPolicy {
            hosts: GITHUB_ARCHIVE_HOSTS,
            max_redirects: 3,
        },
    };
    let mut stats = ScanStats::default();
    let mut cursor: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();
    let mut seen_catalog_observations = BTreeSet::new();

    loop {
        if stats.pages >= MAX_PAGES {
            bail!("ClawHub pagination exceeded the {MAX_PAGES} page safety limit");
        }
        let list_url = catalog_url(&base, cursor.as_deref())?;
        let response = fetch_with_redirects(
            transport,
            list_url,
            MAX_CATALOG_BYTES,
            settings.clawhub_policy,
        )?;
        require_success(&response, "ClawHub catalog")?;
        if !is_json_content_type(response.content_type.as_deref()) {
            bail!("ClawHub catalog response was not JSON");
        }
        let page: CatalogPage =
            serde_json::from_slice(&response.body).context("decode ClawHub catalog response")?;
        if page.items.len() > CATALOG_PAGE_SIZE {
            bail!(
                "ClawHub returned {} catalog items, above the requested page size of {CATALOG_PAGE_SIZE}",
                page.items.len()
            );
        }
        stats.pages += 1;

        for (item_index, item) in page.items.into_iter().enumerate() {
            stats.catalog_items += 1;
            let page_number = stats.pages;
            let slug = match item.slug.as_deref() {
                Some(slug) if valid_slug(slug) => slug.to_owned(),
                _ => {
                    let observation = invalid_catalog_observation(&base, page_number, item_index);
                    if !visit(ClawhubCandidate::Rejected {
                        observation,
                        reason: "catalog item has a missing or unsafe slug".to_owned(),
                    })? {
                        return Ok(stats);
                    }
                    continue;
                }
            };
            let version = item.latest_version.and_then(CatalogVersion::into_version);
            let updated_at = item.updated_at;
            let source_url = skill_detail_url(&base, &slug, None)?.to_string();
            let variant = match version.as_deref() {
                Some(version) if valid_version(version) => CatalogVariant {
                    slug: slug.clone(),
                    owner_handle: None,
                    version: Some(version.to_owned()),
                    updated_at,
                },
                Some(_) => {
                    let observation = ClawhubObservation {
                        source_native_id: slug.clone(),
                        source_url: source_url.clone(),
                        source_revision: catalog_revision(updated_at),
                        source_path: slug.clone(),
                    };
                    if !visit(ClawhubCandidate::Rejected {
                        observation,
                        reason: "catalog item has an unsafe version".to_owned(),
                    })? {
                        return Ok(stats);
                    }
                    continue;
                }
                None => CatalogVariant {
                    slug: slug.clone(),
                    owner_handle: None,
                    version: None,
                    updated_at,
                },
            };
            let provisional = variant.observation(&base)?;

            let catalog_key = (
                provisional.source_native_id.clone(),
                provisional.source_revision.clone(),
            );
            if !seen_catalog_observations.insert(catalog_key) {
                continue;
            }

            match process_variant(
                transport,
                &base,
                &variant,
                settings,
                &mut classify,
                &mut visit,
                &mut stats,
            )? {
                ScanControl::Continue => {}
                ScanControl::Stop => return Ok(stats),
                ScanControl::Ambiguous(observation) => {
                    let variants = match resolve_ambiguous_variants(
                        transport,
                        &base,
                        &slug,
                        settings.clawhub_policy,
                    ) {
                        Ok(variants) => variants,
                        Err(error) => {
                            if !visit(ClawhubCandidate::Error {
                                observation,
                                message: format!("ambiguous slug resolution failed: {error:#}"),
                            })? {
                                return Ok(stats);
                            }
                            continue;
                        }
                    };
                    for variant in variants {
                        match process_variant(
                            transport,
                            &base,
                            &variant,
                            settings,
                            &mut classify,
                            &mut visit,
                            &mut stats,
                        )? {
                            ScanControl::Continue => {}
                            ScanControl::Stop => return Ok(stats),
                            ScanControl::Ambiguous(observation) => {
                                if !visit(ClawhubCandidate::Error {
                                    observation,
                                    message:
                                        "publisher-qualified ClawHub download remained ambiguous"
                                            .to_owned(),
                                })? {
                                    return Ok(stats);
                                }
                            }
                        }
                    }
                }
            }
        }

        let Some(next_cursor) = page.next_cursor else {
            break;
        };
        validate_cursor(&next_cursor)?;
        if cursor.as_deref() == Some(next_cursor.as_str())
            || !seen_cursors.insert(next_cursor.clone())
        {
            bail!("ClawHub returned a repeated pagination cursor");
        }
        cursor = Some(next_cursor);
    }

    Ok(stats)
}

enum ScanControl {
    Continue,
    Stop,
    Ambiguous(ClawhubObservation),
}

#[derive(Clone, Copy)]
struct ScanSettings {
    limits: SecurityLimits,
    clawhub_policy: FetchPolicy,
    github_policy: FetchPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogVariant {
    slug: String,
    owner_handle: Option<String>,
    version: Option<String>,
    updated_at: Option<u64>,
}

impl CatalogVariant {
    fn observation(&self, base: &Url) -> Result<ClawhubObservation> {
        let source_native_id = self
            .owner_handle
            .as_deref()
            .map(|owner| format!("@{owner}/{}", self.slug))
            .unwrap_or_else(|| self.slug.clone());
        let source_revision = self
            .version
            .as_deref()
            .map(|version| hosted_revision(version, self.updated_at))
            .unwrap_or_else(|| catalog_revision(self.updated_at));
        Ok(ClawhubObservation {
            source_native_id: source_native_id.clone(),
            source_url: skill_detail_url(base, &self.slug, self.owner_handle.as_deref())?
                .to_string(),
            source_revision,
            source_path: source_native_id,
        })
    }
}

fn process_variant<T, F, K>(
    transport: &T,
    base: &Url,
    variant: &CatalogVariant,
    settings: ScanSettings,
    classify: &mut K,
    visit: &mut F,
    stats: &mut ScanStats,
) -> Result<ScanControl>
where
    T: HttpTransport,
    F: FnMut(ClawhubCandidate) -> Result<bool>,
    K: FnMut(&ClawhubObservation) -> KnownDisposition,
{
    let provisional = variant.observation(base)?;

    // Hosted skills expose their exact semantic version in the list or in an
    // owner-qualified detail response. Version-less entries can be GitHub
    // handoffs, whose immutable commit is learned from the descriptor below.
    if variant.version.is_some() && variant.updated_at.is_some() {
        match classify(&provisional) {
            KnownDisposition::Discovery => {
                stats.skipped_discoveries += 1;
                return Ok(ScanControl::Continue);
            }
            KnownDisposition::Rejection => {
                stats.skipped_rejections += 1;
                return Ok(ScanControl::Continue);
            }
            KnownDisposition::New => {}
        }
    } else if matches!(classify(&provisional), KnownDisposition::Rejection) {
        stats.skipped_rejections += 1;
        return Ok(ScanControl::Continue);
    }

    let response = match fetch_with_redirects(
        transport,
        download_url(
            base,
            &variant.slug,
            variant.owner_handle.as_deref(),
            variant.version.as_deref(),
        )?,
        MAX_DOWNLOAD_BYTES,
        settings.clawhub_policy,
    ) {
        Ok(response) => response,
        Err(error) => {
            return Ok(
                if visit(ClawhubCandidate::Error {
                    observation: provisional,
                    message: format!("download request failed: {error:#}"),
                })? {
                    ScanControl::Continue
                } else {
                    ScanControl::Stop
                },
            );
        }
    };
    if response.status == 409 && variant.owner_handle.is_none() {
        return Ok(ScanControl::Ambiguous(provisional));
    }
    if let Err(error) = require_success(&response, "ClawHub skill download") {
        return Ok(
            if visit(ClawhubCandidate::Error {
                observation: provisional,
                message: format!("download request failed: {error:#}"),
            })? {
                ScanControl::Continue
            } else {
                ScanControl::Stop
            },
        );
    }
    let download = match decode_download(response) {
        Ok(download) => download,
        Err(error) => {
            return Ok(
                if visit(ClawhubCandidate::Rejected {
                    observation: provisional,
                    reason: format!("download payload rejected: {error:#}"),
                })? {
                    ScanControl::Continue
                } else {
                    ScanControl::Stop
                },
            );
        }
    };

    let candidate = match download {
        DownloadPayload::Zip(bytes) => {
            let Some(version) = variant.version.as_deref() else {
                return Ok(
                    if visit(ClawhubCandidate::Rejected {
                        observation: provisional,
                        reason: "version-less catalog item returned ZIP bytes".to_owned(),
                    })? {
                        ScanControl::Continue
                    } else {
                        ScanControl::Stop
                    },
                );
            };
            match extract_skill_archive(&bytes, None, settings.limits).and_then(|mut extracted| {
                validate_hosted_metadata(&extracted.skill_dir, &variant.slug, version)?;
                extracted.observation = Some(provisional.clone());
                extracted.into_downloaded()
            }) {
                Ok(downloaded) => ClawhubCandidate::Downloaded(downloaded),
                Err(error) => ClawhubCandidate::Rejected {
                    observation: provisional,
                    reason: format!("hosted ZIP rejected: {error:#}"),
                },
            }
        }
        DownloadPayload::GitHub(handoff) => {
            let handoff = match ValidatedHandoff::new(handoff) {
                Ok(handoff) => handoff,
                Err(error) => {
                    return Ok(
                        if visit(ClawhubCandidate::Rejected {
                            observation: provisional,
                            reason: format!("GitHub handoff rejected: {error:#}"),
                        })? {
                            ScanControl::Continue
                        } else {
                            ScanControl::Stop
                        },
                    );
                }
            };
            let observation = handoff.observation(
                &provisional.source_native_id,
                &provisional.source_url,
                variant.version.as_deref(),
            );
            match classify(&observation) {
                KnownDisposition::Discovery => {
                    stats.skipped_discoveries += 1;
                    return Ok(ScanControl::Continue);
                }
                KnownDisposition::Rejection => {
                    stats.skipped_rejections += 1;
                    return Ok(ScanControl::Continue);
                }
                KnownDisposition::New => {}
            }
            match fetch_with_redirects(
                transport,
                handoff.archive_url.clone(),
                MAX_DOWNLOAD_BYTES,
                settings.github_policy,
            ) {
                Err(error) => ClawhubCandidate::Error {
                    observation,
                    message: format!("GitHub archive request failed: {error:#}"),
                },
                Ok(response) => {
                    if let Err(error) = require_success(&response, "GitHub source archive") {
                        ClawhubCandidate::Error {
                            observation,
                            message: format!("GitHub archive request failed: {error:#}"),
                        }
                    } else if !looks_like_zip(&response.body) {
                        ClawhubCandidate::Rejected {
                            observation,
                            reason: "GitHub source archive response was not ZIP data".to_owned(),
                        }
                    } else {
                        match extract_skill_archive(
                            &response.body,
                            Some(&handoff.path),
                            settings.limits,
                        )
                        .and_then(|mut extracted| {
                            extracted.observation = Some(observation.clone());
                            extracted.into_downloaded()
                        }) {
                            Ok(downloaded) => ClawhubCandidate::Downloaded(downloaded),
                            Err(error) => ClawhubCandidate::Rejected {
                                observation,
                                reason: format!("GitHub source ZIP rejected: {error:#}"),
                            },
                        }
                    }
                }
            }
        }
    };

    Ok(if visit(candidate)? {
        ScanControl::Continue
    } else {
        ScanControl::Stop
    })
}

fn resolve_ambiguous_variants<T: HttpTransport>(
    transport: &T,
    base: &Url,
    slug: &str,
    clawhub_policy: FetchPolicy,
) -> Result<Vec<CatalogVariant>> {
    let response = fetch_with_redirects(
        transport,
        skill_detail_url(base, slug, None)?,
        MAX_CATALOG_BYTES,
        clawhub_policy,
    )?;
    if response.status == 200 {
        return Ok(vec![decode_detail_variant(response, slug, None)?]);
    }
    if response.status != 409 {
        require_success(&response, "ClawHub ambiguous skill lookup")?;
    }
    if !is_json_content_type(response.content_type.as_deref()) {
        bail!("ClawHub ambiguous skill response was not JSON");
    }
    let ambiguity: AmbiguousSkillResponse = serde_json::from_slice(&response.body)
        .context("decode ClawHub ambiguous skill response")?;
    if ambiguity.code != "AMBIGUOUS_SKILL_SLUG" || ambiguity.slug != slug {
        bail!("ClawHub ambiguous skill response did not match the requested slug");
    }
    if ambiguity.matches.is_empty() || ambiguity.matches.len() > MAX_AMBIGUOUS_MATCHES {
        bail!("ClawHub ambiguous skill response contained an unsafe number of publisher matches");
    }

    let mut owners = BTreeSet::new();
    for matched in ambiguity.matches {
        if matched.slug != slug || !valid_owner_handle(&matched.owner_handle) {
            bail!("ClawHub ambiguous skill response contained an unsafe publisher match");
        }
        if !owners.insert(matched.owner_handle) {
            bail!("ClawHub ambiguous skill response repeated a publisher match");
        }
    }

    let mut variants = Vec::with_capacity(owners.len());
    for owner_handle in owners {
        let response = fetch_with_redirects(
            transport,
            skill_detail_url(base, slug, Some(&owner_handle))?,
            MAX_CATALOG_BYTES,
            clawhub_policy,
        )?;
        variants.push(decode_detail_variant(response, slug, Some(&owner_handle))?);
    }
    Ok(variants)
}

fn decode_detail_variant(
    response: HttpResponse,
    expected_slug: &str,
    expected_owner: Option<&str>,
) -> Result<CatalogVariant> {
    require_success(&response, "ClawHub publisher-qualified skill lookup")?;
    if !is_json_content_type(response.content_type.as_deref()) {
        bail!("ClawHub publisher-qualified skill response was not JSON");
    }
    let detail: SkillDetailResponse = serde_json::from_slice(&response.body)
        .context("decode ClawHub publisher-qualified skill response")?;
    if detail.skill.slug != expected_slug
        || !valid_owner_handle(&detail.owner.handle)
        || expected_owner.is_some_and(|owner| owner != detail.owner.handle)
    {
        bail!("ClawHub publisher-qualified skill response did not match the request");
    }
    let version = detail.latest_version.and_then(CatalogVersion::into_version);
    if version
        .as_deref()
        .is_some_and(|version| !valid_version(version))
    {
        bail!("ClawHub publisher-qualified skill response contained an unsafe version");
    }
    Ok(CatalogVariant {
        slug: detail.skill.slug,
        owner_handle: Some(detail.owner.handle),
        version,
        updated_at: detail.skill.updated_at,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CatalogPage {
    items: Vec<CatalogItem>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CatalogItem {
    #[serde(default)]
    slug: Option<String>,
    #[serde(default)]
    latest_version: Option<CatalogVersion>,
    #[serde(default)]
    updated_at: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AmbiguousSkillResponse {
    code: String,
    slug: String,
    matches: Vec<AmbiguousSkillMatch>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AmbiguousSkillMatch {
    owner_handle: String,
    slug: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SkillDetailResponse {
    skill: SkillDetail,
    latest_version: Option<CatalogVersion>,
    owner: SkillOwner,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SkillDetail {
    slug: String,
    updated_at: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SkillOwner {
    handle: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CatalogVersion {
    Object { version: String },
    String(String),
}

impl CatalogVersion {
    fn into_version(self) -> Option<String> {
        match self {
            Self::Object { version } | Self::String(version) if !version.is_empty() => {
                Some(version)
            }
            Self::Object { .. } | Self::String(_) => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GitHubHandoff {
    source_ref: String,
    repo: String,
    commit: String,
    path: String,
    content_hash: String,
    archive_url: String,
}

struct ValidatedHandoff {
    repo: String,
    commit: String,
    path: PathBuf,
    portable_path: String,
    content_hash: String,
    archive_url: Url,
}

impl ValidatedHandoff {
    fn new(handoff: GitHubHandoff) -> Result<Self> {
        if handoff.source_ref != "public-github" {
            bail!("unsupported handoff sourceRef");
        }
        validate_github_repo(&handoff.repo)?;
        if handoff.commit.len() != 40
            || !handoff.commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("handoff commit must be a full hexadecimal Git commit ID");
        }
        if handoff.content_hash.len() != 64
            || !handoff
                .content_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("handoff contentHash must be a SHA-256 hexadecimal digest");
        }
        let path = normalized_relative_path(&handoff.path, 500)?;
        let portable_path = portable_path(&path)?;
        if portable_path.is_empty() {
            bail!("handoff path must not be empty");
        }
        let archive_url = Url::parse(&handoff.archive_url).context("parse handoff archiveUrl")?;
        validate_https_url(&archive_url, &["api.github.com"])?;
        let expected = github_zipball_url(&handoff.repo, &handoff.commit)?;
        if archive_url != expected {
            bail!("handoff archiveUrl does not match its repository and commit");
        }
        Ok(Self {
            repo: handoff.repo,
            commit: handoff.commit.to_ascii_lowercase(),
            path,
            portable_path,
            content_hash: handoff.content_hash.to_ascii_lowercase(),
            archive_url,
        })
    }

    fn observation(
        &self,
        source_native_id: &str,
        source_url: &str,
        catalog_version: Option<&str>,
    ) -> ClawhubObservation {
        let source_revision = match catalog_version {
            Some(version) => format!(
                "{version};github:{};content:{}",
                self.commit, self.content_hash
            ),
            None => format!("github:{};content:{}", self.commit, self.content_hash),
        };
        ClawhubObservation {
            source_native_id: source_native_id.to_owned(),
            source_url: source_url.to_owned(),
            source_revision,
            source_path: format!("github:{}/{}", self.repo, self.portable_path),
        }
    }
}

enum DownloadPayload {
    Zip(Vec<u8>),
    GitHub(GitHubHandoff),
}

fn decode_download(response: HttpResponse) -> Result<DownloadPayload> {
    if looks_like_zip(&response.body) {
        return Ok(DownloadPayload::Zip(response.body));
    }
    if response.body.len() > MAX_HANDOFF_BYTES {
        bail!("handoff descriptor exceeded the {MAX_HANDOFF_BYTES} byte limit");
    }
    if !is_json_content_type(response.content_type.as_deref())
        && response
            .body
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace())
            != Some(b'{')
    {
        bail!("download response was neither ZIP nor JSON");
    }
    let handoff = serde_json::from_slice(&response.body).context("decode GitHub handoff")?;
    Ok(DownloadPayload::GitHub(handoff))
}

fn validate_clawhub_base(locator: &str) -> Result<Url> {
    let url = Url::parse(locator).context("parse ClawHub ingest URI")?;
    validate_https_url(&url, &[CLAWHUB_HOST])?;
    if !matches!(url.path(), "" | "/") || url.query().is_some() {
        bail!("ClawHub ingest URI must be the origin https://clawhub.ai");
    }
    Ok(url)
}

fn catalog_url(base: &Url, cursor: Option<&str>) -> Result<Url> {
    let mut url = base.join("/api/v1/skills").context("build catalog URL")?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("limit", &CATALOG_PAGE_SIZE.to_string());
        query.append_pair("sort", "updated");
        if let Some(cursor) = cursor {
            query.append_pair("cursor", cursor);
        }
    }
    Ok(url)
}

fn skill_detail_url(base: &Url, slug: &str, owner_handle: Option<&str>) -> Result<Url> {
    let mut url = base.clone();
    url.set_query(None);
    url.set_fragment(None);
    url.path_segments_mut()
        .map_err(|_| anyhow!("ClawHub base URL cannot hold path segments"))?
        .clear()
        .extend(["api", "v1", "skills", slug]);
    if let Some(owner_handle) = owner_handle {
        url.query_pairs_mut()
            .append_pair("ownerHandle", owner_handle);
    }
    Ok(url)
}

fn download_url(
    base: &Url,
    slug: &str,
    owner_handle: Option<&str>,
    version: Option<&str>,
) -> Result<Url> {
    let mut url = base
        .join("/api/v1/download")
        .context("build download URL")?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("slug", slug);
        if let Some(owner_handle) = owner_handle {
            query.append_pair("ownerHandle", owner_handle);
        }
        if let Some(version) = version {
            query.append_pair("version", version);
        }
    }
    Ok(url)
}

fn github_zipball_url(repo: &str, commit: &str) -> Result<Url> {
    let mut parts = repo.split('/');
    let owner = parts.next().context("missing GitHub repository owner")?;
    let name = parts.next().context("missing GitHub repository name")?;
    let mut url = Url::parse("https://api.github.com/")?;
    url.path_segments_mut()
        .map_err(|_| anyhow!("GitHub API URL cannot hold path segments"))?
        .extend(["repos", owner, name, "zipball", commit]);
    Ok(url)
}

fn validate_https_url(url: &Url, allowed_hosts: &[&str]) -> Result<()> {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port().is_some()
    {
        bail!("remote URL must be credential-free HTTPS on its default port");
    }
    let host = url.host_str().context("remote URL has no host")?;
    if !allowed_hosts.contains(&host) {
        bail!("remote URL host is not allowlisted");
    }
    Ok(())
}

fn validate_github_repo(repo: &str) -> Result<()> {
    let parts = repo.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || parts.iter().any(|part| {
            part.is_empty()
                || part.len() > 100
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        bail!("handoff repository must be an owner/name GitHub repository");
    }
    Ok(())
}

fn valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 200
        && !slug.contains("..")
        && slug.bytes().enumerate().all(|(index, byte)| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => true,
            b'.' | b'_' | b'-' => index > 0,
            _ => false,
        })
}

fn valid_owner_handle(owner_handle: &str) -> bool {
    !owner_handle.is_empty()
        && owner_handle.len() <= 100
        && owner_handle
            .bytes()
            .enumerate()
            .all(|(index, byte)| match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => true,
                b'.' | b'_' | b'-' => index > 0,
                _ => false,
            })
}

fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && !version.chars().any(char::is_control)
        && !version.contains(['\r', '\n'])
}

fn validate_cursor(cursor: &str) -> Result<()> {
    if cursor.is_empty() || cursor.len() > MAX_CURSOR_BYTES || cursor.chars().any(char::is_control)
    {
        bail!("ClawHub returned an unsafe pagination cursor");
    }
    Ok(())
}

fn catalog_revision(updated_at: Option<u64>) -> String {
    format!("catalog-updated:{}", updated_at.unwrap_or_default())
}

fn hosted_revision(version: &str, updated_at: Option<u64>) -> String {
    format!(
        "version:{version};catalog-updated:{}",
        updated_at
            .map(|value| value.to_string())
            .unwrap_or_else(|| "missing".to_owned())
    )
}

fn invalid_catalog_observation(base: &Url, page: usize, item: usize) -> ClawhubObservation {
    let id = format!("catalog-page-{page}-item-{item}");
    ClawhubObservation {
        source_native_id: id.clone(),
        source_url: base.to_string(),
        source_revision: id.clone(),
        source_path: id,
    }
}

#[derive(Clone, Copy)]
struct FetchPolicy {
    hosts: &'static [&'static str],
    max_redirects: usize,
}

#[derive(Clone, Debug)]
struct HttpResponse {
    status: u16,
    content_type: Option<String>,
    location: Option<String>,
    body: Vec<u8>,
}

trait HttpTransport {
    fn get(&self, url: &Url, max_bytes: u64) -> Result<HttpResponse>;
}

struct ReqwestTransport {
    client: Client,
    minimum_interval: Option<Duration>,
    last_request: Mutex<Option<Instant>>,
}

impl ReqwestTransport {
    fn new(rate_limit_per_minute: Option<u32>) -> Result<Self> {
        let minimum_interval = match rate_limit_per_minute {
            Some(0) => bail!("platform rate limit must be greater than zero"),
            Some(requests) => Some(Duration::from_secs_f64(60.0 / f64::from(requests))),
            None => None,
        };
        let client = Client::builder()
            .redirect(Policy::none())
            .https_only(true)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .user_agent("skillsissue-skill-ingest/0.1")
            .referer(false)
            .build()
            .context("build bounded HTTPS client")?;
        Ok(Self {
            client,
            minimum_interval,
            last_request: Mutex::new(None),
        })
    }
}

impl HttpTransport for ReqwestTransport {
    fn get(&self, url: &Url, max_bytes: u64) -> Result<HttpResponse> {
        if let Some(interval) = self.minimum_interval {
            let mut last_request = self
                .last_request
                .lock()
                .map_err(|_| anyhow!("HTTP rate limiter lock was poisoned"))?;
            if let Some(last) = *last_request {
                thread::sleep(interval.saturating_sub(last.elapsed()));
            }
            *last_request = Some(Instant::now());
        }
        let mut response = self
            .client
            .get(url.clone())
            .header(ACCEPT, "application/json, application/zip;q=0.9")
            .send()
            .map_err(|_| anyhow!("HTTPS request failed"))?;
        if response
            .content_length()
            .is_some_and(|size| size > max_bytes)
        {
            bail!("HTTP response exceeded the {max_bytes} byte limit");
        }
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let location = response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        let mut limited = (&mut response).take(max_bytes.saturating_add(1));
        limited
            .read_to_end(&mut body)
            .map_err(|_| anyhow!("failed to read bounded HTTPS response"))?;
        if body.len() as u64 > max_bytes {
            bail!("HTTP response exceeded the {max_bytes} byte limit");
        }
        Ok(HttpResponse {
            status,
            content_type,
            location,
            body,
        })
    }
}

fn fetch_with_redirects<T: HttpTransport>(
    transport: &T,
    mut url: Url,
    max_bytes: u64,
    policy: FetchPolicy,
) -> Result<HttpResponse> {
    for redirects in 0..=policy.max_redirects {
        validate_https_url(&url, policy.hosts)?;
        let response = transport.get(&url, max_bytes)?;
        if !(300..400).contains(&response.status) {
            return Ok(response);
        }
        if redirects == policy.max_redirects {
            bail!("HTTP redirect limit exceeded");
        }
        let location = response
            .location
            .as_deref()
            .context("redirect omitted Location")?;
        let next = url.join(location).context("parse redirect Location")?;
        validate_https_url(&next, policy.hosts)?;
        url = next;
    }
    unreachable!("redirect loop is bounded")
}

fn require_success(response: &HttpResponse, operation: &str) -> Result<()> {
    if response.status != 200 {
        bail!("{operation} returned HTTP {}", response.status);
    }
    Ok(())
}

fn is_json_content_type(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn looks_like_zip(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(..4),
        Some(b"PK\x03\x04") | Some(b"PK\x05\x06") | Some(b"PK\x07\x08")
    )
}

struct ExtractedSkill {
    temp: TempDir,
    source_root: PathBuf,
    skill_dir: PathBuf,
    observation: Option<ClawhubObservation>,
}

impl ExtractedSkill {
    fn into_downloaded(self) -> Result<DownloadedSkill> {
        Ok(DownloadedSkill {
            _temp: self.temp,
            source_root: self.source_root,
            skill_dir: self.skill_dir,
            observation: self.observation.context("missing ClawHub provenance")?,
        })
    }
}

fn extract_skill_archive(
    bytes: &[u8],
    selection: Option<&Path>,
    limits: SecurityLimits,
) -> Result<ExtractedSkill> {
    if bytes.len() as u64 > MAX_DOWNLOAD_BYTES || !looks_like_zip(bytes) {
        bail!("archive is not bounded ZIP data");
    }
    let mut archive = ZipArchive::new(Cursor::new(bytes)).context("open ZIP archive")?;
    if archive.len() > MAX_ZIP_ENTRIES {
        bail!("ZIP contains more than {MAX_ZIP_ENTRIES} entries");
    }
    let selection = selection.map(portable_path).transpose()?;
    let temp = tempfile::tempdir().context("create ZIP extraction staging directory")?;
    let source_root = temp.path().join("tree");
    fs::create_dir(&source_root).context("create ZIP extraction root")?;
    let mut seen_archive_paths = BTreeSet::new();
    let mut extracted_nodes = BTreeSet::new();
    let mut selected_archive_root: Option<String> = None;
    let mut expanded_bytes = 0_u64;
    let mut extracted_files = 0_u64;

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .context("read ZIP directory entry")?;
        let raw_name = entry.name_raw();
        let name = std::str::from_utf8(raw_name).context("ZIP paths must be valid UTF-8")?;
        let archive_path =
            normalized_relative_path(name.trim_end_matches('/'), MAX_ZIP_PATH_BYTES)?;
        let archive_portable = portable_path(&archive_path)?;
        if archive_portable.is_empty() || !seen_archive_paths.insert(archive_portable) {
            bail!("ZIP contains an empty or duplicate path");
        }
        let relative = match &selection {
            Some(selection) => {
                select_github_entry(&archive_path, selection, &mut selected_archive_root)?
            }
            None => Some(archive_path.clone()),
        };
        let Some(relative) = relative else {
            continue;
        };
        if relative.as_os_str().is_empty() {
            continue;
        }
        if relative.components().count() > limits.max_depth.saturating_add(2) {
            bail!("selected ZIP entry exceeds the configured depth limit");
        }
        let unix_mode = entry.unix_mode().unwrap_or_default();
        let node_type = unix_mode & 0o170_000;
        let is_directory = entry.is_dir() || name.ends_with('/');
        if (!is_directory && !matches!(node_type, 0 | 0o100_000))
            || (is_directory && !matches!(node_type, 0 | 0o040_000))
        {
            bail!("selected ZIP entry is a symlink or special filesystem node");
        }

        ensure_output_parents(
            &source_root,
            &relative,
            &mut extracted_nodes,
            limits.max_files_per_skill,
        )?;
        let destination = source_root.join(&relative);
        if is_directory {
            register_directory(
                &destination,
                &relative,
                &mut extracted_nodes,
                limits.max_files_per_skill,
            )?;
            continue;
        }
        if extracted_nodes.contains(&relative) {
            bail!("ZIP output path collides with a directory");
        }
        register_node(&relative, &mut extracted_nodes, limits.max_files_per_skill)?;
        extracted_files = extracted_files.saturating_add(1);
        if entry.size() > limits.max_file_bytes
            || entry.size() > limits.max_bytes_per_skill.saturating_sub(expanded_bytes)
        {
            bail!("selected ZIP file exceeds configured byte limits");
        }
        if entry.size() > 1024 * 1024
            && entry.size()
                > entry
                    .compressed_size()
                    .max(1)
                    .saturating_mul(MAX_COMPRESSION_RATIO)
        {
            bail!("selected ZIP file exceeds the compression-ratio limit");
        }
        let declared_size = entry.size();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options
            .open(&destination)
            .context("create selected ZIP output file")?;
        let mut limited = (&mut entry).take(declared_size.saturating_add(1));
        let copied = io::copy(&mut limited, &mut output).context("extract bounded ZIP file")?;
        if copied != declared_size {
            bail!("ZIP entry size did not match its directory record");
        }
        output.flush().context("flush extracted ZIP file")?;
        set_extracted_permissions(&output, unix_mode)?;
        expanded_bytes = expanded_bytes
            .checked_add(copied)
            .context("ZIP expansion byte count overflow")?;
    }

    if extracted_files == 0 {
        bail!("archive selection contained no regular files");
    }
    let skill_dir = locate_skill_root(&source_root, limits.max_depth)?;
    Ok(ExtractedSkill {
        temp,
        source_root,
        skill_dir,
        observation: None,
    })
}

fn select_github_entry(
    archive_path: &Path,
    selection: &str,
    selected_archive_root: &mut Option<String>,
) -> Result<Option<PathBuf>> {
    let mut components = archive_path.components();
    let Some(Component::Normal(root)) = components.next() else {
        bail!("GitHub ZIP entry has no archive root");
    };
    let root = root.to_str().context("GitHub ZIP root is not UTF-8")?;
    let remainder = components.collect::<PathBuf>();
    let selection = Path::new(selection);
    let Ok(relative) = remainder.strip_prefix(selection) else {
        return Ok(None);
    };
    match selected_archive_root {
        Some(existing) if existing != root => bail!("GitHub ZIP contains multiple archive roots"),
        Some(_) => {}
        None => *selected_archive_root = Some(root.to_owned()),
    }
    Ok(Some(relative.to_owned()))
}

fn ensure_output_parents(
    root: &Path,
    relative: &Path,
    nodes: &mut BTreeSet<PathBuf>,
    max_entries: u64,
) -> Result<()> {
    let mut current = PathBuf::new();
    let components = relative.components().collect::<Vec<_>>();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        let Component::Normal(component) = component else {
            bail!("ZIP output path is not normalized");
        };
        current.push(component);
        if nodes.insert(current.clone()) {
            ensure_entry_limit(nodes, max_entries)?;
            fs::create_dir(root.join(&current)).context("create selected ZIP directory")?;
        } else if !root.join(&current).is_dir() {
            bail!("ZIP output parent collides with a file");
        }
    }
    Ok(())
}

fn register_directory(
    destination: &Path,
    relative: &Path,
    nodes: &mut BTreeSet<PathBuf>,
    max_entries: u64,
) -> Result<()> {
    if nodes.insert(relative.to_owned()) {
        ensure_entry_limit(nodes, max_entries)?;
        fs::create_dir(destination).context("create selected ZIP directory")?;
    } else if !destination.is_dir() {
        bail!("ZIP directory collides with a file");
    }
    Ok(())
}

fn register_node(relative: &Path, nodes: &mut BTreeSet<PathBuf>, max_entries: u64) -> Result<()> {
    if !nodes.insert(relative.to_owned()) {
        bail!("ZIP contains colliding output paths");
    }
    ensure_entry_limit(nodes, max_entries)
}

fn ensure_entry_limit(nodes: &BTreeSet<PathBuf>, max_entries: u64) -> Result<()> {
    if nodes.len() as u64 > max_entries {
        bail!("selected ZIP tree exceeds the {max_entries} entry limit");
    }
    Ok(())
}

#[cfg(unix)]
fn set_extracted_permissions(file: &File, source_mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if source_mode & 0o111 != 0 {
        0o700
    } else {
        0o600
    };
    file.set_permissions(fs::Permissions::from_mode(mode))
        .context("set extracted ZIP permissions")
}

#[cfg(not(unix))]
fn set_extracted_permissions(_file: &File, _source_mode: u32) -> Result<()> {
    Ok(())
}

fn locate_skill_root(source_root: &Path, max_depth: usize) -> Result<PathBuf> {
    let root_marker = source_root.join("SKILL.md");
    if fs::symlink_metadata(&root_marker)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
    {
        return Ok(source_root.to_owned());
    }
    let roots = discover_skill_directories(source_root, 2, max_depth)?;
    match roots.as_slice() {
        [root] => Ok(root.clone()),
        [] => bail!("extracted archive contains no regular SKILL.md"),
        _ => bail!("extracted archive contains multiple skill roots"),
    }
}

fn validate_hosted_metadata(skill_dir: &Path, slug: &str, version: &str) -> Result<()> {
    let path = skill_dir.join("_meta.json");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
        Ok(_) => bail!("hosted _meta.json is not a regular file"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect hosted _meta.json"),
    };
    if metadata.len() > MAX_HANDOFF_BYTES as u64 {
        bail!("hosted _meta.json exceeds its metadata limit");
    }
    #[derive(Deserialize)]
    struct HostedMetadata {
        slug: String,
        version: String,
    }
    let value: HostedMetadata =
        serde_json::from_reader(File::open(path)?).context("decode hosted _meta.json")?;
    if value.slug != slug || value.version != version {
        bail!("hosted ZIP metadata does not match catalog slug/version");
    }
    Ok(())
}

fn normalized_relative_path(value: &str, max_bytes: usize) -> Result<PathBuf> {
    let value = value.trim_end_matches('/');
    if value.is_empty()
        || value.len() > max_bytes
        || value.starts_with('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        bail!("path is empty, non-portable, or too long");
    }
    let mut path = PathBuf::new();
    for component in value.split('/') {
        if component.is_empty() || matches!(component, "." | "..") {
            bail!("path is not normalized");
        }
        path.push(component);
    }
    Ok(path)
}

fn portable_path(path: &Path) -> Result<String> {
    let mut value = String::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            bail!("path is not relative and normalized");
        };
        let component = component.to_str().context("path is not valid UTF-8")?;
        if !value.is_empty() {
            value.push('/');
        }
        value.push_str(component);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Mutex;

    use super::*;
    use zip::CompressionMethod;
    use zip::write::SimpleFileOptions;

    #[derive(Default)]
    struct FixtureTransport {
        responses: Mutex<BTreeMap<String, VecDeque<HttpResponse>>>,
        requests: Mutex<Vec<String>>,
    }

    impl FixtureTransport {
        fn add(&self, url: Url, response: HttpResponse) {
            self.responses
                .lock()
                .unwrap()
                .entry(url.to_string())
                .or_default()
                .push_back(response);
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl HttpTransport for FixtureTransport {
        fn get(&self, url: &Url, max_bytes: u64) -> Result<HttpResponse> {
            self.requests.lock().unwrap().push(url.to_string());
            let response = self
                .responses
                .lock()
                .unwrap()
                .get_mut(url.as_str())
                .and_then(VecDeque::pop_front)
                .with_context(|| format!("no fixture for {url}"))?;
            if response.body.len() as u64 > max_bytes {
                bail!("fixture exceeded response limit");
            }
            Ok(response)
        }
    }

    #[test]
    fn configured_request_rate_is_validated_and_converted_to_spacing() {
        assert!(ReqwestTransport::new(Some(0)).is_err());
        let transport = ReqwestTransport::new(Some(60)).unwrap();
        assert_eq!(transport.minimum_interval, Some(Duration::from_secs(1)));
    }

    #[test]
    fn paginates_past_known_versions_without_downloading_them() {
        let transport = FixtureTransport::default();
        let base = validate_clawhub_base("https://clawhub.ai").unwrap();
        transport.add(
            catalog_url(&base, None).unwrap(),
            json_response(
                br#"{"items":[{"slug":"already-known","latestVersion":{"version":"1.0.0"},"updatedAt":1}],"nextCursor":"next/page"}"#,
            ),
        );
        transport.add(
            catalog_url(&base, Some("next/page")).unwrap(),
            json_response(
                br#"{"items":[{"slug":"fresh","latestVersion":{"version":"2.1.0"},"updatedAt":2}],"nextCursor":null}"#,
            ),
        );
        let fresh_download = download_url(&base, "fresh", None, Some("2.1.0")).unwrap();
        transport.add(
            fresh_download.clone(),
            zip_response(hosted_zip("fresh", "2.1.0")),
        );

        let mut visited = Vec::new();
        let stats = scan_with_transport(
            &transport,
            "https://clawhub.ai",
            SecurityLimits::default(),
            |observation| {
                if observation.source_native_id == "already-known" {
                    KnownDisposition::Discovery
                } else {
                    KnownDisposition::New
                }
            },
            |candidate| {
                let ClawhubCandidate::Downloaded(downloaded) = candidate else {
                    panic!("fixture candidate should be accepted");
                };
                assert!(downloaded.skill_dir().join("SKILL.md").is_file());
                visited.push(downloaded.observation);
                Ok(true)
            },
        )
        .unwrap();

        assert_eq!(stats.pages, 2);
        assert_eq!(stats.catalog_items, 2);
        assert_eq!(stats.skipped_discoveries, 1);
        assert_eq!(visited.len(), 1);
        assert_eq!(visited[0].source_native_id, "fresh");
        assert_eq!(
            visited[0].source_revision,
            "version:2.1.0;catalog-updated:2"
        );
        let requests = transport.requests();
        assert_eq!(requests.len(), 3);
        assert!(
            !requests
                .iter()
                .any(|url| url.contains("already-known") && url.contains("download"))
        );
        assert_eq!(requests.last(), Some(&fresh_download.to_string()));
    }

    #[test]
    fn resolves_ambiguous_slugs_into_owner_qualified_downloads() {
        let transport = FixtureTransport::default();
        let base = validate_clawhub_base("https://clawhub.ai").unwrap();
        transport.add(
            catalog_url(&base, None).unwrap(),
            json_response(
                br#"{"items":[{"slug":"shared","latestVersion":{"version":"2.0.0"},"updatedAt":22}],"nextCursor":null}"#,
            ),
        );
        transport.add(
            download_url(&base, "shared", None, Some("2.0.0")).unwrap(),
            HttpResponse {
                status: 409,
                content_type: Some("text/plain; charset=utf-8".to_owned()),
                location: None,
                body: b"Ambiguous skill slug".to_vec(),
            },
        );
        transport.add(
            skill_detail_url(&base, "shared", None).unwrap(),
            HttpResponse {
                status: 409,
                content_type: Some("application/json".to_owned()),
                location: None,
                body: br#"{"code":"AMBIGUOUS_SKILL_SLUG","slug":"shared","matches":[{"ownerHandle":"beta","slug":"shared"},{"ownerHandle":"alpha","slug":"shared"}]}"#.to_vec(),
            },
        );
        transport.add(
            skill_detail_url(&base, "shared", Some("alpha")).unwrap(),
            json_response(
                br#"{"skill":{"slug":"shared","updatedAt":11},"latestVersion":{"version":"1.0.0"},"owner":{"handle":"alpha"}}"#,
            ),
        );
        transport.add(
            skill_detail_url(&base, "shared", Some("beta")).unwrap(),
            json_response(
                br#"{"skill":{"slug":"shared","updatedAt":22},"latestVersion":{"version":"2.0.0"},"owner":{"handle":"beta"}}"#,
            ),
        );
        let alpha_download = download_url(&base, "shared", Some("alpha"), Some("1.0.0")).unwrap();
        let beta_download = download_url(&base, "shared", Some("beta"), Some("2.0.0")).unwrap();
        transport.add(
            alpha_download.clone(),
            zip_response(hosted_zip("shared", "1.0.0")),
        );
        transport.add(
            beta_download.clone(),
            zip_response(hosted_zip("shared", "2.0.0")),
        );

        let mut observations = Vec::new();
        scan_with_transport(
            &transport,
            "https://clawhub.ai",
            SecurityLimits::default(),
            |_| KnownDisposition::New,
            |candidate| {
                let ClawhubCandidate::Downloaded(downloaded) = candidate else {
                    panic!("publisher-qualified fixture should download");
                };
                observations.push(downloaded.observation);
                Ok(true)
            },
        )
        .unwrap();

        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].source_native_id, "@alpha/shared");
        assert_eq!(observations[0].source_path, "@alpha/shared");
        assert!(observations[0].source_url.contains("ownerHandle=alpha"));
        assert_eq!(
            observations[0].source_revision,
            "version:1.0.0;catalog-updated:11"
        );
        assert_eq!(observations[1].source_native_id, "@beta/shared");
        assert!(observations[1].source_url.contains("ownerHandle=beta"));
        assert_eq!(
            observations[1].source_revision,
            "version:2.0.0;catalog-updated:22"
        );
        let requests = transport.requests();
        assert_eq!(requests.len(), 7);
        assert_eq!(requests[5], alpha_download.to_string());
        assert_eq!(requests[6], beta_download.to_string());
    }

    #[test]
    fn follows_documented_public_github_handoff_with_bounded_redirect() {
        let transport = FixtureTransport::default();
        let base = validate_clawhub_base("https://clawhub.ai").unwrap();
        let commit = "1".repeat(40);
        let content_hash = "a".repeat(64);
        let archive_url = github_zipball_url("acme/skills", &commit).unwrap();
        let redirected = Url::parse(&format!(
            "https://codeload.github.com/acme/skills/legacy.zip/{commit}"
        ))
        .unwrap();
        transport.add(
            catalog_url(&base, None).unwrap(),
            json_response(
                br#"{"items":[{"slug":"github-skill","latestVersion":null,"updatedAt":99}],"nextCursor":null}"#,
            ),
        );
        transport.add(
            download_url(&base, "github-skill", None, None).unwrap(),
            json_response(
                format!(
                    r#"{{"sourceRef":"public-github","repo":"acme/skills","commit":"{commit}","path":"skills/github-skill","contentHash":"{content_hash}","archiveUrl":"{archive_url}"}}"#
                )
                .as_bytes(),
            ),
        );
        transport.add(
            archive_url.clone(),
            HttpResponse {
                status: 302,
                content_type: None,
                location: Some(redirected.to_string()),
                body: Vec::new(),
            },
        );
        transport.add(
            redirected.clone(),
            zip_response(zip_files(&[
                (
                    "acme-skills-123/skills/github-skill/SKILL.md",
                    b"---\nname: github-skill\n---\n".as_slice(),
                ),
                (
                    "acme-skills-123/skills/github-skill/scripts/run.sh",
                    b"#!/bin/sh\n".as_slice(),
                ),
                ("acme-skills-123/unrelated.txt", b"ignored".as_slice()),
            ])),
        );

        let mut observation = None;
        scan_with_transport(
            &transport,
            "https://clawhub.ai",
            SecurityLimits::default(),
            |_| KnownDisposition::New,
            |candidate| {
                let ClawhubCandidate::Downloaded(downloaded) = candidate else {
                    panic!("GitHub handoff should produce a staged skill");
                };
                assert!(downloaded.skill_dir().join("SKILL.md").is_file());
                assert!(downloaded.skill_dir().join("scripts/run.sh").is_file());
                assert!(!downloaded.source_root().join("unrelated.txt").exists());
                observation = Some(downloaded.observation);
                Ok(true)
            },
        )
        .unwrap();

        let observation = observation.unwrap();
        assert_eq!(observation.source_native_id, "github-skill");
        assert_eq!(
            observation.source_path,
            "github:acme/skills/skills/github-skill"
        );
        assert!(observation.source_revision.contains(&commit));
        assert!(observation.source_revision.contains(&content_hash));
        assert_eq!(transport.requests().last(), Some(&redirected.to_string()));
    }

    #[test]
    fn rejects_handoff_redirect_to_non_allowlisted_host_before_requesting_it() {
        let transport = FixtureTransport::default();
        let base = validate_clawhub_base("https://clawhub.ai").unwrap();
        let commit = "2".repeat(40);
        let archive_url = github_zipball_url("acme/skills", &commit).unwrap();
        transport.add(
            catalog_url(&base, None).unwrap(),
            json_response(
                br#"{"items":[{"slug":"redirected","latestVersion":null,"updatedAt":1}],"nextCursor":null}"#,
            ),
        );
        transport.add(
            download_url(&base, "redirected", None, None).unwrap(),
            json_response(
                format!(
                    r#"{{"sourceRef":"public-github","repo":"acme/skills","commit":"{commit}","path":"skills/redirected","contentHash":"{}","archiveUrl":"{archive_url}"}}"#,
                    "b".repeat(64)
                )
                .as_bytes(),
            ),
        );
        transport.add(
            archive_url,
            HttpResponse {
                status: 302,
                content_type: None,
                location: Some("https://evil.example/payload.zip".to_owned()),
                body: Vec::new(),
            },
        );

        let mut rejection = None;
        scan_with_transport(
            &transport,
            "https://clawhub.ai",
            SecurityLimits::default(),
            |_| KnownDisposition::New,
            |candidate| {
                let ClawhubCandidate::Error { message, .. } = candidate else {
                    panic!("unsafe redirect must be rejected");
                };
                rejection = Some(message);
                Ok(true)
            },
        )
        .unwrap();
        assert!(rejection.unwrap().contains("allowlisted"));
        assert!(
            !transport
                .requests()
                .iter()
                .any(|request| request.contains("evil.example"))
        );
    }

    #[test]
    fn rejects_repeated_pagination_cursor() {
        let transport = FixtureTransport::default();
        let base = validate_clawhub_base("https://clawhub.ai").unwrap();
        transport.add(
            catalog_url(&base, None).unwrap(),
            json_response(br#"{"items":[],"nextCursor":"repeat"}"#),
        );
        transport.add(
            catalog_url(&base, Some("repeat")).unwrap(),
            json_response(br#"{"items":[],"nextCursor":"repeat"}"#),
        );
        let error = scan_with_transport(
            &transport,
            "https://clawhub.ai",
            SecurityLimits::default(),
            |_| KnownDisposition::New,
            |_| Ok(true),
        )
        .expect_err("repeated cursor should fail closed");
        assert!(error.to_string().contains("repeated pagination cursor"));
        assert_eq!(transport.requests().len(), 2);
    }

    #[test]
    fn rejects_zip_slip_symlink_and_expansion_caps() {
        let traversal = zip_files(&[("../escape", b"bad".as_slice())]);
        let error = extract_skill_archive(&traversal, None, SecurityLimits::default())
            .err()
            .expect("ZIP traversal should fail");
        assert!(error.to_string().contains("normalized"));

        let limits = SecurityLimits {
            max_files_per_skill: 8,
            max_bytes_per_skill: 16,
            max_file_bytes: 16,
            max_depth: 4,
        };
        let oversized = zip_files(&[("SKILL.md", &[b'x'; 17])]);
        assert!(extract_skill_archive(&oversized, None, limits).is_err());

        let symlink = symlink_zip("SKILL.md", "../../outside");
        let error = extract_skill_archive(&symlink, None, SecurityLimits::default())
            .err()
            .expect("ZIP symlink should be rejected");
        assert!(error.to_string().contains("symlink"));

        let zeros = vec![0_u8; 8 * 1024 * 1024];
        let bomb = zip_files(&[("SKILL.md", &zeros)]);
        let bomb_limits = SecurityLimits {
            max_files_per_skill: 8,
            max_bytes_per_skill: 9 * 1024 * 1024,
            max_file_bytes: 9 * 1024 * 1024,
            max_depth: 4,
        };
        let error = extract_skill_archive(&bomb, None, bomb_limits)
            .err()
            .expect("high-ratio ZIP should be rejected");
        assert!(error.to_string().contains("compression-ratio"));
    }

    #[test]
    fn validates_handoff_archive_url_against_repo_and_commit() {
        let error = ValidatedHandoff::new(GitHubHandoff {
            source_ref: "public-github".to_owned(),
            repo: "acme/skills".to_owned(),
            commit: "3".repeat(40),
            path: "skills/demo".to_owned(),
            content_hash: "c".repeat(64),
            archive_url: "https://api.github.com/repos/other/repo/zipball/deadbeef".to_owned(),
        })
        .err()
        .expect("mismatched archive URL should fail");
        assert!(error.to_string().contains("does not match"));
    }

    fn json_response(body: &[u8]) -> HttpResponse {
        HttpResponse {
            status: 200,
            content_type: Some("application/json; charset=utf-8".to_owned()),
            location: None,
            body: body.to_vec(),
        }
    }

    fn zip_response(body: Vec<u8>) -> HttpResponse {
        HttpResponse {
            status: 200,
            content_type: Some("application/zip".to_owned()),
            location: None,
            body,
        }
    }

    fn hosted_zip(slug: &str, version: &str) -> Vec<u8> {
        let metadata = format!(r#"{{"slug":"{slug}","version":"{version}"}}"#);
        zip_files(&[
            (
                "SKILL.md",
                format!("---\nname: {slug}\nversion: {version}\n---\n").as_bytes(),
            ),
            ("_meta.json", metadata.as_bytes()),
        ])
    }

    fn zip_files(files: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o644);
        for (name, bytes) in files {
            writer.start_file(*name, options).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn symlink_zip(name: &str, target: &str) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .add_symlink(name, target, SimpleFileOptions::default())
            .unwrap();
        writer.finish().unwrap().into_inner()
    }
}
