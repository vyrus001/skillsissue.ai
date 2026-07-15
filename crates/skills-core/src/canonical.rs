//! Versioned skill-tree canonicalization and deterministic archive construction.
//!
//! The v1 digest stream is `domain || entry*`. Each entry is ordered by canonical
//! path bytes and encoded as `kind:u8 || path_len:u64be || path || executable:u8 ||
//! payload_len:u64be || payload`. A file payload is its raw content, a symlink payload
//! is its literal UTF-8 target, and a directory payload is empty. This framing is part
//! of the persistent ID contract and must change only with the version.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{CoreError, Result, SCHEMA_VERSION};

pub const CANONICALIZATION_VERSION: u32 = 1;
const CANONICAL_DOMAIN: &[u8] = b"skillsissue.skill-tree\0v1\0";
const ARCHIVE_ROOT: &str = "skill";
const ARCHIVE_MANIFEST: &str = "manifest.json";
const ZSTD_LEVEL: i32 = 19;

/// Resource ceilings applied while authenticating an existing artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactValidationLimits {
    pub max_archive_bytes: u64,
    pub max_manifest_bytes: u64,
    pub max_entries: u64,
    pub max_expanded_bytes: u64,
    /// Maximum Zstandard window as a base-2 logarithm.
    pub zstd_window_log_max: u32,
}

impl Default for ArtifactValidationLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 256 * 1024 * 1024,
            max_manifest_bytes: 64 * 1024 * 1024,
            max_entries: 100_000,
            max_expanded_bytes: 512 * 1024 * 1024,
            zstd_window_log_max: 27,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Directory,
    File,
    Symlink,
}

impl EntryKind {
    fn tag(self) -> u8 {
        match self {
            Self::Directory => b'd',
            Self::File => b'f',
            Self::Symlink => b'l',
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalEntry {
    /// UTF-8, `/`-separated path relative to the skill root.
    pub path: String,
    pub kind: EntryKind,
    /// Whether any Unix executable bit was set on a regular file.
    pub executable: bool,
    /// Regular-file byte length, symlink-target byte length, or zero for a directory.
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blake3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalSkill {
    pub canonicalization_version: u32,
    /// Versioned identifier: `sha256:v1:<lowercase hex>`.
    pub skill_id: String,
    /// Lowercase SHA-256 of the canonical framed tree stream.
    pub sha256: String,
    /// Lowercase BLAKE3 of the same canonical framed tree stream.
    pub blake3: String,
    /// Sum of regular-file content lengths.
    pub size_bytes: u64,
    /// Count of regular files and symlinks (directories excluded).
    pub file_count: u64,
    pub entries: Vec<CanonicalEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub kind: EntryKind,
    pub executable: bool,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blake3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
}

impl From<&CanonicalEntry> for ManifestEntry {
    fn from(value: &CanonicalEntry) -> Self {
        Self {
            path: value.path.clone(),
            kind: value.kind,
            executable: value.executable,
            size_bytes: value.size_bytes,
            sha256: value.sha256.clone(),
            blake3: value.blake3.clone(),
            symlink_target: value.symlink_target.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub canonicalization_version: u32,
    pub skill_id: String,
    pub sha256: String,
    pub blake3: String,
    pub size_bytes: u64,
    pub file_count: u64,
    pub entries: Vec<ManifestEntry>,
}

impl From<&CanonicalSkill> for Manifest {
    fn from(value: &CanonicalSkill) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            canonicalization_version: value.canonicalization_version,
            skill_id: value.skill_id.clone(),
            sha256: value.sha256.clone(),
            blake3: value.blake3.clone(),
            size_bytes: value.size_bytes,
            file_count: value.file_count,
            entries: value.entries.iter().map(ManifestEntry::from).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillArtifact {
    pub canonical: CanonicalSkill,
    pub archive_path: PathBuf,
    pub manifest_path: PathBuf,
    pub archive_sha256: String,
    pub archive_blake3: String,
}

/// Hash a skill directory as a versioned, deterministic framed byte stream.
///
/// Traversal never follows symlinks. Paths are sorted by their canonical UTF-8
/// bytes; file contents are hashed as raw bytes; any executable bit is significant;
/// and a symlink contributes its literal target. Unsafe/escaping links, non-UTF-8
/// paths, backslash-bearing path segments, and special filesystem nodes are rejected.
pub fn canonicalize_skill_tree(root: impl AsRef<Path>) -> Result<CanonicalSkill> {
    let root = root.as_ref();
    validate_root(root)?;
    let scanned = scan_tree(root)?;

    let mut tree_hash = DualHasher::new();
    tree_hash.update(CANONICAL_DOMAIN);
    let mut entries = Vec::with_capacity(scanned.len());
    let mut size_bytes = 0_u64;
    let mut file_count = 0_u64;

    for node in scanned {
        tree_hash.update(&[node.kind.tag()]);
        tree_hash.update_frame(node.canonical_path.as_bytes());
        tree_hash.update(&[u8::from(node.executable)]);
        tree_hash.update(&node.size_bytes.to_be_bytes());

        let (sha256, blake3) = match node.kind {
            EntryKind::Directory => (None, None),
            EntryKind::Symlink => {
                let target = node
                    .symlink_target
                    .as_deref()
                    .expect("scanned symlink target");
                tree_hash.update(target.as_bytes());
                let digest = digest_bytes(target.as_bytes());
                file_count = file_count
                    .checked_add(1)
                    .expect("skill file count cannot overflow u64");
                (Some(digest.0), Some(digest.1))
            }
            EntryKind::File => {
                let path = root.join(&node.relative_path);
                let mut file = open_regular_file(&path)?;
                let mut content_hash = DualHasher::new();
                copy_exact_into_hashes(
                    &path,
                    &mut file,
                    node.size_bytes,
                    &mut tree_hash,
                    &mut content_hash,
                )?;
                let digest = content_hash.finish();
                size_bytes = size_bytes
                    .checked_add(node.size_bytes)
                    .expect("skill content size cannot overflow u64");
                file_count = file_count
                    .checked_add(1)
                    .expect("skill file count cannot overflow u64");
                (Some(digest.0), Some(digest.1))
            }
        };

        entries.push(CanonicalEntry {
            path: node.canonical_path,
            kind: node.kind,
            executable: node.executable,
            size_bytes: node.size_bytes,
            sha256,
            blake3,
            symlink_target: node.symlink_target,
        });
    }

    let (sha256, blake3) = tree_hash.finish();
    Ok(CanonicalSkill {
        canonicalization_version: CANONICALIZATION_VERSION,
        skill_id: format!("sha256:v{CANONICALIZATION_VERSION}:{sha256}"),
        sha256,
        blake3,
        size_bytes,
        file_count,
        entries,
    })
}

/// Create a deterministic tar.zst bundle plus its deterministic JSON manifest.
///
/// Both destinations are written through same-directory temporary files. Archive
/// members are rooted under `skill/`, with `manifest.json` at archive top level.
pub fn archive_skill_tree(
    root: impl AsRef<Path>,
    archive_path: impl AsRef<Path>,
    manifest_path: impl AsRef<Path>,
) -> Result<SkillArtifact> {
    let root = root.as_ref();
    let archive_path = archive_path.as_ref();
    let manifest_path = manifest_path.as_ref();
    ensure_safe_outputs(root, archive_path, manifest_path)?;

    let canonical = canonicalize_skill_tree(root)?;
    let manifest_bytes = deterministic_manifest_bytes(&canonical)?;

    let archive_parent = archive_path.parent().unwrap_or_else(|| Path::new("."));
    let manifest_parent = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(archive_parent).map_err(|error| CoreError::io(archive_parent, error))?;
    fs::create_dir_all(manifest_parent).map_err(|error| CoreError::io(manifest_parent, error))?;

    let mut archive_temp = tempfile::NamedTempFile::new_in(archive_parent)
        .map_err(|error| CoreError::io(archive_parent, error))?;
    let mut manifest_temp = tempfile::NamedTempFile::new_in(manifest_parent)
        .map_err(|error| CoreError::io(manifest_parent, error))?;

    let archive_temp_path = archive_temp.path().to_owned();
    write_archive(
        root,
        &canonical,
        &manifest_bytes,
        archive_temp.as_file_mut(),
        &archive_temp_path,
    )?;
    manifest_temp
        .write_all(&manifest_bytes)
        .map_err(|error| CoreError::io(manifest_temp.path(), error))?;
    manifest_temp
        .flush()
        .map_err(|error| CoreError::io(manifest_temp.path(), error))?;
    manifest_temp
        .as_file()
        .sync_all()
        .map_err(|error| CoreError::io(manifest_temp.path(), error))?;

    if canonicalize_skill_tree(root)? != canonical {
        return Err(CoreError::TreeChanged);
    }

    let (archive_sha256, archive_blake3) = digest_file(archive_temp.path())?;
    persist_tempfile(archive_temp, archive_path)?;
    persist_tempfile(manifest_temp, manifest_path)?;
    sync_parent(archive_parent)?;
    if manifest_parent != archive_parent {
        sync_parent(manifest_parent)?;
    }

    Ok(SkillArtifact {
        canonical,
        archive_path: archive_path.to_owned(),
        manifest_path: manifest_path.to_owned(),
        archive_sha256,
        archive_blake3,
    })
}

/// Authenticate an existing tar.zst bundle and external manifest against a
/// canonical skill identity without extracting it.
///
/// Validation is bounded by `limits` and checks both manifests, exact member
/// order and metadata, every regular-file byte/hash, every symlink target, and
/// the complete v1 canonical digest stream. Extra archive members are rejected.
pub fn validate_skill_artifact(
    archive_path: impl AsRef<Path>,
    manifest_path: impl AsRef<Path>,
    expected: &CanonicalSkill,
    limits: ArtifactValidationLimits,
) -> Result<()> {
    let archive_path = archive_path.as_ref();
    let manifest_path = manifest_path.as_ref();
    validate_artifact_limits(archive_path, limits)?;

    let expected_manifest_bytes = deterministic_manifest_bytes(expected)?;
    if expected_manifest_bytes.len() as u64 > limits.max_manifest_bytes {
        return Err(invalid_artifact(
            manifest_path,
            "expected manifest exceeds validation limit",
        ));
    }
    let actual_manifest = read_regular_file_bounded(manifest_path, limits.max_manifest_bytes)?;
    if actual_manifest != expected_manifest_bytes {
        return Err(invalid_artifact(
            manifest_path,
            "external manifest does not match canonical skill",
        ));
    }

    let expected_entry_count = (expected.entries.len() as u64)
        .checked_add(2)
        .ok_or_else(|| invalid_artifact(archive_path, "entry count overflow"))?;
    if expected_entry_count > limits.max_entries {
        return Err(invalid_artifact(
            archive_path,
            "expected entry count exceeds validation limit",
        ));
    }
    let symlink_bytes = expected.entries.iter().try_fold(0_u64, |total, entry| {
        let size = if entry.kind == EntryKind::Symlink {
            entry.size_bytes
        } else {
            0
        };
        total
            .checked_add(size)
            .ok_or_else(|| invalid_artifact(archive_path, "expanded size overflow"))
    })?;
    let expected_expanded = expected
        .size_bytes
        .checked_add(symlink_bytes)
        .and_then(|value| value.checked_add(expected_manifest_bytes.len() as u64))
        .ok_or_else(|| invalid_artifact(archive_path, "expanded size overflow"))?;
    if expected_expanded > limits.max_expanded_bytes {
        return Err(invalid_artifact(
            archive_path,
            "expected expanded data exceeds validation limit",
        ));
    }

    let archive_file = open_regular_file(archive_path)?;
    let archive_size = archive_file
        .metadata()
        .map_err(|error| CoreError::io(archive_path, error))?
        .len();
    if archive_size == 0 || archive_size > limits.max_archive_bytes {
        return Err(invalid_artifact(
            archive_path,
            "compressed archive size is outside validation limits",
        ));
    }
    let mut decoder = zstd::stream::read::Decoder::new(archive_file)
        .map_err(|error| CoreError::io(archive_path, error))?;
    decoder
        .window_log_max(limits.zstd_window_log_max)
        .map_err(|error| CoreError::io(archive_path, error))?;
    let mut archive = tar::Archive::new(decoder);
    let mut members = archive
        .entries()
        .map_err(|error| CoreError::io(archive_path, error))?;

    let mut embedded_manifest = next_archive_member(&mut members, archive_path)?;
    validate_member_header(
        &embedded_manifest,
        Path::new(ARCHIVE_MANIFEST),
        tar::EntryType::Regular,
        expected_manifest_bytes.len() as u64,
        0o644,
        archive_path,
    )?;
    let embedded_bytes = read_member_exact(
        &mut embedded_manifest,
        expected_manifest_bytes.len() as u64,
        archive_path,
    )?;
    if embedded_bytes != expected_manifest_bytes {
        return Err(invalid_artifact(
            archive_path,
            "embedded manifest does not match canonical skill",
        ));
    }
    drop(embedded_manifest);

    let skill_root = next_archive_member(&mut members, archive_path)?;
    validate_member_header(
        &skill_root,
        Path::new(ARCHIVE_ROOT),
        tar::EntryType::Directory,
        0,
        0o755,
        archive_path,
    )?;
    drop(skill_root);

    let mut tree_hash = DualHasher::new();
    tree_hash.update(CANONICAL_DOMAIN);
    let mut total_size = 0_u64;
    let mut file_count = 0_u64;
    let mut previous_path: Option<&str> = None;
    for expected_entry in &expected.entries {
        let normalized =
            canonical_relative_path(Path::new(&expected_entry.path)).map_err(|_| {
                invalid_artifact(
                    archive_path,
                    format!("unsafe canonical path {}", expected_entry.path),
                )
            })?;
        if normalized != expected_entry.path
            || previous_path
                .is_some_and(|previous| previous.as_bytes() >= expected_entry.path.as_bytes())
        {
            return Err(invalid_artifact(
                archive_path,
                "canonical entries are not uniquely byte-sorted",
            ));
        }
        previous_path = Some(&expected_entry.path);
        let expected_path = Path::new(ARCHIVE_ROOT).join(&expected_entry.path);
        let mut member = next_archive_member(&mut members, archive_path)?;
        tree_hash.update(&[expected_entry.kind.tag()]);
        tree_hash.update_frame(expected_entry.path.as_bytes());
        tree_hash.update(&[u8::from(expected_entry.executable)]);
        tree_hash.update(&expected_entry.size_bytes.to_be_bytes());

        match expected_entry.kind {
            EntryKind::Directory => {
                validate_expected_directory(expected_entry, archive_path)?;
                validate_member_header(
                    &member,
                    &expected_path,
                    tar::EntryType::Directory,
                    0,
                    0o755,
                    archive_path,
                )?;
            }
            EntryKind::File => {
                validate_member_header(
                    &member,
                    &expected_path,
                    tar::EntryType::Regular,
                    expected_entry.size_bytes,
                    if expected_entry.executable {
                        0o755
                    } else {
                        0o644
                    },
                    archive_path,
                )?;
                let (sha256, blake3) = hash_archive_member(
                    archive_path,
                    &mut member,
                    expected_entry.size_bytes,
                    &mut tree_hash,
                )?;
                if expected_entry.sha256.as_deref() != Some(sha256.as_str())
                    || expected_entry.blake3.as_deref() != Some(blake3.as_str())
                    || expected_entry.symlink_target.is_some()
                {
                    return Err(invalid_artifact(
                        archive_path,
                        format!("file hash metadata mismatch at {}", expected_entry.path),
                    ));
                }
                total_size = total_size
                    .checked_add(expected_entry.size_bytes)
                    .ok_or_else(|| invalid_artifact(archive_path, "content size overflow"))?;
                file_count = file_count
                    .checked_add(1)
                    .ok_or_else(|| invalid_artifact(archive_path, "file count overflow"))?;
            }
            EntryKind::Symlink => {
                let target = expected_entry.symlink_target.as_deref().ok_or_else(|| {
                    invalid_artifact(archive_path, "canonical symlink is missing its target")
                })?;
                let normalized_target = canonical_symlink_target(&expected_path, Path::new(target))
                    .map_err(|_| {
                        invalid_artifact(
                            archive_path,
                            format!("unsafe symlink metadata at {}", expected_entry.path),
                        )
                    })?;
                if validate_symlink_target(Path::new(&expected_entry.path), Path::new(target))
                    .is_err()
                    || normalized_target != target
                {
                    return Err(invalid_artifact(
                        archive_path,
                        format!("unsafe symlink metadata at {}", expected_entry.path),
                    ));
                }
                let target_digest = digest_bytes(target.as_bytes());
                if expected_entry.executable
                    || expected_entry.size_bytes != target.len() as u64
                    || expected_entry.sha256.as_deref() != Some(target_digest.0.as_str())
                    || expected_entry.blake3.as_deref() != Some(target_digest.1.as_str())
                {
                    return Err(invalid_artifact(
                        archive_path,
                        format!("symlink metadata mismatch at {}", expected_entry.path),
                    ));
                }
                validate_member_header(
                    &member,
                    &expected_path,
                    tar::EntryType::Symlink,
                    0,
                    0o777,
                    archive_path,
                )?;
                let actual_target = member
                    .link_name()
                    .map_err(|error| CoreError::io(archive_path, error))?
                    .ok_or_else(|| {
                        invalid_artifact(archive_path, "archive symlink has no target")
                    })?;
                if actual_target.as_ref() != Path::new(target) {
                    return Err(invalid_artifact(
                        archive_path,
                        format!("symlink target mismatch at {}", expected_entry.path),
                    ));
                }
                tree_hash.update(target.as_bytes());
                file_count = file_count
                    .checked_add(1)
                    .ok_or_else(|| invalid_artifact(archive_path, "file count overflow"))?;
            }
        }
    }
    if let Some(member) = members.next() {
        member.map_err(|error| CoreError::io(archive_path, error))?;
        return Err(invalid_artifact(
            archive_path,
            "archive contains unexpected trailing members",
        ));
    }
    let (sha256, blake3) = tree_hash.finish();
    if expected.canonicalization_version != CANONICALIZATION_VERSION
        || expected.skill_id != format!("sha256:v{CANONICALIZATION_VERSION}:{sha256}")
        || expected.sha256 != sha256
        || expected.blake3 != blake3
        || expected.size_bytes != total_size
        || expected.file_count != file_count
    {
        return Err(invalid_artifact(
            archive_path,
            "archive canonical identity does not match expected skill",
        ));
    }
    Ok(())
}

fn validate_artifact_limits(path: &Path, limits: ArtifactValidationLimits) -> Result<()> {
    if limits.max_archive_bytes == 0
        || limits.max_manifest_bytes == 0
        || limits.max_entries < 2
        || limits.max_expanded_bytes == 0
        || !(10..=31).contains(&limits.zstd_window_log_max)
    {
        return Err(invalid_artifact(path, "invalid artifact validation limits"));
    }
    Ok(())
}

fn deterministic_manifest_bytes(canonical: &CanonicalSkill) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(&Manifest::from(canonical))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn read_regular_file_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let file = open_regular_file(path)?;
    let size = file
        .metadata()
        .map_err(|error| CoreError::io(path, error))?
        .len();
    if size > max_bytes {
        return Err(invalid_artifact(path, "file exceeds validation limit"));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(64 * 1024));
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| CoreError::io(path, error))?;
    if bytes.len() as u64 != size || bytes.len() as u64 > max_bytes {
        return Err(invalid_artifact(
            path,
            "file changed while it was validated",
        ));
    }
    Ok(bytes)
}

fn next_archive_member<'a, R: Read>(
    members: &mut tar::Entries<'a, R>,
    archive_path: &Path,
) -> Result<tar::Entry<'a, R>> {
    members
        .next()
        .ok_or_else(|| invalid_artifact(archive_path, "archive ended before expected members"))?
        .map_err(|error| CoreError::io(archive_path, error))
}

fn validate_member_header<R: Read>(
    member: &tar::Entry<'_, R>,
    expected_path: &Path,
    expected_type: tar::EntryType,
    expected_size: u64,
    expected_mode: u32,
    archive_path: &Path,
) -> Result<()> {
    let actual_path = member
        .path()
        .map_err(|error| CoreError::io(archive_path, error))?;
    let header = member.header();
    let size = header
        .size()
        .map_err(|error| CoreError::io(archive_path, error))?;
    let mode = header
        .mode()
        .map_err(|error| CoreError::io(archive_path, error))?;
    let uid = header
        .uid()
        .map_err(|error| CoreError::io(archive_path, error))?;
    let gid = header
        .gid()
        .map_err(|error| CoreError::io(archive_path, error))?;
    let mtime = header
        .mtime()
        .map_err(|error| CoreError::io(archive_path, error))?;
    if actual_path.as_ref() != expected_path
        || header.entry_type() != expected_type
        || size != expected_size
        || mode != expected_mode
        || uid != 0
        || gid != 0
        || mtime != 0
    {
        return Err(invalid_artifact(
            archive_path,
            format!("archive header mismatch at {}", expected_path.display()),
        ));
    }
    Ok(())
}

fn read_member_exact<R: Read>(
    member: &mut tar::Entry<'_, R>,
    expected_size: u64,
    archive_path: &Path,
) -> Result<Vec<u8>> {
    let capacity = usize::try_from(expected_size)
        .map_err(|_| invalid_artifact(archive_path, "member size does not fit memory"))?;
    let mut bytes = Vec::with_capacity(capacity);
    member
        .take(expected_size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| CoreError::io(archive_path, error))?;
    if bytes.len() as u64 != expected_size {
        return Err(invalid_artifact(
            archive_path,
            "archive member length changed while reading",
        ));
    }
    Ok(bytes)
}

fn validate_expected_directory(entry: &CanonicalEntry, archive_path: &Path) -> Result<()> {
    if entry.executable
        || entry.size_bytes != 0
        || entry.sha256.is_some()
        || entry.blake3.is_some()
        || entry.symlink_target.is_some()
    {
        return Err(invalid_artifact(
            archive_path,
            format!("directory metadata mismatch at {}", entry.path),
        ));
    }
    Ok(())
}

fn hash_archive_member<R: Read>(
    archive_path: &Path,
    member: &mut tar::Entry<'_, R>,
    expected_size: u64,
    tree_hash: &mut DualHasher,
) -> Result<(String, String)> {
    let mut remaining = expected_size;
    let mut content_hash = DualHasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
        let count = member
            .read(&mut buffer[..wanted])
            .map_err(|error| CoreError::io(archive_path, error))?;
        if count == 0 {
            return Err(invalid_artifact(
                archive_path,
                "archive member ended before its declared size",
            ));
        }
        tree_hash.update(&buffer[..count]);
        content_hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let mut extra = [0_u8; 1];
    if member
        .read(&mut extra)
        .map_err(|error| CoreError::io(archive_path, error))?
        != 0
    {
        return Err(invalid_artifact(
            archive_path,
            "archive member exceeded its declared size",
        ));
    }
    Ok(content_hash.finish())
}

fn invalid_artifact(path: &Path, reason: impl Into<String>) -> CoreError {
    CoreError::InvalidArtifact {
        path: path.to_owned(),
        reason: reason.into(),
    }
}

#[derive(Debug)]
struct ScannedEntry {
    relative_path: PathBuf,
    canonical_path: String,
    kind: EntryKind,
    executable: bool,
    size_bytes: u64,
    symlink_target: Option<String>,
}

fn validate_root(root: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(root).map_err(|error| CoreError::io(root, error))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(CoreError::InvalidRoot(root.to_owned()));
    }
    Ok(())
}

fn scan_tree(root: &Path) -> Result<Vec<ScannedEntry>> {
    let mut pending = vec![root.to_owned()];
    let mut entries = Vec::new();
    while let Some(directory) = pending.pop() {
        let children =
            fs::read_dir(&directory).map_err(|error| CoreError::io(&directory, error))?;
        for child in children {
            let child = child.map_err(|error| CoreError::io(&directory, error))?;
            let path = child.path();
            let relative = path.strip_prefix(root).map_err(|_| CoreError::UnsafePath {
                path: path.clone(),
                reason: "entry escaped the supplied root".into(),
            })?;
            let canonical_path = canonical_relative_path(relative)?;
            let metadata =
                fs::symlink_metadata(&path).map_err(|error| CoreError::io(&path, error))?;
            let file_type = metadata.file_type();
            let kind = supported_entry_kind(&path, &file_type)?;

            if kind == EntryKind::Directory {
                entries.push(ScannedEntry {
                    relative_path: relative.to_owned(),
                    canonical_path,
                    kind: EntryKind::Directory,
                    executable: false,
                    size_bytes: 0,
                    symlink_target: None,
                });
                pending.push(path);
            } else if kind == EntryKind::File {
                entries.push(ScannedEntry {
                    relative_path: relative.to_owned(),
                    canonical_path,
                    kind: EntryKind::File,
                    executable: is_executable(&metadata),
                    size_bytes: metadata.len(),
                    symlink_target: None,
                });
            } else if kind == EntryKind::Symlink {
                let target = fs::read_link(&path).map_err(|error| CoreError::io(&path, error))?;
                validate_symlink_target(relative, &target)?;
                let target = canonical_symlink_target(&path, &target)?;
                entries.push(ScannedEntry {
                    relative_path: relative.to_owned(),
                    canonical_path,
                    kind: EntryKind::Symlink,
                    executable: false,
                    size_bytes: target.len() as u64,
                    symlink_target: Some(target),
                });
            }
        }
    }
    entries.sort_unstable_by(|left, right| {
        left.canonical_path
            .as_bytes()
            .cmp(right.canonical_path.as_bytes())
    });
    Ok(entries)
}

fn supported_entry_kind(path: &Path, file_type: &fs::FileType) -> Result<EntryKind> {
    if file_type.is_dir() {
        Ok(EntryKind::Directory)
    } else if file_type.is_file() {
        Ok(EntryKind::File)
    } else if file_type.is_symlink() {
        Ok(EntryKind::Symlink)
    } else {
        Err(CoreError::UnsupportedFileType(path.to_owned()))
    }
}

fn canonical_relative_path(path: &Path) -> Result<String> {
    let mut segments = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => {
                let segment = segment.to_str().ok_or_else(|| CoreError::UnsafePath {
                    path: path.to_owned(),
                    reason: "paths must be valid UTF-8".into(),
                })?;
                if segment.is_empty() || segment.contains('\\') || segment.contains('\0') {
                    return Err(CoreError::UnsafePath {
                        path: path.to_owned(),
                        reason: "empty, NUL, and backslash-bearing path segments are forbidden"
                            .into(),
                    });
                }
                if segment.chars().any(char::is_control) {
                    return Err(CoreError::UnsafePath {
                        path: path.to_owned(),
                        reason: "control characters in path segments are forbidden".into(),
                    });
                }
                segments.push(segment);
            }
            _ => {
                return Err(CoreError::UnsafePath {
                    path: path.to_owned(),
                    reason: "path must contain only normal relative components".into(),
                });
            }
        }
    }
    if segments.is_empty() {
        return Err(CoreError::UnsafePath {
            path: path.to_owned(),
            reason: "empty relative path".into(),
        });
    }
    Ok(segments.join("/"))
}

fn validate_symlink_target(link_relative: &Path, target: &Path) -> Result<()> {
    if target.is_absolute() {
        return Err(CoreError::UnsafePath {
            path: link_relative.to_owned(),
            reason: "absolute symlink target".into(),
        });
    }
    let mut depth = link_relative
        .parent()
        .map(|parent| parent.components().count())
        .unwrap_or(0);
    for component in target.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(_) => depth += 1,
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::ParentDir => {
                return Err(CoreError::UnsafePath {
                    path: link_relative.to_owned(),
                    reason: "symlink target escapes skill root".into(),
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(CoreError::UnsafePath {
                    path: link_relative.to_owned(),
                    reason: "absolute or prefixed symlink target".into(),
                });
            }
        }
    }
    Ok(())
}

fn canonical_symlink_target(link_path: &Path, target: &Path) -> Result<String> {
    let target = target.to_str().ok_or_else(|| CoreError::UnsafePath {
        path: link_path.to_owned(),
        reason: "symlink targets must be valid UTF-8".into(),
    })?;
    if target.is_empty() || target.contains('\0') {
        return Err(CoreError::UnsafePath {
            path: link_path.to_owned(),
            reason: "empty or NUL symlink target".into(),
        });
    }
    if target.chars().any(char::is_control) {
        return Err(CoreError::UnsafePath {
            path: link_path.to_owned(),
            reason: "control characters in symlink targets are forbidden".into(),
        });
    }
    #[cfg(not(windows))]
    if target.contains('\\') {
        return Err(CoreError::UnsafePath {
            path: link_path.to_owned(),
            reason: "backslashes in symlink targets are non-portable".into(),
        });
    }
    #[cfg(windows)]
    let target = target.replace('\\', "/");
    #[cfg(not(windows))]
    let target = target.to_owned();
    Ok(target)
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

fn open_regular_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .map_err(|error| CoreError::io(path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| CoreError::io(path, error))?;
    if !metadata.file_type().is_file() {
        return Err(CoreError::UnsupportedFileType(path.to_owned()));
    }
    Ok(file)
}

fn copy_exact_into_hashes(
    path: &Path,
    file: &mut File,
    expected_size: u64,
    tree_hash: &mut DualHasher,
    content_hash: &mut DualHasher,
) -> Result<()> {
    let mut remaining = expected_size;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
        let count = file
            .read(&mut buffer[..wanted])
            .map_err(|error| CoreError::io(path, error))?;
        if count == 0 {
            return Err(CoreError::TreeChanged);
        }
        tree_hash.update(&buffer[..count]);
        content_hash.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|error| CoreError::io(path, error))?
        != 0
    {
        return Err(CoreError::TreeChanged);
    }
    Ok(())
}

fn write_archive(
    root: &Path,
    canonical: &CanonicalSkill,
    manifest_bytes: &[u8],
    destination: &mut File,
    destination_path: &Path,
) -> Result<()> {
    {
        let mut encoder = zstd::stream::write::Encoder::new(&mut *destination, ZSTD_LEVEL)
            .map_err(|error| CoreError::io(destination_path, error))?;
        encoder
            .include_checksum(true)
            .map_err(|error| CoreError::io(destination_path, error))?;
        let mut archive = tar::Builder::new(encoder);

        append_bytes(
            &mut archive,
            Path::new(ARCHIVE_MANIFEST),
            manifest_bytes,
            0o644,
        )?;
        append_directory(&mut archive, Path::new(ARCHIVE_ROOT))?;
        for entry in &canonical.entries {
            let archive_path = Path::new(ARCHIVE_ROOT).join(&entry.path);
            match entry.kind {
                EntryKind::Directory => append_directory(&mut archive, &archive_path)?,
                EntryKind::File => {
                    let source_path = root.join(&entry.path);
                    let mut file = open_regular_file(&source_path)?;
                    let metadata = file
                        .metadata()
                        .map_err(|error| CoreError::io(&source_path, error))?;
                    if metadata.len() != entry.size_bytes {
                        return Err(CoreError::TreeChanged);
                    }
                    let mode = if entry.executable { 0o755 } else { 0o644 };
                    let mut header =
                        deterministic_header(tar::EntryType::Regular, entry.size_bytes, mode);
                    archive
                        .append_data(&mut header, &archive_path, &mut file)
                        .map_err(|error| CoreError::io(&source_path, error))?;
                }
                EntryKind::Symlink => {
                    let target = entry
                        .symlink_target
                        .as_deref()
                        .expect("manifest link target");
                    let mut header = deterministic_header(tar::EntryType::Symlink, 0, 0o777);
                    header
                        .set_link_name(target)
                        .map_err(|error| CoreError::io(&archive_path, error))?;
                    header.set_cksum();
                    archive
                        .append_data(&mut header, &archive_path, io::empty())
                        .map_err(|error| CoreError::io(&archive_path, error))?;
                }
            }
        }
        archive
            .finish()
            .map_err(|error| CoreError::io(destination_path, error))?;
        let encoder = archive
            .into_inner()
            .map_err(|error| CoreError::io(destination_path, error))?;
        encoder
            .finish()
            .map_err(|error| CoreError::io(destination_path, error))?;
    }
    destination
        .flush()
        .map_err(|error| CoreError::io(destination_path, error))?;
    destination
        .sync_all()
        .map_err(|error| CoreError::io(destination_path, error))
}

fn append_bytes<W: Write>(
    archive: &mut tar::Builder<W>,
    path: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<()> {
    let mut header = deterministic_header(tar::EntryType::Regular, bytes.len() as u64, mode);
    archive
        .append_data(&mut header, path, Cursor::new(bytes))
        .map_err(|error| CoreError::io(path, error))
}

fn append_directory<W: Write>(archive: &mut tar::Builder<W>, path: &Path) -> Result<()> {
    let mut header = deterministic_header(tar::EntryType::Directory, 0, 0o755);
    archive
        .append_data(&mut header, path, io::empty())
        .map_err(|error| CoreError::io(path, error))
}

fn deterministic_header(entry_type: tar::EntryType, size: u64, mode: u32) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    header
}

fn ensure_safe_outputs(root: &Path, archive: &Path, manifest: &Path) -> Result<()> {
    validate_root(root)?;
    let root = fs::canonicalize(root).map_err(|error| CoreError::io(root, error))?;
    let archive = absolute_destination(archive)?;
    let manifest = absolute_destination(manifest)?;
    if archive == manifest {
        return Err(CoreError::UnsafePath {
            path: archive,
            reason: "archive and manifest destinations must differ".into(),
        });
    }
    for output in [archive, manifest] {
        if output.starts_with(&root) {
            return Err(CoreError::UnsafePath {
                path: output,
                reason: "artifact destination cannot be inside the skill tree".into(),
            });
        }
    }
    Ok(())
}

fn absolute_destination(path: &Path) -> Result<PathBuf> {
    let absolute;
    let path = if path.is_absolute() {
        path
    } else {
        absolute = std::env::current_dir()
            .map_err(|error| CoreError::io(Path::new("."), error))?
            .join(path);
        &absolute
    };
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| CoreError::UnsafePath {
        path: path.to_owned(),
        reason: "destination has no file name".into(),
    })?;
    let parent = if parent.exists() {
        fs::canonicalize(parent).map_err(|error| CoreError::io(parent, error))?
    } else {
        let mut ancestor = parent;
        let mut missing = Vec::new();
        while !ancestor.exists() {
            let name = ancestor.file_name().ok_or_else(|| CoreError::UnsafePath {
                path: path.to_owned(),
                reason: "destination parent cannot be resolved".into(),
            })?;
            missing.push(name.to_owned());
            ancestor = ancestor.parent().ok_or_else(|| CoreError::UnsafePath {
                path: path.to_owned(),
                reason: "destination parent cannot be resolved".into(),
            })?;
        }
        let mut resolved =
            fs::canonicalize(ancestor).map_err(|error| CoreError::io(ancestor, error))?;
        for name in missing.iter().rev() {
            resolved.push(name);
        }
        resolved
    };
    Ok(parent.join(file_name))
}

fn persist_tempfile(temporary: tempfile::NamedTempFile, path: &Path) -> Result<()> {
    temporary.persist(path).map_err(|error| CoreError::Io {
        path: path.to_owned(),
        source: error.error,
    })?;
    Ok(())
}

fn digest_bytes(bytes: &[u8]) -> (String, String) {
    let mut digest = DualHasher::new();
    digest.update(bytes);
    digest.finish()
}

fn digest_file(path: &Path) -> Result<(String, String)> {
    let mut file = File::open(path).map_err(|error| CoreError::io(path, error))?;
    let mut digest = DualHasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| CoreError::io(path, error))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest.finish())
}

struct DualHasher {
    sha256: Sha256,
    blake3: blake3::Hasher,
}

impl DualHasher {
    fn new() -> Self {
        Self {
            sha256: Sha256::new(),
            blake3: blake3::Hasher::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.sha256.update(bytes);
        self.blake3.update(bytes);
    }

    fn update_frame(&mut self, bytes: &[u8]) {
        self.update(&(bytes.len() as u64).to_be_bytes());
        self.update(bytes);
    }

    fn finish(self) -> (String, String) {
        (
            hex::encode(self.sha256.finalize()),
            self.blake3.finalize().to_hex().to_string(),
        )
    }
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<()> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| CoreError::io(parent, error))
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn write(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn canonicalization_is_independent_of_creation_order_and_preserves_raw_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let left = temp.path().join("left");
        let right = temp.path().join("right");
        fs::create_dir_all(&left).unwrap();
        fs::create_dir_all(&right).unwrap();

        write(&left.join("z.bin"), &[0, 0xff, b'\n']);
        write(&left.join("nested/SKILL.md"), b"---\nname: fixture\n---\n");
        fs::create_dir(left.join("empty")).unwrap();

        fs::create_dir(right.join("empty")).unwrap();
        write(&right.join("nested/SKILL.md"), b"---\nname: fixture\n---\n");
        write(&right.join("z.bin"), &[0, 0xff, b'\n']);

        let first = canonicalize_skill_tree(&left).unwrap();
        let second = canonicalize_skill_tree(&right).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.file_count, 2);
        assert_eq!(first.size_bytes, 25);
        assert_eq!(
            first
                .entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            ["empty", "nested", "nested/SKILL.md", "z.bin"]
        );
        assert_eq!(first.skill_id, format!("sha256:v1:{}", first.sha256));
        assert_eq!(
            first.sha256,
            "8a1ce9477f7f5e1accdbe144e2aaa3038caf33bf9aa7e10e6ecec6356c80ce18"
        );
        assert_eq!(first.sha256.len(), 64);
        assert_eq!(first.blake3.len(), 64);
    }

    #[test]
    fn empty_directories_and_path_framing_are_significant() {
        let temp = tempfile::tempdir().unwrap();
        let one = temp.path().join("one");
        let two = temp.path().join("two");
        fs::create_dir_all(&one).unwrap();
        fs::create_dir_all(&two).unwrap();
        write(&one.join("ab"), b"c");
        write(&two.join("a"), b"bc");
        assert_ne!(
            canonicalize_skill_tree(&one).unwrap().skill_id,
            canonicalize_skill_tree(&two).unwrap().skill_id
        );

        let before = canonicalize_skill_tree(&one).unwrap();
        fs::create_dir(one.join("empty")).unwrap();
        let after = canonicalize_skill_tree(&one).unwrap();
        assert_ne!(before.skill_id, after.skill_id);
    }

    #[cfg(unix)]
    #[test]
    fn executable_bit_is_significant() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("skill");
        fs::create_dir(&root).unwrap();
        let script = root.join("run.sh");
        write(&script, b"#!/bin/sh\nexit 0\n");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o644)).unwrap();
        let plain = canonicalize_skill_tree(&root).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let executable = canonicalize_skill_tree(&root).unwrap();
        assert_ne!(plain.skill_id, executable.skill_id);
        assert!(!plain.entries[0].executable);
        assert!(executable.entries[0].executable);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_hashed_as_links_and_escaping_targets_are_rejected() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("skill");
        fs::create_dir(&root).unwrap();
        symlink("missing-a", root.join("link")).unwrap();
        let first = canonicalize_skill_tree(&root).unwrap();
        assert_eq!(first.entries[0].kind, EntryKind::Symlink);
        assert_eq!(
            first.entries[0].symlink_target.as_deref(),
            Some("missing-a")
        );
        fs::remove_file(root.join("link")).unwrap();
        symlink("missing-b", root.join("link")).unwrap();
        let second = canonicalize_skill_tree(&root).unwrap();
        assert_ne!(first.skill_id, second.skill_id);

        fs::remove_file(root.join("link")).unwrap();
        symlink("../outside", root.join("link")).unwrap();
        assert!(matches!(
            canonicalize_skill_tree(&root),
            Err(CoreError::UnsafePath { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn special_files_and_non_utf8_paths_are_rejected() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let null_metadata = fs::metadata("/dev/null").unwrap();
        assert!(matches!(
            supported_entry_kind(Path::new("/dev/null"), &null_metadata.file_type()),
            Err(CoreError::UnsupportedFileType(_))
        ));

        let invalid = PathBuf::from(OsString::from_vec(vec![0xff]));
        assert!(matches!(
            canonical_relative_path(&invalid),
            Err(CoreError::UnsafePath { .. })
        ));
        assert!(matches!(
            canonical_relative_path(Path::new("bad\nname")),
            Err(CoreError::UnsafePath { .. })
        ));
    }

    #[test]
    fn deterministic_archive_contains_normalized_headers_and_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("skill-source");
        fs::create_dir(&root).unwrap();
        write(&root.join("SKILL.md"), b"---\nname: archive-test\n---\n");
        write(&root.join("references/info.txt"), b"hello\n");

        let first_archive = temp.path().join("one/bundle.tar.zst");
        let first_manifest = temp.path().join("one/manifest.json");
        let second_archive = temp.path().join("two/bundle.tar.zst");
        let second_manifest = temp.path().join("two/manifest.json");
        let first = archive_skill_tree(&root, &first_archive, &first_manifest).unwrap();
        let second = archive_skill_tree(&root, &second_archive, &second_manifest).unwrap();

        assert_eq!(first.canonical, second.canonical);
        assert_eq!(first.archive_sha256, second.archive_sha256);
        assert_eq!(
            fs::read(&first_archive).unwrap(),
            fs::read(&second_archive).unwrap()
        );
        assert_eq!(
            fs::read(&first_manifest).unwrap(),
            fs::read(&second_manifest).unwrap()
        );

        let parsed: Manifest = serde_json::from_slice(&fs::read(&first_manifest).unwrap()).unwrap();
        assert_eq!(parsed, Manifest::from(&first.canonical));
        validate_skill_artifact(
            &first_archive,
            &first_manifest,
            &first.canonical,
            ArtifactValidationLimits::default(),
        )
        .unwrap();

        let file = File::open(&first_archive).unwrap();
        let decoder = zstd::stream::read::Decoder::new(file).unwrap();
        let mut archive = tar::Archive::new(decoder);
        let mut members = BTreeMap::new();
        for member in archive.entries().unwrap() {
            let mut member = member.unwrap();
            let path = member.path().unwrap().to_string_lossy().into_owned();
            assert_eq!(member.header().mtime().unwrap(), 0);
            assert_eq!(member.header().uid().unwrap(), 0);
            assert_eq!(member.header().gid().unwrap(), 0);
            let mut bytes = Vec::new();
            member.read_to_end(&mut bytes).unwrap();
            members.insert(path, bytes);
        }
        assert_eq!(
            members.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "manifest.json",
                "skill",
                "skill/SKILL.md",
                "skill/references",
                "skill/references/info.txt",
            ]
        );
        assert_eq!(members["skill/references/info.txt"], b"hello\n");
    }

    #[test]
    fn artifact_validation_rejects_manifest_archive_and_limit_mismatches() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("skill");
        fs::create_dir(&root).unwrap();
        write(&root.join("SKILL.md"), b"original\n");
        let archive = temp.path().join("bundle.tar.zst");
        let manifest = temp.path().join("manifest.json");
        let artifact = archive_skill_tree(&root, &archive, &manifest).unwrap();
        let archive_bytes = fs::read(&archive).unwrap();
        let manifest_bytes = fs::read(&manifest).unwrap();

        let limits = ArtifactValidationLimits {
            max_archive_bytes: archive_bytes.len() as u64 - 1,
            ..ArtifactValidationLimits::default()
        };
        assert!(validate_skill_artifact(&archive, &manifest, &artifact.canonical, limits).is_err());

        let mut corrupt_manifest = manifest_bytes.clone();
        corrupt_manifest[0] ^= 1;
        fs::write(&manifest, corrupt_manifest).unwrap();
        assert!(
            validate_skill_artifact(
                &archive,
                &manifest,
                &artifact.canonical,
                ArtifactValidationLimits::default()
            )
            .is_err()
        );
        fs::write(&manifest, &manifest_bytes).unwrap();

        let mut corrupt_archive = archive_bytes.clone();
        corrupt_archive[0] ^= 1;
        fs::write(&archive, corrupt_archive).unwrap();
        assert!(
            validate_skill_artifact(
                &archive,
                &manifest,
                &artifact.canonical,
                ArtifactValidationLimits::default()
            )
            .is_err()
        );
        fs::write(&archive, &archive_bytes).unwrap();

        let other_root = temp.path().join("other-skill");
        fs::create_dir(&other_root).unwrap();
        write(&other_root.join("SKILL.md"), b"different\n");
        let other_archive = temp.path().join("other.tar.zst");
        let other_manifest = temp.path().join("other.json");
        archive_skill_tree(&other_root, &other_archive, &other_manifest).unwrap();
        assert!(
            validate_skill_artifact(
                &other_archive,
                &manifest,
                &artifact.canonical,
                ArtifactValidationLimits::default()
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn artifact_validation_authenticates_executable_files_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("skill");
        fs::create_dir(&root).unwrap();
        write(&root.join("SKILL.md"), b"test\n");
        write(&root.join("run.sh"), b"#!/bin/sh\nexit 0\n");
        fs::set_permissions(root.join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("run.sh", root.join("runner")).unwrap();
        let archive = temp.path().join("bundle.tar.zst");
        let manifest = temp.path().join("manifest.json");
        let artifact = archive_skill_tree(&root, &archive, &manifest).unwrap();
        validate_skill_artifact(
            &archive,
            &manifest,
            &artifact.canonical,
            ArtifactValidationLimits::default(),
        )
        .unwrap();
    }

    #[test]
    fn archive_rejects_destinations_inside_source_tree_or_same_file() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("skill");
        fs::create_dir(&root).unwrap();
        write(&root.join("SKILL.md"), b"test");
        assert!(matches!(
            archive_skill_tree(
                &root,
                root.join("bundle.tar.zst"),
                temp.path().join("manifest.json")
            ),
            Err(CoreError::UnsafePath { .. })
        ));
        let same = temp.path().join("same");
        assert!(matches!(
            archive_skill_tree(&root, &same, &same),
            Err(CoreError::UnsafePath { .. })
        ));
    }
}
