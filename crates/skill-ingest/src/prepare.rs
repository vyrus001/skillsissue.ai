use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use tempfile::TempDir;
use walkdir::{DirEntry, WalkDir};

const MAX_DISCOVERY_ENTRIES: u64 = 500_000;

#[derive(Clone, Copy, Debug)]
pub struct SecurityLimits {
    pub max_files_per_skill: u64,
    pub max_bytes_per_skill: u64,
    pub max_file_bytes: u64,
    pub max_depth: usize,
}

impl Default for SecurityLimits {
    fn default() -> Self {
        Self {
            max_files_per_skill: 4_096,
            max_bytes_per_skill: 64 * 1024 * 1024,
            max_file_bytes: 16 * 1024 * 1024,
            max_depth: 32,
        }
    }
}

impl SecurityLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_files_per_skill == 0
            || self.max_bytes_per_skill == 0
            || self.max_file_bytes == 0
            || self.max_depth == 0
            || self.max_file_bytes > self.max_bytes_per_skill
        {
            bail!("invalid security limits");
        }
        Ok(())
    }
}

pub struct PreparedSkill {
    _temp: TempDir,
    root: PathBuf,
    pub source_relative_path: String,
}

impl PreparedSkill {
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Find regular `SKILL.md` files without following directory symlinks. Results
/// are ordered by normalized source-relative path for reproducible limit
/// behavior.
pub fn discover_skill_directories(
    source_root: &Path,
    limit: usize,
    max_depth: usize,
) -> Result<Vec<PathBuf>> {
    discover_skill_directories_filtered(source_root, limit, max_depth, |_| Ok(true))
}

pub(crate) fn discover_skill_directories_filtered<F>(
    source_root: &Path,
    limit: usize,
    max_depth: usize,
    mut include: F,
) -> Result<Vec<PathBuf>>
where
    F: FnMut(&Path) -> Result<bool>,
{
    if limit == 0 {
        bail!("discovery limit must be greater than zero");
    }
    let metadata = fs::symlink_metadata(source_root)
        .with_context(|| format!("inspect source root {}", source_root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("source root must be a non-symlink directory");
    }
    let source_root = fs::canonicalize(source_root)
        .with_context(|| format!("canonicalize source root {}", source_root.display()))?;
    let mut found = Vec::new();
    let mut visited = 0_u64;
    let walker = WalkDir::new(&source_root)
        .follow_links(false)
        .max_depth(max_depth.saturating_add(1))
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| !is_vcs_metadata(entry));
    for entry in walker {
        let entry = entry.with_context(|| format!("walk source root {}", source_root.display()))?;
        visited = visited.saturating_add(1);
        if visited > MAX_DISCOVERY_ENTRIES {
            bail!("source exceeds the {MAX_DISCOVERY_ENTRIES} entry discovery limit");
        }
        if entry.file_name() == OsStr::new("SKILL.md") && entry.file_type().is_file() {
            let parent = entry.path().parent().context("SKILL.md has no parent")?;
            if include(parent)? {
                found.push(parent.to_owned());
                if found.len() == limit {
                    break;
                }
            }
        }
    }
    Ok(found)
}

/// Validate and stage a skill in a fresh directory. Staging excludes `.git`
/// internals and prevents canonicalization from observing a concurrently
/// swapped source path. Safe in-tree links are copied as links; links that are
/// absolute, escape the root, or point into excluded VCS metadata are rejected.
pub fn prepare_skill(
    source_root: &Path,
    skill_dir: &Path,
    limits: SecurityLimits,
) -> Result<PreparedSkill> {
    let source_root = fs::canonicalize(source_root)
        .with_context(|| format!("canonicalize source root {}", source_root.display()))?;
    let metadata = fs::symlink_metadata(skill_dir)
        .with_context(|| format!("inspect skill directory {}", skill_dir.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("skill root must be a non-symlink directory");
    }
    let skill_dir = fs::canonicalize(skill_dir)
        .with_context(|| format!("canonicalize skill directory {}", skill_dir.display()))?;
    let relative = skill_dir
        .strip_prefix(&source_root)
        .context("skill directory escaped its source root")?;
    validate_relative_path(relative)?;
    let source_relative_path = portable_path(relative)?;

    let safe_root = SafeSkillRoot::open(&skill_dir)?;
    safe_root
        .open_regular(Path::new("SKILL.md"))
        .context("SKILL.md must be a regular file")?;

    limits.validate()?;
    let temp = tempfile::tempdir().context("create staged skill directory")?;
    let staged_root = temp.path().join("skill");
    fs::create_dir(&staged_root).context("create staged skill root")?;

    let mut entries = 0_u64;
    let mut bytes = 0_u64;
    let walker = WalkDir::new(&skill_dir)
        .follow_links(false)
        .max_depth(limits.max_depth.saturating_add(1))
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| !is_vcs_metadata(entry));
    for entry in walker {
        let entry = entry.with_context(|| format!("walk skill tree {}", skill_dir.display()))?;
        if entry.depth() == 0 {
            continue;
        }
        if entry.depth() > limits.max_depth {
            bail!("skill exceeds the maximum depth of {}", limits.max_depth);
        }
        entries = entries
            .checked_add(1)
            .context("skill entry count overflow")?;
        if entries > limits.max_files_per_skill {
            bail!(
                "skill exceeds the {} entry limit",
                limits.max_files_per_skill
            );
        }
        let relative = entry
            .path()
            .strip_prefix(&skill_dir)
            .context("walked path escaped skill root")?;
        validate_relative_path(relative)?;
        let destination = staged_root.join(relative);
        let file_type = entry.file_type();
        if file_type.is_dir() {
            safe_root.verify_directory(relative)?;
            fs::create_dir(&destination)
                .with_context(|| format!("stage directory {}", relative.display()))?;
        } else if file_type.is_file() {
            let source = safe_root.open_regular(relative)?;
            let copied = copy_regular_file_bounded(
                source,
                &destination,
                relative,
                limits.max_file_bytes,
                limits.max_bytes_per_skill.saturating_sub(bytes),
            )?;
            bytes = bytes
                .checked_add(copied)
                .context("skill byte count overflow")?;
        } else if file_type.is_symlink() {
            let target = safe_root
                .read_link(relative)
                .with_context(|| format!("read symlink {}", relative.display()))?;
            validate_symlink_target(relative, &target)?;
            bytes = bytes
                .checked_add(target.as_os_str().len() as u64)
                .context("skill byte count overflow")?;
            if bytes > limits.max_bytes_per_skill {
                bail!(
                    "skill exceeds the {} byte payload limit",
                    limits.max_bytes_per_skill
                );
            }
            #[cfg(windows)]
            let target_is_directory = safe_root.symlink_target_is_directory(relative, &target);
            #[cfg(not(windows))]
            let target_is_directory = false;
            create_symlink(&target, &destination, target_is_directory)
                .with_context(|| format!("stage symlink {}", relative.display()))?;
        } else {
            bail!(
                "unsupported special filesystem node: {}",
                relative.display()
            );
        }
    }

    Ok(PreparedSkill {
        _temp: temp,
        root: staged_root,
        source_relative_path: if source_relative_path.is_empty() {
            ".".to_owned()
        } else {
            source_relative_path
        },
    })
}

fn is_vcs_metadata(entry: &DirEntry) -> bool {
    entry.depth() > 0 && entry.file_name() == OsStr::new(".git")
}

fn validate_relative_path(path: &Path) -> Result<()> {
    for component in path.components() {
        match component {
            Component::Normal(value) => {
                let value = value.to_str().context("skill paths must be valid UTF-8")?;
                if value.contains('\\') || value.chars().any(char::is_control) {
                    bail!("skill path contains a non-portable component");
                }
            }
            _ => bail!("skill path is not a normalized relative path"),
        }
    }
    Ok(())
}

fn validate_symlink_target(link_relative: &Path, target: &Path) -> Result<()> {
    if target.as_os_str().is_empty() || target.is_absolute() {
        bail!("symlink target must be a non-empty relative path");
    }
    let parent = link_relative.parent().unwrap_or_else(|| Path::new(""));
    let mut normalized: Vec<&OsStr> = Vec::new();
    for component in parent.components().chain(target.components()) {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => normalized.push(value),
            Component::ParentDir => {
                if normalized.pop().is_none() {
                    bail!("symlink target escapes the skill root");
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                bail!("symlink target escapes the skill root")
            }
        }
    }
    for component in &normalized {
        let component = component
            .to_str()
            .context("symlink targets must be valid UTF-8")?;
        if component == ".git"
            || component.contains('\\')
            || component.chars().any(char::is_control)
        {
            bail!("symlink target is unsafe or non-portable");
        }
    }
    Ok(())
}

fn portable_path(path: &Path) -> Result<String> {
    let mut output = String::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            bail!("path is not relative and normalized");
        };
        let component = component.to_str().context("path is not UTF-8")?;
        if !output.is_empty() {
            output.push('/');
        }
        output.push_str(component);
    }
    Ok(output)
}

fn copy_regular_file_bounded(
    mut source: File,
    destination: &Path,
    relative: &Path,
    max_file_bytes: u64,
    remaining_skill_bytes: u64,
) -> Result<u64> {
    let before = source
        .metadata()
        .with_context(|| format!("inspect open file {}", relative.display()))?;
    if !before.is_file() {
        bail!("{} is no longer a regular file", relative.display());
    }
    let size = before.len();
    if size > max_file_bytes {
        bail!(
            "{} exceeds the {} byte per-file limit",
            relative.display(),
            max_file_bytes
        );
    }
    if size > remaining_skill_bytes {
        bail!("skill exceeds its total byte payload limit");
    }

    let mut output_options = OpenOptions::new();
    output_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        output_options.mode(0o600);
    }
    let mut output = output_options
        .open(destination)
        .with_context(|| format!("create staged file {}", relative.display()))?;
    let mut remaining = size;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .context("file read size overflow")?;
        let count = source
            .read(&mut buffer[..wanted])
            .with_context(|| format!("read {}", relative.display()))?;
        if count == 0 {
            bail!("{} changed size while it was staged", relative.display());
        }
        output
            .write_all(&buffer[..count])
            .with_context(|| format!("write staged file {}", relative.display()))?;
        remaining -= count as u64;
    }
    let mut extra = [0_u8; 1];
    if source
        .read(&mut extra)
        .with_context(|| format!("verify {}", relative.display()))?
        != 0
    {
        bail!("{} grew while it was staged", relative.display());
    }
    let after = source
        .metadata()
        .with_context(|| format!("reinspect {}", relative.display()))?;
    if after.len() != size
        || before
            .modified()
            .ok()
            .zip(after.modified().ok())
            .is_some_and(|(before, after)| before != after)
    {
        bail!("{} changed while it was staged", relative.display());
    }
    output
        .flush()
        .with_context(|| format!("flush staged file {}", relative.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if before.permissions().mode() & 0o111 != 0 {
            0o755
        } else {
            0o644
        };
        output
            .set_permissions(fs::Permissions::from_mode(mode))
            .with_context(|| format!("set staged permissions {}", relative.display()))?;
    }
    Ok(size)
}

#[cfg(unix)]
struct SafeSkillRoot {
    directory: File,
}

#[cfg(unix)]
impl SafeSkillRoot {
    fn open(root: &Path) -> Result<Self> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::FromRawFd;

        let expected = fs::symlink_metadata(root)
            .with_context(|| format!("inspect skill root {}", root.display()))?;
        if !expected.is_dir() || expected.file_type().is_symlink() {
            bail!("skill root must remain a non-symlink directory");
        }
        let encoded = CString::new(root.as_os_str().as_bytes())
            .context("skill root contains an interior NUL")?;
        // SAFETY: encoded is NUL-terminated, flags require a directory and
        // forbid following the final component, and the returned fd is owned
        // immediately by File.
        let descriptor = unsafe {
            libc::open(
                encoded.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("open skill root {}", root.display()));
        }
        // SAFETY: descriptor is a fresh successful open result.
        let directory = unsafe { File::from_raw_fd(descriptor) };
        let actual = directory
            .metadata()
            .with_context(|| format!("inspect open skill root {}", root.display()))?;
        if !actual.is_dir() || actual.dev() != expected.dev() || actual.ino() != expected.ino() {
            bail!("skill root changed while it was opened");
        }
        Ok(Self { directory })
    }

    fn verify_directory(&self, relative: &Path) -> Result<()> {
        let directory = self.open_relative(relative, true)?;
        if !directory.metadata()?.is_dir() {
            bail!("{} is no longer a directory", relative.display());
        }
        Ok(())
    }

    fn open_regular(&self, relative: &Path) -> Result<File> {
        let file = self.open_relative(relative, false)?;
        if !file.metadata()?.is_file() {
            bail!("{} is no longer a regular file", relative.display());
        }
        Ok(file)
    }

    fn read_link(&self, relative: &Path) -> Result<PathBuf> {
        use std::ffi::CString;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        use std::os::unix::io::AsRawFd;

        let mut components = relative.components().collect::<Vec<_>>();
        let Some(Component::Normal(name)) = components.pop() else {
            bail!("symlink path has no file name");
        };
        let parent = self.open_directory_components(&components)?;
        let name =
            CString::new(name.as_bytes()).context("symlink name contains an interior NUL")?;
        let mut capacity = 256_usize;
        loop {
            let mut buffer = vec![0_u8; capacity];
            // SAFETY: the parent fd and name are valid, and buffer exposes
            // capacity writable bytes for readlinkat.
            let count = unsafe {
                libc::readlinkat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if count < 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("read symlink {}", relative.display()));
            }
            let count = count as usize;
            if count < buffer.len() {
                buffer.truncate(count);
                return Ok(PathBuf::from(std::ffi::OsString::from_vec(buffer)));
            }
            if capacity >= 65_536 {
                bail!("symlink target is unreasonably long");
            }
            capacity *= 2;
        }
    }

    fn open_relative(&self, relative: &Path, final_is_directory: bool) -> Result<File> {
        let components = relative.components().collect::<Vec<_>>();
        if components.is_empty() {
            bail!("empty skill-relative path");
        }
        let parent = self.open_directory_components(&components[..components.len() - 1])?;
        let Component::Normal(name) = components[components.len() - 1] else {
            bail!("skill-relative path is not normalized");
        };
        open_at(
            &parent,
            name,
            if final_is_directory {
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
            } else {
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC
            },
            relative,
        )
    }

    fn open_directory_components(&self, components: &[Component<'_>]) -> Result<File> {
        let mut current = open_at(
            &self.directory,
            OsStr::new("."),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            Path::new("."),
        )?;
        for component in components {
            let Component::Normal(name) = component else {
                bail!("skill-relative path is not normalized");
            };
            current = open_at(
                &current,
                name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                Path::new(name),
            )?;
        }
        Ok(current)
    }
}

#[cfg(unix)]
fn open_at(parent: &File, name: &OsStr, flags: i32, display: &Path) -> Result<File> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let name = CString::new(name.as_bytes()).context("path component contains an interior NUL")?;
    // SAFETY: parent is an open directory, name is NUL-terminated, and a
    // successful descriptor is transferred immediately into File.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("open skill entry {}", display.display()));
    }
    // SAFETY: descriptor is a fresh successful openat result.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(not(unix))]
struct SafeSkillRoot {
    root: PathBuf,
}

#[cfg(not(unix))]
impl SafeSkillRoot {
    fn open(root: &Path) -> Result<Self> {
        let root = fs::canonicalize(root)?;
        let metadata = fs::symlink_metadata(&root)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("skill root must remain a non-symlink directory");
        }
        Ok(Self { root })
    }

    fn verify_directory(&self, relative: &Path) -> Result<()> {
        let path = self.root.join(relative);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("{} is no longer a directory", relative.display());
        }
        if !fs::canonicalize(path)?.starts_with(&self.root) {
            bail!("directory escaped skill root");
        }
        Ok(())
    }

    fn open_regular(&self, relative: &Path) -> Result<File> {
        let path = self.root.join(relative);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!("{} is no longer a regular file", relative.display());
        }
        if !fs::canonicalize(&path)?.starts_with(&self.root) {
            bail!("file escaped skill root");
        }
        Ok(File::open(path)?)
    }

    fn read_link(&self, relative: &Path) -> Result<PathBuf> {
        fs::read_link(self.root.join(relative)).map_err(Into::into)
    }

    #[cfg(windows)]
    fn symlink_target_is_directory(&self, relative: &Path, target: &Path) -> bool {
        let link = self.root.join(relative);
        link.parent()
            .map(|parent| parent.join(target))
            .and_then(|target| fs::metadata(target).ok())
            .is_some_and(|metadata| metadata.is_dir())
    }
}

#[cfg(unix)]
fn create_symlink(
    target: &Path,
    destination: &Path,
    _target_is_directory: bool,
) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, destination)
}

#[cfg(windows)]
fn create_symlink(
    target: &Path,
    destination: &Path,
    target_is_directory: bool,
) -> std::io::Result<()> {
    if target_is_directory {
        std::os::windows::fs::symlink_dir(target, destination)
    } else {
        std::os::windows::fs::symlink_file(target, destination)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_in_lexical_order_without_following_links() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("z")).unwrap();
        fs::create_dir_all(temp.path().join("a")).unwrap();
        fs::write(temp.path().join("z/SKILL.md"), "z").unwrap();
        fs::write(temp.path().join("a/SKILL.md"), "a").unwrap();
        let found = discover_skill_directories(temp.path(), 10, 10).unwrap();
        let canonical_root = fs::canonicalize(temp.path()).unwrap();
        let relative = found
            .iter()
            .map(|path| path.strip_prefix(&canonical_root).unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(relative, [PathBuf::from("a"), PathBuf::from("z")]);
    }

    #[test]
    fn enforces_payload_limit() {
        let temp = tempfile::tempdir().unwrap();
        let skill = temp.path().join("skill");
        fs::create_dir(&skill).unwrap();
        fs::write(skill.join("SKILL.md"), "0123456789").unwrap();
        let limits = SecurityLimits {
            max_bytes_per_skill: 4,
            max_file_bytes: 4,
            ..SecurityLimits::default()
        };
        assert!(prepare_skill(temp.path(), &skill, limits).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_escaping_symlink_but_preserves_safe_link() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let skill = temp.path().join("skill");
        fs::create_dir(&skill).unwrap();
        fs::write(skill.join("SKILL.md"), "test").unwrap();
        fs::write(skill.join("target.txt"), "safe").unwrap();
        symlink("target.txt", skill.join("safe-link")).unwrap();
        let prepared = prepare_skill(temp.path(), &skill, SecurityLimits::default()).unwrap();
        assert_eq!(
            fs::read_link(prepared.root().join("safe-link")).unwrap(),
            Path::new("target.txt")
        );

        symlink("../../outside", skill.join("escape")).unwrap();
        assert!(prepare_skill(temp.path(), &skill, SecurityLimits::default()).is_err());
    }

    #[test]
    fn excludes_git_metadata_from_staging() {
        let temp = tempfile::tempdir().unwrap();
        let skill = temp.path().join("skill");
        fs::create_dir_all(skill.join(".git/objects")).unwrap();
        fs::write(skill.join("SKILL.md"), "test").unwrap();
        fs::write(skill.join(".git/objects/object"), "not skill content").unwrap();
        let prepared = prepare_skill(temp.path(), &skill, SecurityLimits::default()).unwrap();
        assert!(!prepared.root().join(".git").exists());
    }

    #[cfg(unix)]
    #[test]
    fn read_only_source_directories_do_not_make_staging_incomplete() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let skill = temp.path().join("skill");
        fs::create_dir_all(skill.join("references")).unwrap();
        fs::write(skill.join("SKILL.md"), "test").unwrap();
        fs::write(skill.join("references/guide.md"), "guide").unwrap();
        fs::set_permissions(skill.join("references"), fs::Permissions::from_mode(0o555)).unwrap();
        let prepared = prepare_skill(temp.path(), &skill, SecurityLimits::default()).unwrap();
        assert_eq!(
            fs::read_to_string(prepared.root().join("references/guide.md")).unwrap(),
            "guide"
        );
    }
}
