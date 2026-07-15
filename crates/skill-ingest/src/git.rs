use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tempfile::TempDir;
use url::Url;
use walkdir::WalkDir;

const GIT_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_GIT_CHECKOUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_GIT_CHECKOUT_ENTRIES: u64 = 500_000;
const GIT_USAGE_CHECK_INTERVAL: Duration = Duration::from_millis(200);

pub struct GitCheckout {
    _temp: TempDir,
    pub root: PathBuf,
    pub source_url: String,
    pub revision: String,
}

/// Clone a repository without recursive submodules, hooks, global/system Git
/// configuration, credential prompts, local object hardlinks, or
/// repository-provided executables.
pub fn clone_read_only(locator: &str, requested_revision: Option<&str>) -> Result<GitCheckout> {
    let source = validate_locator(locator)?;
    let temp = tempfile::tempdir().context("create temporary Git checkout")?;
    let checkout = temp.path().join("checkout");
    let home = temp.path().join("home");
    fs::create_dir(&home).context("create isolated Git home")?;

    let mut args: Vec<&OsStr> = vec![
        OsStr::new("-c"),
        OsStr::new("core.hooksPath=/dev/null"),
        OsStr::new("-c"),
        OsStr::new("protocol.ext.allow=never"),
        OsStr::new("-c"),
        OsStr::new(if source.is_local {
            "protocol.file.allow=always"
        } else {
            "protocol.file.allow=never"
        }),
        OsStr::new("-c"),
        OsStr::new("submodule.recurse=false"),
        OsStr::new("clone"),
        OsStr::new("--quiet"),
        OsStr::new("--no-tags"),
        OsStr::new("--no-recurse-submodules"),
        OsStr::new("--no-local"),
        OsStr::new("--depth=1"),
        OsStr::new("--single-branch"),
    ];
    if let Some(revision) = requested_revision {
        validate_revision(revision)?;
        args.push(OsStr::new("--branch"));
        args.push(OsStr::new(revision));
    }
    args.push(source.command_value.as_os_str());
    args.push(checkout.as_os_str());
    run_git(&args, &home, Some(temp.path()))
        .with_context(|| format!("clone {}", source.display_value))?;

    let revision = git_stdout(
        &[
            OsStr::new("-C"),
            checkout.as_os_str(),
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("HEAD^{commit}"),
        ],
        &home,
    )?;
    if revision.len() != 40 && revision.len() != 64 {
        bail!("Git returned an unexpected commit identifier");
    }
    Ok(GitCheckout {
        _temp: temp,
        root: checkout,
        source_url: source.display_value,
        revision,
    })
}

struct ValidatedLocator {
    command_value: PathBuf,
    display_value: String,
    is_local: bool,
}

fn validate_locator(locator: &str) -> Result<ValidatedLocator> {
    let locator = locator.trim();
    if locator.is_empty() || locator.starts_with('-') || locator.contains('\0') {
        bail!("invalid Git repository locator");
    }
    let path_candidate = Path::new(locator);
    if path_candidate.is_absolute() || path_candidate.exists() {
        return validate_local_locator(path_candidate);
    }
    if let Ok(url) = Url::parse(locator) {
        if url.scheme() != "https" {
            bail!("only HTTPS Git URLs and explicit local paths are supported");
        }
        if !url.username().is_empty() || url.password().is_some() {
            bail!("Git repository URLs must not contain credentials");
        }
        if url.query().is_some() || url.fragment().is_some() {
            bail!("Git repository URLs must not contain query strings or fragments");
        }
        return Ok(ValidatedLocator {
            command_value: PathBuf::from(url.as_str()),
            display_value: url.to_string(),
            is_local: false,
        });
    }

    validate_local_locator(path_candidate)
}

fn validate_local_locator(locator: &Path) -> Result<ValidatedLocator> {
    let path = fs::canonicalize(locator)
        .with_context(|| format!("canonicalize local Git repository {locator:?}"))?;
    if !path.is_dir() {
        bail!(
            "local Git repository is not a directory: {}",
            path.display()
        );
    }
    let display_value = Url::from_file_path(&path)
        .map_err(|()| anyhow::anyhow!("local Git path cannot be represented as a file URL"))?
        .to_string();
    Ok(ValidatedLocator {
        command_value: path.clone(),
        display_value,
        is_local: true,
    })
}

fn validate_revision(revision: &str) -> Result<()> {
    if revision.is_empty()
        || revision.len() > 255
        || revision.starts_with('-')
        || revision.contains("..")
        || revision.contains("@{")
        || revision.ends_with('.')
        || revision.ends_with('/')
        || revision.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
    {
        bail!("unsafe Git revision {revision:?}");
    }
    Ok(())
}

fn base_command(home: &Path) -> Command {
    let mut command = Command::new("git");
    command.env_clear();
    for key in [
        "PATH",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ] {
        if let Some(value) = env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GCM_INTERACTIVE", "never")
        .env("GIT_ASKPASS", "/bin/false")
        .stdin(Stdio::null());
    command
}

fn run_git(args: &[&OsStr], home: &Path, monitor_root: Option<&Path>) -> Result<()> {
    let mut child = base_command(home)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("start git")?;
    let started = Instant::now();
    let mut last_usage_check = Instant::now()
        .checked_sub(GIT_USAGE_CHECK_INTERVAL)
        .unwrap_or_else(Instant::now);
    loop {
        match child.try_wait().context("wait for git")? {
            Some(status) if status.success() => {
                if let Some(root) = monitor_root {
                    enforce_checkout_limits(root)?;
                }
                return Ok(());
            }
            Some(status) => bail!("git exited with {status}"),
            None if started.elapsed() < GIT_TIMEOUT => {
                if last_usage_check.elapsed() >= GIT_USAGE_CHECK_INTERVAL {
                    if let Some(root) = monitor_root
                        && let Err(error) = enforce_checkout_limits(root)
                    {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(error);
                    }
                    last_usage_check = Instant::now();
                }
                thread::sleep(Duration::from_millis(50));
            }
            None => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("git exceeded the {} second timeout", GIT_TIMEOUT.as_secs())
            }
        }
    }
}

fn enforce_checkout_limits(root: &Path) -> Result<()> {
    let mut entries = 0_u64;
    let mut bytes = 0_u64;
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error)
                if error
                    .io_error()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue;
            }
            Err(error) => return Err(error).context("inspect temporary Git checkout"),
        };
        entries = entries.saturating_add(1);
        if entries > MAX_GIT_CHECKOUT_ENTRIES {
            bail!(
                "Git checkout exceeds the {} entry limit",
                MAX_GIT_CHECKOUT_ENTRIES
            );
        }
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect Git entry {}", entry.path().display()));
            }
        };
        if metadata.is_file() || metadata.file_type().is_symlink() {
            bytes = bytes.saturating_add(metadata.len());
            if bytes > MAX_GIT_CHECKOUT_BYTES {
                bail!(
                    "Git checkout exceeds the {} byte limit",
                    MAX_GIT_CHECKOUT_BYTES
                );
            }
        }
    }
    Ok(())
}

fn git_stdout(args: &[&OsStr], home: &Path) -> Result<String> {
    let output = base_command(home)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .context("run git")?;
    if !output.status.success() {
        bail!("git exited with {}", output.status);
    }
    String::from_utf8(output.stdout)
        .context("Git output was not UTF-8")
        .map(|value| value.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn rejects_credentialed_or_active_transport_urls() {
        assert!(validate_locator("ext::sh -c boom").is_err());
        assert!(validate_locator("ssh://example.test/repo").is_err());
        assert!(validate_locator("http://example.test/repo").is_err());
        assert!(validate_locator("https://token@example.test/repo").is_err());
        assert!(validate_locator("https://example.test/repo?token=secret").is_err());
        assert!(validate_locator("https://example.test/repo#secret").is_err());
    }

    #[test]
    fn rejects_revision_option_injection_and_reflog_syntax() {
        assert!(validate_revision("--upload-pack=evil").is_err());
        assert!(validate_revision("main@{1}").is_err());
        assert!(validate_revision("main").is_ok());
    }

    #[test]
    fn clones_a_local_repository_and_resolves_the_commit() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let source = tempfile::tempdir().unwrap();
        run_test_git(source.path(), &["init", "--quiet"]);
        run_test_git(source.path(), &["config", "user.name", "ingest-test"]);
        run_test_git(
            source.path(),
            &["config", "user.email", "ingest-test@example.invalid"],
        );
        fs::write(source.path().join("SKILL.md"), "# Fixture\n").unwrap();
        run_test_git(source.path(), &["add", "SKILL.md"]);
        run_test_git(source.path(), &["commit", "--quiet", "-m", "fixture"]);
        let expected = test_git_stdout(source.path(), &["rev-parse", "HEAD"]);

        let checkout = clone_read_only(source.path().to_str().unwrap(), None).unwrap();
        assert_eq!(checkout.revision, expected);
        assert_eq!(
            fs::read_to_string(checkout.root.join("SKILL.md")).unwrap(),
            "# Fixture\n"
        );
    }

    fn run_test_git(directory: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn test_git_stdout(directory: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
}
