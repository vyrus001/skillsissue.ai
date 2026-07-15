//! Bounded adapter host for deterministic, Codex CLI, and Claude CLI detonation.
//!
//! The deterministic adapter executes explicit shell fences and in-tree script
//! references. CLI adapters stage the unmodified seed under each provider's
//! official project skill layout and run a pinned non-interactive client.

use anyhow::{Context, Result, bail};
use blake3::Hash;
use clap::Parser;
use regex::Regex;
use serde::Serialize;
use skill_detonate::{
    CLAUDE_ADAPTER, CODEX_ADAPTER, DETERMINISTIC_ADAPTER, HARNESS_COMPLETION_EXIT_BASE,
    MAX_ENCODED_CLOSURE_LIFTS, agent_cli_invocation,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File};
use std::io::Read;
use std::net::TcpListener;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

const RELAY_SOCKET_PATH: &str = "/run/skillsissue/relay.sock";
const RELAY_LISTEN_ADDRESS: &str = "127.0.0.1:8787";
const MAX_ACTIVE_RELAY_CONNECTIONS: usize = 4;
const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "/work/skill")]
    skill_root: PathBuf,
    /// Validated, read-only skill tree copied into the bounded mutable tmpfs.
    #[arg(long)]
    seed_root: Option<PathBuf>,
    #[arg(long, default_value_t = 4_096)]
    max_seed_entries: u64,
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_seed_bytes: u64,
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    max_single_file_bytes: u64,
    #[arg(long, default_value_t = 32)]
    max_depth: usize,
    #[arg(
        long = "instruction-extension",
        value_delimiter = ',',
        default_value = "md,txt"
    )]
    instruction_extensions: Vec<String>,
    #[arg(long, default_value_t = 32)]
    max_actions: usize,
    #[arg(long, default_value_t = 32)]
    max_lifts: usize,
    #[arg(long, default_value_t = 60)]
    action_timeout_seconds: u64,
    #[arg(long, default_value = DETERMINISTIC_ADAPTER)]
    adapter: String,
    #[arg(long, default_value = "none")]
    agent_model: String,
    #[arg(long)]
    agent_base_url: Option<String>,
    /// Read-only per-run Unix socket used by the trusted loopback relay forwarder.
    #[arg(long)]
    relay_socket: Option<PathBuf>,
    #[arg(long, default_value_t = 120)]
    adapter_timeout_seconds: u64,
    #[arg(long, default_value_t = 8)]
    agent_max_turns: u32,
    #[arg(long, default_value = "1.00")]
    agent_max_budget_usd: String,
    /// Supervisor-created gate used to start the container before Tracee and
    /// re-exec this PID after the collector is attached.
    #[arg(long)]
    start_gate: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct HarnessEvent<'a> {
    schema_version: u8,
    event: &'a str,
    path: String,
    detail: String,
}

#[derive(Debug)]
enum Action {
    Shell { origin: PathBuf, body: String },
    Script { origin: PathBuf, path: PathBuf },
}

fn main() -> Result<()> {
    let args = Args::parse();
    validate_relay_socket(&args)?;
    wait_for_start_gate_and_reexec(&args)?;
    let stats = run_session(&args)?;
    std::process::exit(completion_exit_code(&stats)?);
}

fn validate_relay_socket(args: &Args) -> Result<()> {
    match args.adapter.as_str() {
        DETERMINISTIC_ADAPTER if args.relay_socket.is_some() => {
            bail!("deterministic adapter forbids a relay socket")
        }
        DETERMINISTIC_ADAPTER => Ok(()),
        CODEX_ADAPTER | CLAUDE_ADAPTER => match args.relay_socket.as_deref() {
            Some(path) if path == Path::new(RELAY_SOCKET_PATH) => Ok(()),
            Some(_) => bail!("CLI adapter requires the fixed relay socket path"),
            None => bail!("CLI adapter requires a relay socket"),
        },
        _ if args.relay_socket.is_some() => {
            bail!("relay socket is valid only for a supported CLI adapter")
        }
        _ => Ok(()),
    }
}

fn wait_for_start_gate_and_reexec(args: &Args) -> Result<()> {
    let Some(gate) = &args.start_gate else {
        return Ok(());
    };
    if std::env::var_os("SKILLSISSUE_GATE_RELEASED").as_deref() == Some("1".as_ref()) {
        return Ok(());
    }
    if gate != Path::new("/tmp/skillsissue-start") {
        bail!("start gate must use the fixed target tmpfs path");
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match fs::symlink_metadata(gate) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => break,
            Ok(_) => bail!("start gate is not a regular file"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect start gate"),
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for the supervisor start gate");
        }
        thread::sleep(Duration::from_millis(50));
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        let executable = std::env::current_exe().context("resolve harness for gated re-exec")?;
        let error = Command::new(executable)
            .args(std::env::args_os().skip(1))
            .env("SKILLSISSUE_GATE_RELEASED", "1")
            .exec();
        Err(error).context("re-exec gated skill harness")
    }
    #[cfg(not(unix))]
    bail!("start-gated detonation requires Unix exec semantics")
}

#[derive(Debug, Eq, PartialEq)]
struct HarnessStats {
    action_count: usize,
    lift_count: usize,
}

fn run_session(args: &Args) -> Result<HarnessStats> {
    validate_relay_socket(args)?;
    let skill_destination = skill_destination(args)?;
    if let Some(seed_root) = &args.seed_root {
        seed_skill_tree(seed_root, &skill_destination, args)?;
    }
    let project_root = args
        .skill_root
        .canonicalize()
        .context("canonicalize skill root")?;
    let content_root = skill_destination
        .canonicalize()
        .context("canonicalize staged skill")?;
    let stats = match args.adapter.as_str() {
        DETERMINISTIC_ADAPTER => run_deterministic_session(args, &content_root)?,
        CODEX_ADAPTER | CLAUDE_ADAPTER => run_cli_session(args, &project_root)?,
        _ => bail!("unsupported harness adapter"),
    };
    emit(
        "complete",
        &project_root,
        &format!(
            "adapter={},actions={},lifts={}",
            args.adapter, stats.action_count, stats.lift_count
        ),
    )?;
    Ok(stats)
}

fn skill_destination(args: &Args) -> Result<PathBuf> {
    match args.adapter.as_str() {
        DETERMINISTIC_ADAPTER => Ok(args.skill_root.clone()),
        CODEX_ADAPTER => Ok(args.skill_root.join(".agents/skills/detonated-skill")),
        CLAUDE_ADAPTER => Ok(args.skill_root.join(".claude/skills/detonated-skill")),
        _ => bail!("unsupported harness adapter"),
    }
}

fn run_deterministic_session(args: &Args, root: &Path) -> Result<HarnessStats> {
    let mut seen_instructions: BTreeMap<PathBuf, Hash> = BTreeMap::new();
    let mut seen_actions = BTreeSet::new();
    let mut queue = VecDeque::new();
    let mut action_count = 0;
    let mut lift_count = 0;
    let mut initial_scan = true;

    'session: loop {
        let instructions = instruction_files(root, &args.instruction_extensions)?;
        for path in instructions {
            let Some(bytes) = read_instruction_bounded(&path)? else {
                emit("instruction_skipped", &path, "larger than 1 MiB")?;
                continue;
            };
            let digest = blake3::hash(&bytes);
            if seen_instructions.get(&path) == Some(&digest) {
                continue;
            }
            if !initial_scan {
                if lift_count >= args.max_lifts {
                    emit("limit", &path, "closure lift limit reached")?;
                    break 'session;
                }
                lift_count += 1;
                emit("closure_lift", &path, &digest.to_hex())?;
            } else {
                emit("instruction", &path, &digest.to_hex())?;
            }
            seen_instructions.insert(path.clone(), digest);
            let text = String::from_utf8_lossy(&bytes);
            for action in actions_from_instruction(root, &path, &text)? {
                let key = action_key(&action);
                if seen_actions.insert(key) {
                    queue.push_back(action);
                }
            }
        }
        initial_scan = false;

        let Some(action) = queue.pop_front() else {
            break;
        };
        action_count += 1;
        if action_count > args.max_actions {
            emit("limit", root, "action limit reached")?;
            break;
        }
        run_action(
            root,
            action,
            Duration::from_secs(args.action_timeout_seconds),
        )?;
    }
    Ok(HarnessStats {
        action_count,
        lift_count,
    })
}

fn run_cli_session(args: &Args, project_root: &Path) -> Result<HarnessStats> {
    fs::create_dir_all("/tmp/codex-home")?;
    fs::create_dir_all("/tmp/claude-home")?;
    let before = instruction_snapshot(project_root, &args.instruction_extensions, true)?;
    for (path, digest) in &before {
        emit("instruction", path, &digest.to_hex())?;
    }

    let invocation = agent_cli_invocation(
        &args.adapter,
        &args.agent_model,
        args.agent_max_turns,
        &args.agent_max_budget_usd,
    )?
    .context("CLI adapter has no invocation")?;
    let base_url = args
        .agent_base_url
        .as_deref()
        .context("CLI adapter requires a loopback relay base URL")?;
    let relay_socket = args
        .relay_socket
        .as_deref()
        .context("CLI adapter requires a relay socket")?;
    let mut relay_forwarder = RelayForwarder::start(relay_socket)?;
    let adapter_result = (|| -> Result<()> {
        let version = adapter_version(&invocation[0], project_root)?;
        emit("adapter_version", project_root, &version)?;
        emit(
            "adapter_invocation",
            project_root,
            &serde_json::to_string(&invocation)?,
        )?;
        run_adapter(
            args,
            project_root,
            base_url,
            &invocation,
            Duration::from_secs(args.adapter_timeout_seconds),
        )
    })();
    let forwarder_result = relay_forwarder.stop();
    adapter_result?;
    forwarder_result?;

    let after = instruction_snapshot(project_root, &args.instruction_extensions, false)?;
    let mut lift_count = 0_usize;
    for (path, digest) in after {
        if before.get(&path) == Some(&digest) {
            continue;
        }
        if lift_count >= args.max_lifts {
            emit("limit", &path, "closure lift limit reached")?;
            break;
        }
        lift_count += 1;
        emit("closure_lift", &path, &digest.to_hex())?;
    }
    Ok(HarnessStats {
        action_count: 1,
        lift_count,
    })
}

struct RelayForwarder {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<thread::JoinHandle<Result<()>>>,
}

impl RelayForwarder {
    fn start(relay_socket: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            let listener = TcpListener::bind(RELAY_LISTEN_ADDRESS)
                .context("bind fixed loopback relay listener")?;
            Self::from_listener(listener, relay_socket)
        }

        #[cfg(not(unix))]
        {
            let _ = relay_socket;
            bail!("CLI relay forwarding requires Unix sockets")
        }
    }

    #[cfg(unix)]
    fn from_listener(listener: TcpListener, relay_socket: &Path) -> Result<Self> {
        listener
            .set_nonblocking(true)
            .context("configure loopback relay listener")?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context("build loopback relay runtime")?;
        let listener = {
            let _guard = runtime.enter();
            tokio::net::TcpListener::from_std(listener).context("adopt loopback relay listener")?
        };
        let relay_socket = relay_socket.to_path_buf();
        let (shutdown, shutdown_receiver) = tokio::sync::oneshot::channel();
        let join = thread::Builder::new()
            .name("skillsissue-relay-forwarder".into())
            .spawn(move || {
                runtime.block_on(forward_relay_connections(
                    listener,
                    relay_socket,
                    shutdown_receiver,
                ))
            })
            .context("start loopback relay forwarder")?;
        Ok(Self {
            shutdown: Some(shutdown),
            join: Some(join),
        })
    }

    #[cfg(all(test, unix))]
    fn start_for_test(relay_socket: &Path) -> Result<(Self, std::net::SocketAddr)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        Ok((Self::from_listener(listener, relay_socket)?, address))
    }

    fn stop(&mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        join.join()
            .map_err(|_| anyhow::anyhow!("loopback relay forwarder panicked"))?
    }
}

impl Drop for RelayForwarder {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(unix)]
async fn forward_relay_connections(
    listener: tokio::net::TcpListener,
    relay_socket: PathBuf,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> Result<()> {
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_ACTIVE_RELAY_CONNECTIONS));
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accept loopback relay connection")?;
                let Some(permit) = acquire_relay_permit(&permits) else {
                    drop(stream);
                    continue;
                };
                let relay_socket = relay_socket.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = forward_relay_connection(stream, &relay_socket).await;
                });
            }
        }
    }
}

#[cfg(unix)]
fn acquire_relay_permit(
    permits: &Arc<tokio::sync::Semaphore>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    Arc::clone(permits).try_acquire_owned().ok()
}

#[cfg(unix)]
async fn forward_relay_connection(
    mut stream: tokio::net::TcpStream,
    relay_socket: &Path,
) -> Result<()> {
    let mut relay = tokio::time::timeout(
        RELAY_CONNECT_TIMEOUT,
        tokio::net::UnixStream::connect(relay_socket),
    )
    .await
    .context("timed out connecting to credential relay")?
    .context("connect to credential relay")?;
    tokio::io::copy_bidirectional(&mut stream, &mut relay)
        .await
        .context("forward credential relay connection")?;
    Ok(())
}

fn instruction_snapshot(
    root: &Path,
    extensions: &[String],
    require_root: bool,
) -> Result<BTreeMap<PathBuf, Hash>> {
    if !root.exists() {
        if require_root {
            bail!("instruction root disappeared before adapter execution");
        }
        return Ok(BTreeMap::new());
    }
    let mut snapshot = BTreeMap::new();
    for path in instruction_files(root, extensions)? {
        let Some(bytes) = read_instruction_bounded(&path)? else {
            emit("instruction_skipped", &path, "larger than 1 MiB")?;
            continue;
        };
        snapshot.insert(path, blake3::hash(&bytes));
    }
    Ok(snapshot)
}

fn adapter_version(binary: &str, project_root: &Path) -> Result<String> {
    let output = safe_adapter_command(binary, project_root)
        .arg("--version")
        .output()
        .with_context(|| format!("query adapter version from {binary}"))?;
    if !output.status.success() {
        bail!("adapter version probe failed");
    }
    let mut version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if version.len() > 256 {
        version.truncate(256);
    }
    if version.is_empty() || version.chars().any(char::is_control) {
        bail!("adapter returned an invalid version string");
    }
    Ok(version)
}

fn run_adapter(
    args: &Args,
    project_root: &Path,
    base_url: &str,
    invocation: &[String],
    timeout: Duration,
) -> Result<()> {
    let mut command = safe_adapter_command(&invocation[0], project_root);
    command
        .args(&invocation[1..])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    match args.adapter.as_str() {
        CODEX_ADAPTER => {
            command
                .env("CODEX_HOME", "/tmp/codex-home")
                .env("CODEX_API_KEY", "skillsissue-dummy-target-key")
                .env("OPENAI_API_KEY", "skillsissue-dummy-target-key")
                .env("OPENAI_BASE_URL", base_url);
        }
        CLAUDE_ADAPTER => {
            command
                .env("CLAUDE_CONFIG_DIR", "/tmp/claude-home")
                .env("ANTHROPIC_API_KEY", "skillsissue-dummy-target-key")
                .env("ANTHROPIC_BASE_URL", base_url);
        }
        _ => bail!("unsupported CLI adapter"),
    }
    emit("adapter_start", project_root, &args.adapter)?;
    let mut child = command
        .spawn()
        .with_context(|| format!("execute {}", args.adapter))?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            emit(
                "adapter_exit",
                project_root,
                &format!("{}:{}", args.adapter, status.code().unwrap_or(-1)),
            )?;
            if !status.success() {
                bail!("{} exited unsuccessfully", args.adapter);
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            emit("adapter_timeout", project_root, &args.adapter)?;
            bail!("{} exceeded its adapter timeout", args.adapter);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn safe_adapter_command(binary: &str, project_root: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .current_dir(project_root)
        .stdin(Stdio::null())
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/home/detonator")
        .env("LANG", "C.UTF-8")
        .env("TERM", "dumb")
        .env("NO_COLOR", "1")
        .env("CODEX_HOME", "/tmp/codex-home")
        .env("CLAUDE_CONFIG_DIR", "/tmp/claude-home")
        .env("SKILLSISSUE_MARKER_PREFIX", "#data_");
    command
}

fn completion_exit_code(stats: &HarnessStats) -> Result<i32> {
    let count = u32::try_from(stats.lift_count).context("closure lift count overflow")?;
    if count > MAX_ENCODED_CLOSURE_LIFTS {
        bail!("closure lift count exceeds completion protocol capacity");
    }
    Ok(HARNESS_COMPLETION_EXIT_BASE + i32::try_from(count)?)
}

fn seed_skill_tree(source: &Path, destination: &Path, args: &Args) -> Result<()> {
    let source = source
        .canonicalize()
        .with_context(|| format!("canonicalize seed root {}", source.display()))?;
    if !source.is_dir() {
        bail!("seed root is not a directory");
    }
    fs::create_dir_all(destination)?;
    if fs::read_dir(destination)?.next().transpose()?.is_some() {
        bail!("mutable skill workspace must be empty before seeding");
    }

    let mut entries = 0_u64;
    let mut bytes = 0_u64;
    for entry in WalkDir::new(&source)
        .min_depth(1)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry?;
        if entry.depth() > args.max_depth {
            bail!("seed tree exceeds configured path depth");
        }
        entries = entries.checked_add(1).context("seed entry overflow")?;
        if entries > args.max_seed_entries {
            bail!("seed tree exceeds configured entry limit");
        }
        let relative = entry.path().strip_prefix(&source)?;
        if relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        {
            bail!("seed tree contains an unsafe path");
        }
        let target = destination.join(relative);
        let metadata = fs::symlink_metadata(entry.path())?;
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            fs::create_dir(&target)?;
        } else if file_type.is_file() {
            let declared_size = metadata.len();
            if declared_size > args.max_single_file_bytes {
                bail!("seed file exceeds configured per-file limit");
            }
            bytes = bytes
                .checked_add(declared_size)
                .context("seed byte count overflow")?;
            if bytes > args.max_seed_bytes {
                bail!("seed tree exceeds configured byte limit");
            }
            copy_file_bounded(
                entry.path(),
                &target,
                declared_size,
                args.max_single_file_bytes,
            )?;
            fs::set_permissions(&target, metadata.permissions())?;
        } else if file_type.is_symlink() {
            let link_target = fs::read_link(entry.path())?;
            if !safe_seed_symlink(relative, &link_target) {
                bail!("seed tree contains an unsafe symlink");
            }
            bytes = bytes
                .checked_add(link_target.as_os_str().len() as u64)
                .context("seed byte count overflow")?;
            if bytes > args.max_seed_bytes {
                bail!("seed tree exceeds configured byte limit");
            }
            #[cfg(unix)]
            std::os::unix::fs::symlink(link_target, target)?;
            #[cfg(not(unix))]
            bail!("skill symlinks require a Unix target");
        } else {
            bail!("seed tree contains an unsupported file type");
        }
    }
    let entrypoint = fs::symlink_metadata(destination.join("SKILL.md"))
        .context("seed tree is missing regular SKILL.md")?;
    if !entrypoint.is_file() || entrypoint.file_type().is_symlink() {
        bail!("seed tree SKILL.md must be a regular file");
    }
    Ok(())
}

fn copy_file_bounded(source: &Path, target: &Path, expected: u64, limit: u64) -> Result<()> {
    let mut source = File::open(source)?;
    let mut target = File::create(target)?;
    let copied = std::io::copy(
        &mut source.by_ref().take(limit.saturating_add(1)),
        &mut target,
    )?;
    if copied != expected || copied > limit {
        bail!("seed file changed or exceeded its bound while copying");
    }
    Ok(())
}

fn safe_seed_symlink(link_path: &Path, target: &Path) -> bool {
    if target.as_os_str().is_empty() || target.is_absolute() {
        return false;
    }
    let mut depth = 0_usize;
    for component in link_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .components()
        .chain(target.components())
    {
        match component {
            Component::CurDir => {}
            Component::Normal(_) => depth += 1,
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

const MAX_INSTRUCTION_BYTES: u64 = 1024 * 1024;

fn read_instruction_bounded(path: &Path) -> Result<Option<Vec<u8>>> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_INSTRUCTION_BYTES {
        return Ok(None);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(MAX_INSTRUCTION_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INSTRUCTION_BYTES {
        return Ok(None);
    }
    Ok(Some(bytes))
}

fn instruction_files(root: &Path, extensions: &[String]) -> Result<Vec<PathBuf>> {
    let extensions = extensions
        .iter()
        .map(|extension| extension.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut files = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let ext = entry
            .path()
            .extension()
            .and_then(|x| x.to_str())
            .unwrap_or_default();
        if extensions.contains(&ext.to_ascii_lowercase()) {
            files.push(entry.path().to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

fn actions_from_instruction(root: &Path, origin: &Path, text: &str) -> Result<Vec<Action>> {
    let canonical_root = root.canonicalize()?;
    let fence = Regex::new(r"(?ms)```(?:bash|sh|shell)[^\n]*\n(?P<body>.*?)```")?;
    let script = Regex::new(r"(?i)(?P<path>(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:sh|py))")?;
    let mut actions = Vec::new();
    for capture in fence.captures_iter(text) {
        let body = capture["body"].trim();
        if !body.is_empty() {
            actions.push(Action::Shell {
                origin: origin.to_path_buf(),
                body: body.to_string(),
            });
        }
    }
    for capture in script.captures_iter(text) {
        let relative = Path::new(&capture["path"]);
        if relative.is_absolute()
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
        {
            continue;
        }
        let candidates = [
            origin.parent().unwrap_or(root).join(relative),
            root.join(relative),
        ];
        if let Some(candidate) = candidates.into_iter().find(|path| path.is_file()) {
            let canonical = candidate.canonicalize()?;
            if canonical.starts_with(&canonical_root) {
                actions.push(Action::Script {
                    origin: origin.to_path_buf(),
                    path: canonical,
                });
            }
        }
    }
    Ok(actions)
}

fn action_key(action: &Action) -> String {
    match action {
        Action::Shell { origin, body } => format!(
            "shell:{}:{}",
            origin.display(),
            blake3::hash(body.as_bytes()).to_hex()
        ),
        Action::Script { origin, path } => {
            format!("script:{}:{}", origin.display(), path.display())
        }
    }
}

fn run_action(root: &Path, action: Action, timeout: Duration) -> Result<()> {
    let (origin, label, mut command) = match action {
        Action::Shell { origin, body } => {
            let mut command = Command::new("/bin/sh");
            command.args(["-eu", "-c", &body]);
            (origin, "shell".to_string(), command)
        }
        Action::Script { origin, path } => {
            let ext = path
                .extension()
                .and_then(|x| x.to_str())
                .unwrap_or_default();
            let mut command = if ext.eq_ignore_ascii_case("py") {
                Command::new("python3")
            } else {
                Command::new("/bin/sh")
            };
            command.arg(&path);
            (origin, path.display().to_string(), command)
        }
    };
    emit("action_start", &origin, &label)?;
    command.current_dir(root).stdin(Stdio::null());
    let mut child = command
        .spawn()
        .with_context(|| format!("execute {label}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            emit(
                "action_exit",
                &origin,
                &format!("{label}:{}", status.code().unwrap_or(-1)),
            )?;
            return Ok(());
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            emit("action_timeout", &origin, &label)?;
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn emit(event: &str, path: &Path, detail: &str) -> Result<()> {
    let value = HarnessEvent {
        schema_version: 1,
        event,
        path: path.display().to_string(),
        detail: detail.to_string(),
    };
    println!("SKILLSISSUE_EVENT {}", serde_json::to_string(&value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn args(skill_root: &Path) -> Args {
        Args {
            skill_root: skill_root.to_path_buf(),
            seed_root: None,
            max_seed_entries: 4_096,
            max_seed_bytes: 64 * 1024 * 1024,
            max_single_file_bytes: 16 * 1024 * 1024,
            max_depth: 32,
            instruction_extensions: vec!["md".into(), "txt".into()],
            max_actions: 4,
            max_lifts: 4,
            action_timeout_seconds: 2,
            adapter: DETERMINISTIC_ADAPTER.into(),
            agent_model: "none".into(),
            agent_base_url: None,
            relay_socket: None,
            adapter_timeout_seconds: 2,
            agent_max_turns: 2,
            agent_max_budget_usd: "0.10".into(),
            start_gate: None,
        }
    }

    #[test]
    fn relay_socket_is_fixed_and_cli_only() {
        let root = Path::new("/work/skill");
        let mut deterministic = args(root);
        assert!(validate_relay_socket(&deterministic).is_ok());
        deterministic.relay_socket = Some(PathBuf::from(RELAY_SOCKET_PATH));
        assert!(validate_relay_socket(&deterministic).is_err());

        let mut codex = args(root);
        codex.adapter = CODEX_ADAPTER.into();
        assert!(validate_relay_socket(&codex).is_err());
        codex.relay_socket = Some(PathBuf::from("/tmp/attacker.sock"));
        assert!(validate_relay_socket(&codex).is_err());
        codex.relay_socket = Some(PathBuf::from(RELAY_SOCKET_PATH));
        assert!(validate_relay_socket(&codex).is_ok());

        let mut claude = args(root);
        claude.adapter = CLAUDE_ADAPTER.into();
        claude.relay_socket = Some(PathBuf::from(RELAY_SOCKET_PATH));
        assert!(validate_relay_socket(&claude).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn loopback_forwarder_copies_bidirectionally_and_stops() -> Result<()> {
        use std::io::{Read as _, Write as _};
        use std::net::{Shutdown, TcpStream};
        use std::os::unix::net::UnixListener;

        let temp = TempDir::new()?;
        let socket = temp.path().join("relay.sock");
        let listener = UnixListener::bind(&socket)?;
        let server = thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request)?;
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong")?;
            Ok(())
        });

        let (mut forwarder, address) = RelayForwarder::start_for_test(&socket)?;
        let mut client = TcpStream::connect(address)?;
        client.set_read_timeout(Some(Duration::from_secs(2)))?;
        client.set_write_timeout(Some(Duration::from_secs(2)))?;
        client.write_all(b"ping")?;
        client.shutdown(Shutdown::Write)?;
        let mut response = [0_u8; 4];
        client.read_exact(&mut response)?;
        assert_eq!(&response, b"pong");

        forwarder.stop()?;
        server
            .join()
            .map_err(|_| anyhow::anyhow!("Unix relay test server panicked"))??;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn loopback_forwarder_caps_active_connections() {
        let permits = Arc::new(tokio::sync::Semaphore::new(MAX_ACTIVE_RELAY_CONNECTIONS));
        let mut held = (0..MAX_ACTIVE_RELAY_CONNECTIONS)
            .map(|_| acquire_relay_permit(&permits).expect("connection permit"))
            .collect::<Vec<_>>();
        assert!(acquire_relay_permit(&permits).is_none());
        held.pop();
        assert!(acquire_relay_permit(&permits).is_some());
    }

    #[test]
    fn extracts_fences_and_in_tree_scripts_only() -> Result<()> {
        let temp = TempDir::new()?;
        let root = temp.path();
        fs::create_dir(root.join("scripts"))?;
        fs::write(root.join("scripts/setup.sh"), "true")?;
        let origin = root.join("SKILL.md");
        let text = "run `scripts/setup.sh`\n```bash\necho ok\n```\n`../../evil.sh`";
        let actions = actions_from_instruction(root, &origin, text)?;
        assert_eq!(actions.len(), 2);
        Ok(())
    }

    #[test]
    fn shipped_instruction_set_does_not_consume_runtime_lift_budget() -> Result<()> {
        let temp = TempDir::new()?;
        for index in 0..64 {
            fs::write(
                temp.path().join(format!("doc-{index}.md")),
                "# documentation\n",
            )?;
        }
        let mut args = args(temp.path());
        args.max_lifts = 1;
        let stats = run_session(&args)?;
        assert_eq!(stats.lift_count, 0);
        Ok(())
    }

    #[test]
    fn newly_materialized_instruction_counts_as_a_lift() -> Result<()> {
        let temp = TempDir::new()?;
        fs::write(
            temp.path().join("SKILL.md"),
            "```bash\nprintf '# next\\n' > WORKFLOW.md\n```\n",
        )?;
        let stats = run_session(&args(temp.path()))?;
        assert_eq!(stats.lift_count, 1);
        Ok(())
    }

    #[test]
    fn validated_seed_is_copied_before_runtime_lifts_are_counted() -> Result<()> {
        let temp = TempDir::new()?;
        let seed = temp.path().join("seed");
        let workspace = temp.path().join("workspace");
        fs::create_dir(&seed)?;
        fs::write(
            seed.join("SKILL.md"),
            "```bash\nprintf '# next\\n' > WORKFLOW.md\n```\n",
        )?;
        let mut args = args(&workspace);
        args.seed_root = Some(seed);
        let stats = run_session(&args)?;
        assert_eq!(stats.lift_count, 1);
        assert!(workspace.join("SKILL.md").is_file());
        assert!(workspace.join("WORKFLOW.md").is_file());
        Ok(())
    }

    #[test]
    fn seed_copy_enforces_entry_and_byte_limits() -> Result<()> {
        let temp = TempDir::new()?;
        let seed = temp.path().join("seed");
        fs::create_dir(&seed)?;
        fs::write(seed.join("SKILL.md"), "12345")?;

        let entry_workspace = temp.path().join("entry-workspace");
        let mut entry_args = args(&entry_workspace);
        entry_args.max_seed_entries = 0;
        assert!(seed_skill_tree(&seed, &entry_workspace, &entry_args).is_err());

        let byte_workspace = temp.path().join("byte-workspace");
        let mut byte_args = args(&byte_workspace);
        byte_args.max_seed_bytes = 4;
        assert!(seed_skill_tree(&seed, &byte_workspace, &byte_args).is_err());
        Ok(())
    }

    #[test]
    fn oversized_instruction_is_rejected_before_reading_contents() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("large.md");
        let file = File::create(&path)?;
        file.set_len(MAX_INSTRUCTION_BYTES + 1)?;
        assert!(read_instruction_bounded(&path)?.is_none());
        Ok(())
    }

    #[test]
    fn completion_exit_protocol_encodes_bounded_lift_count() -> Result<()> {
        assert_eq!(
            completion_exit_code(&HarnessStats {
                action_count: 2,
                lift_count: 7,
            })?,
            HARNESS_COMPLETION_EXIT_BASE + 7
        );
        assert!(
            completion_exit_code(&HarnessStats {
                action_count: 0,
                lift_count: MAX_ENCODED_CLOSURE_LIFTS as usize + 1,
            })
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn cli_adapters_use_official_project_skill_layouts() -> Result<()> {
        let root = Path::new("/work/skill");
        let mut codex = args(root);
        codex.adapter = CODEX_ADAPTER.into();
        assert_eq!(
            skill_destination(&codex)?,
            root.join(".agents/skills/detonated-skill")
        );
        let mut claude = args(root);
        claude.adapter = CLAUDE_ADAPTER.into();
        assert_eq!(
            skill_destination(&claude)?,
            root.join(".claude/skills/detonated-skill")
        );
        Ok(())
    }

    #[test]
    fn cli_invocations_are_noninteractive_and_bounded() -> Result<()> {
        let codex = agent_cli_invocation(CODEX_ADAPTER, "codex-test", 3, "0.25")?
            .context("codex invocation")?;
        assert!(codex.iter().any(|arg| arg == "--ephemeral"));
        assert!(codex.iter().any(|arg| arg == "--ignore-user-config"));
        assert!(
            codex
                .windows(2)
                .any(|args| args == ["--sandbox", "danger-full-access"])
        );

        let claude = agent_cli_invocation(CLAUDE_ADAPTER, "claude-test", 3, "0.25")?
            .context("claude invocation")?;
        assert!(!claude.iter().any(|arg| arg == "--bare"));
        assert!(
            claude
                .windows(2)
                .any(|args| args == ["--setting-sources", "project"])
        );
        assert!(claude.iter().any(|arg| arg == "--no-session-persistence"));
        assert!(claude.windows(2).any(|args| args == ["--max-turns", "3"]));
        assert!(
            claude
                .windows(2)
                .any(|args| args == ["--max-budget-usd", "0.25"])
        );
        Ok(())
    }
}
