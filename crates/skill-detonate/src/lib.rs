//! Trusted detonation supervisor primitives.
//!
//! The supervisor never executes a skill in its own process. It creates a
//! capability-dropped target container and a separate privileged Tracee sensor.

use anyhow::{Context, Result, anyhow, bail};
use blake3::Hasher;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub use skills_core::{RunRecord, SkillRecord};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const SCHEMA_VERSION: &str = "1";
pub const HARNESS_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Successful harness exits encode the trusted closure-lift count in this
/// reserved range. Signal-derived container exits start at 128.
pub const HARNESS_COMPLETION_EXIT_BASE: i32 = 64;
pub const MAX_ENCODED_CLOSURE_LIFTS: u32 = 63;
pub const DETERMINISTIC_ADAPTER: &str = "deterministic-closure-harness";
pub const CODEX_ADAPTER: &str = "codex-cli";
pub const CLAUDE_ADAPTER: &str = "claude-cli";
pub const INVOCATION_MARKER_PATH: &str = "/tmp/skillsissue-invocation-boundary";
const RELAY_PORT: u16 = 8787;
const RELAY_REQUEST_BYTES: u64 = 256 * 1024;
const RELAY_TOTAL_REQUEST_BYTES: u64 = 768 * 1024;
const RELAY_MAX_OUTPUT_TOKENS: u64 = 4096;
const RELAY_CONTRACT_VERSION: &str = "strict-local-tools-uds-v3-transcript";
const RELAY_SOCKET_CONTAINER_PATH: &str = "/run/skillsissue/relay.sock";
const RELAY_SOCKET_CONTAINER_DIR: &str = "/run/skillsissue";
const RELAY_TRANSCRIPT_CONTAINER_PATH: &str = "/run/evidence/network.jsonl";
const RELAY_MAX_TRANSCRIPT_BYTES: u64 = 32 * 1024 * 1024;
const RELAY_MAX_TRANSCRIPT_BODY_BYTES: u64 = 16 * 1024 * 1024;
const EGRESS_PROXY_IMAGE: &str = "skillsissue-egress-proxy:local";
const EGRESS_PROXY_ALIAS: &str = "skillsissue-egress-proxy";
const EGRESS_PROXY_PORT: u16 = 8080;
const EGRESS_PROXY_CA_CONTAINER_PATH: &str = "/run/skillsissue/egress-ca.pem";
const EGRESS_PROXY_CA_HOST_NAME: &str = "mitmproxy-ca-cert.pem";
const EGRESS_PROXY_EVIDENCE_CONTAINER_PATH: &str = "/run/evidence/egress-network.jsonl";
const EGRESS_PROXY_MAX_REQUESTS: u64 = 32;
const EGRESS_PROXY_MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const EGRESS_PROXY_MAX_TOTAL_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
const EGRESS_CONTRACT_VERSION: &str = "public-download-mitm-v1";
const INTERCEPTED_NETWORK_MODE: &str = "intercepted-http";
const CODEX_RELAY_BASE_URL: &str = "http://127.0.0.1:8787/v1";
const CLAUDE_RELAY_BASE_URL: &str = "http://127.0.0.1:8787";
const PROVIDER_SECRET_ENV: &str = "SKILLSISSUE_PROVIDER_API_KEY";
const TARGET_START_GATE: &str = "/tmp/skillsissue-start";

const CODEX_PROMPT: &str = "Use the project skill at .agents/skills/detonated-skill/SKILL.md. Read its instructions, then execute exactly one documented primary or mandatory command from the skill root with the dependencies already installed. Do not install packages, retry, or troubleshoot. Report the command and observed result, then exit.";
const CLAUDE_PROMPT: &str = "/detonated-skill Read the skill instructions, then change directory to /work/skill/.claude/skills/detonated-skill and execute exactly one documented primary or mandatory command with the dependencies already installed. Do not install packages, retry, or troubleshoot. Report the command and observed result, then exit.";

/// A validated, zero-based partition of the skill corpus.
///
/// Assignment depends only on the immutable skill ID, so workers using the
/// same shard count select disjoint work regardless of registry ordering or
/// policy/configuration changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardSpec {
    index: u32,
    count: u32,
}

impl ShardSpec {
    pub fn new(index: u32, count: u32) -> Result<Self> {
        if count == 0 {
            bail!("--shard-count must be greater than zero");
        }
        if index >= count {
            bail!(
                "--shard-index must be less than --shard-count (got index {index}, count {count})"
            );
        }
        Ok(Self { index, count })
    }

    pub const fn index(self) -> u32 {
        self.index
    }

    pub const fn count(self) -> u32 {
        self.count
    }

    pub fn contains(self, skill_id: &str) -> bool {
        skills_core::detonation_shard_index(skill_id, self.count) == Some(self.index)
    }
}

impl Default for ShardSpec {
    fn default() -> Self {
        Self { index: 0, count: 1 }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetonatorConfig {
    pub tracee_image: String,
    pub sandbox_image: String,
    pub timeout_seconds: u64,
    pub memory: String,
    pub cpus: String,
    pub pids_limit: u32,
    pub max_attempts_per_run_key: u32,
    pub network_mode: String,
    pub max_telemetry_bytes: u64,
    pub max_agent_output_bytes: u64,
    pub max_skill_entries: u64,
    pub max_skill_bytes: u64,
    pub max_single_file_bytes: u64,
    pub max_skill_depth: usize,
    pub max_workspace_bytes: u64,
    pub max_workspace_inodes: u64,
    pub max_closure_lifts: u32,
    pub instruction_extensions: Vec<String>,
    pub agent_adapter: String,
    pub agent_model: String,
    pub agent_base_url: Option<String>,
    pub agent_relay_image: String,
    pub agent_timeout_seconds: u64,
    pub agent_max_turns: u32,
    pub agent_max_budget_usd: String,
    pub skillject_commit: String,
    #[serde(skip)]
    pub target_image_digest: String,
    #[serde(skip)]
    pub agent_relay_image_digest: String,
    #[serde(skip)]
    pub egress_proxy_image_digest: String,
    #[serde(skip)]
    pub supervisor_digest: String,
}

impl Default for DetonatorConfig {
    fn default() -> Self {
        Self {
            tracee_image: "aquasec/tracee:0.24.1@sha256:cfbbfee972e64a644f6b1bac74ee26998e6e12442697be4c797ae563553a2a5b".into(),
            sandbox_image: "skillsissue-sandbox:local".into(),
            timeout_seconds: 900,
            memory: "1g".into(),
            cpus: "1.0".into(),
            pids_limit: 128,
            max_attempts_per_run_key: 3,
            network_mode: "none".into(),
            max_telemetry_bytes: 4 * 1024 * 1024,
            max_agent_output_bytes: 512 * 1024,
            max_skill_entries: 4_096,
            max_skill_bytes: 64 * 1024 * 1024,
            max_single_file_bytes: 16 * 1024 * 1024,
            max_skill_depth: 32,
            max_workspace_bytes: 128 * 1024 * 1024,
            max_workspace_inodes: 8_192,
            max_closure_lifts: 32,
            instruction_extensions: vec!["md".into(), "txt".into()],
            agent_adapter: DETERMINISTIC_ADAPTER.into(),
            agent_model: "none".into(),
            agent_base_url: None,
            agent_relay_image: "skillsissue-relay:local".into(),
            agent_timeout_seconds: 120,
            agent_max_turns: 8,
            agent_max_budget_usd: "1.00".into(),
            skillject_commit: "6598997b76044fa00abe0a4416064fbd2eab33ff".into(),
            target_image_digest: String::new(),
            agent_relay_image_digest: String::new(),
            egress_proxy_image_digest: String::new(),
            supervisor_digest: String::new(),
        }
    }
}

impl DetonatorConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("read detonator config {}", path.display()))?;
        let config: Self =
            toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_skill_entries == 0
            || self.max_skill_bytes == 0
            || self.max_single_file_bytes == 0
            || self.max_skill_depth == 0
            || self.max_single_file_bytes > self.max_skill_bytes
        {
            bail!("invalid detonation extraction limits");
        }
        if self.max_workspace_bytes < self.max_skill_bytes {
            bail!("workspace byte limit must cover the maximum validated skill size");
        }
        if self.max_workspace_inodes < self.max_skill_entries.saturating_add(1) {
            bail!("workspace inode limit must cover the maximum validated skill entries");
        }
        if self.max_closure_lifts == 0 || self.max_closure_lifts > MAX_ENCODED_CLOSURE_LIFTS {
            bail!("max_closure_lifts must be between 1 and {MAX_ENCODED_CLOSURE_LIFTS}");
        }
        if self.max_agent_output_bytes == 0 || self.max_telemetry_bytes == 0 {
            bail!("detonation output limits must be non-zero");
        }
        if self.instruction_extensions.is_empty()
            || self.instruction_extensions.len() > 16
            || self.instruction_extensions.iter().any(|extension| {
                extension.is_empty()
                    || extension.len() > 16
                    || !extension.bytes().all(|byte| byte.is_ascii_alphanumeric())
            })
        {
            bail!("instruction extensions must be 1-16 short ASCII alphanumeric values");
        }
        if self.agent_timeout_seconds == 0 || self.agent_timeout_seconds > self.timeout_seconds {
            bail!("agent timeout must be non-zero and no greater than the detonation timeout");
        }
        if self.agent_max_turns == 0 || self.agent_max_turns > 64 {
            bail!("agent_max_turns must be between 1 and 64");
        }
        let budget = self.agent_max_budget_usd.parse::<f64>().ok();
        if self.agent_max_budget_usd.len() > 16
            || !self
                .agent_max_budget_usd
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
            || budget.is_none_or(|value| !value.is_finite() || !(0.01..=100.0).contains(&value))
        {
            bail!("agent_max_budget_usd must be a decimal between 0.01 and 100.00");
        }
        match self.agent_adapter.as_str() {
            DETERMINISTIC_ADAPTER => {
                if self.agent_model != "none"
                    || self.agent_base_url.is_some()
                    || !matches!(
                        self.network_mode.as_str(),
                        "none" | INTERCEPTED_NETWORK_MODE
                    )
                {
                    bail!(
                        "deterministic adapter requires agent_model=none, a supported network mode, and no base URL"
                    );
                }
            }
            CODEX_ADAPTER | CLAUDE_ADAPTER => {
                if self.agent_model.is_empty()
                    || self.agent_model == "none"
                    || self.agent_model.len() > 128
                    || self.agent_model.chars().any(char::is_control)
                {
                    bail!("CLI adapters require a bounded non-empty agent model");
                }
                if !matches!(
                    self.network_mode.as_str(),
                    "none" | INTERCEPTED_NETWORK_MODE
                ) {
                    bail!("CLI adapters require a supported network mode");
                }
                let base_url = self
                    .agent_base_url
                    .as_deref()
                    .ok_or_else(|| anyhow!("CLI adapters require agent_base_url"))?;
                let parsed = url::Url::parse(base_url).context("parse agent_base_url")?;
                let expected = if self.agent_adapter == CODEX_ADAPTER {
                    CODEX_RELAY_BASE_URL
                } else {
                    CLAUDE_RELAY_BASE_URL
                };
                if base_url != expected
                    || parsed.scheme() != "http"
                    || parsed.host_str() != Some("127.0.0.1")
                    || parsed.port_or_known_default() != Some(RELAY_PORT)
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                    || parsed.query().is_some()
                    || parsed.fragment().is_some()
                {
                    bail!("agent_base_url must be the adapter's fixed per-run relay URL");
                }
                if self.agent_relay_image.trim().is_empty()
                    || self.agent_relay_image.len() > 512
                    || self.agent_relay_image.chars().any(char::is_control)
                {
                    bail!("CLI adapters require a bounded agent_relay_image");
                }
            }
            _ => bail!("unsupported agent_adapter"),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RunManifest {
    pub schema_version: &'static str,
    pub run_id: String,
    pub run_key: String,
    pub skill_id: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub collector: String,
    pub collector_image: String,
    pub sandbox_image: String,
    pub agent_relay_image: Option<String>,
    pub agent_relay_image_digest: Option<String>,
    pub agent_network_internal: bool,
    pub egress_proxy_image: Option<String>,
    pub egress_proxy_image_digest: Option<String>,
    pub egress_proxy_internal: bool,
    pub target_image_digest: String,
    pub supervisor_digest: String,
    pub config_digest: String,
    pub effective_config: DetonatorConfig,
    pub network_mode: String,
    pub exit_code: Option<i32>,
    pub termination_reason: String,
    pub closure_lift_count: u64,
    pub closure_lift_count_trusted: bool,
    pub harness_invocation: Vec<String>,
    pub agent_invocation: Option<Vec<String>>,
    pub raw_event_count: u64,
    pub pre_detonation_event_count: u64,
    pub invocation_boundary_seen: bool,
    pub telemetry_path: Option<String>,
    pub telemetry_sha256: Option<String>,
    pub telemetry_size_bytes: Option<u64>,
    pub network_capture_mode: String,
    pub network_transcript_path: Option<String>,
    pub network_transcript_sha256: Option<String>,
    pub network_transcript_size_bytes: Option<u64>,
    pub network_transcript_truncated: bool,
    pub collector_healthy: bool,
    pub collector_harness_exec_seen: bool,
    pub collector_adapter_exec_seen: bool,
    pub collector_lost_events: u64,
    pub collector_log_truncated: bool,
    pub telemetry_truncated: bool,
    pub agent_stdout_truncated: bool,
    pub agent_stderr_truncated: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
struct CollectorStats {
    started: bool,
    running_before_stop: bool,
    stopped_after_flush: bool,
    logs_collected: bool,
    healthy: bool,
    exit_code: Option<i64>,
    oom_killed: bool,
    error: String,
    lost_events: u64,
    log_truncated: bool,
}

#[derive(Debug, Clone)]
pub struct DetonationRequest {
    pub skill: SkillRecord,
    pub repo_root: PathBuf,
    pub policy_path: PathBuf,
    pub config: DetonatorConfig,
    pub allow_untraced: bool,
}

#[derive(Debug, Clone)]
pub struct DetonationResult {
    pub record: RunRecord,
    pub manifest: RunManifest,
    /// Present when the attempt was durably recorded but did not complete.
    pub failure: Option<String>,
}

pub fn read_skills(path: &Path) -> Result<Vec<SkillRecord>> {
    skills_core::read_csv_records(path).map_err(Into::into)
}

pub fn read_runs(path: &Path) -> Result<Vec<RunRecord>> {
    skills_core::read_csv_records(path).map_err(Into::into)
}

pub fn write_runs_atomic(path: &Path, runs: &[RunRecord]) -> Result<()> {
    let ordered = runs
        .iter()
        .cloned()
        .map(|run| (run.run_id.clone(), run))
        .collect::<BTreeMap<_, _>>();
    skills_core::write_csv_records_atomic(path, ordered.into_values())?;
    Ok(())
}

pub fn policy_digest(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read policy {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn run_key(skill_id: &str, policy_sha256: &str, config: &DetonatorConfig) -> String {
    let config_digest = config_fingerprint(config);
    let mut h = Hasher::new();
    for field in [
        "detonation-run-v1",
        skill_id,
        policy_sha256,
        &config_digest,
        "default",
        "0",
    ] {
        h.update(&(field.len() as u64).to_le_bytes());
        h.update(field.as_bytes());
    }
    format!("b3:v1:{}", h.finalize().to_hex())
}

pub fn config_fingerprint(config: &DetonatorConfig) -> String {
    let mut instruction_extensions = config.instruction_extensions.clone();
    instruction_extensions.sort();
    instruction_extensions.dedup();
    let relay_contract = relay_contract_fingerprint(config);
    let fields = vec![
        HARNESS_VERSION.to_string(),
        config.supervisor_digest.clone(),
        config.tracee_image.clone(),
        config.sandbox_image.clone(),
        config.target_image_digest.clone(),
        config.timeout_seconds.to_string(),
        config.memory.clone(),
        config.cpus.clone(),
        config.pids_limit.to_string(),
        config.max_attempts_per_run_key.to_string(),
        config.network_mode.clone(),
        config.max_telemetry_bytes.to_string(),
        config.max_agent_output_bytes.to_string(),
        config.max_skill_entries.to_string(),
        config.max_skill_bytes.to_string(),
        config.max_single_file_bytes.to_string(),
        config.max_skill_depth.to_string(),
        config.max_workspace_bytes.to_string(),
        config.max_workspace_inodes.to_string(),
        config.max_closure_lifts.to_string(),
        instruction_extensions.join("\0"),
        config.agent_adapter.clone(),
        config.agent_model.clone(),
        config.agent_base_url.clone().unwrap_or_default(),
        config.agent_relay_image.clone(),
        config.agent_relay_image_digest.clone(),
        relay_contract,
        EGRESS_PROXY_IMAGE.to_string(),
        config.egress_proxy_image_digest.clone(),
        egress_contract_fingerprint(config),
        config.agent_timeout_seconds.to_string(),
        config.agent_max_turns.to_string(),
        config.agent_max_budget_usd.clone(),
        config.skillject_commit.clone(),
    ];
    let mut hasher = Hasher::new();
    hasher.update(b"detonation-config-v1\0");
    for field in fields {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    format!("b3:v1:{}", hasher.finalize().to_hex())
}

fn relay_contract_fingerprint(config: &DetonatorConfig) -> String {
    if config.agent_adapter == DETERMINISTIC_ADAPTER {
        "disabled".to_string()
    } else {
        format!(
            "{RELAY_CONTRACT_VERSION}:request_bytes={RELAY_REQUEST_BYTES}:total_request_bytes={RELAY_TOTAL_REQUEST_BYTES}:max_output_tokens={RELAY_MAX_OUTPUT_TOKENS}:transcript_bytes={RELAY_MAX_TRANSCRIPT_BYTES}:transcript_body_bytes={RELAY_MAX_TRANSCRIPT_BODY_BYTES}"
        )
    }
}

fn egress_contract_fingerprint(config: &DetonatorConfig) -> String {
    if config.network_mode != INTERCEPTED_NETWORK_MODE {
        "disabled".to_string()
    } else {
        format!(
            "{EGRESS_CONTRACT_VERSION}:methods=GET,HEAD:ports=80,443:request_body=0:upgrades=0:destinations=public-only:requests={EGRESS_PROXY_MAX_REQUESTS}:response_bytes={EGRESS_PROXY_MAX_RESPONSE_BYTES}:total_response_bytes={EGRESS_PROXY_MAX_TOTAL_RESPONSE_BYTES}"
        )
    }
}

pub fn pending_skills(
    skills: Vec<SkillRecord>,
    runs: &[RunRecord],
    policy_sha256: &str,
    config: &DetonatorConfig,
    limit: usize,
) -> Vec<SkillRecord> {
    pending_skills_sharded(
        skills,
        runs,
        policy_sha256,
        config,
        limit,
        ShardSpec::default(),
    )
}

pub fn pending_skills_sharded(
    skills: Vec<SkillRecord>,
    runs: &[RunRecord],
    policy_sha256: &str,
    config: &DetonatorConfig,
    limit: usize,
    shard: ShardSpec,
) -> Vec<SkillRecord> {
    let completed: BTreeSet<&str> = runs
        .iter()
        .filter(|run| matches!(run.status.as_str(), "captured" | "analyzed" | "complete"))
        .map(|run| run.run_key.as_str())
        .collect();
    let mut attempts = BTreeMap::<&str, u32>::new();
    for run in runs {
        *attempts.entry(run.run_key.as_str()).or_default() += 1;
    }
    let mut skills = skills
        .into_iter()
        .filter(|skill| shard.contains(&skill.skill_id))
        .collect::<Vec<_>>();
    skills.sort_by_cached_key(|skill| {
        let key = run_key(&skill.skill_id, policy_sha256, config);
        (
            attempts.get(key.as_str()).copied().unwrap_or(0),
            skill.skill_id.clone(),
        )
    });
    skills
        .into_iter()
        .filter(|skill| {
            let key = run_key(&skill.skill_id, policy_sha256, config);
            !completed.contains(key.as_str())
                && attempts.get(key.as_str()).copied().unwrap_or(0)
                    < config.max_attempts_per_run_key.max(1)
        })
        .take(limit)
        .collect()
}

pub fn ensure_docker_preflight(config: &DetonatorConfig, require_ebpf: bool) -> Result<()> {
    config.validate()?;
    command_ok(Command::new("docker").arg("version"), "Docker daemon")?;
    if require_ebpf {
        if std::env::consts::OS != "linux" {
            bail!(
                "eBPF detonation requires a disposable Linux host, found {}",
                std::env::consts::OS
            );
        }
        if !config.tracee_image.contains("@sha256:") {
            bail!("eBPF collector image must be pinned by sha256 digest");
        }
        for path in [
            "/sys/kernel/btf/vmlinux",
            "/sys/fs/cgroup/cgroup.controllers",
        ] {
            if !Path::new(path).exists() {
                bail!("required eBPF/cgroup v2 facility missing: {path}");
            }
        }
    }
    command_ok(
        Command::new("docker").args(["image", "inspect", &config.sandbox_image]),
        "sandbox image",
    )?;
    if config.network_mode == INTERCEPTED_NETWORK_MODE {
        command_ok(
            Command::new("docker").args(["image", "inspect", EGRESS_PROXY_IMAGE]),
            "egress proxy image",
        )?;
    }
    if config.agent_adapter != DETERMINISTIC_ADAPTER {
        command_ok(
            Command::new("docker").args(["image", "inspect", &config.agent_relay_image]),
            "agent relay image",
        )?;
        provider_secret(&config.agent_adapter)?;
    }
    Ok(())
}

pub fn resolve_target_image(config: &mut DetonatorConfig) -> Result<()> {
    config.target_image_digest = image_digest(&config.sandbox_image)?;
    if config.target_image_digest.is_empty() {
        bail!(
            "Docker returned an empty image ID for {}",
            config.sandbox_image
        );
    }
    config.agent_relay_image_digest = if config.agent_adapter == DETERMINISTIC_ADAPTER {
        String::new()
    } else {
        let digest = image_digest(&config.agent_relay_image)?;
        if digest.is_empty() {
            bail!(
                "Docker returned an empty image ID for {}",
                config.agent_relay_image
            );
        }
        digest
    };
    config.egress_proxy_image_digest = if config.network_mode == INTERCEPTED_NETWORK_MODE {
        let digest = image_digest(EGRESS_PROXY_IMAGE)?;
        if digest.is_empty() {
            bail!("Docker returned an empty image ID for {EGRESS_PROXY_IMAGE}");
        }
        digest
    } else {
        String::new()
    };
    let executable = std::env::current_exe().context("resolve supervisor executable")?;
    let mut file = File::open(&executable)?;
    let mut digest = Sha256::new();
    std::io::copy(&mut file, &mut digest)?;
    config.supervisor_digest = format!("sha256:{}", hex::encode(digest.finalize()));
    Ok(())
}

fn command_ok(command: &mut Command, label: &str) -> Result<()> {
    let output = command
        .output()
        .with_context(|| format!("start {label} check"))?;
    if !output.status.success() {
        bail!(
            "{label} check failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

pub fn detonate(request: DetonationRequest) -> Result<DetonationResult> {
    request.config.validate()?;
    let policy_sha256 = policy_digest(&request.policy_path)?;
    let config_digest = config_fingerprint(&request.config);
    let key = run_key(&request.skill.skill_id, &policy_sha256, &request.config);
    let started_at = Utc::now();
    let mut id_hasher = Hasher::new();
    id_hasher.update(key.as_bytes());
    id_hasher.update(started_at.to_rfc3339().as_bytes());
    let run_id = format!("run_{}", &id_hasher.finalize().to_hex()[..24]);
    let day_path = started_at.format("%Y/%m/%d").to_string();
    let relative_run_dir = PathBuf::from("telemetry").join(day_path).join(&run_id);
    let run_dir = request.repo_root.join(&relative_run_dir);
    fs::create_dir_all(&run_dir)?;
    let mut agent_network_internal = false;
    let mut egress_proxy_internal = false;

    let attempt = (|| -> Result<DetonationResult> {
        fs::create_dir_all(request.repo_root.join(".state"))?;
        let work = tempfile::Builder::new()
            .prefix("skillsissue-detonation-")
            .tempdir_in(request.repo_root.join(".state"))?;
        let archive_path = checked_repo_path(&request.repo_root, &request.skill.bundle_path)?;
        let extraction_root = work.path().join("extracted");
        fs::create_dir_all(&extraction_root)?;
        let skill_root = extract_bundle(&archive_path, &extraction_root, &request.config)?;
        verify_extracted_skill(&extraction_root, &skill_root, &request.skill)?;
        make_target_owned(&skill_root)?;
        let canary_root = work.path().join("canary-home");
        seed_canaries(&canary_root, &run_id)?;

        let target_name = docker_name("skillsissue-target", &run_id);
        let tracee_name = docker_name("skillsissue-tracee", &run_id);
        let relay_name = docker_name("skillsissue-relay", &run_id);
        let egress_proxy_name = docker_name("skillsissue-egress-proxy", &run_id);
        let egress_network = docker_name("skillsissue-relay-egress", &run_id);
        let target_network = docker_name("skillsissue-target-internal", &run_id);
        let relay_socket_volume = docker_name("skillsissue-relay-socket", &run_id);
        let relay_enabled = request.config.agent_adapter != DETERMINISTIC_ADAPTER;
        let egress_enabled = request.config.network_mode == INTERCEPTED_NETWORK_MODE;
        let mut containers = vec![target_name.clone(), tracee_name.clone()];
        let mut networks = Vec::new();
        if relay_enabled {
            containers.push(relay_name.clone());
        }
        if egress_enabled {
            containers.push(egress_proxy_name.clone());
            networks.push(target_network.clone());
        }
        if relay_enabled || egress_enabled {
            networks.push(egress_network.clone());
        }
        let volumes = if relay_enabled {
            vec![relay_socket_volume.clone()]
        } else {
            Vec::new()
        };
        let _cleanup = DockerCleanup::new(containers, networks, volumes);
        if relay_enabled || egress_enabled {
            create_docker_network(&egress_network, false)?;
        }
        let egress_ca_path = if egress_enabled {
            create_docker_network(&target_network, true)?;
            let ca_path = start_egress_proxy(
                &egress_proxy_name,
                &egress_network,
                &target_network,
                work.path(),
                &run_dir.join("egress-network.jsonl"),
            )?;
            egress_proxy_internal = true;
            Some(ca_path)
        } else {
            None
        };
        let relay_socket_transport = if relay_enabled {
            start_agent_relay(
                &relay_name,
                &egress_network,
                &relay_socket_volume,
                &request.config,
                work.path(),
                &run_dir.join("provider-network.jsonl"),
            )?;
            // `true` now denotes an isolated per-run relay transport. The target
            // reaches it only through the read-only UDS shared with the harness.
            agent_network_internal = true;
            Some(relay_socket_volume.as_str())
        } else {
            None
        };
        let uncompressed_events = run_dir.join("events.jsonl");
        File::create(&uncompressed_events)?;
        create_target(
            &target_name,
            &request.config,
            &skill_root,
            &canary_root,
            relay_socket_transport,
            egress_enabled.then_some(target_network.as_str()),
            egress_ca_path.as_deref(),
        )?;
        let target_id = container_id(&target_name)?;
        fs::write(run_dir.join("target-container-id"), &target_id)?;
        let tracee_policy = run_dir.join("tracee-policy.yaml");
        fs::write(&tracee_policy, tracee_policy_yaml(&target_id))?;
        start_target_waiting(&target_name)?;
        let collector_started = match start_tracee(
            &tracee_name,
            &request.config.tracee_image,
            &run_dir,
            &tracee_policy,
            request.config.max_agent_output_bytes,
        )
        .and_then(|()| wait_for_tracee_capture(&tracee_name, &target_name, &uncompressed_events))
        {
            Ok(()) => true,
            Err(error) if request.allow_untraced => {
                stop_container(&tracee_name);
                writeln!(
                    File::create(run_dir.join("collector-error.txt"))?,
                    "{error:#}"
                )?;
                false
            }
            Err(error) => return Err(error.context("start required eBPF collector")),
        };
        let stdout_path = run_dir.join("agent.stdout");
        let stderr_path = run_dir.join("agent.stderr");
        let target_outcome = run_target(
            &target_name,
            TargetRunOptions {
                timeout: Duration::from_secs(request.config.timeout_seconds),
                stdout_path: &stdout_path,
                stderr_path: &stderr_path,
                max_output_bytes: request.config.max_agent_output_bytes,
                telemetry_path: &uncompressed_events,
                max_telemetry_bytes: request.config.max_telemetry_bytes,
                max_closure_lifts: request.config.max_closure_lifts,
                collector_name: collector_started.then_some(tracee_name.as_str()),
                start_gate: TARGET_START_GATE,
            },
        )?;
        let collector_log = run_dir.join("collector.log");
        let collector_stats = finalize_collector(
            &tracee_name,
            collector_started,
            &collector_log,
            request.config.max_agent_output_bytes,
        )?;
        fs::write(
            run_dir.join("collector-stats.json"),
            serde_json::to_vec_pretty(&collector_stats)?,
        )?;
        if collector_log.exists() {
            compress_and_remove(&collector_log)?;
        }

        // `/work/skill` is a size/inode-bounded tmpfs and disappears when the
        // target exits. The trusted PID 1 harness therefore returns its bounded
        // session lift count in a reserved exit-code range. Never infer a count
        // from an abnormal, timed-out, or supervisor-terminated target.
        let closure_lift_count = target_outcome.closure_lift_count.unwrap_or(0);
        let harness_completed = target_outcome.closure_lift_count.is_some();
        let expected_adapter_exec = expected_adapter_executable(&request.config.agent_adapter);
        let filtered_trace = filter_trace_to_container(
            &uncompressed_events,
            &target_id,
            request.config.max_telemetry_bytes,
            expected_adapter_exec,
        )?;
        let event_count = filtered_trace.event_count;
        let telemetry_truncated = filtered_trace.telemetry_truncated;
        let harness_exec_seen = filtered_trace.harness_exec_seen;
        let adapter_exec_seen = filtered_trace.adapter_exec_seen;
        let compressed_path = run_dir.join("events.jsonl.zst");
        compress_zstd(&uncompressed_events, &compressed_path)?;
        fs::remove_file(&uncompressed_events)?;
        let telemetry_sha256 = file_sha256(&compressed_path)?;
        let telemetry_size_bytes = fs::metadata(&compressed_path)?.len();
        if relay_enabled && !container_is_running(&relay_name)? {
            bail!("credential relay exited before evidence finalization");
        }
        if egress_enabled && !container_is_running(&egress_proxy_name)? {
            bail!("egress interception proxy exited before evidence finalization");
        }
        if relay_enabled {
            stop_container(&relay_name);
        }
        if egress_enabled {
            stop_container(&egress_proxy_name);
        }
        let network_evidence = finalize_network_transcript(
            &run_dir,
            &relative_run_dir,
            relay_enabled,
            egress_enabled,
        )?;
        compress_and_remove(&stdout_path)?;
        compress_and_remove(&stderr_path)?;

        let finished_at = Utc::now();
        // A live Tracee process is not sufficient evidence that its policy matched
        // the target.  Every target executes the harness, so an empty stream means
        // the capture is unusable and must never produce a benign verdict.
        let telemetry_usable = capture_is_usable(
            collector_stats.healthy,
            telemetry_truncated,
            event_count,
            harness_exec_seen,
            expected_adapter_exec.is_none() || adapter_exec_seen,
            harness_completed && filtered_trace.invocation_boundary_seen,
        ) && !network_evidence.truncated;
        let status_name = if telemetry_usable {
            "captured"
        } else {
            "captured_untraced"
        };
        let telemetry_path = relative_run_dir
            .join("events.jsonl.zst")
            .to_string_lossy()
            .into_owned();
        let record = RunRecord {
            schema_version: 1,
            run_id: run_id.clone(),
            run_key: key.clone(),
            skill_id: request.skill.skill_id.clone(),
            status: status_name.into(),
            scenario: "default".into(),
            seed: 0,
            queued_at: started_at.to_rfc3339(),
            started_at: Some(started_at.to_rfc3339()),
            finished_at: Some(finished_at.to_rfc3339()),
            harness_version: format!("{}@{}", HARNESS_VERSION, request.config.supervisor_digest),
            policy_sha256: policy_sha256.clone(),
            agent_adapter: request.config.agent_adapter.clone(),
            agent_model: request.config.agent_model.clone(),
            target_image_digest: request.config.target_image_digest.clone(),
            skillject_commit: request.config.skillject_commit.clone(),
            telemetry_path: Some(telemetry_path.clone()),
            event_count: Some(event_count),
            exit_code: target_outcome.status.code(),
            termination_reason: Some(target_outcome.termination_reason.clone()),
            closure_lift_count: target_outcome.closure_lift_count,
            // One of the paper's three propagation planes is portable here: the
            // process/inode graph. Value-level and LLM-context adapters are absent.
            taint_coverage: Some(if status_name == "captured" {
                1.0 / 3.0
            } else {
                0.0
            }),
        };
        let manifest = RunManifest {
            schema_version: SCHEMA_VERSION,
            run_id: run_id.clone(),
            run_key: key.clone(),
            skill_id: request.skill.skill_id.clone(),
            status: status_name.into(),
            started_at,
            finished_at,
            collector: if collector_started {
                "tracee-ebpf"
            } else {
                "none"
            }
            .into(),
            collector_image: request.config.tracee_image.clone(),
            sandbox_image: request.config.sandbox_image.clone(),
            agent_relay_image: relay_enabled.then(|| request.config.agent_relay_image.clone()),
            agent_relay_image_digest: relay_enabled
                .then(|| request.config.agent_relay_image_digest.clone()),
            agent_network_internal,
            egress_proxy_image: egress_enabled.then(|| EGRESS_PROXY_IMAGE.to_string()),
            egress_proxy_image_digest: egress_enabled
                .then(|| request.config.egress_proxy_image_digest.clone()),
            egress_proxy_internal,
            target_image_digest: request.config.target_image_digest.clone(),
            supervisor_digest: request.config.supervisor_digest.clone(),
            config_digest: config_digest.clone(),
            effective_config: request.config.clone(),
            network_mode: request.config.network_mode.clone(),
            exit_code: target_outcome.status.code(),
            termination_reason: target_outcome.termination_reason,
            closure_lift_count,
            closure_lift_count_trusted: harness_completed,
            harness_invocation: configured_harness_invocation(&request.config),
            agent_invocation: agent_cli_invocation(
                &request.config.agent_adapter,
                &request.config.agent_model,
                request.config.agent_max_turns,
                &request.config.agent_max_budget_usd,
            )?,
            raw_event_count: event_count,
            pre_detonation_event_count: filtered_trace.pre_detonation_event_count,
            invocation_boundary_seen: filtered_trace.invocation_boundary_seen,
            telemetry_path: Some(telemetry_path),
            telemetry_sha256: Some(telemetry_sha256),
            telemetry_size_bytes: Some(telemetry_size_bytes),
            network_capture_mode: network_capture_mode(relay_enabled, egress_enabled).to_string(),
            network_transcript_path: network_evidence.path,
            network_transcript_sha256: network_evidence.sha256,
            network_transcript_size_bytes: network_evidence.size_bytes,
            network_transcript_truncated: network_evidence.truncated,
            collector_healthy: collector_stats.healthy,
            collector_harness_exec_seen: harness_exec_seen,
            collector_adapter_exec_seen: adapter_exec_seen,
            collector_lost_events: collector_stats.lost_events,
            collector_log_truncated: collector_stats.log_truncated,
            telemetry_truncated,
            agent_stdout_truncated: target_outcome.stdout_truncated,
            agent_stderr_truncated: target_outcome.stderr_truncated,
        };
        fs::write(
            run_dir.join("run.json"),
            serde_json::to_vec_pretty(&manifest)?,
        )?;
        Ok(DetonationResult {
            record,
            manifest,
            failure: None,
        })
    })();

    match attempt {
        Ok(result) => Ok(result),
        Err(error) => failed_attempt_result(
            &request,
            &policy_sha256,
            &config_digest,
            &key,
            &run_id,
            started_at,
            &relative_run_dir,
            &run_dir,
            agent_network_internal,
            egress_proxy_internal,
            &error,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn failed_attempt_result(
    request: &DetonationRequest,
    policy_sha256: &str,
    config_digest: &str,
    key: &str,
    run_id: &str,
    started_at: DateTime<Utc>,
    relative_run_dir: &Path,
    run_dir: &Path,
    agent_network_internal: bool,
    egress_proxy_internal: bool,
    error: &anyhow::Error,
) -> Result<DetonationResult> {
    let finished_at = Utc::now();
    let failure = format!("{error:#}");
    fs::write(
        run_dir.join("failure.txt"),
        truncate_text(&failure, 64 * 1024),
    )?;

    let final_events = run_dir.join("events.jsonl.zst");
    let partial_events = run_dir.join("events.partial.jsonl.zst");
    let raw_events = run_dir.join("events.jsonl");
    let mut partial_event_count = None;
    let mut partial_harness_exec_seen = false;
    let mut partial_adapter_exec_seen = false;
    let mut partial_pre_detonation_event_count = 0;
    let mut partial_invocation_boundary_seen = false;
    let mut partial_truncated = true;
    let telemetry_relative = if final_events.is_file() {
        Some(relative_run_dir.join("events.jsonl.zst"))
    } else if raw_events.is_file() {
        let target_id = fs::read_to_string(run_dir.join("target-container-id"));
        match target_id.and_then(|target_id| {
            filter_trace_to_container(
                &raw_events,
                target_id.trim(),
                request.config.max_telemetry_bytes,
                expected_adapter_executable(&request.config.agent_adapter),
            )
            .map_err(std::io::Error::other)
        }) {
            Ok(stats) => {
                partial_event_count = Some(stats.event_count);
                partial_harness_exec_seen = stats.harness_exec_seen;
                partial_adapter_exec_seen = stats.adapter_exec_seen;
                partial_pre_detonation_event_count = stats.pre_detonation_event_count;
                partial_invocation_boundary_seen = stats.invocation_boundary_seen;
                partial_truncated = stats.telemetry_truncated;
                compress_zstd(&raw_events, &partial_events)?;
                fs::remove_file(&raw_events)?;
                Some(relative_run_dir.join("events.partial.jsonl.zst"))
            }
            Err(filter_error) => {
                fs::remove_file(&raw_events)?;
                fs::write(
                    run_dir.join("telemetry-rejected.txt"),
                    format!("partial telemetry was not target-attributable: {filter_error}\n"),
                )?;
                None
            }
        }
    } else {
        None
    };
    let (telemetry_sha256, telemetry_size_bytes) = match telemetry_relative.as_ref() {
        Some(relative) => {
            let path = request.repo_root.join(relative);
            (Some(file_sha256(&path)?), Some(fs::metadata(path)?.len()))
        }
        None => (None, None),
    };
    let telemetry_path = telemetry_relative
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned());
    let relay_configured = request.config.agent_adapter != DETERMINISTIC_ADAPTER;
    let egress_configured = request.config.network_mode == INTERCEPTED_NETWORK_MODE;
    let mut network_evidence = finalize_network_transcript(
        run_dir,
        relative_run_dir,
        agent_network_internal,
        egress_proxy_internal,
    )?;
    let network_unavailable = (relay_configured && !agent_network_internal)
        || (egress_configured && !egress_proxy_internal);
    if network_unavailable {
        network_evidence.truncated = true;
    }
    let network_capture_mode = if network_unavailable {
        "network-interception-unavailable"
    } else {
        network_capture_mode(agent_network_internal, egress_proxy_internal)
    };
    for output in [run_dir.join("agent.stdout"), run_dir.join("agent.stderr")] {
        compress_and_remove(&output)?;
    }

    let manifest = RunManifest {
        schema_version: SCHEMA_VERSION,
        run_id: run_id.to_string(),
        run_key: key.to_string(),
        skill_id: request.skill.skill_id.clone(),
        status: "failed".into(),
        started_at,
        finished_at,
        collector: "failed-attempt".into(),
        collector_image: request.config.tracee_image.clone(),
        sandbox_image: request.config.sandbox_image.clone(),
        agent_relay_image: (request.config.agent_adapter != DETERMINISTIC_ADAPTER)
            .then(|| request.config.agent_relay_image.clone()),
        agent_relay_image_digest: (request.config.agent_adapter != DETERMINISTIC_ADAPTER)
            .then(|| request.config.agent_relay_image_digest.clone()),
        agent_network_internal,
        egress_proxy_image: egress_configured.then(|| EGRESS_PROXY_IMAGE.to_string()),
        egress_proxy_image_digest: egress_configured
            .then(|| request.config.egress_proxy_image_digest.clone()),
        egress_proxy_internal,
        target_image_digest: request.config.target_image_digest.clone(),
        supervisor_digest: request.config.supervisor_digest.clone(),
        config_digest: config_digest.to_string(),
        effective_config: request.config.clone(),
        network_mode: request.config.network_mode.clone(),
        exit_code: None,
        termination_reason: "detonation_error".into(),
        closure_lift_count: 0,
        closure_lift_count_trusted: false,
        harness_invocation: configured_harness_invocation(&request.config),
        agent_invocation: agent_cli_invocation(
            &request.config.agent_adapter,
            &request.config.agent_model,
            request.config.agent_max_turns,
            &request.config.agent_max_budget_usd,
        )?,
        raw_event_count: partial_event_count.unwrap_or(0),
        pre_detonation_event_count: partial_pre_detonation_event_count,
        invocation_boundary_seen: partial_invocation_boundary_seen,
        telemetry_path: telemetry_path.clone(),
        telemetry_sha256,
        telemetry_size_bytes,
        network_capture_mode: network_capture_mode.to_string(),
        network_transcript_path: network_evidence.path,
        network_transcript_sha256: network_evidence.sha256,
        network_transcript_size_bytes: network_evidence.size_bytes,
        network_transcript_truncated: network_evidence.truncated,
        collector_healthy: false,
        collector_harness_exec_seen: partial_harness_exec_seen,
        collector_adapter_exec_seen: partial_adapter_exec_seen,
        collector_lost_events: 0,
        collector_log_truncated: false,
        telemetry_truncated: partial_truncated,
        agent_stdout_truncated: false,
        agent_stderr_truncated: false,
    };
    fs::write(
        run_dir.join("run.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    let record = RunRecord {
        schema_version: 1,
        run_id: run_id.to_string(),
        run_key: key.to_string(),
        skill_id: request.skill.skill_id.clone(),
        status: "failed".into(),
        scenario: "default".into(),
        seed: 0,
        queued_at: started_at.to_rfc3339(),
        started_at: Some(started_at.to_rfc3339()),
        finished_at: Some(finished_at.to_rfc3339()),
        harness_version: format!("{}@{}", HARNESS_VERSION, request.config.supervisor_digest),
        policy_sha256: policy_sha256.to_string(),
        agent_adapter: request.config.agent_adapter.clone(),
        agent_model: request.config.agent_model.clone(),
        target_image_digest: request.config.target_image_digest.clone(),
        skillject_commit: request.config.skillject_commit.clone(),
        telemetry_path,
        event_count: partial_event_count,
        exit_code: None,
        termination_reason: Some("detonation_error".into()),
        closure_lift_count: None,
        taint_coverage: Some(0.0),
    };
    Ok(DetonationResult {
        record,
        manifest,
        failure: Some(failure),
    })
}

fn truncate_text(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn checked_repo_path(repo_root: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
    {
        bail!("registry contains unsafe repository-relative path: {relative}");
    }
    let canonical_root = fs::canonicalize(repo_root)?;
    let components = path.components().collect::<Vec<_>>();
    let mut current = canonical_root.clone();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(component) = component else {
            bail!("registry contains unsafe repository-relative path: {relative}");
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("inspect corpus path {}", current.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("corpus path traverses a symlink: {}", current.display());
        }
        if index + 1 == components.len() {
            if !metadata.is_file() {
                bail!("corpus bundle is not a regular file: {}", current.display());
            }
        } else if !metadata.is_dir() {
            bail!(
                "corpus path component is not a directory: {}",
                current.display()
            );
        }
    }
    let resolved = fs::canonicalize(&current)?;
    if !resolved.starts_with(&canonical_root) {
        bail!("corpus bundle escaped repository root");
    }
    Ok(resolved)
}

pub fn extract_bundle(
    archive_path: &Path,
    output: &Path,
    config: &DetonatorConfig,
) -> Result<PathBuf> {
    if config.max_skill_entries == 0
        || config.max_skill_bytes == 0
        || config.max_single_file_bytes == 0
        || config.max_skill_depth == 0
        || config.max_single_file_bytes > config.max_skill_bytes
    {
        bail!("invalid detonation extraction limits");
    }
    let input = File::open(archive_path)
        .with_context(|| format!("open bundle {}", archive_path.display()))?;
    let decoder = zstd::Decoder::new(input)?;
    let mut archive = tar::Archive::new(decoder);
    let mut seen = BTreeSet::new();
    let mut symlinks = BTreeSet::new();
    let mut entry_count = 0_u64;
    let mut expanded_bytes = 0_u64;
    let mut saw_manifest = false;
    let mut saw_skill_root = false;
    for item in archive.entries()? {
        let mut entry = item?;
        let path = entry.path()?.into_owned();
        if path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            bail!("unsafe archive entry: {}", path.display());
        }
        if !seen.insert(path.clone()) {
            bail!("duplicate archive entry: {}", path.display());
        }
        entry_count = entry_count
            .checked_add(1)
            .context("archive entry count overflow")?;
        if entry_count > config.max_skill_entries.saturating_add(2) {
            bail!("bundle exceeds configured entry limit");
        }
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir() || kind.is_symlink()) {
            bail!("unsupported archive entry type at {}", path.display());
        }
        if path == Path::new("manifest.json") {
            if !kind.is_file() {
                bail!("bundle manifest must be a regular file");
            }
            saw_manifest = true;
        } else {
            if !path.starts_with("skill") {
                bail!("unexpected archive member: {}", path.display());
            }
            if path == Path::new("skill") {
                if !kind.is_dir() {
                    bail!("bundle skill root must be a directory");
                }
                saw_skill_root = true;
            }
            let depth = path.components().count().saturating_sub(1);
            if depth > config.max_skill_depth {
                bail!("bundle exceeds configured path depth");
            }
        }
        for ancestor in path.ancestors().skip(1) {
            if symlinks.contains(ancestor) {
                bail!(
                    "archive member descends through a symlink: {}",
                    path.display()
                );
            }
        }
        let header_size = entry.size();
        if kind.is_file() && header_size > config.max_single_file_bytes {
            bail!(
                "archive member exceeds configured per-file limit: {}",
                path.display()
            );
        }
        if path != Path::new("manifest.json") {
            expanded_bytes = expanded_bytes
                .checked_add(header_size)
                .context("expanded archive size overflow")?;
        }
        if kind.is_symlink() {
            let target = entry
                .link_name()?
                .ok_or_else(|| anyhow!("symlink missing target"))?;
            if !safe_archive_symlink(&path, &target) {
                bail!("unsafe symlink target at {}", path.display());
            }
            expanded_bytes = expanded_bytes
                .checked_add(target.as_os_str().len() as u64)
                .context("expanded archive size overflow")?;
            if seen
                .iter()
                .any(|seen_path| seen_path != &path && seen_path.starts_with(&path))
            {
                bail!(
                    "symlink replaces an existing archive directory: {}",
                    path.display()
                );
            }
            symlinks.insert(path.clone());
        }
        if expanded_bytes > config.max_skill_bytes {
            bail!("bundle exceeds configured expanded byte limit");
        }
        if !entry.unpack_in(output)? {
            bail!("archive library rejected member: {}", path.display());
        }
    }
    if !saw_manifest || !saw_skill_root {
        bail!("bundle is missing manifest.json or skill root");
    }
    let skill_root = output.join("skill");
    let entrypoint = skill_root.join("SKILL.md");
    let metadata =
        fs::symlink_metadata(&entrypoint).context("bundle is missing regular skill/SKILL.md")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("bundle skill/SKILL.md is not a regular file");
    }
    Ok(skill_root)
}

fn verify_extracted_skill(
    extraction_root: &Path,
    skill_root: &Path,
    record: &SkillRecord,
) -> Result<()> {
    let manifest_path = extraction_root.join("manifest.json");
    let manifest: skills_core::Manifest =
        serde_json::from_slice(&fs::read(&manifest_path)?).context("parse bundle manifest")?;
    let canonical = skills_core::canonicalize_skill_tree(skill_root)
        .context("recompute extracted skill identity")?;
    let expected_manifest = skills_core::Manifest::from(&canonical);
    if manifest != expected_manifest {
        bail!("bundle manifest does not match extracted skill tree");
    }
    if canonical.skill_id != record.skill_id
        || canonical.sha256 != record.sha256
        || canonical.blake3 != record.blake3
        || canonical.canonicalization_version != record.canonicalization_version
        || canonical.size_bytes != record.size_bytes
        || canonical.file_count != record.file_count
    {
        bail!(
            "bundle identity does not match data/skills.csv record {}",
            record.skill_id
        );
    }
    Ok(())
}

fn safe_archive_symlink(link_path: &Path, target: &Path) -> bool {
    if target.as_os_str().is_empty() || target.is_absolute() {
        return false;
    }
    let mut normalized = Vec::new();
    for component in link_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .components()
        .chain(target.components())
    {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => {
                if value == ".git" {
                    return false;
                }
                normalized.push(value);
            }
            Component::ParentDir => {
                if normalized.pop().is_none() {
                    return false;
                }
            }
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

fn seed_canaries(home: &Path, run_id: &str) -> Result<()> {
    let files = [
        (".ssh/id_ed25519", "SSH_PRIVATE_KEY"),
        (".aws/credentials", "AWS_CREDENTIALS"),
        (
            ".config/gcloud/application_default_credentials.json",
            "GCP_CREDENTIALS",
        ),
        (".env", "DOTENV"),
    ];
    for (relative, role) in files {
        let path = home.join(relative);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(&path, format!("#data_{}_{}\n", safe_token(run_id), role))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o444))?;
        }
    }
    Ok(())
}

fn safe_token(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

fn docker_name(prefix: &str, run_id: &str) -> String {
    format!("{}-{}", prefix, safe_token(run_id))
}

fn tracee_policy_yaml(target_id: &str) -> String {
    let events = [
        "sched_process_exec",
        "sched_process_fork",
        "sched_process_exit",
        "security_file_open",
        "openat",
        "read",
        "write",
        "pwrite64",
        "writev",
        "pipe",
        "pipe2",
        "dup",
        "dup2",
        "dup3",
        "close",
        "renameat",
        "renameat2",
        "unlinkat",
        "chmod",
        "fchmod",
        "fchmodat",
        "chown",
        "fchown",
        "setuid",
        "setgid",
        "setreuid",
        "setregid",
        "setresuid",
        "setresgid",
        "capset",
        "ptrace",
        "process_vm_writev",
        "process_vm_readv",
        "mmap",
        "mprotect",
        "memfd_create",
        "socket",
        "bind",
        "listen",
        "accept",
        "accept4",
        "connect",
        "security_socket_connect",
        "sendto",
        "sendmsg",
        "recvfrom",
        "recvmsg",
        "net_packet_dns",
        "dropped_executable",
        "file_modification",
    ];
    let mut text = format!(
        "apiVersion: tracee.aquasec.com/v1beta1\nkind: Policy\nmetadata:\n  name: skillsissue-detonation\n  annotations:\n    description: Per-container skill detonation evidence\nspec:\n  scope:\n    - container={}\n  rules:\n",
        target_id
    );
    for event in events {
        text.push_str(&format!("    - event: {event}\n"));
    }
    text
}

fn start_tracee(
    tracee_name: &str,
    image: &str,
    run_dir: &Path,
    policy: &Path,
    max_log_bytes: u64,
) -> Result<()> {
    let mut command = Command::new("docker");
    command.args([
        "run",
        "--detach",
        "--name",
        tracee_name,
        "--network",
        "none",
        "--pid=host",
        "--cgroupns=host",
        "--privileged",
        "--read-only",
    ]);
    command.args(bounded_log_options(max_log_bytes));
    command.args([
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=64m,nr_inodes=1024",
        "-v",
        "/etc/os-release:/etc/os-release-host:ro",
        "-v",
        "/var/run:/var/run:ro",
        "-v",
        &format!("{}:/output", run_dir.display()),
        "-v",
        &format!("{}:/policy.yaml:ro", policy.display()),
        image,
        "--policy",
        "/policy.yaml",
        "--output",
        "json:/output/events.jsonl",
        "--output",
        "option:parse-arguments",
        "--output",
        "option:sort-events",
    ]);
    let status = command.status().context("launch Tracee container")?;
    if !status.success() {
        bail!("Tracee container exited during launch");
    }
    for attempt in 0..20 {
        thread::sleep(Duration::from_millis(100));
        let output = Command::new("docker")
            .args(["inspect", "--format", "{{.State.Running}}", tracee_name])
            .output()?;
        if attempt >= 9
            && output.status.success()
            && String::from_utf8_lossy(&output.stdout).trim() == "true"
        {
            return Ok(());
        }
    }
    let logs = Command::new("docker")
        .args(["logs", tracee_name])
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stderr).into_owned())
        .unwrap_or_default();
    bail!("Tracee collector did not stay running: {logs}");
}

fn wait_for_tracee_capture(tracee_name: &str, target_name: &str, events: &Path) -> Result<()> {
    // A running Tracee container is not yet proof that its eBPF programs and
    // container-scoped policy are attached. Cold hosted VMs can take several
    // seconds after container startup to finish that work. Probe from the
    // still-gated target until Tracee records one attributable exec event,
    // then release the untrusted workload.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if !container_is_running(tracee_name)? {
            let logs = Command::new("docker")
                .args(["logs", tracee_name])
                .output()?;
            bail!(
                "Tracee collector exited before capture readiness: {}",
                String::from_utf8_lossy(&logs.stderr).trim()
            );
        }
        if !container_is_running(target_name)? {
            bail!("gated target exited during Tracee capture readiness probe");
        }

        let probe = Command::new("docker")
            .args(["exec", target_name, "/usr/bin/true"])
            .output()
            .context("execute Tracee capture readiness probe")?;
        if !probe.status.success() {
            bail!(
                "Tracee capture readiness probe failed: {}",
                String::from_utf8_lossy(&probe.stderr).trim()
            );
        }

        thread::sleep(Duration::from_millis(250));
        if fs::metadata(events).is_ok_and(|metadata| metadata.len() > 0) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let logs = Command::new("docker")
                .args(["logs", tracee_name])
                .output()?;
            let mut combined = logs.stdout;
            combined.extend_from_slice(&logs.stderr);
            bail!(
                "Tracee did not emit a target-scoped readiness event within 30 seconds: {}",
                String::from_utf8_lossy(&combined).trim()
            );
        }
    }
}

fn container_id(name: &str) -> Result<String> {
    let output = Command::new("docker")
        .args(["inspect", "--format", "{{.Id}}", name])
        .output()
        .context("inspect target container ID")?;
    if !output.status.success() {
        bail!(
            "inspect target container ID: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let id = String::from_utf8(output.stdout)?.trim().to_string();
    if id.len() < 12 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("Docker returned an invalid target container ID");
    }
    Ok(id)
}

fn make_target_owned(root: &Path) -> Result<()> {
    if std::env::consts::OS != "linux" {
        return Ok(());
    }
    let output = Command::new("chown")
        .args(["-R", "65532:65532"])
        .arg(root)
        .output()
        .context("make extracted skill writable by target uid")?;
    if !output.status.success() {
        bail!(
            "chown extracted skill: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn start_agent_relay(
    relay_name: &str,
    egress_network: &str,
    socket_volume: &str,
    config: &DetonatorConfig,
    work_root: &Path,
    transcript_path: &Path,
) -> Result<()> {
    let credential = provider_secret(&config.agent_adapter)?;
    if credential.is_empty()
        || credential.len() > 16 * 1024
        || credential.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        bail!("trusted provider credential is empty, oversized, or contains whitespace");
    }
    let secret_path = work_root.join("provider-api-key");
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut secret = options
        .open(&secret_path)
        .context("create per-run provider credential file")?;
    secret.write_all(credential.as_bytes())?;
    secret.sync_all()?;
    drop(secret);
    #[cfg(unix)]
    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o400))?;
    make_target_owned(&secret_path)?;
    File::create(transcript_path).context("create per-run network transcript")?;
    make_target_owned(transcript_path)?;

    create_docker_volume(socket_volume)?;
    if docker_network_is_internal(egress_network)? {
        bail!("Docker created the relay egress network as internal");
    }

    let provider = match config.agent_adapter.as_str() {
        CODEX_ADAPTER => "openai",
        CLAUDE_ADAPTER => "anthropic",
        _ => bail!("agent relay requested for a non-CLI adapter"),
    };
    let secret_mount = format!(
        "type=bind,src={},dst=/run/secrets/provider-api-key,readonly",
        secret_path.display()
    );
    // Docker seeds this fresh volume from the image's empty UID-65532-owned
    // directory, so the non-root relay can create its socket without a helper.
    let socket_mount = relay_socket_volume_mount(socket_volume, false);
    let transcript_mount = format!(
        "type=bind,src={},dst={}",
        transcript_path.display(),
        RELAY_TRANSCRIPT_CONTAINER_PATH
    );
    let mut relay_args = vec![
        "create".to_string(),
        "--name".into(),
        relay_name.into(),
        "--network".into(),
        egress_network.into(),
        "--read-only".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges=true".into(),
        "--pids-limit".into(),
        "64".into(),
        "--memory".into(),
        "256m".into(),
        "--cpus".into(),
        "0.5".into(),
        "--tmpfs".into(),
        "/tmp:rw,nosuid,nodev,noexec,size=16m,nr_inodes=256".into(),
        "--mount".into(),
        secret_mount,
        "--mount".into(),
        socket_mount,
        "--mount".into(),
        transcript_mount,
        "--label".into(),
        "ai.skillsissue.role=credential-relay".into(),
        config.agent_relay_image.clone(),
    ];
    relay_args.extend(relay_process_args(config, provider));
    let output = Command::new("docker")
        .args(relay_args)
        .output()
        .context("create credential relay container")?;
    if !output.status.success() {
        bail!(
            "create credential relay container: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    command_ok(
        Command::new("docker").args(["start", relay_name]),
        "start credential relay",
    )?;
    wait_for_relay_health(relay_name)?;
    Ok(())
}

fn start_egress_proxy(
    proxy_name: &str,
    egress_network: &str,
    target_network: &str,
    work_root: &Path,
    transcript_path: &Path,
) -> Result<PathBuf> {
    if docker_network_is_internal(egress_network)? {
        bail!("Docker created the proxy egress network as internal");
    }
    if !docker_network_is_internal(target_network)? {
        bail!("Docker created the target network without internal isolation");
    }

    let config_dir = work_root.join("mitmproxy");
    fs::create_dir(&config_dir).context("create per-run MITM configuration directory")?;
    make_target_owned(&config_dir)?;
    File::create(transcript_path).context("create per-run egress transcript")?;
    make_target_owned(transcript_path)?;

    let config_mount = format!("type=bind,src={},dst=/run/mitmproxy", config_dir.display());
    let transcript_mount = format!(
        "type=bind,src={},dst={EGRESS_PROXY_EVIDENCE_CONTAINER_PATH}",
        transcript_path.display()
    );
    let proxy_args = vec![
        "create".to_string(),
        "--name".into(),
        proxy_name.into(),
        "--network".into(),
        egress_network.into(),
        "--read-only".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges=true".into(),
        "--pids-limit".into(),
        "64".into(),
        "--memory".into(),
        "384m".into(),
        "--cpus".into(),
        "0.5".into(),
        "--user".into(),
        "65532:65532".into(),
        "--tmpfs".into(),
        "/tmp:rw,nosuid,nodev,noexec,size=32m,nr_inodes=512".into(),
        "--mount".into(),
        config_mount,
        "--mount".into(),
        transcript_mount,
        "--env".into(),
        format!("SKILLSISSUE_EGRESS_EVIDENCE_FILE={EGRESS_PROXY_EVIDENCE_CONTAINER_PATH}"),
        "--env".into(),
        format!("SKILLSISSUE_EGRESS_MAX_REQUESTS={EGRESS_PROXY_MAX_REQUESTS}"),
        "--env".into(),
        format!("SKILLSISSUE_EGRESS_MAX_RESPONSE_BYTES={EGRESS_PROXY_MAX_RESPONSE_BYTES}"),
        "--env".into(),
        format!(
            "SKILLSISSUE_EGRESS_MAX_TOTAL_RESPONSE_BYTES={EGRESS_PROXY_MAX_TOTAL_RESPONSE_BYTES}"
        ),
        "--label".into(),
        "ai.skillsissue.role=egress-interception-proxy".into(),
        EGRESS_PROXY_IMAGE.into(),
    ];
    let output = Command::new("docker")
        .args(proxy_args)
        .output()
        .context("create egress interception proxy container")?;
    if !output.status.success() {
        bail!(
            "create egress interception proxy container: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    command_ok(
        Command::new("docker").args([
            "network",
            "connect",
            "--alias",
            EGRESS_PROXY_ALIAS,
            target_network,
            proxy_name,
        ]),
        "connect interception proxy to internal target network",
    )?;
    command_ok(
        Command::new("docker").args(["start", proxy_name]),
        "start egress interception proxy",
    )?;

    let ca_path = config_dir.join(EGRESS_PROXY_CA_HOST_NAME);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if !container_is_running(proxy_name)? {
            let logs = Command::new("docker").args(["logs", proxy_name]).output()?;
            let mut combined = logs.stdout;
            combined.extend_from_slice(&logs.stderr);
            bail!(
                "egress interception proxy exited during startup: {}",
                String::from_utf8_lossy(&combined).trim()
            );
        }
        if let Ok(metadata) = fs::symlink_metadata(&ca_path)
            && metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() > 0
        {
            return Ok(ca_path);
        }
        if Instant::now() >= deadline {
            bail!("egress interception proxy did not generate its per-run CA within 30 seconds");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn relay_process_args(config: &DetonatorConfig, provider: &str) -> Vec<String> {
    let max_requests = u64::from(config.agent_max_turns)
        .saturating_mul(2)
        .clamp(2, 64);
    vec![
        "--unix-socket".into(),
        RELAY_SOCKET_CONTAINER_PATH.into(),
        "--provider".into(),
        provider.into(),
        "--credential-file".into(),
        "/run/secrets/provider-api-key".into(),
        "--expected-model".into(),
        config.agent_model.clone(),
        "--max-output-tokens".into(),
        RELAY_MAX_OUTPUT_TOKENS.to_string(),
        "--max-request-bytes".into(),
        RELAY_REQUEST_BYTES.to_string(),
        "--max-total-request-bytes".into(),
        RELAY_TOTAL_REQUEST_BYTES.to_string(),
        "--max-response-bytes".into(),
        (16 * 1024 * 1024_u64).to_string(),
        "--max-requests".into(),
        max_requests.to_string(),
        "--max-concurrency".into(),
        "1".into(),
        "--timeout-seconds".into(),
        config.agent_timeout_seconds.to_string(),
        "--transcript-file".into(),
        RELAY_TRANSCRIPT_CONTAINER_PATH.into(),
        "--max-transcript-bytes".into(),
        RELAY_MAX_TRANSCRIPT_BYTES.to_string(),
        "--max-transcript-body-bytes".into(),
        RELAY_MAX_TRANSCRIPT_BODY_BYTES.to_string(),
    ]
}

fn provider_secret(adapter: &str) -> Result<Zeroizing<String>> {
    let provider_env = match adapter {
        CODEX_ADAPTER => "OPENAI_API_KEY",
        CLAUDE_ADAPTER => "ANTHROPIC_API_KEY",
        _ => PROVIDER_SECRET_ENV,
    };
    for name in [PROVIDER_SECRET_ENV, provider_env] {
        if let Ok(value) = std::env::var(name)
            && !value.is_empty()
        {
            return Ok(Zeroizing::new(value));
        }
    }
    bail!(
        "CLI adapter requires {PROVIDER_SECRET_ENV} (or its provider-specific equivalent) in the trusted supervisor only"
    )
}

fn create_docker_network(name: &str, internal: bool) -> Result<()> {
    let mut command = Command::new("docker");
    command.args([
        "network",
        "create",
        "--driver",
        "bridge",
        "--label",
        "ai.skillsissue.role=detonation-network",
    ]);
    if internal {
        command.arg("--internal");
    }
    command.arg(name);
    command_ok(&mut command, "create detonation network")
}

fn create_docker_volume(name: &str) -> Result<()> {
    let existing = Command::new("docker")
        .args(["volume", "inspect", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("inspect per-run relay socket volume")?;
    if existing.success() {
        bail!("per-run relay socket volume already exists");
    }
    command_ok(
        Command::new("docker").args([
            "volume",
            "create",
            "--label",
            "ai.skillsissue.role=detonation-socket",
            name,
        ]),
        "create per-run relay socket volume",
    )
}

fn relay_socket_volume_mount(name: &str, readonly: bool) -> String {
    let access = if readonly {
        ",readonly,volume-nocopy"
    } else {
        ""
    };
    format!("type=volume,src={name},dst={RELAY_SOCKET_CONTAINER_DIR}{access}")
}

fn docker_network_is_internal(name: &str) -> Result<bool> {
    let output = Command::new("docker")
        .args(["network", "inspect", "--format", "{{.Internal}}", name])
        .output()
        .context("inspect detonation network")?;
    if !output.status.success() {
        bail!(
            "inspect detonation network: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    match String::from_utf8_lossy(&output.stdout).trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => bail!("Docker returned an invalid network Internal value"),
    }
}

fn wait_for_relay_health(name: &str) -> Result<()> {
    for _ in 0..100 {
        let output = Command::new("docker")
            .args([
                "exec",
                name,
                "skill-relay",
                "check",
                "--unix-socket",
                RELAY_SOCKET_CONTAINER_PATH,
                "--timeout-seconds",
                "1",
            ])
            .output()?;
        if output.status.success() {
            return Ok(());
        }
        if !container_is_running(name)? {
            let logs = Command::new("docker").args(["logs", name]).output()?;
            bail!(
                "credential relay exited during startup: {}",
                String::from_utf8_lossy(&logs.stderr).trim()
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("credential relay did not become healthy")
}

fn create_target(
    name: &str,
    config: &DetonatorConfig,
    skill: &Path,
    home: &Path,
    relay_socket_volume: Option<&str>,
    egress_network: Option<&str>,
    egress_ca_path: Option<&Path>,
) -> Result<()> {
    let relay_expected = config.agent_adapter != DETERMINISTIC_ADAPTER;
    if relay_expected != relay_socket_volume.is_some() {
        bail!("target relay socket mount does not match configured adapter");
    }
    let egress_expected = config.network_mode == INTERCEPTED_NETWORK_MODE;
    if egress_expected != egress_network.is_some() || egress_expected != egress_ca_path.is_some() {
        bail!("target egress proxy inputs do not match configured network mode");
    }
    let args = target_create_args(
        name,
        config,
        skill,
        home,
        relay_socket_volume,
        egress_network,
        egress_ca_path,
    );
    let mut command = Command::new("docker");
    command.args(args);
    let output = command.output().context("create target container")?;
    if !output.status.success() {
        bail!(
            "create target container: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn bounded_log_options(max_bytes: u64) -> Vec<String> {
    vec![
        "--log-driver".into(),
        "local".into(),
        "--log-opt".into(),
        format!("max-size={max_bytes}"),
        "--log-opt".into(),
        "max-file=1".into(),
        "--log-opt".into(),
        "compress=false".into(),
    ]
}

pub fn agent_cli_invocation(
    adapter: &str,
    model: &str,
    max_turns: u32,
    max_budget_usd: &str,
) -> Result<Option<Vec<String>>> {
    let invocation = match adapter {
        DETERMINISTIC_ADAPTER => return Ok(None),
        CODEX_ADAPTER => vec![
            "/usr/local/bin/codex".into(),
            "exec".into(),
            "--ephemeral".into(),
            "--ignore-user-config".into(),
            "--ignore-rules".into(),
            "--skip-git-repo-check".into(),
            "--sandbox".into(),
            "danger-full-access".into(),
            "--config".into(),
            format!(
                "model_providers.skillsissue_relay={{ name='skillsissue-relay', base_url='{CODEX_RELAY_BASE_URL}', wire_api='responses', supports_websockets=false }}"
            ),
            "--config".into(),
            "model_provider='skillsissue_relay'".into(),
            "--config".into(),
            "model_reasoning_effort='low'".into(),
            "--config".into(),
            "web_search='disabled'".into(),
            "--cd".into(),
            "/work/skill".into(),
            "--model".into(),
            model.into(),
            "--json".into(),
            CODEX_PROMPT.into(),
        ],
        CLAUDE_ADAPTER => vec![
            "/usr/local/bin/claude".into(),
            "--print".into(),
            "--output-format".into(),
            "stream-json".into(),
            "--verbose".into(),
            "--no-session-persistence".into(),
            "--no-chrome".into(),
            "--setting-sources".into(),
            "project".into(),
            "--strict-mcp-config".into(),
            "--mcp-config".into(),
            r#"{"mcpServers":{}}"#.into(),
            "--dangerously-skip-permissions".into(),
            "--tools".into(),
            "Bash,Read,Edit,Write,Glob,Grep".into(),
            "--model".into(),
            model.into(),
            "--max-turns".into(),
            max_turns.to_string(),
            "--max-budget-usd".into(),
            max_budget_usd.into(),
            CLAUDE_PROMPT.into(),
        ],
        _ => bail!("unsupported agent adapter"),
    };
    Ok(Some(invocation))
}

fn harness_arguments(config: &DetonatorConfig) -> Vec<String> {
    let mut args = vec![
        "--skill-root".into(),
        "/work/skill".into(),
        "--seed-root".into(),
        "/seed".into(),
        "--max-seed-entries".into(),
        config.max_skill_entries.to_string(),
        "--max-seed-bytes".into(),
        config.max_skill_bytes.to_string(),
        "--max-single-file-bytes".into(),
        config.max_single_file_bytes.to_string(),
        "--max-depth".into(),
        config.max_skill_depth.to_string(),
        "--max-lifts".into(),
        config.max_closure_lifts.to_string(),
        "--adapter".into(),
        config.agent_adapter.clone(),
        "--agent-model".into(),
        config.agent_model.clone(),
        "--adapter-timeout-seconds".into(),
        config.agent_timeout_seconds.to_string(),
        "--agent-max-turns".into(),
        config.agent_max_turns.to_string(),
        "--agent-max-budget-usd".into(),
        config.agent_max_budget_usd.clone(),
        "--start-gate".into(),
        TARGET_START_GATE.into(),
    ];
    if let Some(base_url) = &config.agent_base_url {
        args.push("--agent-base-url".into());
        args.push(base_url.clone());
    }
    if config.agent_adapter != DETERMINISTIC_ADAPTER {
        args.push("--relay-socket".into());
        args.push(RELAY_SOCKET_CONTAINER_PATH.into());
    }
    for extension in &config.instruction_extensions {
        args.push("--instruction-extension".into());
        args.push(extension.clone());
    }
    args
}

fn configured_harness_invocation(config: &DetonatorConfig) -> Vec<String> {
    let mut invocation = vec!["/usr/local/bin/skill-harness".into()];
    invocation.extend(harness_arguments(config));
    invocation
}

fn target_create_args(
    name: &str,
    config: &DetonatorConfig,
    skill: &Path,
    home: &Path,
    relay_socket_volume: Option<&str>,
    egress_network: Option<&str>,
    egress_ca_path: Option<&Path>,
) -> Vec<String> {
    let tmpfs = format!(
        "/work/skill:rw,nosuid,nodev,noexec,size={},nr_inodes={},uid=65532,gid=65532,mode=0700",
        config.max_workspace_bytes, config.max_workspace_inodes
    );
    let seed_mount = format!("type=bind,src={},dst=/seed,readonly", skill.display());
    let home_mount = format!(
        "type=bind,src={},dst=/home/detonator,readonly",
        home.display()
    );
    let mut args = vec![
        "create".into(),
        "--name".into(),
        name.into(),
        "--network".into(),
        egress_network.unwrap_or("none").into(),
        "--read-only".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges=true".into(),
        "--pids-limit".into(),
        config.pids_limit.to_string(),
        "--memory".into(),
        config.memory.clone(),
        "--cpus".into(),
        config.cpus.clone(),
        "--user".into(),
        "65532:65532".into(),
    ];
    args.extend(bounded_log_options(config.max_agent_output_bytes));
    args.extend([
        "--tmpfs".into(),
        "/tmp:rw,nosuid,nodev,noexec,size=64m,nr_inodes=1024".into(),
        "--tmpfs".into(),
        tmpfs,
        "--mount".into(),
        seed_mount,
        "--mount".into(),
        home_mount,
        "--env".into(),
        "HOME=/home/detonator".into(),
        "--env".into(),
        "SKILLSISSUE_MARKER_PREFIX=#data_".into(),
    ]);
    if let Some(socket_volume) = relay_socket_volume {
        args.extend([
            "--mount".into(),
            relay_socket_volume_mount(socket_volume, true),
        ]);
    }
    if let Some(ca_path) = egress_ca_path {
        let proxy_url = format!("http://{EGRESS_PROXY_ALIAS}:{EGRESS_PROXY_PORT}");
        args.extend([
            "--mount".into(),
            format!(
                "type=bind,src={},dst={EGRESS_PROXY_CA_CONTAINER_PATH},readonly",
                ca_path.display()
            ),
            "--env".into(),
            format!("HTTP_PROXY={proxy_url}"),
            "--env".into(),
            format!("HTTPS_PROXY={proxy_url}"),
            "--env".into(),
            format!("http_proxy={proxy_url}"),
            "--env".into(),
            format!("https_proxy={proxy_url}"),
            "--env".into(),
            "NO_PROXY=127.0.0.1,localhost".into(),
            "--env".into(),
            "no_proxy=127.0.0.1,localhost".into(),
            "--env".into(),
            format!("SSL_CERT_FILE={EGRESS_PROXY_CA_CONTAINER_PATH}"),
            "--env".into(),
            format!("REQUESTS_CA_BUNDLE={EGRESS_PROXY_CA_CONTAINER_PATH}"),
            "--env".into(),
            format!("CURL_CA_BUNDLE={EGRESS_PROXY_CA_CONTAINER_PATH}"),
            "--env".into(),
            format!("GIT_SSL_CAINFO={EGRESS_PROXY_CA_CONTAINER_PATH}"),
            "--env".into(),
            format!("NODE_EXTRA_CA_CERTS={EGRESS_PROXY_CA_CONTAINER_PATH}"),
            "--env".into(),
            format!("PIP_CERT={EGRESS_PROXY_CA_CONTAINER_PATH}"),
            "--env".into(),
            format!("NPM_CONFIG_CAFILE={EGRESS_PROXY_CA_CONTAINER_PATH}"),
        ]);
    }
    args.extend([
        "--label".into(),
        "ai.skillsissue.role=detonation-target".into(),
        config.sandbox_image.clone(),
    ]);
    args.extend(harness_arguments(config));
    args
}

struct TargetRunOptions<'a> {
    timeout: Duration,
    stdout_path: &'a Path,
    stderr_path: &'a Path,
    max_output_bytes: u64,
    telemetry_path: &'a Path,
    max_telemetry_bytes: u64,
    max_closure_lifts: u32,
    collector_name: Option<&'a str>,
    start_gate: &'a str,
}

struct TargetRunOutcome {
    status: ExitStatus,
    termination_reason: String,
    closure_lift_count: Option<u64>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

fn start_target_waiting(name: &str) -> Result<()> {
    command_ok(
        Command::new("docker").args(["start", name]),
        "start gated target",
    )?;
    if !container_is_running(name)? {
        let logs = Command::new("docker").args(["logs", name]).output()?;
        bail!(
            "gated target exited before collector startup: {}",
            String::from_utf8_lossy(&logs.stderr).trim()
        );
    }
    Ok(())
}

fn run_target(name: &str, options: TargetRunOptions<'_>) -> Result<TargetRunOutcome> {
    let mut child = Command::new("docker")
        .args(["attach", name])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start target container")?;
    let stdout = child.stdout.take().context("capture target stdout")?;
    let stderr = child.stderr.take().context("capture target stderr")?;
    let stdout_path = options.stdout_path.to_path_buf();
    let stderr_path = options.stderr_path.to_path_buf();
    let max_output_bytes = options.max_output_bytes;
    let stdout_thread = thread::spawn(move || drain_capped(stdout, &stdout_path, max_output_bytes));
    let stderr_thread = thread::spawn(move || drain_capped(stderr, &stderr_path, max_output_bytes));
    thread::sleep(Duration::from_millis(100));
    command_ok(
        Command::new("docker").args(["exec", name, "/usr/bin/touch", options.start_gate]),
        "release target start gate",
    )?;
    let deadline = Instant::now() + options.timeout;
    let mut next_collector_check = Instant::now() + Duration::from_secs(1);
    let (status, reason, closure_lift_count) = loop {
        if let Some(status) = child.try_wait()? {
            let closure_lift_count =
                decode_harness_completion(status.code(), options.max_closure_lifts);
            let reason = if closure_lift_count.is_some() {
                "completed"
            } else {
                "target_error"
            };
            break (status, reason.to_string(), closure_lift_count);
        }
        if Instant::now() >= deadline {
            stop_container(name);
            let status = child.wait()?;
            break (status, "timeout".to_string(), None);
        }
        if fs::metadata(options.telemetry_path)
            .map(|metadata| metadata.len() > options.max_telemetry_bytes.saturating_mul(2))
            .unwrap_or(false)
        {
            stop_container(name);
            let status = child.wait()?;
            break (status, "telemetry_limit".to_string(), None);
        }
        if Instant::now() >= next_collector_check
            && let Some(collector_name) = options.collector_name
            && !container_is_running(collector_name)?
        {
            stop_container(name);
            let status = child.wait()?;
            break (status, "collector_failure".to_string(), None);
        }
        if Instant::now() >= next_collector_check {
            next_collector_check = Instant::now() + Duration::from_secs(1);
        }
        thread::sleep(Duration::from_millis(200));
    };
    let stdout_truncated = stdout_thread
        .join()
        .map_err(|_| anyhow!("target stdout drain panicked"))??;
    let stderr_truncated = stderr_thread
        .join()
        .map_err(|_| anyhow!("target stderr drain panicked"))??;
    Ok(TargetRunOutcome {
        status,
        termination_reason: reason,
        closure_lift_count,
        stdout_truncated,
        stderr_truncated,
    })
}

fn decode_harness_completion(code: Option<i32>, max_closure_lifts: u32) -> Option<u64> {
    let count = code?.checked_sub(HARNESS_COMPLETION_EXIT_BASE)?;
    let count = u32::try_from(count).ok()?;
    (count <= max_closure_lifts && count <= MAX_ENCODED_CLOSURE_LIFTS).then_some(u64::from(count))
}

fn capture_is_usable(
    collector_healthy: bool,
    telemetry_truncated: bool,
    event_count: u64,
    harness_exec_seen: bool,
    adapter_exec_requirement_satisfied: bool,
    harness_completed: bool,
) -> bool {
    collector_healthy
        && !telemetry_truncated
        && event_count > 0
        && harness_exec_seen
        && adapter_exec_requirement_satisfied
        && harness_completed
}

fn expected_adapter_executable(adapter: &str) -> Option<&'static str> {
    match adapter {
        CODEX_ADAPTER => Some("/usr/local/bin/codex"),
        CLAUDE_ADAPTER => Some("/usr/local/bin/claude"),
        _ => None,
    }
}

fn drain_capped(mut reader: impl Read, path: &Path, max_bytes: u64) -> Result<bool> {
    let mut output = BufWriter::new(File::create(path)?);
    let mut written = 0_u64;
    let mut truncated = false;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = max_bytes.saturating_sub(written) as usize;
        let keep = count.min(remaining);
        if keep > 0 {
            output.write_all(&buffer[..keep])?;
            written += keep as u64;
        }
        truncated |= keep < count;
    }
    output.flush()?;
    Ok(truncated)
}

fn stop_container(name: &str) {
    let _ = Command::new("docker")
        .args(["stop", "--time", "5", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn container_is_running(name: &str) -> Result<bool> {
    let output = Command::new("docker")
        .args(["inspect", "--format", "{{.State.Running}}", name])
        .output()?;
    Ok(output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "true")
}

fn finalize_collector(
    name: &str,
    started: bool,
    log_path: &Path,
    max_log_bytes: u64,
) -> Result<CollectorStats> {
    if !started {
        return Ok(CollectorStats::default());
    }
    let running_before_stop = container_is_running(name)?;
    let mut supervisor_errors = Vec::new();
    if running_before_stop {
        let stopped = Command::new("docker")
            .args(["stop", "--time", "5", name])
            .output()
            .context("stop Tracee collector for output flush")?;
        if !stopped.status.success() {
            supervisor_errors.push(format!(
                "collector stop failed: {}",
                String::from_utf8_lossy(&stopped.stderr).trim()
            ));
        }
    }
    thread::sleep(Duration::from_millis(200));
    let stopped_after_flush = !container_is_running(name)?;
    if !stopped_after_flush {
        supervisor_errors.push("collector remained running after stop".to_string());
    }

    let logs = Command::new("docker").args(["logs", name]).output()?;
    let logs_collected = logs.status.success();
    if !logs_collected {
        supervisor_errors.push(format!(
            "collector logs failed: {}",
            String::from_utf8_lossy(&logs.stderr).trim()
        ));
    }
    let mut combined = logs.stdout;
    combined.extend_from_slice(&logs.stderr);
    let log_truncated = combined.len() as u64 > max_log_bytes;
    combined.truncate(max_log_bytes.min(usize::MAX as u64) as usize);
    fs::write(log_path, &combined)?;
    let log_text = String::from_utf8_lossy(&combined);
    let lost_events = tracee_lost_events(&log_text);
    if tracee_reported_error(&log_text) {
        supervisor_errors.push("collector emitted an error-level log".to_string());
    }

    let state_output = Command::new("docker")
        .args(["inspect", "--format", "{{json .State}}", name])
        .output()?;
    let state: serde_json::Value = if state_output.status.success() {
        serde_json::from_slice(&state_output.stdout).unwrap_or_default()
    } else {
        serde_json::Value::Null
    };
    let exit_code = state.get("ExitCode").and_then(|value| value.as_i64());
    let oom_killed = state
        .get("OOMKilled")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let state_error = state
        .get("Error")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    if !state_error.is_empty() {
        supervisor_errors.push(state_error);
    }
    let error = supervisor_errors.join("; ");
    let healthy = running_before_stop
        && stopped_after_flush
        && logs_collected
        && !oom_killed
        && error.is_empty()
        && lost_events == 0
        && !log_truncated;
    Ok(CollectorStats {
        started,
        running_before_stop,
        stopped_after_flush,
        logs_collected,
        healthy,
        exit_code,
        oom_killed,
        error,
        lost_events,
        log_truncated,
    })
}

fn tracee_lost_events(log: &str) -> u64 {
    let metric_losses = [
        "LostEvCount",
        "LostWrCount",
        "LostNtCapCount",
        "LostBPFLogsCount",
        "lost_events",
    ]
    .iter()
    .map(|key| {
        log.match_indices(key)
            .filter_map(|(index, _)| {
                log[index + key.len()..]
                    .trim_start_matches(|character: char| {
                        character.is_ascii_whitespace() || matches!(character, ':' | '=' | '"')
                    })
                    .split(|character: char| !character.is_ascii_digit())
                    .next()
                    .and_then(|digits| digits.parse::<u64>().ok())
            })
            .sum::<u64>()
    })
    .sum::<u64>();
    // Tracee v0.24.x reports perf-buffer loss as warning text rather than in
    // its JSON epilogue: "Lost N events", "Lost N capture events", etc.
    // Treat every numeric Tracee "Lost N ..." diagnostic as evidence loss;
    // this also covers control-plane signals, not only event buffers.
    let warning =
        regex::Regex::new(r"(?i)\blost\s+(\d+)\b").expect("static Tracee loss regex is valid");
    metric_losses
        + warning
            .captures_iter(log)
            .filter_map(|captures| captures.get(1)?.as_str().parse::<u64>().ok())
            .sum::<u64>()
}

fn tracee_reported_error(log: &str) -> bool {
    regex::Regex::new(r#"(?im)"?level"?\s*[:=]\s*"?error\b|(?:^|\s)(?:err|error)\b"#)
        .expect("static Tracee error regex is valid")
        .is_match(log)
}

struct DockerCleanup {
    containers: Vec<String>,
    networks: Vec<String>,
    volumes: Vec<String>,
}

impl DockerCleanup {
    fn new(containers: Vec<String>, networks: Vec<String>, volumes: Vec<String>) -> Self {
        Self {
            containers,
            networks,
            volumes,
        }
    }
}

impl Drop for DockerCleanup {
    fn drop(&mut self) {
        for name in &self.containers {
            stop_container(name);
            let _ = Command::new("docker")
                .args(["rm", "--force", name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        for name in &self.networks {
            let _ = Command::new("docker")
                .args(["network", "rm", name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        for name in &self.volumes {
            let _ = Command::new("docker")
                .args(["volume", "rm", "--force", name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FilteredTraceStats {
    event_count: u64,
    pre_detonation_event_count: u64,
    telemetry_truncated: bool,
    harness_exec_seen: bool,
    adapter_exec_seen: bool,
    invocation_boundary_seen: bool,
}

fn filter_trace_to_container(
    path: &Path,
    target_id: &str,
    max_bytes: u64,
    expected_adapter_executable: Option<&str>,
) -> Result<FilteredTraceStats> {
    let file = File::open(path)?;
    let mut foreign = 0_u64;
    let mut harness_exec_seen = false;
    let mut adapter_exec_seen = false;
    let mut target_index = 0_u64;
    let mut invocation_boundary_index = None;
    let mut invocation_boundary_timestamp = None;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(&line).context("Tracee output contained a non-JSON line")?;
        let values = match value {
            serde_json::Value::Array(values) => values,
            value => vec![value],
        };
        for value in values {
            let event_container = value
                .get("containerId")
                .and_then(|value| value.as_str())
                .or_else(|| {
                    value
                        .pointer("/container/id")
                        .and_then(|value| value.as_str())
                })
                .unwrap_or_default();
            if !container_id_matches(target_id, event_container) {
                foreign += 1;
                continue;
            }
            if invocation_boundary_index.is_none()
                && json_contains_string(&value, INVOCATION_MARKER_PATH)
            {
                invocation_boundary_index = Some(target_index);
                invocation_boundary_timestamp = json_event_timestamp(&value);
            }
            harness_exec_seen |= json_event_name(&value) == Some("sched_process_exec")
                && json_contains_string(&value, "/usr/local/bin/skill-harness");
            adapter_exec_seen |= json_event_name(&value) == Some("sched_process_exec")
                && expected_adapter_executable
                    .is_some_and(|executable| json_contains_string(&value, executable));
            target_index += 1;
        }
    }
    if foreign > 0 {
        bail!("Tracee emitted {foreign} event(s) outside target container {target_id}");
    }

    let filtered = path.with_extension("filtered.jsonl");
    let mut output = BufWriter::new(File::create(&filtered)?);
    let mut count = 0_u64;
    let mut pre_detonation_event_count = 0_u64;
    let mut bytes_written = 0_u64;
    let mut truncated = false;
    let mut target_index = 0_u64;
    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(&line).context("Tracee output contained a non-JSON line")?;
        let values = match value {
            serde_json::Value::Array(values) => values,
            value => vec![value],
        };
        for mut value in values {
            let event_container = value
                .get("containerId")
                .and_then(|value| value.as_str())
                .or_else(|| {
                    value
                        .pointer("/container/id")
                        .and_then(|value| value.as_str())
                })
                .unwrap_or_default();
            if !container_id_matches(target_id, event_container) {
                continue;
            }
            let pre_detonation = match (invocation_boundary_timestamp, json_event_timestamp(&value))
            {
                (Some(boundary), Some(timestamp)) => timestamp <= boundary,
                _ => invocation_boundary_index.is_some_and(|boundary| target_index <= boundary),
            };
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "skillsissuePhase".to_string(),
                    serde_json::Value::String(
                        if pre_detonation {
                            "pre-detonation"
                        } else {
                            "detonation"
                        }
                        .to_string(),
                    ),
                );
            }
            let encoded = serde_json::to_vec(&value)?;
            let required = encoded.len() as u64 + 1;
            if bytes_written.saturating_add(required) <= max_bytes {
                output.write_all(&encoded)?;
                output.write_all(b"\n")?;
                bytes_written += required;
                count += 1;
                pre_detonation_event_count += u64::from(pre_detonation);
            } else {
                truncated = true;
            }
            target_index += 1;
        }
    }
    output.flush()?;
    fs::rename(&filtered, path)?;
    Ok(FilteredTraceStats {
        event_count: count,
        pre_detonation_event_count,
        telemetry_truncated: truncated,
        harness_exec_seen,
        adapter_exec_seen,
        invocation_boundary_seen: invocation_boundary_index.is_some(),
    })
}

fn json_event_name(value: &serde_json::Value) -> Option<&str> {
    value
        .get("eventName")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            value
                .pointer("/event/eventName")
                .and_then(serde_json::Value::as_str)
        })
}

fn json_event_timestamp(value: &serde_json::Value) -> Option<u64> {
    ["timestamp", "timestamp_ns", "timeStamp", "monotonic_ns"]
        .iter()
        .find_map(|name| {
            value
                .get(*name)
                .or_else(|| value.get("event").and_then(|event| event.get(*name)))
                .and_then(|value| {
                    value
                        .as_u64()
                        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
                })
        })
}

fn json_contains_string(value: &serde_json::Value, needle: &str) -> bool {
    match value {
        serde_json::Value::String(value) => value.contains(needle),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| json_contains_string(value, needle)),
        serde_json::Value::Object(values) => values
            .values()
            .any(|value| json_contains_string(value, needle)),
        _ => false,
    }
}

fn container_id_matches(expected: &str, observed: &str) -> bool {
    observed.len() >= 12
        && observed.bytes().all(|byte| byte.is_ascii_hexdigit())
        && (expected == observed
            || expected.starts_with(observed)
            || observed.starts_with(expected))
}

fn compress_zstd(input: &Path, output: &Path) -> Result<()> {
    let mut reader = BufReader::new(File::open(input)?);
    let writer = BufWriter::new(File::create(output)?);
    let mut encoder = zstd::Encoder::new(writer, 9)?;
    std::io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?.flush()?;
    Ok(())
}

#[derive(Debug, Default)]
struct NetworkEvidence {
    path: Option<String>,
    sha256: Option<String>,
    size_bytes: Option<u64>,
    truncated: bool,
}

fn network_capture_mode(relay_enabled: bool, egress_enabled: bool) -> &'static str {
    match (relay_enabled, egress_enabled) {
        (true, true) => "provider-relay-and-intercepted-http-egress",
        (true, false) => "provider-relay-tls-termination",
        (false, true) => "intercepted-http-egress",
        (false, false) => "blocked-no-egress",
    }
}

fn finalize_network_transcript(
    run_dir: &Path,
    relative_run_dir: &Path,
    relay_enabled: bool,
    egress_enabled: bool,
) -> Result<NetworkEvidence> {
    let provider_raw = run_dir.join("provider-network.jsonl");
    let egress_raw = run_dir.join("egress-network.jsonl");
    if !relay_enabled && !egress_enabled {
        for path in [&provider_raw, &egress_raw] {
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
        return Ok(NetworkEvidence::default());
    }
    let raw = run_dir.join("network.jsonl");
    let compressed = run_dir.join("network.jsonl.zst");
    if compressed.is_file() && !raw.exists() && !provider_raw.exists() && !egress_raw.exists() {
        return Ok(NetworkEvidence {
            path: Some(
                relative_run_dir
                    .join("network.jsonl.zst")
                    .to_string_lossy()
                    .into_owned(),
            ),
            sha256: Some(file_sha256(&compressed)?),
            size_bytes: Some(fs::metadata(&compressed)?.len()),
            truncated: false,
        });
    }

    let mut truncated = false;
    let mut output = BufWriter::new(File::create(&raw)?);
    for (enabled, source) in [
        (relay_enabled, &provider_raw),
        (egress_enabled, &egress_raw),
    ] {
        if !enabled {
            if source.exists() {
                fs::remove_file(source)?;
            }
            continue;
        }
        if !source.is_file() {
            truncated = true;
            continue;
        }
        for line in BufReader::new(File::open(source)?).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<serde_json::Value>(&line) {
                Ok(value) => {
                    truncated |= value
                        .pointer("/request/capture_truncated")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    truncated |= value
                        .pointer("/response/capture_truncated")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                }
                Err(_) => truncated = true,
            }
            output.write_all(line.as_bytes())?;
            output.write_all(b"\n")?;
        }
        fs::remove_file(source)?;
    }
    output.flush()?;
    compress_zstd(&raw, &compressed)?;
    fs::remove_file(&raw)?;
    let relative = relative_run_dir.join("network.jsonl.zst");
    Ok(NetworkEvidence {
        path: Some(relative.to_string_lossy().into_owned()),
        sha256: Some(file_sha256(&compressed)?),
        size_bytes: Some(fs::metadata(&compressed)?.len()),
        truncated,
    })
}

fn compress_and_remove(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let output = path.with_extension(format!(
        "{}.zst",
        path.extension().and_then(OsStr::to_str).unwrap_or("log")
    ));
    compress_zstd(path, &output)?;
    fs::remove_file(path)?;
    Ok(())
}

fn image_digest(image: &str) -> Result<String> {
    let output = Command::new("docker")
        .args(["image", "inspect", "--format", "{{.Id}}", image])
        .output()?;
    if !output.status.success() {
        return Ok(String::new());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn file_sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    std::io::copy(&mut file, &mut digest)?;
    Ok(hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::TempDir;
    use walkdir::WalkDir;

    fn config() -> DetonatorConfig {
        DetonatorConfig::default()
    }

    fn skill(id: &str) -> SkillRecord {
        SkillRecord {
            schema_version: 1,
            skill_id: id.into(),
            sha256: String::new(),
            blake3: String::new(),
            canonicalization_version: 1,
            name: Some(id.into()),
            publisher: None,
            declared_version: None,
            entrypoint: Some("SKILL.md".into()),
            license: None,
            size_bytes: 0,
            file_count: 0,
            bundle_path: String::new(),
            manifest_path: String::new(),
            first_seen_at: String::new(),
            last_seen_at: String::new(),
        }
    }

    #[test]
    fn run_key_is_stable_and_policy_bound() {
        let a = run_key("sha256:v1:abc", "policy-a", &config());
        assert_eq!(a, run_key("sha256:v1:abc", "policy-a", &config()));
        assert_ne!(a, run_key("sha256:v1:abc", "policy-b", &config()));
    }

    #[test]
    fn workspace_limits_are_policy_bound_and_validated() {
        let baseline = config();
        let mut changed = baseline.clone();
        changed.max_workspace_bytes += 1;
        assert_ne!(config_fingerprint(&baseline), config_fingerprint(&changed));

        let mut invalid = baseline;
        invalid.max_workspace_inodes = invalid.max_skill_entries;
        assert!(invalid.validate().is_err());
        invalid.max_workspace_inodes = 8_192;
        invalid.instruction_extensions = vec![".md".into()];
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn cli_adapters_require_model_network_none_and_exact_loopback_relay_contract() {
        for adapter in [CODEX_ADAPTER, CLAUDE_ADAPTER] {
            let mut cfg = config();
            cfg.agent_adapter = adapter.into();
            cfg.agent_model = "test-model".into();
            assert!(cfg.validate().is_err());
            cfg.agent_base_url = Some(
                if adapter == CODEX_ADAPTER {
                    CODEX_RELAY_BASE_URL
                } else {
                    CLAUDE_RELAY_BASE_URL
                }
                .into(),
            );
            cfg.validate().unwrap();

            cfg.network_mode = "internal-relay".into();
            assert!(cfg.validate().is_err());
            cfg.network_mode = "none".into();

            cfg.agent_base_url = Some("http://user:pass@127.0.0.1:8787/v1".into());
            assert!(cfg.validate().is_err());
        }
    }

    #[test]
    fn durable_invocations_are_sanitized_and_provider_bounded() -> Result<()> {
        let mut cfg = config();
        cfg.agent_adapter = CLAUDE_ADAPTER.into();
        cfg.agent_model = "test-model".into();
        cfg.agent_base_url = Some(CLAUDE_RELAY_BASE_URL.into());
        let harness = configured_harness_invocation(&cfg);
        assert!(
            harness
                .windows(2)
                .any(|args| args == ["--adapter", CLAUDE_ADAPTER])
        );
        assert!(
            harness
                .windows(2)
                .any(|args| args == ["--agent-base-url", CLAUDE_RELAY_BASE_URL])
        );
        let agent = agent_cli_invocation(
            &cfg.agent_adapter,
            &cfg.agent_model,
            cfg.agent_max_turns,
            &cfg.agent_max_budget_usd,
        )?
        .context("agent invocation")?;
        assert!(!agent.iter().any(|arg| arg.contains("key")));
        assert!(!agent.iter().any(|arg| arg.contains("skillsissue-relay")));
        assert!(agent.iter().any(|arg| arg == "--no-session-persistence"));
        assert!(
            harness
                .windows(2)
                .any(|args| args == ["--relay-socket", RELAY_SOCKET_CONTAINER_PATH])
        );
        Ok(())
    }

    #[test]
    fn relay_launch_pins_model_token_and_request_body_limits() {
        let mut cfg = config();
        cfg.agent_adapter = CLAUDE_ADAPTER.into();
        cfg.agent_model = "wire-model".into();
        cfg.agent_max_turns = 4;
        cfg.agent_timeout_seconds = 180;

        let args = relay_process_args(&cfg, "anthropic");
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--expected-model", "wire-model"])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--max-output-tokens", "4096"])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--max-request-bytes", "262144"])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--max-total-request-bytes", "786432"])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--unix-socket", RELAY_SOCKET_CONTAINER_PATH])
        );
        assert!(!args.iter().any(|arg| arg.contains("0.0.0.0")));
        assert!(args.windows(2).any(|pair| pair == ["--max-requests", "8"]));
        assert_eq!(
            relay_contract_fingerprint(&cfg),
            "strict-local-tools-uds-v3-transcript:request_bytes=262144:total_request_bytes=786432:max_output_tokens=4096:transcript_bytes=33554432:transcript_body_bytes=16777216"
        );

        let mut changed_model = cfg.clone();
        changed_model.agent_model = "other-wire-model".into();
        assert_ne!(config_fingerprint(&cfg), config_fingerprint(&changed_model));
    }

    #[test]
    fn target_uses_bounded_tmpfs_read_only_seed_and_bounded_logs() {
        let mut cfg = config();
        cfg.instruction_extensions = vec!["md".into(), "rst".into()];
        let args = target_create_args(
            "target",
            &cfg,
            Path::new("/host/seed"),
            Path::new("/host/home"),
            None,
            None,
            None,
        );
        let rendered = args.join("\n");
        assert!(rendered.contains(
            "/work/skill:rw,nosuid,nodev,noexec,size=134217728,nr_inodes=8192,uid=65532,gid=65532,mode=0700"
        ));
        assert!(rendered.contains("type=bind,src=/host/seed,dst=/seed,readonly"));
        assert!(!rendered.contains("dst=/work/skill,rw"));
        assert!(rendered.contains("max-size=524288"));
        assert!(rendered.contains("max-file=1"));
        assert!(rendered.contains("compress=false"));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--instruction-extension", "rst"])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--adapter", DETERMINISTIC_ADAPTER])
        );
        assert!(args.windows(2).any(|pair| pair == ["--network", "none"]));
        assert!(!rendered.contains(RELAY_SOCKET_CONTAINER_DIR));
    }

    #[test]
    fn cli_target_has_no_network_and_only_read_only_socket_directory() {
        let mut cfg = config();
        cfg.agent_adapter = CODEX_ADAPTER.into();
        cfg.agent_model = "wire-model".into();
        cfg.agent_base_url = Some(CODEX_RELAY_BASE_URL.into());
        let args = target_create_args(
            "target",
            &cfg,
            Path::new("/host/seed"),
            Path::new("/host/home"),
            Some("skillsissue-relay-socket-test"),
            None,
            None,
        );
        assert!(args.windows(2).any(|pair| pair == ["--network", "none"]));
        assert!(args.windows(2).any(|pair| {
            pair == [
                "--mount",
                "type=volume,src=skillsissue-relay-socket-test,dst=/run/skillsissue,readonly,volume-nocopy",
            ]
        }));
        assert_eq!(
            relay_socket_volume_mount("skillsissue-relay-socket-test", false),
            "type=volume,src=skillsissue-relay-socket-test,dst=/run/skillsissue"
        );
        assert!(!args.iter().any(|argument| {
            argument.contains("type=bind") && argument.contains(RELAY_SOCKET_CONTAINER_DIR)
        }));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--relay-socket", RELAY_SOCKET_CONTAINER_PATH])
        );
        let agent = agent_cli_invocation(CODEX_ADAPTER, "wire-model", 4, "0.50")
            .unwrap()
            .unwrap();
        assert!(
            agent
                .windows(2)
                .any(|pair| pair == ["--config", "web_search='disabled'"])
        );
    }

    #[test]
    fn intercepted_target_has_only_internal_proxy_transport_and_per_run_ca() {
        let mut cfg = config();
        cfg.network_mode = INTERCEPTED_NETWORK_MODE.into();
        let args = target_create_args(
            "target",
            &cfg,
            Path::new("/host/seed"),
            Path::new("/host/home"),
            None,
            Some("skillsissue-target-internal-test"),
            Some(Path::new("/host/mitmproxy-ca-cert.pem")),
        );
        let rendered = args.join("\n");
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--network", "skillsissue-target-internal-test"])
        );
        assert!(rendered.contains(
            "type=bind,src=/host/mitmproxy-ca-cert.pem,dst=/run/skillsissue/egress-ca.pem,readonly"
        ));
        for variable in [
            "HTTP_PROXY=http://skillsissue-egress-proxy:8080",
            "HTTPS_PROXY=http://skillsissue-egress-proxy:8080",
            "SSL_CERT_FILE=/run/skillsissue/egress-ca.pem",
            "NODE_EXTRA_CA_CERTS=/run/skillsissue/egress-ca.pem",
        ] {
            assert!(rendered.contains(variable));
        }
        assert!(!rendered.contains("--network\nbridge"));
        assert!(!rendered.contains("--network\nhost"));
        assert_eq!(
            egress_contract_fingerprint(&cfg),
            "public-download-mitm-v1:methods=GET,HEAD:ports=80,443:request_body=0:upgrades=0:destinations=public-only:requests=32:response_bytes=16777216:total_response_bytes=33554432"
        );
    }

    #[test]
    fn only_reserved_harness_exit_is_a_trusted_completion() {
        assert_eq!(
            decode_harness_completion(Some(HARNESS_COMPLETION_EXIT_BASE + 7), 32),
            Some(7)
        );
        assert_eq!(decode_harness_completion(Some(0), 32), None);
        assert_eq!(decode_harness_completion(Some(1), 32), None);
        assert_eq!(
            decode_harness_completion(Some(HARNESS_COMPLETION_EXIT_BASE + 33), 32),
            None
        );
        assert_eq!(decode_harness_completion(None, 32), None);
    }

    #[test]
    fn healthy_trace_without_trusted_harness_completion_is_partial() {
        assert!(capture_is_usable(true, false, 1, true, true, true));
        assert!(!capture_is_usable(true, false, 1, true, true, false));
        assert!(!capture_is_usable(true, false, 1, true, false, true));
    }

    #[test]
    fn pending_selection_is_stable_and_idempotent() {
        let cfg = config();
        let key = run_key("a", "p", &cfg);
        let run = RunRecord {
            schema_version: 1,
            run_id: "run-a".into(),
            run_key: key,
            skill_id: "a".into(),
            status: "captured".into(),
            scenario: String::new(),
            seed: 0,
            queued_at: String::new(),
            started_at: None,
            finished_at: None,
            harness_version: String::new(),
            policy_sha256: String::new(),
            agent_adapter: String::new(),
            agent_model: String::new(),
            target_image_digest: String::new(),
            skillject_commit: String::new(),
            telemetry_path: None,
            event_count: None,
            exit_code: None,
            termination_reason: None,
            closure_lift_count: None,
            taint_coverage: None,
        };
        let pending = pending_skills(vec![skill("b"), skill("a")], &[run], "p", &cfg, 10);
        assert_eq!(
            pending
                .iter()
                .map(|s| s.skill_id.as_str())
                .collect::<Vec<_>>(),
            ["b"]
        );
    }

    #[test]
    fn shard_spec_rejects_invalid_partitions() {
        assert_eq!(ShardSpec::default(), ShardSpec::new(0, 1).unwrap());
        assert!(ShardSpec::new(0, 0).is_err());
        assert!(ShardSpec::new(1, 1).is_err());
        assert!(ShardSpec::new(4, 4).is_err());
        assert_eq!(ShardSpec::new(3, 4).unwrap().index(), 3);
        assert_eq!(ShardSpec::new(3, 4).unwrap().count(), 4);
    }

    #[test]
    fn skill_shard_assignment_has_a_stable_fixture() {
        assert_eq!(
            skills_core::detonation_shard_index("sha256:v1:alpha", 8),
            Some(4)
        );
        assert_eq!(
            skills_core::detonation_shard_index("sha256:v1:beta", 8),
            Some(2)
        );
        assert_eq!(
            skills_core::detonation_shard_index(
                "sha256:v1:ddfdc36b29b870328ffdcd8c43bead736ffe4358fcf55178a4481263b5d0c4de",
                8,
            ),
            Some(6)
        );
    }

    #[test]
    fn sharded_pending_selection_is_disjoint_complete_and_order_independent() {
        let cfg = config();
        let skills = (0..64)
            .map(|index| skill(&format!("sha256:v1:{index:02}")))
            .collect::<Vec<_>>();
        let expected = pending_skills(skills.clone(), &[], "p", &cfg, usize::MAX)
            .into_iter()
            .map(|skill| skill.skill_id)
            .collect::<BTreeSet<_>>();
        let mut observed = BTreeSet::new();

        for index in 0..4 {
            let shard = ShardSpec::new(index, 4).unwrap();
            let selected =
                pending_skills_sharded(skills.clone(), &[], "p", &cfg, usize::MAX, shard);
            let mut reversed = skills.clone();
            reversed.reverse();
            assert_eq!(
                selected,
                pending_skills_sharded(reversed, &[], "p", &cfg, usize::MAX, shard)
            );
            for skill in selected {
                assert!(shard.contains(&skill.skill_id));
                assert!(
                    observed.insert(skill.skill_id),
                    "a skill was assigned to more than one shard"
                );
            }
        }

        assert_eq!(observed, expected);
    }

    #[test]
    fn sharded_limit_is_applied_per_worker_after_partitioning() {
        let cfg = config();
        let skills = (0..64)
            .map(|index| skill(&format!("sha256:v1:{index:02}")))
            .collect::<Vec<_>>();
        let shard = ShardSpec::new(2, 4).unwrap();
        let all = pending_skills_sharded(skills.clone(), &[], "p", &cfg, usize::MAX, shard);
        assert!(all.len() > 2);
        let limited = pending_skills_sharded(skills, &[], "p", &cfg, 2, shard);
        assert_eq!(limited, all[..2]);
    }

    #[test]
    fn failed_attempt_does_not_starve_unattempted_skills() {
        let cfg = config();
        let failed = RunRecord {
            schema_version: 1,
            run_id: "run-failed".into(),
            run_key: run_key("a", "p", &cfg),
            skill_id: "a".into(),
            status: "failed".into(),
            scenario: "default".into(),
            seed: 0,
            queued_at: String::new(),
            started_at: None,
            finished_at: None,
            harness_version: String::new(),
            policy_sha256: "p".into(),
            agent_adapter: String::new(),
            agent_model: String::new(),
            target_image_digest: String::new(),
            skillject_commit: String::new(),
            telemetry_path: None,
            event_count: None,
            exit_code: None,
            termination_reason: Some("detonation_error".into()),
            closure_lift_count: None,
            taint_coverage: Some(0.0),
        };
        let pending = pending_skills(vec![skill("a"), skill("b")], &[failed], "p", &cfg, 1);
        assert_eq!(pending[0].skill_id, "b");
    }

    #[test]
    fn run_csv_is_sorted_and_round_trips() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("runs.csv");
        let base = RunRecord {
            schema_version: 1,
            run_id: "b".into(),
            run_key: "k".into(),
            skill_id: "s".into(),
            status: "captured".into(),
            scenario: String::new(),
            seed: 0,
            queued_at: String::new(),
            started_at: None,
            finished_at: None,
            harness_version: String::new(),
            policy_sha256: String::new(),
            agent_adapter: String::new(),
            agent_model: String::new(),
            target_image_digest: String::new(),
            skillject_commit: String::new(),
            telemetry_path: None,
            event_count: None,
            exit_code: None,
            termination_reason: None,
            closure_lift_count: None,
            taint_coverage: None,
        };
        let mut first = base.clone();
        first.run_id = "a".into();
        write_runs_atomic(&path, &[base.clone(), first.clone()])?;
        let read = read_runs(&path)?;
        assert_eq!(read, vec![first, base]);
        Ok(())
    }

    #[test]
    fn target_output_is_drained_but_bounded() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("stdout");
        let truncated = drain_capped(std::io::Cursor::new(vec![b'x'; 32]), &path, 8)?;
        assert!(truncated);
        assert_eq!(fs::read(path)?, vec![b'x'; 8]);
        Ok(())
    }

    #[test]
    fn archive_links_may_walk_within_but_not_outside_skill() {
        assert!(safe_archive_symlink(
            Path::new("skill/scripts/tool"),
            Path::new("../shared/tool")
        ));
        assert!(!safe_archive_symlink(
            Path::new("skill/tool"),
            Path::new("../../outside")
        ));
        assert!(!safe_archive_symlink(
            Path::new("skill/tool"),
            Path::new("../.git/config")
        ));
    }

    #[test]
    fn tracee_policy_uses_supported_container_id_scope() {
        let policy = tracee_policy_yaml("0123456789abcdef");
        assert!(policy.contains("    - container=0123456789abcdef\n"));
        assert!(!policy.contains("containerName="));
    }

    #[test]
    fn raw_trace_rejects_foreign_container_events() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("events.jsonl");
        fs::write(
            &path,
            "{\"containerId\":\"0123456789ab\",\"eventName\":\"read\"}\n{\"containerId\":\"fedcba987654\",\"eventName\":\"execve\"}\n",
        )?;
        assert!(filter_trace_to_container(&path, "0123456789abcdef", 4096, None).is_err());
        Ok(())
    }

    #[test]
    fn raw_trace_cap_keeps_only_complete_target_json_lines() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("events.jsonl");
        let event = "{\"containerId\":\"0123456789ab\",\"eventName\":\"read\"}\n";
        fs::write(&path, format!("{event}{event}"))?;
        let stats = filter_trace_to_container(&path, "0123456789abcdef", 120, None)?;
        assert_eq!(stats.event_count, 1);
        assert!(stats.telemetry_truncated);
        assert!(!stats.harness_exec_seen);
        assert!(!stats.adapter_exec_seen);
        let retained = fs::read_to_string(path)?;
        assert_eq!(retained.lines().count(), 1);
        serde_json::from_str::<serde_json::Value>(retained.trim())?;
        Ok(())
    }

    #[test]
    fn raw_trace_requires_target_harness_exec_sentinel() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("events.jsonl");
        fs::write(
            &path,
            "{\"containerId\":\"0123456789ab\",\"eventName\":\"sched_process_exec\",\"args\":[{\"name\":\"cmdpath\",\"value\":\"/usr/local/bin/skill-harness\"}]}\n",
        )?;
        let stats = filter_trace_to_container(&path, "0123456789abcdef", 4096, None)?;
        assert_eq!(stats.event_count, 1);
        assert!(!stats.telemetry_truncated);
        assert!(stats.harness_exec_seen);
        assert!(!stats.adapter_exec_seen);
        Ok(())
    }

    #[test]
    fn raw_trace_requires_configured_cli_exec_sentinel() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("events.jsonl");
        fs::write(
            &path,
            "{\"containerId\":\"0123456789ab\",\"eventName\":\"sched_process_exec\",\"args\":[{\"name\":\"cmdpath\",\"value\":\"/usr/local/bin/skill-harness\"}]}\n{\"containerId\":\"0123456789ab\",\"eventName\":\"sched_process_exec\",\"args\":[{\"name\":\"cmdpath\",\"value\":\"/usr/local/bin/codex\"}]}\n",
        )?;
        let stats = filter_trace_to_container(
            &path,
            "0123456789abcdef",
            4096,
            Some("/usr/local/bin/codex"),
        )?;
        assert_eq!(stats.event_count, 2);
        assert!(!stats.telemetry_truncated);
        assert!(stats.harness_exec_seen);
        assert!(stats.adapter_exec_seen);
        Ok(())
    }

    #[test]
    fn raw_trace_marks_events_before_invocation_boundary() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("events.jsonl");
        fs::write(
            &path,
            format!(
                "{{\"containerId\":\"0123456789ab\",\"timestamp\":1,\"eventName\":\"openat\",\"args\":{{\"pathname\":\"/tmp/setup\"}}}}\n\
                 {{\"containerId\":\"0123456789ab\",\"timestamp\":10,\"eventName\":\"openat\",\"args\":{{\"pathname\":\"{INVOCATION_MARKER_PATH}\"}}}}\n\
                 {{\"containerId\":\"0123456789ab\",\"timestamp\":11,\"eventName\":\"execve\",\"args\":{{\"pathname\":\"/bin/sh\"}}}}\n\
                 {{\"containerId\":\"0123456789ab\",\"timestamp\":5,\"eventName\":\"read\",\"args\":{{\"fd\":3}}}}\n\
                 {{\"containerId\":\"0123456789ab\",\"timestamp\":12,\"eventName\":\"openat\",\"args\":{{\"pathname\":\"{INVOCATION_MARKER_PATH}\"}}}}\n"
            ),
        )?;
        let stats = filter_trace_to_container(&path, "0123456789abcdef", 4096, None)?;
        assert!(stats.invocation_boundary_seen);
        assert_eq!(stats.pre_detonation_event_count, 3);
        let phases = fs::read_to_string(path)?
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["skillsissuePhase"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            vec![
                "pre-detonation",
                "pre-detonation",
                "detonation",
                "pre-detonation",
                "detonation"
            ]
        );
        Ok(())
    }

    #[test]
    fn collector_loss_counters_are_detected_without_counting_zeroes() {
        let log = r#"{"LostEvCount":0,"LostWrCount":7,"LostNtCapCount":2}
lost_events=3
WARN Lost 4 events
WARN Lost 5 capture events
WARN Lost 6 network capture events
WARN Lost 7 ebpf logs events"#;
        assert_eq!(tracee_lost_events(log), 34);
        assert_eq!(tracee_lost_events(r#"{"LostEvCount":0}"#), 0);
        assert!(tracee_reported_error("level=error msg=failed to attach"));
        assert!(tracee_reported_error(r#"{"level":"error","msg":"failed"}"#));
        assert!(!tracee_reported_error("level=info msg=healthy"));
    }

    #[test]
    fn extracted_bundle_is_bounded_and_reverified_against_registry() -> Result<()> {
        let temp = TempDir::new()?;
        let source = temp.path().join("source");
        fs::create_dir(&source)?;
        fs::write(source.join("SKILL.md"), "# fixture\n")?;
        let bundle = temp.path().join("bundle.tar.zst");
        let manifest = temp.path().join("manifest.json");
        let artifact = skills_core::archive_skill_tree(&source, &bundle, &manifest)?;
        let record = SkillRecord::from_canonical(
            &artifact.canonical,
            "corpus/bundle.tar.zst",
            "corpus/manifest.json",
            "2026-01-01T00:00:00Z",
        );
        let output = temp.path().join("output");
        fs::create_dir(&output)?;
        let root = extract_bundle(&bundle, &output, &config())?;
        verify_extracted_skill(&output, &root, &record)?;

        let mut wrong = record;
        wrong.skill_id = format!("{}0", wrong.skill_id);
        assert!(verify_extracted_skill(&output, &root, &wrong).is_err());

        let constrained_output = temp.path().join("constrained");
        fs::create_dir(&constrained_output)?;
        let mut constrained = config();
        constrained.max_skill_bytes = 1;
        constrained.max_single_file_bytes = 1;
        assert!(extract_bundle(&bundle, &constrained_output, &constrained).is_err());
        Ok(())
    }

    #[test]
    fn failed_attempt_is_returned_with_durable_manifest() -> Result<()> {
        let temp = TempDir::new()?;
        fs::create_dir(temp.path().join("data"))?;
        fs::write(
            temp.path().join("policy.toml"),
            "policy_version = \"test\"\n",
        )?;
        let mut missing = skill("missing");
        missing.bundle_path = "corpus/missing.tar.zst".into();
        let result = detonate(DetonationRequest {
            skill: missing,
            repo_root: temp.path().to_path_buf(),
            policy_path: temp.path().join("policy.toml"),
            config: config(),
            allow_untraced: false,
        })?;
        assert_eq!(result.record.status, "failed");
        assert!(result.failure.is_some());
        let run_json = WalkDir::new(temp.path().join("telemetry"))
            .into_iter()
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.into_path())
            .find(|path| path.file_name().is_some_and(|name| name == "run.json"))
            .expect("failure run manifest exists");
        let manifest: serde_json::Value = serde_json::from_slice(&fs::read(run_json)?)?;
        assert_eq!(manifest["termination_reason"], "detonation_error");
        assert_eq!(manifest["collector_healthy"], false);
        Ok(())
    }
}
