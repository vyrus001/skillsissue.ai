use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use flate2::{Compression, write::GzEncoder};
use rayon::prelude::*;
use serde::Serialize;
use skills_core::{
    AssessmentRecord, DiscoveryRecord, FindingRecord, PlatformRecord, RunRecord, SkillRecord,
    read_csv_records,
};
use url::Url;

use crate::graph::build_graph;
use crate::input::{LoadLimits, load};
use crate::model::{GraphModel, GraphSettings};
use crate::normalize::normalize;

const SITE_INDEX: &str = include_str!("../site/index.html");
const SITE_JS: &str = include_str!("../site/app.js");
const SITE_CSS: &str = include_str!("../site/style.css");
const GRAPH_INDEX: &str = include_str!("../web/index.html");
const GRAPH_JS: &str = include_str!("../web/app.js");
const GRAPH_CSS: &str = include_str!("../web/style.css");
const LOCAL_GRAPH_DATA_ROOT: &str = "../runs";
const GRAPH_SNAPSHOT_VERSION: &str = "v1";
const README_VIEWER_URL: &str =
    "https://github.com/vyrus001/skillsissue.ai#interactive-telemetry-viewer";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildSummary {
    pub output: String,
    pub graph_output: String,
    pub scanned_skills: usize,
    pub published_graphs: usize,
    pub fallback_links: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Catalog {
    data_updated_at: Option<String>,
    total_scanned: usize,
    total_pending: usize,
    total_known: usize,
    published_graphs: usize,
    platforms: Vec<String>,
    finding_types: Vec<String>,
    skills: Vec<PublishedSkill>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublishedSkill {
    skill_id: String,
    name: String,
    detected_at: String,
    sha256: String,
    verdict: String,
    risk_score: Option<f64>,
    max_severity: String,
    coverage_state: String,
    assessed_at: Option<String>,
    run_id: Option<String>,
    platforms: Vec<PublishedPlatform>,
    detail_url: String,
    graph_available: bool,
    finding_count: usize,
    finding_types: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublishedPlatform {
    id: String,
    name: String,
    url: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StaticGraph {
    graph: GraphModel,
    assessment: PublishedAssessment,
    event_count: usize,
    event_page_size: usize,
    network_capture_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublishedAssessment {
    verdict: String,
    risk_score: f64,
    max_severity: String,
    coverage_state: String,
    assessed_at: String,
    findings: Vec<PublishedFinding>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublishedFinding {
    finding_id: String,
    rule_id: String,
    category: String,
    severity: String,
    source_marker: Option<String>,
    sink_kind: String,
    sink_value: String,
    evidence_seq_start: u64,
    evidence_seq_end: u64,
    summary: String,
}

const EVENT_PAGE_SIZE: usize = 100;
const MAX_STATIC_NETWORK_RECORDS: usize = 64;
const MAX_STATIC_NETWORK_BYTES: usize = 96 * 1024 * 1024;
const MAX_STATIC_NETWORK_LINE_BYTES: usize = 24 * 1024 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StaticNetworkIndex {
    capture_count: usize,
    published_capture_count: usize,
    publication_truncated: bool,
    captures: Vec<StaticNetworkSummary>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StaticNetworkSummary {
    id: usize,
    sequence: Option<u64>,
    recorded_at_unix_ms: Option<String>,
    method: String,
    url: String,
    status: Option<u64>,
    response_bytes: u64,
    body_sha256: Option<String>,
    failure: Option<String>,
    tls_intercepted: bool,
    capture_truncated: bool,
    detail_url: String,
}

pub fn build(repo_root: &Path, output: &Path, max_published_events: usize) -> Result<BuildSummary> {
    build_internal(
        repo_root,
        output,
        None,
        LOCAL_GRAPH_DATA_ROOT,
        max_published_events,
    )
}

pub fn build_with_graph_store(
    repo_root: &Path,
    output: &Path,
    graph_output: &Path,
    graph_base_url: &str,
    max_published_events: usize,
) -> Result<BuildSummary> {
    let graph_base_url = validated_graph_base_url(graph_base_url)?;
    ensure!(
        graph_output != output && !graph_output.starts_with(output),
        "graph-output must be outside the deployable site output"
    );
    build_internal(
        repo_root,
        output,
        Some(graph_output),
        &graph_base_url,
        max_published_events,
    )
}

fn build_internal(
    repo_root: &Path,
    output: &Path,
    separate_graph_output: Option<&Path>,
    graph_base_url: &str,
    max_published_events: usize,
) -> Result<BuildSummary> {
    ensure!(
        max_published_events > 0,
        "max-published-events must be positive"
    );
    prepare_output(repo_root, output)?;
    if let Some(graph_output) = separate_graph_output {
        prepare_output(repo_root, graph_output)?;
    }
    let graph_output = separate_graph_output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| output.join("runs"));
    let compress_graphs = separate_graph_output.is_some();

    let data = repo_root.join("data");
    let skills: Vec<SkillRecord> = read_csv_records(data.join("skills.csv"))?;
    let discoveries: Vec<DiscoveryRecord> = read_csv_records(data.join("discoveries.csv"))?;
    let platforms: Vec<PlatformRecord> = read_csv_records(data.join("platforms.csv"))?;
    let runs: Vec<RunRecord> = read_csv_records(data.join("runs.csv"))?;
    let assessments: Vec<AssessmentRecord> = read_csv_records(data.join("assessments.csv"))?;
    let findings: Vec<FindingRecord> = read_csv_records(data.join("findings.csv"))?;

    let platforms_by_id = platforms
        .iter()
        .map(|platform| (platform.platform_id.as_str(), platform))
        .collect::<BTreeMap<_, _>>();
    let runs_by_id = runs
        .iter()
        .map(|run| (run.run_id.as_str(), run))
        .collect::<BTreeMap<_, _>>();
    let discoveries_by_skill = group_discoveries(&discoveries);
    let findings_by_run = group_findings(&findings);
    let latest = latest_assessments(&assessments);

    write_asset(output.join("index.html"), SITE_INDEX)?;
    write_asset(output.join("app.js"), SITE_JS)?;
    write_asset(output.join("style.css"), SITE_CSS)?;
    write_asset(output.join(".nojekyll"), "")?;
    write_asset(output.join("graph/index.html"), GRAPH_INDEX)?;
    write_asset(output.join("graph/app.js"), GRAPH_JS)?;
    write_asset(output.join("graph/style.css"), GRAPH_CSS)?;
    write_asset(
        output.join("graph/config.js"),
        &graph_config(graph_base_url)?,
    )?;
    fs::create_dir_all(&graph_output)?;

    let mut published = Vec::new();
    let mut published_graphs = 0_usize;
    let mut scanned_skills = 0_usize;
    let mut platform_names = BTreeSet::new();
    let mut finding_types = BTreeSet::new();

    let graph_availability = skills
        .par_iter()
        .map(|skill| {
            let graph_available = match latest.get(skill.skill_id.as_str()).copied() {
                Some(assessment) => match runs_by_id.get(assessment.run_id.as_str()).copied() {
                    Some(run) => publish_graph(
                        repo_root,
                        &graph_output,
                        run,
                        assessment,
                        findings_by_run
                            .get(assessment.run_id.as_str())
                            .map(Vec::as_slice)
                            .unwrap_or_default(),
                        max_published_events,
                        compress_graphs,
                    )?,
                    None => false,
                },
                None => false,
            };
            Ok((skill.skill_id.clone(), graph_available))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    for skill in &skills {
        let assessment = latest.get(skill.skill_id.as_str()).copied();
        let platform_rows = discoveries_by_skill
            .get(skill.skill_id.as_str())
            .map(Vec::as_slice)
            .unwrap_or_default();
        let published_platforms = public_platforms(platform_rows, &platforms_by_id);
        platform_names.extend(
            published_platforms
                .iter()
                .map(|platform| platform.name.clone()),
        );

        let graph_available = if assessment.is_some() {
            scanned_skills += 1;
            graph_availability
                .get(skill.skill_id.as_str())
                .copied()
                .unwrap_or(false)
        } else {
            false
        };
        if graph_available {
            published_graphs += 1;
        }

        let (verdict, risk_score, max_severity, coverage_state, assessed_at, run_id) =
            if let Some(assessment) = assessment {
                (
                    assessment.verdict.clone(),
                    Some(assessment.risk_score),
                    assessment.max_severity.clone(),
                    assessment.coverage_state.clone(),
                    Some(assessment.assessed_at.clone()),
                    Some(assessment.run_id.clone()),
                )
            } else {
                (
                    "pending-scan".to_string(),
                    None,
                    "not-assessed".to_string(),
                    "pending".to_string(),
                    None,
                    None,
                )
            };

        let finding_count = assessment
            .and_then(|assessment| findings_by_run.get(assessment.run_id.as_str()))
            .map_or(0, Vec::len);
        let skill_finding_types = assessment
            .and_then(|assessment| findings_by_run.get(assessment.run_id.as_str()))
            .map(|findings| {
                findings
                    .iter()
                    .map(|finding| finding.summary.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        finding_types.extend(skill_finding_types.iter().cloned());
        published.push(PublishedSkill {
            skill_id: skill.skill_id.clone(),
            name: skill
                .name
                .clone()
                .unwrap_or_else(|| "Unnamed skill".to_string()),
            detected_at: skill.first_seen_at.clone(),
            sha256: skill.sha256.clone(),
            verdict,
            risk_score,
            max_severity,
            coverage_state,
            assessed_at,
            run_id,
            platforms: published_platforms,
            detail_url: assessment
                .filter(|_| graph_available)
                .map(|assessment| {
                    let view = if finding_count > 0 {
                        "&view=findings"
                    } else {
                        ""
                    };
                    format!(
                        "./graph/?run={}&snapshot={}{}",
                        assessment.run_id,
                        assessment_snapshot_id(&assessment.assessment_id)
                            .expect("validated assessment ID used for published graph"),
                        view
                    )
                })
                .unwrap_or_else(|| README_VIEWER_URL.to_string()),
            graph_available,
            finding_count,
            finding_types: skill_finding_types,
        });
    }

    published.sort_by(|left, right| {
        right
            .detected_at
            .cmp(&left.detected_at)
            .then_with(|| left.name.cmp(&right.name))
    });
    let data_updated_at = skills
        .iter()
        .map(|skill| skill.last_seen_at.as_str())
        .chain(
            assessments
                .iter()
                .map(|assessment| assessment.assessed_at.as_str()),
        )
        .max()
        .map(str::to_owned);
    let catalog = Catalog {
        data_updated_at,
        total_scanned: scanned_skills,
        total_pending: published.len().saturating_sub(scanned_skills),
        total_known: skills.len(),
        published_graphs,
        platforms: platform_names.into_iter().collect(),
        finding_types: finding_types.into_iter().collect(),
        skills: published,
    };
    write_json(output.join("skills.json"), &catalog)?;

    Ok(BuildSummary {
        output: output.display().to_string(),
        graph_output: graph_output.display().to_string(),
        scanned_skills: catalog.total_scanned,
        published_graphs,
        fallback_links: scanned_skills.saturating_sub(published_graphs),
    })
}

fn prepare_output(repo_root: &Path, output: &Path) -> Result<()> {
    ensure!(
        output != repo_root && output.components().next().is_some(),
        "refusing to replace the repository root"
    );
    if let Ok(metadata) = fs::symlink_metadata(output) {
        ensure!(
            !metadata.file_type().is_symlink(),
            "output must not be a symlink"
        );
        ensure!(metadata.is_dir(), "output exists and is not a directory");
        fs::remove_dir_all(output)
            .with_context(|| format!("clearing generated site {}", output.display()))?;
    }
    fs::create_dir_all(output)
        .with_context(|| format!("creating generated site {}", output.display()))
}

fn group_discoveries(discoveries: &[DiscoveryRecord]) -> BTreeMap<&str, Vec<&DiscoveryRecord>> {
    let mut grouped: BTreeMap<&str, Vec<&DiscoveryRecord>> = BTreeMap::new();
    for discovery in discoveries {
        grouped
            .entry(discovery.skill_id.as_str())
            .or_default()
            .push(discovery);
    }
    grouped
}

fn latest_assessments(assessments: &[AssessmentRecord]) -> BTreeMap<&str, &AssessmentRecord> {
    let mut latest = BTreeMap::new();
    for assessment in assessments {
        latest
            .entry(assessment.skill_id.as_str())
            .and_modify(|current: &mut &AssessmentRecord| {
                if assessment.assessed_at > current.assessed_at {
                    *current = assessment;
                }
            })
            .or_insert(assessment);
    }
    latest
}

fn group_findings(findings: &[FindingRecord]) -> BTreeMap<&str, Vec<&FindingRecord>> {
    let mut grouped: BTreeMap<&str, Vec<&FindingRecord>> = BTreeMap::new();
    for finding in findings {
        grouped
            .entry(finding.run_id.as_str())
            .or_default()
            .push(finding);
    }
    for rows in grouped.values_mut() {
        rows.sort_by(|left, right| {
            severity_rank(&right.severity)
                .cmp(&severity_rank(&left.severity))
                .then_with(|| left.evidence_seq_start.cmp(&right.evidence_seq_start))
                .then_with(|| left.finding_id.cmp(&right.finding_id))
        });
    }
    grouped
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn published_assessment(
    assessment: &AssessmentRecord,
    findings: &[&FindingRecord],
) -> PublishedAssessment {
    PublishedAssessment {
        verdict: assessment.verdict.clone(),
        risk_score: assessment.risk_score,
        max_severity: assessment.max_severity.clone(),
        coverage_state: assessment.coverage_state.clone(),
        assessed_at: assessment.assessed_at.clone(),
        findings: findings
            .iter()
            .map(|finding| PublishedFinding {
                finding_id: finding.finding_id.clone(),
                rule_id: finding.rule_id.clone(),
                category: finding.category.clone(),
                severity: finding.severity.clone(),
                source_marker: finding.source_marker.clone(),
                sink_kind: finding.sink_kind.clone(),
                sink_value: finding.sink_value.clone(),
                evidence_seq_start: finding.evidence_seq_start,
                evidence_seq_end: finding.evidence_seq_end,
                summary: finding.summary.clone(),
            })
            .collect(),
    }
}

fn public_platforms(
    discoveries: &[&DiscoveryRecord],
    platforms: &BTreeMap<&str, &PlatformRecord>,
) -> Vec<PublishedPlatform> {
    let mut rows = BTreeMap::new();
    for discovery in discoveries {
        let name = platforms
            .get(discovery.platform_id.as_str())
            .map(|platform| platform.display_name.as_str())
            .unwrap_or(discovery.platform_id.as_str());
        rows.entry(discovery.platform_id.as_str())
            .or_insert_with(|| PublishedPlatform {
                id: discovery.platform_id.clone(),
                name: name.to_string(),
                url: public_http_url(
                    platforms
                        .get(discovery.platform_id.as_str())
                        .map(|platform| platform.base_url.as_str())
                        .unwrap_or_default(),
                    Some(&discovery.source_url),
                ),
            });
    }
    rows.into_values().collect()
}

fn publish_graph(
    repo_root: &Path,
    graph_output: &Path,
    run: &RunRecord,
    assessment: &AssessmentRecord,
    findings: &[&FindingRecord],
    max_published_events: usize,
    compress: bool,
) -> Result<bool> {
    ensure!(safe_run_id(&run.run_id), "unsafe run ID: {}", run.run_id);
    let snapshot_id = assessment_snapshot_id(&assessment.assessment_id)
        .context("assessment ID is unsafe for static publication")?;
    let Some(telemetry_path) = run.telemetry_path.as_deref() else {
        return Ok(false);
    };
    if run
        .event_count
        .is_some_and(|count| count > max_published_events as u64)
    {
        return Ok(false);
    }
    let relative = Path::new(telemetry_path);
    if !safe_telemetry_path(relative) {
        bail!("unsafe telemetry path for {}: {telemetry_path}", run.run_id);
    }
    let event_path = repo_root.join(relative);
    if !event_path.is_file() {
        return Ok(false);
    }
    let run_directory = event_path
        .parent()
        .context("telemetry path has no run directory")?;
    let limits = LoadLimits {
        max_events: max_published_events,
        ..LoadLimits::default()
    };
    let trace = normalize(load(run_directory, limits)?);
    ensure!(
        trace.events.len() <= max_published_events,
        "{} exceeds the static publication event limit",
        run.run_id
    );
    let graph = build_graph(&trace, GraphSettings::default());
    ensure!(
        graph.represented_event_count == trace.events.len(),
        "{} graph omits parsed events",
        run.run_id
    );
    let run_output = graph_output.join(&run.run_id).join(snapshot_id);
    fs::create_dir_all(run_output.join("events"))?;
    let network_capture_count =
        publish_network_captures_with_format(run_directory, &run_output, compress)?;
    write_json_with_format(
        run_output.join("graph.json"),
        &StaticGraph {
            graph,
            assessment: published_assessment(assessment, findings),
            event_count: trace.events.len(),
            event_page_size: EVENT_PAGE_SIZE,
            network_capture_count,
        },
        compress,
    )?;
    for (page, events) in trace.events.chunks(EVENT_PAGE_SIZE).enumerate() {
        write_json_with_format(
            run_output.join("events").join(format!("{page}.json")),
            events,
            compress,
        )?;
    }
    Ok(true)
}

#[cfg(test)]
fn publish_network_captures(run_directory: &Path, run_output: &Path) -> Result<usize> {
    publish_network_captures_with_format(run_directory, run_output, false)
}

fn publish_network_captures_with_format(
    run_directory: &Path,
    run_output: &Path,
    compress: bool,
) -> Result<usize> {
    let transcript = run_directory.join("network.jsonl.zst");
    if !transcript.is_file() {
        return Ok(0);
    }
    let decoder = zstd::Decoder::new(File::open(&transcript)?)
        .context("open compressed network transcript")?;
    let mut captures = Vec::new();
    let mut capture_count = 0_usize;
    let mut publication_truncated = false;
    let mut decoded_bytes = 0_usize;
    for line in BufReader::new(decoder).lines() {
        let line = line.context("read network transcript line")?;
        decoded_bytes = decoded_bytes
            .checked_add(line.len() + 1)
            .context("network transcript byte count overflow")?;
        ensure!(
            decoded_bytes <= MAX_STATIC_NETWORK_BYTES,
            "network transcript exceeds the static publication byte limit"
        );
        ensure!(
            line.len() <= MAX_STATIC_NETWORK_LINE_BYTES,
            "network transcript record exceeds the static publication line limit"
        );
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(&line).context("parse network transcript record")?;
        if value.get("capture").and_then(serde_json::Value::as_str)
            != Some("intercepted-http-egress")
        {
            continue;
        }
        capture_count = capture_count
            .checked_add(1)
            .context("network capture count overflow")?;
        if captures.len() >= MAX_STATIC_NETWORK_RECORDS {
            publication_truncated = true;
            continue;
        }
        let response = value
            .get("response")
            .context("egress transcript record has no response object")?;
        let body = response
            .get("body_base64")
            .and_then(serde_json::Value::as_str)
            .context("egress transcript record has no response body evidence")?;
        ensure!(
            body.len() <= MAX_STATIC_NETWORK_LINE_BYTES,
            "egress response evidence exceeds the static publication body limit"
        );

        let id = captures.len() + 1;
        let detail_url = format!("network/{id}.json");
        fs::create_dir_all(run_output.join("network"))?;
        write_json_with_format(run_output.join(&detail_url), &value, compress)?;
        captures.push(StaticNetworkSummary {
            id,
            sequence: value.get("sequence").and_then(serde_json::Value::as_u64),
            recorded_at_unix_ms: value
                .get("recorded_at_unix_ms")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            method: value
                .get("method")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            url: value
                .get("url")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            status: response.get("status").and_then(serde_json::Value::as_u64),
            response_bytes: response
                .get("original_bytes")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            body_sha256: response
                .get("body_sha256")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            failure: value
                .get("failure")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            tls_intercepted: value
                .get("tls_intercepted")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            capture_truncated: response
                .get("capture_truncated")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true),
            detail_url,
        });
    }
    if capture_count == 0 {
        return Ok(0);
    }
    let published_capture_count = captures.len();
    write_json_with_format(
        run_output.join("network/index.json"),
        &StaticNetworkIndex {
            capture_count,
            published_capture_count,
            publication_truncated,
            captures,
        },
        compress,
    )?;
    Ok(capture_count)
}

fn safe_telemetry_path(path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(Component::Normal(first)) if first == "telemetry")
        && components.all(|component| matches!(component, Component::Normal(_)))
}

fn safe_run_id(run_id: &str) -> bool {
    run_id.strip_prefix("run_").is_some_and(|value| {
        value.len() == 24 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn assessment_snapshot_id(assessment_id: &str) -> Option<String> {
    let digest = assessment_id.strip_prefix("assessment:v1:")?;
    (digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| format!("{GRAPH_SNAPSHOT_VERSION}-{}", digest.to_ascii_lowercase()))
}

fn validated_graph_base_url(candidate: &str) -> Result<String> {
    let mut parsed = Url::parse(candidate).context("graph-base-url must be an absolute URL")?;
    ensure!(parsed.scheme() == "https", "graph-base-url must use HTTPS");
    ensure!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "graph-base-url must not contain credentials"
    );
    ensure!(
        parsed.query().is_none() && parsed.fragment().is_none(),
        "graph-base-url must not contain a query or fragment"
    );
    let path = parsed.path().trim_end_matches('/').to_string();
    parsed.set_path(&path);
    Ok(parsed.into())
}

fn graph_config(data_root: &str) -> Result<String> {
    Ok(format!(
        "window.SKILLSISSUE_VIEWER = {{\n  mode: \"static\",\n  dataRoot: {},\n  indexUrl: \"../\"\n}};\n",
        serde_json::to_string(data_root)?
    ))
}

fn public_http_url(candidate: &str, fallback: Option<&str>) -> String {
    [Some(candidate), fallback]
        .into_iter()
        .flatten()
        .find_map(|value| {
            let parsed = Url::parse(value).ok()?;
            let safe = matches!(parsed.scheme(), "http" | "https")
                && parsed.username().is_empty()
                && parsed.password().is_none();
            safe.then(|| parsed.into())
        })
        .unwrap_or_else(|| "#".to_string())
}

fn write_asset(path: PathBuf, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, contents).with_context(|| format!("writing {}", path.display()))
}

fn write_json<T: Serialize + ?Sized>(path: PathBuf, value: &T) -> Result<()> {
    write_json_with_format(path, value, false)
}

fn write_json_with_format<T: Serialize + ?Sized>(
    path: PathBuf,
    value: &T,
    compress: bool,
) -> Result<()> {
    let file = File::create(&path).with_context(|| format!("creating {}", path.display()))?;
    if compress {
        let mut writer = GzEncoder::new(BufWriter::new(file), Compression::fast());
        serde_json::to_writer(&mut writer, value)
            .with_context(|| format!("serializing {}", path.display()))?;
        writer.write_all(b"\n")?;
        let mut writer = writer.finish()?;
        writer.flush()?;
    } else {
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, value)
            .with_context(|| format!("serializing {}", path.display()))?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_STATIC_NETWORK_RECORDS, README_VIEWER_URL, assessment_snapshot_id, build,
        build_with_graph_store, graph_config, public_http_url, public_platforms,
        publish_network_captures, published_assessment, safe_run_id, safe_telemetry_path,
        validated_graph_base_url, write_json_with_format,
    };
    use flate2::read::GzDecoder;
    use serde_json::Value;
    use skills_core::{
        AssessmentRecord, DiscoveryRecord, FindingRecord, PlatformRecord, RunRecord, SkillRecord,
        write_csv_records_atomic,
    };
    use std::{
        collections::BTreeMap,
        fs,
        io::{Cursor, Read},
        path::Path,
    };

    #[test]
    fn static_publication_accepts_only_repository_telemetry_paths() {
        assert!(safe_telemetry_path(Path::new(
            "telemetry/2026/07/22/run_deadbeef/events.jsonl.zst"
        )));
        assert!(!safe_telemetry_path(Path::new(
            "../telemetry/events.jsonl.zst"
        )));
        assert!(!safe_telemetry_path(Path::new("data/events.jsonl.zst")));
        assert!(!safe_telemetry_path(Path::new(
            "telemetry/run/../../data/skills.csv"
        )));
    }

    #[test]
    fn public_links_and_run_ids_are_safe_for_static_assets() {
        assert!(safe_run_id("run_7108802c8540f41dfc0761d8"));
        assert!(!safe_run_id("run_../../skills"));
        assert_eq!(
            public_http_url("javascript:alert(1)", Some("https://clawhub.ai")),
            "https://clawhub.ai/"
        );
        assert_eq!(public_http_url("file:///tmp/data", None), "#");
    }

    #[test]
    fn external_graph_configuration_is_https_and_content_versioned() {
        let digest = "a".repeat(64);
        assert_eq!(
            assessment_snapshot_id(&format!("assessment:v1:{digest}")),
            Some(format!("v1-{digest}"))
        );
        assert!(assessment_snapshot_id("assessment:v1:../../data").is_none());
        assert_eq!(
            validated_graph_base_url("https://graphs.skillsissue.ai/runs/")
                .expect("valid graph base URL"),
            "https://graphs.skillsissue.ai/runs"
        );
        assert!(validated_graph_base_url("http://graphs.skillsissue.ai/runs").is_err());
        assert_eq!(
            graph_config("https://graphs.skillsissue.ai/runs")
                .expect("serialized graph configuration"),
            concat!(
                "window.SKILLSISSUE_VIEWER = {\n",
                "  mode: \"static\",\n",
                "  dataRoot: \"https://graphs.skillsissue.ai/runs\",\n",
                "  indexUrl: \"../\"\n",
                "};\n"
            )
        );
    }

    #[test]
    fn external_graph_objects_are_valid_gzip_json() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("graph.json");
        write_json_with_format(path.clone(), &serde_json::json!({"ok": true}), true)
            .expect("compressed JSON");
        let mut decoded = String::new();
        GzDecoder::new(fs::File::open(path).expect("compressed graph"))
            .read_to_string(&mut decoded)
            .expect("decode graph");
        assert_eq!(decoded, "{\"ok\":true}\n");
    }

    #[test]
    fn external_graph_store_stays_outside_the_pages_artifact() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let repo_root = temporary.path().join("repository");
        let data = repo_root.join("data");
        let run_id = "run_0123456789abcdef01234567";
        let skill_id = "sha256:v1:fixture";
        let assessment_digest = "c".repeat(64);
        let assessment_id = format!("assessment:v1:{assessment_digest}");
        let telemetry_relative = format!("telemetry/2026/08/02/{run_id}/events.jsonl.zst");
        let telemetry_file = repo_root.join(&telemetry_relative);
        let output = temporary.path().join("site");
        let graph_output = temporary.path().join("graph-store");
        fs::create_dir_all(&data).expect("data directory");
        fs::create_dir_all(telemetry_file.parent().expect("telemetry parent"))
            .expect("telemetry directory");
        fs::write(
            &telemetry_file,
            zstd::stream::encode_all(
                Cursor::new(
                    b"{\"skillsissuePhase\":\"detonation\",\"eventName\":\"execve\",\"processId\":1}\n",
                ),
                1,
            )
            .expect("telemetry compression"),
        )
        .expect("telemetry fixture");
        write_csv_records_atomic::<SkillRecord, _>(
            data.join("skills.csv"),
            [SkillRecord {
                schema_version: 1,
                skill_id: skill_id.to_string(),
                sha256: "a".repeat(64),
                blake3: "b".repeat(64),
                canonicalization_version: 1,
                name: Some("Published example".to_string()),
                publisher: None,
                declared_version: None,
                entrypoint: None,
                license: None,
                size_bytes: 1,
                file_count: 1,
                bundle_path: "corpus/example/bundle.tar.zst".to_string(),
                manifest_path: "corpus/example/manifest.json".to_string(),
                first_seen_at: "2026-08-02T00:00:00Z".to_string(),
                last_seen_at: "2026-08-02T00:00:00Z".to_string(),
            }],
        )
        .expect("skills CSV");
        write_csv_records_atomic::<RunRecord, _>(
            data.join("runs.csv"),
            [RunRecord {
                schema_version: 1,
                run_id: run_id.to_string(),
                run_key: "fixture".to_string(),
                skill_id: skill_id.to_string(),
                status: "captured".to_string(),
                scenario: "default".to_string(),
                seed: 0,
                queued_at: "2026-08-02T00:00:00Z".to_string(),
                started_at: Some("2026-08-02T00:00:00Z".to_string()),
                finished_at: Some("2026-08-02T00:00:01Z".to_string()),
                harness_version: "fixture".to_string(),
                policy_sha256: "d".repeat(64),
                agent_adapter: "fixture".to_string(),
                agent_model: "none".to_string(),
                target_image_digest: "sha256:fixture".to_string(),
                skillject_commit: "fixture".to_string(),
                telemetry_path: Some(telemetry_relative),
                event_count: Some(1),
                exit_code: Some(0),
                termination_reason: Some("completed".to_string()),
                closure_lift_count: Some(0),
                taint_coverage: Some(1.0),
            }],
        )
        .expect("runs CSV");
        write_csv_records_atomic::<AssessmentRecord, _>(
            data.join("assessments.csv"),
            [AssessmentRecord {
                schema_version: 1,
                assessment_id,
                run_id: run_id.to_string(),
                skill_id: skill_id.to_string(),
                verdict: "benign".to_string(),
                risk_score: 0.0,
                max_severity: "none".to_string(),
                confidentiality_findings: 0,
                integrity_findings: 0,
                behavioral_findings: 0,
                unknown_platform_interaction: false,
                unknown_platform_count: 0,
                coverage_state: "complete".to_string(),
                policy_version: "fixture".to_string(),
                analyzer_version: "fixture".to_string(),
                assessed_at: "2026-08-02T00:00:02Z".to_string(),
            }],
        )
        .expect("assessments CSV");

        let summary = build_with_graph_store(
            &repo_root,
            &output,
            &graph_output,
            "https://graphs.skillsissue.ai/runs",
            100,
        )
        .expect("external graph build");
        let catalog: Value = serde_json::from_slice(
            &fs::read(output.join("skills.json")).expect("generated catalog"),
        )
        .expect("catalog JSON");
        let snapshot = format!("v1-{assessment_digest}");

        assert_eq!(summary.published_graphs, 1);
        assert!(!output.join("runs").exists());
        assert_eq!(
            catalog["skills"][0]["detailUrl"],
            format!("./graph/?run={run_id}&snapshot={snapshot}")
        );
        assert!(
            graph_output
                .join(run_id)
                .join(snapshot)
                .join("graph.json")
                .is_file()
        );
        assert_eq!(
            fs::read_to_string(output.join("graph/config.js")).expect("graph configuration"),
            graph_config("https://graphs.skillsissue.ai/runs").expect("expected configuration")
        );
    }

    #[test]
    fn platform_badges_prefer_the_public_storefront_over_raw_sources() {
        let platform = PlatformRecord {
            schema_version: 1,
            platform_id: "clawhub".to_string(),
            display_name: "ClawHub".to_string(),
            canonical_domain: "clawhub.ai".to_string(),
            base_url: "https://clawhub.ai".to_string(),
            ingest_uri: "https://clawhub.ai/api/v1/skills/example/download".to_string(),
            adapter: "clawhub_api".to_string(),
            status: "supported".to_string(),
            enabled: true,
            discovery_method: "api_catalog".to_string(),
            confidence: 1.0,
            first_seen_at: None,
            last_seen_at: None,
            rate_limit_per_minute: Some(60),
            terms_url: None,
            evidence_url: None,
            notes: None,
        };
        let discovery = DiscoveryRecord {
            schema_version: 1,
            discovery_id: "discovery_fixture".to_string(),
            skill_id: "skill_fixture".to_string(),
            platform_id: platform.platform_id.clone(),
            source_native_id: "example".to_string(),
            source_url: "https://clawhub.ai/api/v1/skills/example/download".to_string(),
            source_revision: None,
            source_path: Some("SKILL.md".to_string()),
            etag: None,
            publisher_display: None,
            published_at: None,
            first_seen_at: "2026-07-31T00:00:00Z".to_string(),
            last_seen_at: "2026-07-31T00:00:00Z".to_string(),
            ingest_run_id: "ingest_fixture".to_string(),
            adapter_version: "fixture".to_string(),
        };
        let platforms = BTreeMap::from([(platform.platform_id.as_str(), &platform)]);

        let published = public_platforms(&[&discovery], &platforms);

        assert_eq!(published.len(), 1);
        assert_eq!(published[0].url, "https://clawhub.ai/");
    }

    #[test]
    fn static_assessment_publishes_rule_explanations_and_event_ranges() {
        let assessment = AssessmentRecord {
            schema_version: 1,
            assessment_id: "assessment_fixture".to_string(),
            run_id: "run_deadbeef".to_string(),
            skill_id: "skill_fixture".to_string(),
            verdict: "malicious".to_string(),
            risk_score: 100.0,
            max_severity: "critical".to_string(),
            confidentiality_findings: 1,
            integrity_findings: 0,
            behavioral_findings: 0,
            unknown_platform_interaction: false,
            unknown_platform_count: 0,
            coverage_state: "complete".to_string(),
            policy_version: "fixture".to_string(),
            analyzer_version: "fixture".to_string(),
            assessed_at: "2026-07-31T00:00:00Z".to_string(),
        };
        let finding = FindingRecord {
            schema_version: 1,
            finding_id: "finding_fixture".to_string(),
            run_id: assessment.run_id.clone(),
            rule_id: "confidentiality.fixture".to_string(),
            category: "confidentiality".to_string(),
            severity: "critical".to_string(),
            source_marker: Some("/root/.ssh/id_ed25519".to_string()),
            sink_kind: "network".to_string(),
            sink_value: "example.test".to_string(),
            evidence_seq_start: 41,
            evidence_seq_end: 57,
            summary: "Sensitive material reached an untrusted endpoint".to_string(),
        };

        let published = serde_json::to_value(published_assessment(&assessment, &[&finding]))
            .expect("published assessment JSON");
        assert_eq!(published["verdict"], "malicious");
        assert_eq!(
            published["findings"][0]["ruleId"],
            "confidentiality.fixture"
        );
        assert_eq!(published["findings"][0]["evidenceSeqStart"], 41);
        assert_eq!(published["findings"][0]["evidenceSeqEnd"], 57);
        assert_eq!(
            published["findings"][0]["sourceMarker"],
            "/root/.ssh/id_ed25519"
        );
    }

    #[test]
    fn static_network_publication_keeps_exact_response_evidence_separate() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let run_directory = temporary.path().join("run");
        let run_output = temporary.path().join("site-run");
        fs::create_dir_all(&run_directory).expect("run directory");
        fs::create_dir_all(&run_output).expect("output directory");
        let records = concat!(
            "{\"capture\":\"provider-relay\",\"response\":{\"body_base64\":\"ignored\"}}\n",
            "{\"capture\":\"intercepted-http-egress\",\"sequence\":1,\"recorded_at_unix_ms\":\"10\",",
            "\"method\":\"GET\",\"url\":\"https://example.test/tool\",\"tls_intercepted\":true,",
            "\"failure\":null,\"request\":{\"headers\":[],\"body_base64\":\"\"},",
            "\"response\":{\"status\":200,\"headers\":[[\"content-type\",\"application/octet-stream\"]],",
            "\"body_base64\":\"dG9vbA==\",\"body_sha256\":\"fixture\",\"original_bytes\":4,",
            "\"capture_truncated\":false}}\n"
        );
        let compressed =
            zstd::stream::encode_all(Cursor::new(records.as_bytes()), 1).expect("compression");
        fs::write(run_directory.join("network.jsonl.zst"), compressed).expect("transcript");

        assert_eq!(
            publish_network_captures(&run_directory, &run_output).expect("publication"),
            1
        );
        let index: Value = serde_json::from_slice(
            &fs::read(run_output.join("network/index.json")).expect("network index"),
        )
        .expect("index JSON");
        let detail: Value = serde_json::from_slice(
            &fs::read(run_output.join("network/1.json")).expect("network detail"),
        )
        .expect("detail JSON");
        assert_eq!(index["captureCount"], 1);
        assert_eq!(index["publishedCaptureCount"], 1);
        assert_eq!(index["publicationTruncated"], false);
        assert_eq!(index["captures"][0]["responseBytes"], 4);
        assert_eq!(detail["response"]["body_base64"], "dG9vbA==");
    }

    #[test]
    fn static_network_publication_bounds_details_without_hiding_total_count() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let run_directory = temporary.path().join("run");
        let run_output = temporary.path().join("site-run");
        fs::create_dir_all(&run_directory).expect("run directory");
        fs::create_dir_all(&run_output).expect("output directory");
        let record_count = MAX_STATIC_NETWORK_RECORDS + 1;
        let records = (1..=record_count)
            .map(|sequence| {
                serde_json::to_string(&serde_json::json!({
                    "capture": "intercepted-http-egress",
                    "sequence": sequence,
                    "method": "GET",
                    "url": format!("https://example.test/{sequence}"),
                    "tls_intercepted": true,
                    "failure": "request_limit_exceeded",
                    "response": {
                        "status": 429,
                        "body_base64": "",
                        "body_sha256": "fixture",
                        "original_bytes": 0,
                        "capture_truncated": false
                    }
                }))
                .expect("network record JSON")
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let compressed =
            zstd::stream::encode_all(Cursor::new(records.as_bytes()), 1).expect("compression");
        fs::write(run_directory.join("network.jsonl.zst"), compressed).expect("transcript");

        assert_eq!(
            publish_network_captures(&run_directory, &run_output).expect("publication"),
            record_count
        );
        let index: Value = serde_json::from_slice(
            &fs::read(run_output.join("network/index.json")).expect("network index"),
        )
        .expect("index JSON");
        assert_eq!(index["captureCount"], record_count);
        assert_eq!(index["publishedCaptureCount"], MAX_STATIC_NETWORK_RECORDS);
        assert_eq!(index["publicationTruncated"], true);
        assert_eq!(
            index["captures"]
                .as_array()
                .expect("capture summaries")
                .len(),
            MAX_STATIC_NETWORK_RECORDS
        );
        assert!(
            !run_output
                .join("network")
                .join(format!("{}.json", MAX_STATIC_NETWORK_RECORDS + 1))
                .exists()
        );
    }

    #[test]
    fn unassessed_skills_are_published_as_pending() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let repo_root = temporary.path().join("repository");
        let data = repo_root.join("data");
        let output = temporary.path().join("site");
        fs::create_dir_all(&data).expect("data directory");
        write_csv_records_atomic::<SkillRecord, _>(
            data.join("skills.csv"),
            [SkillRecord {
                schema_version: 1,
                skill_id: "skill_pending".to_string(),
                sha256: "a".repeat(64),
                blake3: "b".repeat(64),
                canonicalization_version: 1,
                name: Some("Pending example".to_string()),
                publisher: None,
                declared_version: None,
                entrypoint: None,
                license: None,
                size_bytes: 1,
                file_count: 1,
                bundle_path: "corpus/pending/bundle.tar.zst".to_string(),
                manifest_path: "corpus/pending/manifest.json".to_string(),
                first_seen_at: "2026-07-24T01:00:00Z".to_string(),
                last_seen_at: "2026-07-24T02:00:00Z".to_string(),
            }],
        )
        .expect("skills CSV");

        let summary = build(&repo_root, &output, 100).expect("site build");
        let catalog: Value = serde_json::from_slice(
            &fs::read(output.join("skills.json")).expect("generated catalog"),
        )
        .expect("catalog JSON");
        let skill = &catalog["skills"][0];

        assert_eq!(summary.scanned_skills, 0);
        assert_eq!(catalog["totalKnown"], 1);
        assert_eq!(catalog["totalScanned"], 0);
        assert_eq!(catalog["totalPending"], 1);
        assert_eq!(catalog["dataUpdatedAt"], "2026-07-24T02:00:00Z");
        assert_eq!(skill["verdict"], "pending-scan");
        assert!(skill["riskScore"].is_null());
        assert!(skill["assessedAt"].is_null());
        assert!(skill["runId"].is_null());
        assert_eq!(skill["detailUrl"], README_VIEWER_URL);
        assert_eq!(skill["graphAvailable"], false);
    }
}
