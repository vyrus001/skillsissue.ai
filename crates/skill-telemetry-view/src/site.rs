use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use skills_core::{
    AssessmentRecord, DiscoveryRecord, PlatformRecord, RunRecord, SkillRecord, read_csv_records,
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
const GRAPH_CONFIG: &str = r#"window.SKILLSISSUE_VIEWER = {
  mode: "static",
  dataRoot: "../runs",
  indexUrl: "../"
};
"#;
const README_VIEWER_URL: &str =
    "https://github.com/vyrus001/skillsissue.ai#interactive-telemetry-viewer";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildSummary {
    pub output: String,
    pub scanned_skills: usize,
    pub published_graphs: usize,
    pub fallback_links: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Catalog {
    data_updated_at: Option<String>,
    total_scanned: usize,
    total_known: usize,
    published_graphs: usize,
    platforms: Vec<String>,
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
    risk_score: f64,
    max_severity: String,
    coverage_state: String,
    assessed_at: String,
    run_id: String,
    platforms: Vec<PublishedPlatform>,
    detail_url: String,
    graph_available: bool,
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
    event_count: usize,
    event_page_size: usize,
}

const EVENT_PAGE_SIZE: usize = 100;

pub fn build(repo_root: &Path, output: &Path, max_published_events: usize) -> Result<BuildSummary> {
    ensure!(
        max_published_events > 0,
        "max-published-events must be positive"
    );
    prepare_output(repo_root, output)?;

    let data = repo_root.join("data");
    let skills: Vec<SkillRecord> = read_csv_records(data.join("skills.csv"))?;
    let discoveries: Vec<DiscoveryRecord> = read_csv_records(data.join("discoveries.csv"))?;
    let platforms: Vec<PlatformRecord> = read_csv_records(data.join("platforms.csv"))?;
    let runs: Vec<RunRecord> = read_csv_records(data.join("runs.csv"))?;
    let assessments: Vec<AssessmentRecord> = read_csv_records(data.join("assessments.csv"))?;

    let skills_by_id = skills
        .iter()
        .map(|skill| (skill.skill_id.as_str(), skill))
        .collect::<BTreeMap<_, _>>();
    let platforms_by_id = platforms
        .iter()
        .map(|platform| (platform.platform_id.as_str(), platform))
        .collect::<BTreeMap<_, _>>();
    let runs_by_id = runs
        .iter()
        .map(|run| (run.run_id.as_str(), run))
        .collect::<BTreeMap<_, _>>();
    let discoveries_by_skill = group_discoveries(&discoveries);
    let latest = latest_assessments(&assessments);

    write_asset(output.join("index.html"), SITE_INDEX)?;
    write_asset(output.join("app.js"), SITE_JS)?;
    write_asset(output.join("style.css"), SITE_CSS)?;
    write_asset(output.join(".nojekyll"), "")?;
    write_asset(output.join("graph/index.html"), GRAPH_INDEX)?;
    write_asset(output.join("graph/app.js"), GRAPH_JS)?;
    write_asset(output.join("graph/style.css"), GRAPH_CSS)?;
    write_asset(output.join("graph/config.js"), GRAPH_CONFIG)?;
    fs::create_dir_all(output.join("runs"))?;

    let mut published = Vec::new();
    let mut published_graphs = 0_usize;
    let mut platform_names = BTreeSet::new();

    for assessment in latest.values() {
        let Some(skill) = skills_by_id.get(assessment.skill_id.as_str()).copied() else {
            continue;
        };
        let platform_rows = discoveries_by_skill
            .get(assessment.skill_id.as_str())
            .map(Vec::as_slice)
            .unwrap_or_default();
        let published_platforms = public_platforms(platform_rows, &platforms_by_id);
        platform_names.extend(
            published_platforms
                .iter()
                .map(|platform| platform.name.clone()),
        );

        let graph_available = match runs_by_id.get(assessment.run_id.as_str()).copied() {
            Some(run) => publish_graph(repo_root, output, run, max_published_events)?,
            None => false,
        };
        if graph_available {
            published_graphs += 1;
        }

        published.push(PublishedSkill {
            skill_id: skill.skill_id.clone(),
            name: skill
                .name
                .clone()
                .unwrap_or_else(|| "Unnamed skill".to_string()),
            detected_at: skill.first_seen_at.clone(),
            sha256: skill.sha256.clone(),
            verdict: assessment.verdict.clone(),
            risk_score: assessment.risk_score,
            max_severity: assessment.max_severity.clone(),
            coverage_state: assessment.coverage_state.clone(),
            assessed_at: assessment.assessed_at.clone(),
            run_id: assessment.run_id.clone(),
            platforms: published_platforms,
            detail_url: if graph_available {
                format!("./graph/?run={}", assessment.run_id)
            } else {
                README_VIEWER_URL.to_string()
            },
            graph_available,
        });
    }

    published.sort_by(|left, right| {
        right
            .detected_at
            .cmp(&left.detected_at)
            .then_with(|| left.name.cmp(&right.name))
    });
    let data_updated_at = published
        .iter()
        .map(|skill| skill.assessed_at.as_str())
        .max()
        .map(str::to_owned);
    let catalog = Catalog {
        data_updated_at,
        total_scanned: published.len(),
        total_known: skills.len(),
        published_graphs,
        platforms: platform_names.into_iter().collect(),
        skills: published,
    };
    write_json(output.join("skills.json"), &catalog)?;

    Ok(BuildSummary {
        output: output.display().to_string(),
        scanned_skills: catalog.total_scanned,
        published_graphs,
        fallback_links: catalog.total_scanned.saturating_sub(published_graphs),
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
                    &discovery.source_url,
                    platforms
                        .get(discovery.platform_id.as_str())
                        .map(|platform| platform.base_url.as_str()),
                ),
            });
    }
    rows.into_values().collect()
}

fn publish_graph(
    repo_root: &Path,
    output: &Path,
    run: &RunRecord,
    max_published_events: usize,
) -> Result<bool> {
    ensure!(safe_run_id(&run.run_id), "unsafe run ID: {}", run.run_id);
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
    let run_output = output.join("runs").join(&run.run_id);
    fs::create_dir_all(run_output.join("events"))?;
    write_json(
        run_output.join("graph.json"),
        &StaticGraph {
            graph,
            event_count: trace.events.len(),
            event_page_size: EVENT_PAGE_SIZE,
        },
    )?;
    for (page, events) in trace.events.chunks(EVENT_PAGE_SIZE).enumerate() {
        write_json(
            run_output.join("events").join(format!("{page}.json")),
            events,
        )?;
    }
    Ok(true)
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
    let file = File::create(&path).with_context(|| format!("creating {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, value)
        .with_context(|| format!("serializing {}", path.display()))?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{public_http_url, safe_run_id, safe_telemetry_path};
    use std::path::Path;

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
}
