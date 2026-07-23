use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Result, ensure};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use skill_telemetry_view::{GraphSettings, LoadLimits, build_graph, load, normalize};

#[derive(Debug, Parser)]
#[command(name = "skill-telemetry-view", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Load a run and serve the interactive viewer on loopback.
    Serve {
        /// A run directory, run.json, events.jsonl, or events.jsonl.zst.
        path: PathBuf,

        #[arg(long, default_value = "127.0.0.1")]
        host: IpAddr,

        /// Use 0 to ask the OS for an available port.
        #[arg(long, default_value_t = 8788)]
        port: u16,

        #[command(flatten)]
        limits: LimitArgs,
    },
    /// Validate and summarize a run without starting a server.
    Inspect {
        /// A run directory, run.json, events.jsonl, or events.jsonl.zst.
        path: PathBuf,

        #[command(flatten)]
        limits: LimitArgs,
    },
    /// Build the public scan index and static telemetry snapshots.
    BuildSite {
        /// Repository root containing data/, telemetry/, and Cargo.toml.
        #[arg(long, default_value = ".")]
        root: PathBuf,

        /// Destination directory uploaded to GitHub Pages.
        #[arg(long, default_value = "target/site")]
        output: PathBuf,

        /// Largest telemetry run published into a browser-readable snapshot.
        #[arg(long, default_value_t = 25_000)]
        max_published_events: usize,
    },
}

#[derive(Clone, Copy, Debug, Args)]
struct LimitArgs {
    /// Maximum number of parsed events; exceeding it fails rather than truncates.
    #[arg(long, default_value_t = 1_000_000)]
    max_events: usize,

    /// Maximum decompressed JSONL bytes; exceeding it fails rather than truncates.
    #[arg(long, default_value_t = 256 * 1024 * 1024)]
    max_uncompressed_bytes: u64,

    /// Maximum bytes in one JSONL record.
    #[arg(long, default_value_t = 4 * 1024 * 1024)]
    max_line_bytes: usize,
}

impl From<LimitArgs> for LoadLimits {
    fn from(value: LimitArgs) -> Self {
        Self {
            max_events: value.max_events,
            max_uncompressed_bytes: value.max_uncompressed_bytes,
            max_line_bytes: value.max_line_bytes,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            path,
            host,
            port,
            limits,
        } => {
            let trace = normalize(load(&path, limits.into())?);
            validate_representation(&trace)?;
            skill_telemetry_view::server::serve(trace, host, port)
        }
        Command::Inspect { path, limits } => {
            let trace = normalize(load(&path, limits.into())?);
            let graph = validate_representation(&trace)?;
            let summary = InspectSummary {
                run_id: trace.meta.run_id.as_deref(),
                source: &trace.meta.source,
                events: trace.events.len(),
                declared_events: trace.meta.declared_event_count,
                malformed_lines: trace.meta.malformed_lines,
                uncompressed_bytes: trace.meta.uncompressed_bytes,
                processes: trace.processes.len(),
                forks: trace.forks.len(),
                activity_nodes: graph.activity_node_count,
                categories: graph.facets.categories,
                transports: graph.facets.transports,
                directions: graph.facets.directions,
            };
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        Command::BuildSite {
            root,
            output,
            max_published_events,
        } => {
            let summary = skill_telemetry_view::site::build(&root, &output, max_published_events)?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
    }
}

fn validate_representation(
    trace: &skill_telemetry_view::TraceData,
) -> Result<skill_telemetry_view::model::GraphModel> {
    let graph = build_graph(trace, GraphSettings::default());
    ensure!(
        graph.represented_event_count == trace.events.len(),
        "graph represents {} of {} parsed events",
        graph.represented_event_count,
        trace.events.len()
    );
    Ok(graph)
}

#[derive(Serialize)]
struct InspectSummary<'a> {
    run_id: Option<&'a str>,
    source: &'a str,
    events: usize,
    declared_events: Option<u64>,
    malformed_lines: usize,
    uncompressed_bytes: u64,
    processes: usize,
    forks: usize,
    activity_nodes: usize,
    categories: BTreeMap<String, usize>,
    transports: BTreeMap<String, usize>,
    directions: BTreeMap<String, usize>,
}
