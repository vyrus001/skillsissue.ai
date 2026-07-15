use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use skill_analyze::{run_once, AnalyzerPaths};

#[derive(Debug, Parser)]
#[command(name = "skill-analyze", version, about)]
struct Cli {
    /// Detonation run ledger.
    #[arg(
        long = "runs-csv",
        visible_alias = "runs",
        global = true,
        default_value = "data/runs.csv"
    )]
    runs_csv: PathBuf,

    /// Per-run assessment ledger.
    #[arg(
        long = "assessments-csv",
        visible_alias = "assessments",
        global = true,
        default_value = "data/assessments.csv"
    )]
    assessments_csv: PathBuf,

    /// Finding ledger.
    #[arg(
        long = "findings-csv",
        visible_alias = "findings",
        global = true,
        default_value = "data/findings.csv"
    )]
    findings_csv: PathBuf,

    /// Runtime platform-discovery evidence ledger.
    #[arg(
        long = "platform-evidence-csv",
        visible_alias = "platform-evidence",
        global = true,
        default_value = "data/platform_evidence.csv"
    )]
    platform_evidence_csv: PathBuf,

    /// Skill platform registry.
    #[arg(
        long = "platforms-csv",
        visible_alias = "platforms",
        global = true,
        default_value = "data/platforms.csv"
    )]
    platforms_csv: PathBuf,

    /// Information-flow policy. Safe built-in defaults are used when absent.
    #[arg(
        long = "policy-config",
        global = true,
        default_value = "config/policy.toml"
    )]
    policy_config: PathBuf,

    /// Platform-discovery thresholds and indicators. Conservative defaults are used when absent.
    #[arg(
        long = "discovery-config",
        global = true,
        default_value = "config/discovery.toml"
    )]
    discovery_config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Analyze pending completed detonation runs once.
    Once {
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Continuously poll for pending completed detonation runs.
    Loop {
        #[arg(long, default_value_t = 30)]
        interval_seconds: u64,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let paths = AnalyzerPaths {
        runs_csv: cli.runs_csv,
        assessments_csv: cli.assessments_csv,
        findings_csv: cli.findings_csv,
        platform_evidence_csv: cli.platform_evidence_csv,
        platforms_csv: cli.platforms_csv,
        policy_config: cli.policy_config,
        discovery_config: cli.discovery_config,
    };

    match cli.command {
        Command::Once { limit } => {
            let summary = run_once(&paths, limit)?;
            println!(
                "analyzed={} findings={} platform_candidates={} unknown_platform_interactions={} unknown_platform_count={}",
                summary.analyzed,
                summary.findings,
                summary.platform_candidates,
                summary.unknown_platform_interactions,
                summary.unknown_platform_count
            );
        }
        Command::Loop {
            interval_seconds,
            limit,
        } => loop {
            match run_once(&paths, limit) {
                Ok(summary) => println!(
                    "analyzed={} findings={} platform_candidates={} unknown_platform_interactions={} unknown_platform_count={}",
                    summary.analyzed,
                    summary.findings,
                    summary.platform_candidates,
                    summary.unknown_platform_interactions,
                    summary.unknown_platform_count
                ),
                Err(error) => eprintln!("analysis pass failed: {error:#}"),
            }
            std::thread::sleep(Duration::from_secs(interval_seconds));
        },
    }

    Ok(())
}
