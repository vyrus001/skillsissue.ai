use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use skill_eval::{EvaluateRequest, PrepareRequest, evaluate, prepare};

#[derive(Debug, Parser)]
#[command(
    name = "skill-eval",
    version,
    about = "Generate and score bounded SkillJect detonation fixtures"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build an isolated repository workspace containing deterministic fixtures.
    Prepare {
        #[arg(long, default_value = "SkillJect")]
        skillject_root: PathBuf,
        #[arg(long, default_value = "config")]
        config_root: PathBuf,
        #[arg(long, default_value = "evaluation/workspace")]
        workspace: PathBuf,
        #[arg(long, default_value = "evaluation/results/manifest.csv")]
        manifest: PathBuf,
        #[arg(long)]
        skillject_commit: String,
        #[arg(long, default_value_t = 4)]
        limit: usize,
    },
    /// Score repository ledgers against the generated fixture manifest.
    Evaluate {
        #[arg(long, default_value = "evaluation/workspace")]
        workspace: PathBuf,
        #[arg(long, default_value = "evaluation/results/manifest.csv")]
        manifest: PathBuf,
        #[arg(long, default_value = "evaluation/results/evaluation.csv")]
        output: PathBuf,
        #[arg(long, default_value = "evaluation/results/confusion.csv")]
        confusion: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Prepare {
            skillject_root,
            config_root,
            workspace,
            manifest,
            skillject_commit,
            limit,
        } => {
            let count = prepare(&PrepareRequest {
                skillject_root,
                config_root,
                workspace,
                manifest,
                skillject_commit,
                limit,
            })?;
            println!("prepared={count}");
        }
        Command::Evaluate {
            workspace,
            manifest,
            output,
            confusion,
        } => {
            let summary = evaluate(&EvaluateRequest {
                workspace,
                manifest,
                output,
                confusion,
            })?;
            println!(
                "evaluated={} passed={} failed={}",
                summary.total, summary.passed, summary.failed
            );
        }
    }
    Ok(())
}
