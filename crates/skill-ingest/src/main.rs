use std::thread;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::Parser;
use skill_ingest::{Cli, Command, IngestRequest, SecurityLimits, Worker};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let limits = SecurityLimits {
        max_files_per_skill: cli.max_files_per_skill,
        max_bytes_per_skill: cli.max_bytes_per_skill,
        max_file_bytes: cli.max_file_bytes,
        max_depth: cli.max_depth,
    };
    let worker = Worker::new(&cli.repo_root, limits)?;
    match cli.command {
        Command::Once(args) => {
            let summary = worker.run_once(args.limit)?;
            print_summary(&summary)?;
            finish_summary(&summary, args.allow_source_errors)
        }
        Command::IngestPath(args) => {
            let summary = worker.ingest_path(IngestRequest {
                path: args.path,
                platform_id: args.platform_id,
                allow_unregistered_platform: args.allow_unregistered_platform,
                source_url: args.source_url,
                revision: args.revision,
                limit: args.limit,
            })?;
            print_summary(&summary)?;
            fail_on_errors(&summary)
        }
        Command::Loop(args) => loop {
            match worker.run_once(args.limit) {
                Ok(summary) => {
                    print_summary(&summary)?;
                    if summary.has_errors() {
                        eprintln!(
                            "ingestion poll completed with {} error(s); retrying after interval",
                            summary.errors.len()
                        );
                    }
                }
                Err(error) => {
                    eprintln!("ingestion poll failed: {error:#}; retrying after interval");
                }
            }
            thread::sleep(Duration::from_secs(args.interval_seconds));
        },
    }
}

fn print_summary(summary: &skill_ingest::IngestSummary) -> Result<()> {
    println!("{}", serde_json::to_string(summary)?);
    Ok(())
}

fn fail_on_errors(summary: &skill_ingest::IngestSummary) -> Result<()> {
    if summary.has_errors() {
        bail!(
            "ingestion completed with {} rejected or failed source(s)",
            summary.errors.len()
        );
    }
    Ok(())
}

fn finish_summary(summary: &skill_ingest::IngestSummary, allow_source_errors: bool) -> Result<()> {
    if allow_source_errors && summary.has_errors() {
        eprintln!(
            "ingestion retained a validated partial result with {} source error(s)",
            summary.errors.len()
        );
        return Ok(());
    }
    fail_on_errors(summary)
}

#[cfg(test)]
mod tests {
    use super::finish_summary;

    #[test]
    fn source_error_policy_distinguishes_strict_and_validated_partial_runs() {
        let mut summary = skill_ingest::IngestSummary::default();
        summary.errors.push("transient source failure".to_string());

        assert!(finish_summary(&summary, true).is_ok());
        assert!(finish_summary(&summary, false).is_err());
    }
}
