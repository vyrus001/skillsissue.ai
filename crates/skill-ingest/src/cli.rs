use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Continuously acquire and content-address agent skills without executing them.
#[derive(Debug, Parser)]
#[command(name = "skill-ingest", version, about)]
pub struct Cli {
    /// Root of the repository containing data/platforms.csv and the corpus.
    #[arg(long, env = "SKILLS_REPO_ROOT", default_value = ".", global = true)]
    pub repo_root: PathBuf,

    /// Reject a skill containing more filesystem entries than this.
    #[arg(long, default_value_t = 4_096, value_parser = parse_positive_u64, global = true)]
    pub max_files_per_skill: u64,

    /// Reject a skill whose regular-file payload exceeds this many bytes.
    #[arg(long, default_value_t = 67_108_864, value_parser = parse_positive_u64, global = true)]
    pub max_bytes_per_skill: u64,

    /// Reject an individual file larger than this many bytes.
    #[arg(long, default_value_t = 16_777_216, value_parser = parse_positive_u64, global = true)]
    pub max_file_bytes: u64,

    /// Reject trees deeper than this many path components.
    #[arg(long, default_value_t = 32, value_parser = parse_positive_usize, global = true)]
    pub max_depth: usize,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Poll every enabled platform once.
    Once(Limited),

    /// Poll every enabled platform forever, sleeping between completed polls.
    Loop(LoopArgs),

    /// Ingest a local fixture deterministically through the same validation path.
    IngestPath(IngestPathArgs),
}

#[derive(Clone, Debug, Args)]
pub struct Limited {
    /// Maximum number of previously unindexed skill directories to attempt.
    #[arg(long, default_value_t = 100, value_parser = parse_positive_usize)]
    pub limit: usize,
}

#[derive(Clone, Debug, Args)]
pub struct LoopArgs {
    /// Seconds between the end of one poll and the start of the next.
    #[arg(long, default_value_t = 300, value_parser = parse_positive_u64)]
    pub interval_seconds: u64,

    /// Maximum number of previously unindexed skill directories to attempt per poll.
    #[arg(long, default_value_t = 100, value_parser = parse_positive_usize)]
    pub limit: usize,
}

#[derive(Clone, Debug, Args)]
pub struct IngestPathArgs {
    /// A directory containing a SKILL.md or directories containing skills.
    pub path: PathBuf,

    /// Enabled platform ID to associate with this discovery.
    #[arg(long, default_value = "fixture:local")]
    pub platform_id: String,

    /// Test-only: allow an ID prefixed with `fixture:` that is not in the
    /// supported platform registry. This never applies to once/loop polling.
    #[arg(long, default_value_t = false)]
    pub allow_unregistered_platform: bool,

    /// Stable provenance URL. Avoid embedding a temporary fixture path when
    /// comparing discovery IDs across machines.
    #[arg(long, default_value = "local://ingest-path")]
    pub source_url: String,

    /// Immutable source revision or snapshot label; change it when local content changes.
    #[arg(long, default_value = "working-tree")]
    pub revision: String,

    /// Maximum number of previously unindexed skill directories to attempt.
    #[arg(long, default_value_t = 100, value_parser = parse_positive_usize)]
    pub limit: usize,
}

fn parse_positive_usize(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("{value:?} is not an unsigned integer"))
        .and_then(|value| {
            if value == 0 {
                Err("value must be greater than zero".to_owned())
            } else {
                Ok(value)
            }
        })
}

fn parse_positive_u64(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{value:?} is not an unsigned integer"))
        .and_then(|value| {
            if value == 0 {
                Err("value must be greater than zero".to_owned())
            } else {
                Ok(value)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_once_and_loop_contracts() {
        let once = Cli::try_parse_from(["skill-ingest", "once", "--limit", "7"]).unwrap();
        assert!(matches!(once.command, Command::Once(Limited { limit: 7 })));

        let looping = Cli::try_parse_from([
            "skill-ingest",
            "loop",
            "--interval-seconds",
            "10",
            "--limit",
            "4",
        ])
        .unwrap();
        assert!(matches!(
            looping.command,
            Command::Loop(LoopArgs {
                interval_seconds: 10,
                limit: 4
            })
        ));
    }

    #[test]
    fn rejects_zero_limits_and_intervals() {
        assert!(Cli::try_parse_from(["skill-ingest", "once", "--limit", "0"]).is_err());
        assert!(Cli::try_parse_from(["skill-ingest", "loop", "--interval-seconds", "0"]).is_err());
    }

    #[test]
    fn parses_explicit_fixture_platform_escape_hatch() {
        let parsed = Cli::try_parse_from([
            "skill-ingest",
            "ingest-path",
            "fixture-dir",
            "--platform-id",
            "fixture:test",
            "--allow-unregistered-platform",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::IngestPath(IngestPathArgs {
                allow_unregistered_platform: true,
                ..
            })
        ));
    }
}
