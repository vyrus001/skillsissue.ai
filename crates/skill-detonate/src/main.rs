use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use skill_detonate::{
    DetonationRequest, DetonatorConfig, ShardSpec, detonate, ensure_docker_preflight,
    pending_skills_sharded, policy_digest, read_runs, read_skills, resolve_target_image,
    write_runs_atomic,
};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "skill-detonate",
    version,
    about = "eBPF-backed isolated skill detonation loop"
)]
struct Cli {
    #[arg(long, default_value = ".", global = true)]
    repo_root: PathBuf,
    #[arg(long, default_value = "config/detonator.toml", global = true)]
    config: PathBuf,
    #[arg(long, default_value = "config/policy.toml", global = true)]
    policy: PathBuf,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Validate Docker, Linux eBPF/BTF, cgroup v2, and the sandbox image.
    Preflight {
        #[arg(long)]
        allow_untraced: bool,
    },
    /// Process a bounded batch and exit (the GitHub Actions mode).
    Once {
        #[arg(long, default_value_t = 1)]
        limit: usize,
        /// Zero-based worker partition. Must be less than --shard-count.
        #[arg(long, default_value_t = 0)]
        shard_index: u32,
        /// Total number of disjoint worker partitions.
        #[arg(long, default_value_t = 1)]
        shard_count: u32,
        #[arg(long)]
        allow_untraced: bool,
    },
    /// Repeatedly process bounded batches (for disposable long-lived runners).
    Loop {
        #[arg(long, default_value_t = 300)]
        interval_seconds: u64,
        #[arg(long, default_value_t = 1)]
        limit: usize,
        /// Zero-based worker partition. Must be less than --shard-count.
        #[arg(long, default_value_t = 0)]
        shard_index: u32,
        /// Total number of disjoint worker partitions.
        #[arg(long, default_value_t = 1)]
        shard_count: u32,
        #[arg(long)]
        allow_untraced: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = cli
        .repo_root
        .canonicalize()
        .context("canonicalize repository root")?;
    let mut config = DetonatorConfig::load(&root.join(&cli.config))?;
    match cli.command {
        Commands::Preflight { allow_untraced } => {
            ensure_docker_preflight(&config, !allow_untraced)?;
            resolve_target_image(&mut config)?;
            println!("target_image_digest={}", config.target_image_digest);
        }
        Commands::Once {
            limit,
            shard_index,
            shard_count,
            allow_untraced,
        } => {
            let shard = ShardSpec::new(shard_index, shard_count)?;
            ensure_docker_preflight(&config, !allow_untraced)?;
            resolve_target_image(&mut config)?;
            run_once(&root, &cli.policy, &config, limit, shard, allow_untraced)?;
        }
        Commands::Loop {
            interval_seconds,
            limit,
            shard_index,
            shard_count,
            allow_untraced,
        } => {
            let shard = ShardSpec::new(shard_index, shard_count)?;
            ensure_docker_preflight(&config, !allow_untraced)?;
            resolve_target_image(&mut config)?;
            loop {
                run_once(&root, &cli.policy, &config, limit, shard, allow_untraced)?;
                thread::sleep(Duration::from_secs(interval_seconds));
            }
        }
    }
    Ok(())
}

fn run_once(
    root: &Path,
    policy_relative: &Path,
    config: &DetonatorConfig,
    limit: usize,
    shard: ShardSpec,
    allow_untraced: bool,
) -> Result<()> {
    if limit == 0 {
        bail!("--limit must be greater than zero");
    }
    let policy_path = root.join(policy_relative);
    let digest = policy_digest(&policy_path)?;
    let skills_path = root.join("data/skills.csv");
    let runs_path = root.join("data/runs.csv");
    // Snapshot registries under a short lock. The expensive, untrusted run is
    // deliberately outside it so acquisition and analysis loops stay independent.
    let pending = {
        let _lock = skills_core::WorkspaceLock::acquire(root)?;
        let skills = read_skills(&skills_path)?;
        let runs = read_runs(&runs_path)?;
        pending_skills_sharded(skills, &runs, &digest, config, limit, shard)
    };
    let mut failures = Vec::new();
    for skill in pending {
        let result = detonate(DetonationRequest {
            skill,
            repo_root: root.to_path_buf(),
            policy_path: policy_path.clone(),
            config: config.clone(),
            allow_untraced,
        })?;
        println!("{} {}", result.record.run_id, result.record.status);
        {
            let _lock = skills_core::WorkspaceLock::acquire(root)?;
            let mut runs = read_runs(&runs_path)?;
            if !runs.iter().any(|run| run.run_id == result.record.run_id) {
                runs.push(result.record);
                write_runs_atomic(&runs_path, &runs)?;
            }
        }
        if let Some(failure) = result.failure {
            failures.push(failure);
        }
    }
    if !failures.is_empty() {
        bail!(
            "{} detonation attempt(s) failed: {}",
            failures.len(),
            failures.join(" | ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn once_cli_accepts_explicit_shard() {
        let cli = Cli::try_parse_from([
            "skill-detonate",
            "once",
            "--limit",
            "7",
            "--shard-index",
            "2",
            "--shard-count",
            "8",
        ])
        .unwrap();
        match cli.command {
            Commands::Once {
                limit,
                shard_index,
                shard_count,
                allow_untraced,
            } => {
                assert_eq!(limit, 7);
                assert_eq!(shard_index, 2);
                assert_eq!(shard_count, 8);
                assert!(!allow_untraced);
            }
            _ => panic!("expected once command"),
        }
    }

    #[test]
    fn loop_cli_defaults_to_one_unsharded_worker() {
        let cli = Cli::try_parse_from(["skill-detonate", "loop"]).unwrap();
        match cli.command {
            Commands::Loop {
                shard_index,
                shard_count,
                ..
            } => {
                assert_eq!(shard_index, 0);
                assert_eq!(shard_count, 1);
            }
            _ => panic!("expected loop command"),
        }
    }
}
